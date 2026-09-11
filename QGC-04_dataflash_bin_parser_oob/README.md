# QGC-04 — APM DataFlash `.bin` log parser: out-of-bounds read and integer underflow on untrusted `FMT` records

| Field | Value |
|---|---|
| **Product** | QGroundControl |
| **Severity** | **MEDIUM** — CVSS 3.1 **6.5** `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` |
| **CWE** | CWE-125 (out-of-bounds read) · CWE-191 (integer underflow) |
| **Affected** | `>= 5.1.0, <= 5.1.4` and `master`. The parser does not exist in `v5.0.8` or `v4.4.4` |
| **Fixed in** | nothing yet |
| **Verified** | master `4fd86f9ae` (2026-09-10). Every line below is unchanged since `41bebb2` |
| **Interaction** | The operator downloads a log and opens it in **Analyze → Log Viewer** or **Analyze → GeoTag** |
| **Platform** | Cross-platform |
| **Status** | CWE-191 live-confirmed 2026-08-26 on Windows 11: a vehicle-hosted log served over MAVLink-FTP pinned one core at 100% indefinitely, and the burn survived closing the application. CWE-125 silent in-page over-read confirmed on macOS. The page-crossing crash and an ASan build are not yet tested |
| **Advisory** | [GHSA-xr3f-6cgq-q3v7](https://github.com/mavlink/qgroundcontrol/security/advisories/GHSA-xr3f-6cgq-q3v7) |
| **Fix** | [`fix/qgc-04-dataflash-fmt-validation`](https://github.com/nicholasaleks/qgroundcontrol/tree/fix/qgc-04-dataflash-fmt-validation) against `4fd86f9ae`, no PR opened yet |

---

## Demo

<a href="https://www.youtube.com/watch?v=uwUmLvNIBYQ">
  <img src="https://img.youtube.com/vi/uwUmLvNIBYQ/maxresdefault.jpg" alt="QGC-04 — vehicle-hosted DataFlash log to permanent CPU denial of service" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=uwUmLvNIBYQ)**

---

## Summary

QGroundControl's ArduPilot DataFlash (`.bin`) log parser trusts two attacker-controlled,
**unreconciled** size fields inside each log's `FMT` (format-definition) records:

1. **Out-of-bounds read (CWE-125).** `parseMessage()` walks each format string and, for every
   field, reads a fixed number of bytes determined *only* by the format character — up to **64
   bytes** for an `'a'`/`'Z'` field — accumulating an `offset` with **no bound against the actual
   message payload length**. A short message whose format string declares a 64-byte field reads
   ~63 bytes past the end of the record. The buffer is a memory-mapped file, so the over-read reads either the
   **zero-filled tail of the last page** (silent, no observable effect) or **faults into an
   unmapped page** (SIGSEGV/SIGBUS). It cannot reach adjacent heap: `LogViewerDataFlashParser.cc`
   maps the file and wraps it with `QByteArray::fromRawData(raw, fileSize)`, which does **not**
   copy, and `GeoTagController.cc` maps too (its `readAll()` heap path runs only if `map()` fails).
   **There is therefore no information-disclosure impact** — an earlier version of this write-up
   claimed one, and that claim was wrong.

2. **Integer underflow (CWE-191).** `iterateMessages()` computes `payloadSize = fmt.length - 3`.
   `fmt.length` is fully attacker-controlled; with `length` ∈ {0,1,2} the result is a **negative
   `int`**. The value that matters is **`length == 0`**: both loops do `pos += 3` to consume the
   header and then `pos += payloadSize`, so `-3` is exactly **net zero movement** and the same
   record is re-parsed forever. `length == 1` gives net **+1** — a byte-at-a-time crawl that still
   terminates. Only `0` is a true non-advancing loop, and it bites in `parseFmtMessages` (the format
   scan) before a single message is iterated. The `pos + payloadSize > size` guard then evaluates *false* (the over-large-read check
   never fires), the callback runs with a **negative size**, and `pos += payloadSize` **rewinds the
   cursor** — a non-advancing / backward loop (**stall / livelock-style DoS**).

Both sinks are reachable when an operator opens a vehicle-supplied or tampered `.bin` log in the
**Analyze → GeoTag** tool or the **Log Viewer** in a default build. No exploit primitive beyond
"open a malicious log" is required.

---

## Root cause

### 1. A single format character can demand 64 bytes

```cpp
// src/Utilities/Parsing/APMDataFlash/APMDataFlashUtility.cc:15-35
int formatCharSize(char c)
{
    switch (c) {
    case 'b': case 'B': case 'M':                                            return 1;
    case 'h': case 'H': case 'c': case 'C': case 'g':                        return 2;
    case 'i': case 'I': case 'e': case 'E': case 'L': case 'f':              return 4;
    case 'd': case 'q': case 'Q':                                            return 8;
    case 'n':                                                                return 4;
    case 'N':                                                                return 16;
    case 'Z': case 'a':  // Z = 64-char string, a = 64-byte array            return 64;   // :31
    default:                                                                 return 0;
    }
}
```

### 2. `offset` accumulates from the format string, with nothing to check it against

```cpp
// src/Utilities/Parsing/APMDataFlash/APMDataFlashUtility.cc:166-185
QMap<QString, QVariant> parseMessage(const char *data, const MessageFormat &fmt)
{
    QMap<QString, QVariant> result;
    int offset = 0;

    for (int i = 0; i < fmt.format.length() && i < fmt.columns.size(); ++i) {
        const char formatChar = fmt.format.at(i).toLatin1();
        const QString &columnName = fmt.columns.at(i);

        const int size = formatCharSize(formatChar);
        if (size == 0) {
            continue;
        }

        result[columnName] = parseValue(data + offset, formatChar);   // unchecked read
        offset += size;                                               // :181  from the format string only
    }

    return result;
}
```

The loop bound and the widths both come from the attacker's `FMT` record. There is no parameter for,
and no check against, the number of payload bytes actually available — the caller's `payloadSize` is
discarded at the call site.

### 3. The widest reads are unconditional

```cpp
// src/Utilities/Parsing/APMDataFlash/APMDataFlashUtility.cc:157-160
case 'Z':
    return QString::fromLatin1(data, qstrnlen(data, 64));   // up to a 64-byte scan
case 'a':
    return QByteArray(data, 64);                            // :160  unconditional 64-byte copy
```

### 4. `iterateMessages` — the underflow, the bypassed guard, and the rewind

```cpp
// src/Utilities/Parsing/APMDataFlash/APMDataFlashUtility.cc:275-318
while (pos + 3 <= size) {
    if (static_cast<uint8_t>(data[pos]) != kHeaderByte1 ||
        static_cast<uint8_t>(data[pos + 1]) != kHeaderByte2) {
        ++pos;
        continue;
    }

    const uint8_t msgType = static_cast<uint8_t>(data[pos + 2]);
    pos += 3;
    ...
    const int payloadSize = fmt.length - 3;      // :299  uint8_t promoted to int, negative for length < 3

    if (pos + payloadSize > size) {              // :301  false when payloadSize is negative
        break;
    }

    ++count;
    if (!callback(msgType, data + pos, payloadSize, fmt)) {   // callback receives a negative size
        break;
    }

    pos += payloadSize;                          // cursor moves backward
```

### 5. The same underflow in the format scan, which runs first

```cpp
// src/Utilities/Parsing/APMDataFlash/APMDataFlashUtility.cc:247-262
    const uint8_t msgType = static_cast<uint8_t>(data[pos + 2]);
    pos += 3;
    ...
    } else {
        // Skip message if we know its length
        if (formats.contains(msgType)) {
            pos += formats[msgType].length - 3;  // :260  same underflow, and no guard at all here
        } else {
            ++pos;
        }
    }
```

`parseFmtMessages` has no bounds guard on this addition, and it runs before any message is iterated.
The attacker controls record ordering, so registering a `length = 0` format and then emitting one
record of that type is enough to hang the format scan.

### 6. Two size sources that are never reconciled

`parseFmtMessages` (`:260`) and `iterateMessages` (`:299`) derive the payload window from
`fmt.length - 3`. `parseMessage` derives its read extent from the format string via `formatCharSize`.
These are independent, attacker-chosen numbers and nothing compares them. An `FMT` can advertise
`length = 4`, so `iterateMessages` hands out a 1-byte payload window, while `format = "a"` makes
`parseMessage` read 64 bytes — a guaranteed ~63-byte over-read with the cursor still considered valid.

---

## Taint trace

```
[log file]  attacker controls every byte, including each FMT record's length and format
   |
   |  delivered by: a malicious vehicle serving @MAV_LOG or /APM/logs/*.BIN over MAVLink-FTP,
   |  a tampered .bin handed over out of band, or a MITM substituting bytes mid-download
   v
QFile::map()  ->  QByteArray::fromRawData(raw, fileSize)     LogViewerDataFlashParser.cc:261,283
                                                             APMDataFlashLogParser.cc:394,411
                                                             GeoTagController.cc:775  (readAll() at :786 only if map() fails)
   v
APMDataFlashUtility::parseFmtMessages(data, size, formats)    :228
   |-- pos += 3                                               :247
   '-- pos += formats[msgType].length - 3                     :260   <- UNDERFLOW, no guard, net 0 when length==0
   v                                                                    ===> FORMAT SCAN HANGS
APMDataFlashUtility::iterateMessages(data, size, formats, cb) :275
   |-- payloadSize = fmt.length - 3                           :299   <- UNDERFLOW
   |-- if (pos + payloadSize > size) break                    :301   <- guard false when negative
   |-- callback(msgType, data + pos, payloadSize, fmt)                <- negative size handed out
   '-- pos += payloadSize                                             <- CURSOR REWINDS
   v
APMDataFlashUtility::parseMessage(data, fmt)                  :166
   |-- offset += formatCharSize(formatChar)                   :181   <- from the format string, unbounded
   '-- parseValue(data + offset, formatChar)                  :157/:160  up to 64 bytes
                                                                    ===> OUT-OF-BOUNDS READ
```

Three consumers reach the parser: `src/AnalyzeView/LogViewer/APMDataFlash/LogViewerDataFlashParser.cc`
(`:286`, `:318`), `src/AnalyzeView/LogViewer/APMDataFlash/APMDataFlashLogParser.cc` (`:414`, `:447`),
and `src/AnalyzeView/GeoTag/DataFlashParser.cc` (`:91`, `:113`).

---

## Impact

The realised impact is availability only, and it is worth being precise about why.

**Denial of service, confirmed.** A `length = 0` format record makes the parse loop stop advancing.
On Windows this pinned one core at 100% indefinitely, with QGC reporting no error and the UI still
responding, and the loop **survived closing the application** — the process was gone from the Apps
list while remaining a top CPU consumer, recoverable only by killing it.

**No information disclosure.** The over-read cannot reach adjacent heap. All three consumers
memory-map the file and wrap it with `QByteArray::fromRawData`, which does not copy, so a read past
the record lands either in the zero-filled tail of the final page — silent, no observable effect — or
in an unmapped page, which faults. Nothing is returned to the attacker either way. The one exception
is `GeoTagController.cc:786`, a `readAll()` fallback that runs only when `map()` fails; on that path
the buffer is heap, so an over-read there could touch adjacent allocations.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Non-terminating parse, CPU exhaustion | **Yes** | `length == 0` gives net zero cursor movement; confirmed on Windows 11 |
| Survives closing the application | **Yes** | observed; the parse runs on a worker that outlives the window |
| Out-of-bounds read past the record | **Yes** | `offset` is bounded only by the declared format string |
| Reads adjacent heap | **No** | the buffer is a memory-mapped file wrapped with `fromRawData`, except the `readAll()` fallback |
| Information disclosure | **No** | nothing is echoed back to the attacker |
| Crash from crossing into an unmapped page | plausible, **not tested** | requires the record to sit within 64 bytes of the final page boundary |
| Memory corruption or negative indexing | **No** | `pos` is at least 3 when the subtraction happens, so it never goes negative |
| Code execution | **No** | read-only over-read, no write primitive |

---

## Version scope

| Version | `APMDataFlashUtility.cc` | Affected |
|---|---|---|
| `master` `4fd86f9ae` | present | **yes** |
| `v5.1.4`, `v5.1.0` | present | **yes** |
| `v5.0.8` | absent | no |
| `v4.4.4` | absent | no |

The parser arrived with the 5.1 log-viewer work, so this is a 5.1-and-later issue. Every line
citation above is identical at `41bebb2`, `d62dcff` and `4fd86f9ae` — the file has not moved.

---

## Reproduction

Authorized bench only. Requires `pymavlink`.

```bash
cd poc
python3 make_malicious_bin.py                    # writes the crafted .bin logs
python3 poc_QGC04_onboard_log_dos.py             # serves them over MAVLink-FTP at @MAV_LOG
```

Connect QGC to the harness, open **Analyze → Onboard Logs**, refresh, download, then open the
downloaded log in **Analyze → Log Viewer**. The underflow log stays on "Loading…" forever with one
core saturated.

`make_malicious_bin.py` writes four logs, each isolating one behaviour:

| File | `FMT` | Expected |
|---|---|---|
| `underflow_hang.bin` | `length = 0`, payload `-3`, net **0** | infinite loop, one core at 100% |
| `underflow_stall.bin` | `length = 1`, payload `-2`, net **+1** | slow crawl, terminates |
| `oob_overread.bin` | `length = 4`, `format = "a"` | silent 64-byte read from a 1-byte window, no visible effect |
| `oob_overread_pagecross.bin` | same, padded to 16 KiB | the record sits near a page boundary, so the over-read should fault |

Only `underflow_hang.bin` is confirmed end to end. `oob_overread.bin` was observed to be silent on
macOS, which is the expected outcome when the read lands in the zero-filled tail of a mapped page.
`oob_overread_pagecross.bin` is built to push the read into an unmapped page but has not been run,
and there is no ASan build here, which is why the crash is listed as untested rather than as a
result.

The crafted logs are regenerable and are not committed.

---

## Fix scope

The branch adds one condition, at the point where a format is registered in
`parseFmtMessages`: a record is accepted only when `length >= 3` and
`calculatePayloadSize(format) <= length - 3`.

That is the only place both sizes are known together, and checking there fixes all three
behaviours at once. `length - 3` can no longer be negative, so neither skip path rewinds and the
`pos + payloadSize > size` guard stops being bypassable. The format string can no longer declare more
bytes than the record holds, which bounds the offset `parseMessage()` accumulates.

`parseMessage()` is deliberately untouched. Giving it the payload length means changing its signature
and both call sites, which is a wider change than the defect needs.
