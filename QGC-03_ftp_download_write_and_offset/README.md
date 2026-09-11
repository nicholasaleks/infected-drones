# QGC-03 — MAVLink-FTP client: vehicle-supplied listing filename → path-traversal local write, and an unbounded burst offset → disk fill

| Field | Value |
|---|---|
| **Product** | QGroundControl |
| **Severity** | **HIGH** — traversal, CVSS 3.1 **7.1** `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L`. Disk fill **5.3** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`, zero-click but source-verified only |
| **CWE** | CWE-22 (path traversal, write is `WriteOnly \| Truncate`) · CWE-770 (allocation without limits) |
| **Affected** | **Traversal:** `>= 5.1.0, <= 5.1.4` and `master`. **Disk fill:** every version checked, including `v5.0.8` and `v4.4.4` |
| **Fixed in** | nothing yet |
| **Verified** | master `4fd86f9ae` (2026-09-10), plus tags `v5.1.4`, `v5.1.0`, `v5.0.8`, `v4.4.4` |
| **Interaction** | **Traversal:** one **download** click on the Scripting page. **Disk fill: none**, it rides the automatic `param.pck` fetch on connect |
| **Status** | Traversal live-confirmed 2026-08-26 on macOS (write to `/tmp`) and Windows 11 (`.bat` into the per-user Startup folder, executed at next logon). Disk fill is source-verified, not bench-tested |
| **Advisory** | [GHSA-9q69-3f77-jhw8](https://github.com/mavlink/qgroundcontrol/security/advisories/GHSA-9q69-3f77-jhw8) |
| **Fix** | traversal: [`fix/qgc-03-ftp-download-filename`](https://github.com/nicholasaleks/qgroundcontrol/tree/fix/qgc-03-ftp-download-filename) against `e6aeacb96`, no PR opened yet. Offset: left to the maintainers, see below |

---

## Demo

<a href="https://www.youtube.com/watch?v=hWIozA_k_pg">
  <img src="https://img.youtube.com/vi/hWIozA_k_pg/maxresdefault.jpg" alt="QGC-03 — MAVLink-FTP listing traversal to Startup-folder persistence" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=hWIozA_k_pg)**

---

## Summary

Two separate defects in QGC's MAVLink-FTP client, sharing one root cause: values that arrive from the
vehicle are used to drive local file I/O without validation.

**Traversal.** The ArduPilot Scripting page lists `/APM/scripts/` over MAVLink-FTP and turns each
returned filename into a download button. On click, QGC passes the vehicle-supplied listing filename
verbatim as the *local* output filename. The QML strips only the 1-byte type prefix and the
`\t<size>` suffix, never `/` or `..`, and the C++ sink builds the output path with
`QDir::filePath()`, which does not collapse `..`. A listing entry named `../../../../tmp/EVIL.lua`
writes outside the chosen save folder. Nothing constrains the content or extension either, so the
same primitive delivers a `.bat` into the Windows Startup folder, a `.lua` into an autoloaded scripts
directory, or a `.plan` the operator later opens and flies.

Because the traversed path is opened `WriteOnly | Truncate` on the OpenFileRO ACK, **before a single
body byte is read**, aiming the traversal at an existing file empties it even if the transfer then
fails. That is a destruction primitive needing no payload at all.

**Disk fill.** Separately, the burst-download handler seeks to a `uint32_t` offset taken straight off
the wire and writes there, with no bound and no comparison against the expected file size. A single
ACK claiming `offset = 0xFFFFFFF0` extends the output file to roughly 4 GiB. This one needs **no
operator interaction and no Scripting page**: it rides the `param.pck` download QGC issues
automatically on every connect, so it reaches every version, not just 5.1.

---

## Root cause

### 1. Listing entries are parsed with no character filtering

```cpp
// src/Vehicle/FTPManager.cc:975-981
const char* curDataPtr = (const char*)ackOrNak->data;
while (curDataPtr < (const char*)ackOrNak->data + ackOrNak->hdr.size) {
    QString dirEntry = curDataPtr;
    curDataPtr += dirEntry.size() + 1;
    _listDirectoryState.rgDirectoryList.append(dirEntry);      // as-is
    _listDirectoryState.expectedOffset++;
}
```

No check for `/`, `..`, control characters, or length. The entries reach QML verbatim via
`FTPController::_handleDirectoryComplete` and the `directoryEntries` property.

### 2. The QML strips the type byte and the size, but not the path

```qml
// src/AutoPilotPlugins/Common/ScriptingComponent.qml:36-40
let filenameEntries = []
for (let i=0; i<rawEntries.length; i++) {
    filenameEntries.push(rawEntries[i].slice(1).split("\t")[0])
}
return filenameEntries
```

`slice(1)` removes the 1-char `F` type prefix; `split("\t")[0]` removes the `\t<size>` suffix. `/`
and `..` survive. That string becomes `fileToDownload` and is passed as the **local** filename:

```qml
// src/AutoPilotPlugins/Common/ScriptingComponent.qml:273
if (!ftpController.downloadFile(root.fullRemotePath(fileToDownload), folder, fileToDownload)) {
```

The page already has the sanitiser it needs, `fileNameFromPath()`, and applies it correctly on the
**upload** path at `:243`. The download path does not call it.

### 3. The explicit-filename branch skips the basename strip

```cpp
// src/Vehicle/FTPManager.cc:65-76
int lastDirSlashIndex;
for (lastDirSlashIndex=_downloadState.fullPathOnVehicle.size()-1; lastDirSlashIndex>=0; lastDirSlashIndex--) {
    if (_downloadState.fullPathOnVehicle[lastDirSlashIndex] == '/') { break; }
}
lastDirSlashIndex++;

if (fileName.isEmpty()) {
    _downloadState.fileName = _downloadState.fullPathOnVehicle.right(...);   // stripped to a basename
} else {
    _downloadState.fileName = fileName;                                     // :76  stored verbatim
}
```

The Scripting page always supplies `fileName`, so `:76` runs and the slash-stripping above is skipped
entirely.

### 4. The write sink does not collapse `..`, and truncates before any body byte arrives

```cpp
// src/Vehicle/FTPManager.cc:790-791
_downloadState.file.setFileName(_downloadState.toDir.filePath(_downloadState.fileName));
if (_downloadState.file.open(QFile::WriteOnly | QFile::Truncate)) {
```

`QDir::filePath()` returns `toDir + "/" + name` without resolving `..`; only `QDir::cleanPath` or
`canonicalFilePath` would. This runs in `_openFileROAckOrNak`, so the `Truncate` fires on the
OpenFileRO ACK. `:333` builds the *reported* path the same way, which is why QGC announces success
against a path it never validated.

### 5. The burst offset is unbounded

```cpp
// src/Vehicle/FTPManager.cc:851-856
if (ackOrNak->hdr.offset != _downloadState.expectedOffset) {
    if (ackOrNak->hdr.offset > _downloadState.expectedOffset) {
        MissingData_t missingData;
        missingData.offset          = _downloadState.expectedOffset;
        missingData.cBytesMissing   = ackOrNak->hdr.offset - _downloadState.expectedOffset;
        _downloadState.rgMissingData.append(missingData);
    }
    ...
}

// src/Vehicle/FTPManager.cc:867-868
_downloadState.file.seek(ackOrNak->hdr.offset);
int bytesWritten = _downloadState.file.write((const char*)ackOrNak->data, ackOrNak->hdr.size);
```

`hdr.offset` is a `uint32_t` from the wire. Nothing bounds it, and nothing compares it against
`_downloadState.fileSize` (which is itself `openFileLength`, also vehicle-supplied). Seeking past
end-of-file and writing extends the file to `offset + size`, so one ACK carrying ~239 bytes at
`offset = 0xFFFFFFF0` produces a ~4 GiB file. `:1108-1109` is a second, identical seek-and-write in
the fill-missing handler.

The recorded hole compounds it: `cBytesMissing` can be nearly 4 GiB, and
`_fillMissingBlocksBegin` re-requests it in `sizeof(request.data)` chunks of ~239 bytes, so QGC also
commits to millions of round trips.

**Filesystem nuance, and the reason this is labelled source-verified rather than measured.** Whether
that 4 GiB is *allocated* depends on the filesystem. NTFS zero-fills a write past end-of-file, so on
Windows the space is really consumed. APFS and ext4 create a sparse file, so the logical size is
4 GiB while few blocks are used. The logical-size explosion and the round-trip cost hold everywhere;
the actual disk consumption is a Windows claim.

---

## Taint trace

```
[wire] MAVFTP ListDirectory ACK -> NUL-separated entry strings
   |    FTPManager.cc:975-981   QString dirEntry = curDataPtr -> rgDirectoryList.append()   (no filtering)
   v
FTPController::_handleDirectoryComplete -> _directoryEntries -> QML directoryEntries property
   |    ScriptingComponent.qml:36-40   slice(1).split("\t")[0]        (strips type byte + size only)
   |    ScriptingComponent.qml:172     fileToDownload = modelData     (raw, keeps '/' and '..')
   v
operator clicks download
   |    ScriptingComponent.qml:273     downloadFile(remotePath, folder, fileToDownload)
   |                                                              ^^^^^^^^^^^^^^ local filename
   v
FTPController::downloadFile -> FTPManager::download(..., fileName)
   |    FTPManager.cc:76      _downloadState.fileName = fileName    (basename strip at :65-73 bypassed)
   v
FTPManager.cc:790  toDir.filePath(fileName)   (QDir does not collapse '..')
FTPManager.cc:791  open(WriteOnly | Truncate) on the OpenFileRO ACK, before any body byte
   ===> WRITE AND TRUNCATE OUTSIDE THE CHOSEN FOLDER


[wire] MAVFTP BurstReadFile ACK -> hdr.offset (uint32_t), hdr.size
   |    FTPManager.cc:851-856  cBytesMissing = offset - expectedOffset      (up to ~4 GiB)
   v
FTPManager.cc:867-868  file.seek(offset); file.write(data, size)            (no bound, no size check)
FTPManager.cc:1108-1109  same seek-and-write in the fill-missing handler
   ===> FILE EXTENDED TO offset + size

   reached without any click via ParameterManager's automatic download of
   "@PARAM/param.pck?withdefaults=1" on connect (ParameterManager.cc:673-677, checksize=false)
```

---

## Preconditions

| Condition | Traversal | Disk fill |
|---|---|---|
| Vehicle advertises ArduPilot | required, so QGC builds the APM Scripting page | not required |
| Operator opens Scripting and clicks **download** | **required**, one click | **not required** |
| Operator picks the save folder | yes, but never types the filename — QGC reuses the vehicle's | n/a |
| MAVLink-FTP auth or signing | none by default | none by default |
| Path or offset validation | none | none |
| Reachable on connect with no interaction | no | **yes**, via the automatic `param.pck` fetch |

The traversal is not zero-click: it needs the operator to use the Scripting download UI. But within
that one expected action the *filename* is entirely attacker-controlled, and the operator has no
signal that it traversed. The disk fill has no such gate.

One thing that cannot be hidden: visual obfuscation of the traversal does not work. Homoglyphs and a
bidi RTLO override were both tried against the entry name, and neither can touch the `../` segments —
the OS path walker splits on a literal `/` and needs an exact byte match against `..` before any
rendering happens, so a lookalike character breaks the traversal instead of disguising it.
Obfuscation is structurally confined to the leaf filename, and the `../../` prefix stays visible in
the download button's label.

---

## Impact

- **Arbitrary-path local write, with attacker-chosen content and extension.** Confined to what the
  QGC process can write, but not confined to a basename. Confirmed planting a `.bat` in the per-user
  Startup folder that executed at the next logon, which converts the write into persistence and code
  execution.
- **Arbitrary file destruction with no payload.** The traversed path is truncated on the OpenFileRO
  ACK, before any body byte is read, so pointing the traversal at an existing file empties it even if
  the transfer then fails. Saved missions, geofences, logs and QGC's own settings can be zeroed by a
  vehicle that never sends a byte of content.
- **Zero-click disk fill.** A malicious vehicle answering the automatic `param.pck` fetch with a
  single large-offset burst ACK extends the output file to ~4 GiB in the operator's temp directory.
  No click, no Scripting page, and present in every version checked.
- **Stealth.** Both effects ride normal, expected behaviour: downloading a script the vehicle says it
  has, and the parameter fetch that happens on every connect.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Arbitrary relative path for the write | **Yes** | `QDir::filePath()` does not collapse `..`, and the basename strip is bypassed |
| Arbitrary content and extension | **Yes** | the body and the listed name are both attacker-chosen |
| Code execution | **Yes, on Windows** | confirmed via the Startup folder at next logon |
| Writes outside the QGC user's account | **No** | constrained to what the process can write |
| Truncation without a payload | **Yes** | `Truncate` fires on the OpenFileRO ACK |
| Traversal is zero-click | **No** | needs one download click on the Scripting page |
| Disk fill is zero-click | **Yes** | rides `param.pck` on connect |
| Disk fill really consumes 4 GiB | **Windows only** | NTFS zero-fills past EOF; APFS and ext4 create a sparse file. Source-verified, not bench-tested |
| Traversal can be visually disguised | **No** | measured negative, the `../` segments must match byte-for-byte |

---

## Version scope

The two halves have different reach, and conflating them understates the disk fill.

| | master `4fd86f9ae` | v5.1.4 | v5.1.0 | v5.0.8 | v4.4.4 |
|---|---|---|---|---|---|
| `FTPController.cc` | yes | yes | yes | **absent** | **absent** |
| `ScriptingComponent.qml` | yes | yes | yes | **absent** | **absent** |
| **Traversal reachable** | **yes** | **yes** | **yes** | no | no |
| Burst `seek(hdr.offset)` + `write` | `:867`, `:1108` | `:863`, `:1104` | `:855`, `:1096` | `:417`, `:639` | `:371`, `:504` |
| `param.pck` auto-download | yes | yes | yes | yes | yes |
| **Disk fill reachable** | **yes** | **yes** | **yes** | **yes** | **yes** |

The Scripting page is genuinely not compiled into 5.0.x, not merely hidden: `FTPController.cc` and
`ScriptingComponent.qml` do not exist in those trees. If Vehicle Setup has no Scripting entry, that
is a release predating the feature rather than a failed reproduction.

---

## Reproduction

Authorized bench only. Requires `pymavlink`.

```bash
cd poc
python3 poc_QGC03_ftp_listing_traversal_and_offset_fill.py --mode traversal
python3 poc_QGC03_ftp_listing_traversal_and_offset_fill.py --mode diskfill
```

In QGroundControl, connect to the harness, then for `traversal` open **Vehicle Setup → Scripting**,
click **download**, and pick any folder. The file appears outside it. `diskfill` needs no interaction;
it answers the automatic `param.pck` burst with a large offset.

Test the traversal against **v5.1.0 or newer**. The `diskfill` mode uses a large-but-bounded offset
and writes a few benign bytes, so check the *logical* size of the output rather than free space,
especially on APFS or ext4 where the result is sparse.
