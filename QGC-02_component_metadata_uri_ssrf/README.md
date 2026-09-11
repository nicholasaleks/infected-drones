# QGC-02 — Vehicle-controlled `COMPONENT_METADATA` URI picks both the bytes and the output path of a GCS download → zero-click arbitrary file write → RCE

| Field | Value |
|---|---|
| **Product** | QGroundControl |
| **Severity** | **CRITICAL** — CVSS 3.1 **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-22 · CWE-73 · CWE-494 · CWE-918 · CWE-295 |
| **Affected** | `>= 5.1.0, <= 5.1.4` and `master`. Not 5.0.x / 4.4.x — this is a 5.1 regression |
| **Fixed in** | nothing yet |
| **Verified** | master `4fd86f9ae` (2026-09-10) and tag `v5.1.4` (2026-08-30) — code unchanged, line numbers below are master |
| **Interaction** | **None.** Fires on connect |
| **Platform** | Arbitrary-path write and RCE are **Windows-only**. SSRF, attacker-named file, and file destruction are cross-platform |
| **Status** | Live-confirmed 2026-08-26 on v5.1.3 / Windows 11 x64 — write, destroy, persist, and code execution at next logon |
| **Advisory** | [GHSA-fpm2-gxf4-mf9j](https://github.com/mavlink/qgroundcontrol/security/advisories/GHSA-fpm2-gxf4-mf9j) |
| **Fix** | [`fix/qgc-02-download-output-path`](https://github.com/nicholasaleks/qgroundcontrol/tree/fix/qgc-02-download-output-path) — branch against `4fd86f9ae`, no PR opened yet |

---

## Demo

<a href="https://www.youtube.com/watch?v=DJPc3p9d0LI">
  <img src="https://img.youtube.com/vi/DJPc3p9d0LI/maxresdefault.jpg" alt="QGC-02 — COMPONENT_METADATA uri to zero-click RCE on the operator's workstation" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=DJPc3p9d0LI)**

---

## Summary

A connected vehicle hands QGroundControl a URI in `COMPONENT_METADATA.uri`. QGC fetches it with no
scheme allowlist causing an SSRF. The same attacker string also decides the
**output filename**, with no extension constraint, and `QUrl::fileName()` returns that segment
**fully decoded** — so `%5C` becomes a real backslash and the write escapes the temp directory on
Windows.

Zero-click and upon connection impacts include:

1. **Destroy** any file the QGC user can write. The output file is opened `WriteOnly|Truncate`
   *before* the request is issued, so the target is emptied even when the fetch 404s or no server
   exists at all.
2. **Write** attacker bytes to an attacker path, but on a *successful* metadata fetch the artifact
   is renamed into QGC's cache, so it is transient.
3. **Persist**, via the translation chain: metadata JSON declares a `translationUri` whose download
   skips the cache-move and whose cleanup is gated on the wrong CRC. That file stays, and its URL
   travels in JSON rather than the 100-byte MAVLink field — so long paths like the per-user Startup
   folder become reachable.

Chaining 3 into `…\Start Menu\Programs\Startup\x.bat` is unauthenticated, zero-click RCE on the
operator's Windows workstation, surviving reboot, running as the operator.

---

## Root cause

### 1. The wire field becomes the URI, unchecked

```cpp
// src/Vehicle/ComponentInformation/RequestMetaDataTypeStateMachine.cc:272
_compInfo->setUriMetaData(componentMetadata.uri, componentMetadata.file_crc);   // attacker uri, char[100]
```

The deprecated fallback at `:314` trusts `COMPONENT_INFORMATION.general_metadata_uri` identically.

### 2. The CRC "gate" is attacker-satisfiable

```cpp
// src/Vehicle/ComponentInformation/CompInfo.cc:12-17
void CompInfo::setUriMetaData(const QString &uri, uint32_t crc)
{
    _uris.uriMetaData = uri;
    _uris.crcMetaData = crc;
    _uris.crcMetaDataValid = true;     // always true — "valid" means "a value was provided"
}
```

The CRC is never checked against fetched bytes. It is a cache key, not integrity.

### 3. The only scheme check is "is it mavlinkftp?"

```cpp
// src/Vehicle/ComponentInformation/RequestMetaDataTypeStateMachine.cc:504-525
if (_uriIsMAVLinkFTP(uri)) {
    ...
} else {                                    // http, https, file, qrc, AND bare paths all land here
    if (_compMgr->_cachedFileDownload->download(uri, crcValid ? 0 : ComponentInformationManager::cachedFileMaxAgeSec)) {
```

### 4. The sink treats anything unrecognised as a local file

```cpp
// src/Utilities/Network/QGCFileDownload.cc:91-99
QUrl url;
if (QGCFileHelper::isLocalPath(remoteUrl)) {          // file:// or qrc:// -> local read
    url = QUrl::fromLocalFile(QGCFileHelper::toLocalPath(remoteUrl));
} else if (remoteUrl.startsWith(QLatin1String("http:")) || remoteUrl.startsWith(QLatin1String("https:"))) {
    url.setUrl(remoteUrl);                            // any host/IP -> SSRF, no allowlist
} else {
    url = QUrl::fromLocalFile(remoteUrl);             // ANY bare string -> opened as a local file
}
```

`QGCFileHelper::isLocalPath` (`QGCFileHelper.cc:332-353`) accepts `file`, `qrc`, and returns `true`
for any bare string.

### 5. The URI also names the output file — the part that turns SSRF into a write

```cpp
// src/Utilities/Network/QGCFileDownload.cc:480-508
QString QGCFileDownload::_generateOutputPath(const QString &remoteUrl) const
{
    if (!_outputPath.isEmpty()) { return _outputPath; }   // never set on this path
    QString fileName = QUrl(remoteUrl).fileName();        // :488  ATTACKER NAMES THE FILE
    ...
    return QGCFileHelper::joinPath(downloadDir, fileName);
}
```

`QGCCachedFileDownload` — the wrapper the metadata path uses — never calls `setOutputPath()`, so
`_outputPath` is empty and `:488` is always reached with the attacker's string. `joinPath` is raw
concatenation; nothing normalises or contains the result, and no extension is enforced.

`QUrl::fileName()` percent-decodes **before** splitting on `/`. That ordering creates a sharp
asymmetry, measured in both directions:

| Encoded | Decodes to | Survives `fileName()`? | Result |
|---|---|---|---|
| `%5C` | `\` | **yes** — not a `/`, so the split ignores it | Windows resolves it as a separator later → **traversal** |
| `%2F` | `/` | **no** — becomes a separator the split consumes | only the final component survives → **no traversal** |

This is why the traversal is Windows-only, and it was measured rather than assumed.

### 6. Truncate happens before the fetch

```cpp
// src/Utilities/Network/QGCFileDownload.cc:121-151
_localPath = _generateOutputPath(remoteUrl);                                   // :121
if (!QGCFileHelper::ensureParentExists(_localPath)) { ... }                    // :129  creates directories
_outputFile = new QFile(_localPath, this);
if (!_outputFile->open(QIODevice::WriteOnly | QIODevice::Truncate)) { ... }    // :136  TRUNCATES
...
_currentReply = _networkManager->get(request);                                 // :151  ...only now does it fetch
```

Destroying a file needs no server, no reply, and no egress — only the URI.

### 7. Why a *successful* write disappears, and why the translation chain does not

On success, `_downloadCompleteJsonWorker` (`:546`) calls `fileCache().insert()`, which renames the
artifact into QGC's cache. So:

| Fetch outcome | What remains at the attacker's path |
|---|---|
| succeeds | written, then moved into the cache — transient |
| fails (404 / no server) | created and truncated, insert never runs — **persists** |

The translation download is issued as `_requestFile("", /*crcValid*/ false, uri, _jsonTranslationFileName, false)`
(`:376`), so the cache insert is skipped. The only cleanup left is:

```cpp
// src/Vehicle/ComponentInformation/RequestMetaDataTypeStateMachine.cc:424-426
if (!_jsonMetadataCrcValid && !_jsonTranslationFileName.isEmpty()) {
    QFile(_jsonTranslationFileName).remove();
}
```

That is gated on the **metadata** CRC, not the translation's. And `CompInfoGeneral.cc:72,79` refuses
to register a metadata type at all unless its JSON entry carries a `fileCrc` key, so whenever this
chain runs, `_jsonMetadataCrcValid` is true, the cleanup is skipped, and the file stays where the
attacker put it.

Two consequences:

- **The 100-byte cap is gone.** `COMPONENT_METADATA.uri` is `char[100]`; the Startup-folder URL needs
  ~126 bytes. `translationUri` travels inside JSON fetched over HTTP, so it is unbounded. This is the
  entire reason RCE is reachable.
- **The locale gate does not apply.** `ComponentInformationTranslation.cc:27` returns early for `en*`
  locales, but that check lives in `downloadAndTranslate()` — the *next* state. The write at `:376`
  has already happened. Confirmed live on `en-US`.

### 8. Camera-definition variant: TLS verification disabled

```cpp
// src/Camera/VehicleCameraControl.cc:2243-2245
request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, true);   // follows redirects
QSslConfiguration conf = request.sslConfiguration();
conf.setPeerVerifyMode(QSslSocket::VerifyNone);                         // TLS validation DISABLED
```

`CAMERA_INFORMATION.cam_definition_uri` (`char[140]`) reaches this separate fetch path
(`VehicleCameraControl.cc:127-129` → `:2187` → `:2235`). An on-path attacker can substitute any TLS
server for an `https://` camera-definition URI with no certificate warning, and a public URL can
redirect QGC into an internal host.

### 9. Transport variant: `mftp://` — same write, no IP egress at all

Changing one thing, the URI scheme, removes the two deflections ("needs GCS Internet/LAN
egress" and "needs a TCP/UDP link"). QGC special-cases `mftp://` **before** `QGCFileDownload` is ever
reached, routing it to `FTPManager::download()` — so the payload bytes arrive over the MAVLink link
itself. No HTTP server, no egress, works on an air-gapped GCS, and over serial/USB as well as
TCP/UDP.

```cpp
// src/Vehicle/ComponentInformation/RequestMetaDataTypeStateMachine.cc:504-509
if (_uriIsMAVLinkFTP(uri)) {
    ...
    if (ftpManager->download(MAV_COMP_ID_AUTOPILOT1, uri,
                             QStandardPaths::writableLocation(QStandardPaths::TempLocation))) {
    //                       ^ 4th arg `fileName` omitted -> defaults to ""
```

```cpp
// src/Vehicle/FTPManager.h:33
bool download(uint8_t fromCompId, const QString& fromURI, const QString& toDir,
              const QString& fileName = "", bool checksize = true);
```

With `fileName` empty, `FTPManager` derives the name from the vehicle's URI, splitting on `'/'`
**only** — so a `\` survives into the filename exactly as it does in the HTTP variant:

```cpp
// src/Vehicle/FTPManager.cc:66-74
for (lastDirSlashIndex = ...; lastDirSlashIndex >= 0; lastDirSlashIndex--) {
    if (_downloadState.fullPathOnVehicle[lastDirSlashIndex] == '/') { break; }
}
if (fileName.isEmpty()) {
    _downloadState.fileName = _downloadState.fullPathOnVehicle.right(...);   // keeps "a\..\..\.."
}
```

```cpp
// src/Vehicle/FTPManager.cc:790-791
_downloadState.file.setFileName(_downloadState.toDir.filePath(_downloadState.fileName));
if (_downloadState.file.open(QFile::WriteOnly | QFile::Truncate)) { ...
```

Same sink, same Startup-folder outcome, reached over the one channel the attacker is guaranteed to
already have. **Status:** mechanism source-verified at master `4fd86f9ae`; PoC self-test green
(`poc_QGC02_mftp_transport_write.py`); the live Windows run for this variant specifically is
outstanding — the HTTP variant is the one confirmed end to end in §Demo.

---

## Taint trace

```
[A] METADATA (request/response)
  COMPONENT_METADATA.uri (char[100])          <- wire, attacker-controlled
   -> _handleCompMetadataResult()              RequestMetaDataTypeStateMachine.cc:272
   -> CompInfo::setUriMetaData()               CompInfo.cc:12   (crcMetaDataValid := true)
   -> _requestFile(...)                        RequestMetaDataTypeStateMachine.cc:504
   -> _cachedFileDownload->download(uri)       RequestMetaDataTypeStateMachine.cc:525
   -> QGCFileDownload::download()              QGCFileDownload.cc:91
        |- _generateOutputPath(remoteUrl)      QGCFileDownload.cc:488   -> ARBITRARY OUTPUT PATH
        |- open(WriteOnly|Truncate)            QGCFileDownload.cc:136   -> DESTRUCTION
        |- file:// / qrc:// / bare -> local    QGCFileDownload.cc:92,97 -> LOCAL FILE READ
        '- http(s) any host -> GET             QGCFileDownload.cc:94    -> SSRF

[A'] COMPONENT_INFORMATION.general_metadata_uri -> :314 -> same sink

[B] TRANSLATION (persistent write, unbounded URL)
  metadata JSON "translationUri"               CompInfoGeneral.cc:76
   -> _requestTranslationJson -> _requestFile("", false, uri, ...)   :376
   -> cleanup gated on _jsonMetadataCrcValid   :424   -> NEVER FIRES -> PERSISTS -> RCE

[C] CAMERA (push)
  CAMERA_INFORMATION.cam_definition_uri (char[140])   VehicleCameraControl.cc:127
   -> _handleDefinitionFile -> _httpRequest    :2187 / :2235
   -> RedirectPolicy=true + VerifyNone         :2243-2245  -> SSRF + TLS MITM
```

`requestAllComponentInformation` is called unconditionally from `InitialConnectStateMachine.cc:384`
on every connect, for every autopilot. There is no capability negotiation and no operator prompt.

---

## Impact

| Primitive | Windows | macOS / Linux |
|---|---|---|
| SSRF over the operator's egress | yes | yes |
| Arbitrary local file read (`file://`, `qrc://`, bare path) | yes | yes |
| TLS bypass + redirect-follow on the camera path | yes | yes |
| Attacker-chosen filename **inside** the download dir | yes | yes |
| Truncate-before-fetch destruction of a file there | yes | yes |
| **Arbitrary path** — escape the download dir | **yes** | **no** (measured) |
| **Code execution** | **yes** | no |

On Linux `QStandardPaths::TempLocation` is normally `/tmp`, shared between users. The cross-platform
half still means an unauthenticated vehicle drops an attacker-named, attacker-authored file into
`/tmp` on every connect and can truncate anything there the QGC user owns. The sticky bit prevents
touching other users' files, so that is an integrity and hygiene problem rather than a second RCE.

**Not claimed:** privilege escalation (this runs as the operator's user, not SYSTEM), and traversal
or RCE on non-Windows platforms.

---

## Version scope

Both defects came in with the 5.1 rewrite of `QGCFileDownload` into a streaming downloader. The
5.0.x/4.4.x implementation did the same job in the reply-finished handler and was accidentally safe:

| | 5.1.0 – 5.1.4, master | v5.0.8 | v4.4.4 |
|---|---|---|---|
| Path | `src/Utilities/Network/QGCFileDownload.cc` | `src/Utilities/FileSystem/QGCFileDownload.cc` | `src/QGCFileDownload.cc` |
| Output name from | `QUrl(remoteUrl).fileName()` `:485` | `QFileInfo(reply->url().toString()).fileName()` `:130` | same, `:92` |
| Decoded `\` survives into the name? | **yes** — `QUrl` does not treat `\` as a separator | no — `QFileInfo` strips it on Windows | no |
| File opened | `:136`, **before** the request at `:149` | `:155`, after the reply at `:84` | `:118`, after the reply |
| Traversal | **yes** | no | no |
| Truncate-before-fetch | **yes** | no | no |

Affected range is therefore **`>= 5.1.0, <= 5.1.4`** plus `master`. The 5.0.x/4.4.x rows are
source-verified across the release tags, not bench-tested.

---

## Reproduction

Authorized bench only.

Authorized bench/localhost only. Requires `pymavlink`.

```bash
cd poc
python3 -m http.server 8000                                  # terminal 1 — SSRF callback catcher
python3 poc_QGC02_metadata_uri_write.py --tcp 127.0.0.1:5760 # terminal 2 — malicious vehicle
```

In QGroundControl: **Application Settings → Comm Links → Add → TCP**, host `127.0.0.1`, port `5760`,
**Connect**. Nothing else is clicked.

Modes: `control`, `traversal`, `truncate`, `fileread`, `persist`, `startup`. `--sep slash` reproduces
the measured `%2F` negative result.

Two things make a working attack look broken, both worth knowing before you run it:

- A **successful** write deletes itself — `fileCache().insert()` renames it into the cache. Check the
  cache, not the target path.
- `file_crc` is the cache key. A *constant* CRC makes every run after the first a silent cache hit
  with no download at all. The PoC varies it per answer.

On Windows QGC is a GUI-subsystem app, so `QT_LOGGING_RULES` never reaches the launching console. Use
**Settings → Logging → Categories** and enable `ComponentInformation.*`,
`Utilities.QGCFileDownload`, `Utilities.QGCCachedFileDownload`.

`poc_G05_qgc_mavsdk_component_metadata_ssrf.py` is the earlier SSRF-only reproducer, kept because it
is the smaller of the two.
