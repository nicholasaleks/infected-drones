# QGC-01 — `CAMERA_INFORMATION` vendor/model strings formatted into a cache path → zero-click path-traversal file write with attacker content

| Field | Value |
|---|---|
| **Product** | QGroundControl |
| **Severity** | **HIGH** — CVSS 3.1 **8.2** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L` |
| **CWE** | CWE-22 · CWE-73 · secondary CWE-170 (improper null termination → over-read) |
| **Affected** | every supported version. `master`, `v5.1.x`, `v5.0.x`, `v4.4.x`. Not a regression |
| **Fixed in** | nothing yet |
| **Verified** | master `e6aeacb96` (2026-09-10), plus tags `v5.1.4`, `v5.1.0`, `v5.0.8`, `v4.4.4` |
| **Interaction** | **None.** QGC solicits `CAMERA_INFORMATION` itself after connect |
| **Platform** | Creation and truncation are cross-platform. The NTFS alternate-data-stream variant is Windows-only |
| **Status** | Live-confirmed 2026-08-26 on Windows 11 x64 — creation, truncation, and a hidden NTFS stream write, all with zero operator interaction |
| **Advisory** | [GHSA-c538-95gv-476f](https://github.com/mavlink/qgroundcontrol/security/advisories/GHSA-c538-95gv-476f) |
| **Fix** | [`fix/qgc-01-camera-info-path-traversal`](https://github.com/nicholasaleks/qgroundcontrol/tree/fix/qgc-01-camera-info-path-traversal) — branch against `e6aeacb96`, no PR opened yet |

---

## Demo

<a href="https://www.youtube.com/watch?v=xO2YaAExNas">
  <img src="https://img.youtube.com/vi/xO2YaAExNas/maxresdefault.jpg" alt="QGC-01 — CAMERA_INFORMATION vendor string to a traversed file write on the operator's Desktop" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=xO2YaAExNas)**

---

## Summary

QGroundControl builds the on-disk filename for a camera's cached definition XML by `asprintf`
formatting the raw, vehicle-supplied `CAMERA_INFORMATION.vendor_name` and `model_name` straight into a
path, with no sanitisation of `/`, `\`, `..` or `:`. `parameterSavePath()` does not collapse `..`, so
a malicious camera writes anywhere the QGC user can write, not merely outside the `CameraDefinitions`
cache. The content is attacker-controlled, it is whatever the attacker's `cam_definition_uri`
serves, over the vehicle's own MAVLink-FTP or over HTTP.

No operator interaction is involved. QGC solicits `CAMERA_INFORMATION` by itself once a component in
the 100–105 range heartbeats, so connecting to the vehicle is the operator's entire contribution.

Three impacts confirmed:

1. **Create** a file at any traversed path with any bytes, over pure MAVLink-FTP, with no XML validity
   requirement.
2. **Truncate and replace** an existing file, via the HTTP route.
3. **Write hidden content onto an existing file** through an NTFS alternate data stream, leaving the
   visible file byte-identical, over pure MAVLink.

A secondary over-read exists because the 32-byte fixed arrays are read as C strings without enforcing
NUL termination.

---

## Root cause

### 1. The wire fields are decoded and passed on verbatim

```cpp
// src/Camera/QGCCameraManager.cc:333-339
mavlink_camera_information_t info{};
mavlink_msg_camera_information_decode(&message, &info);          // :334
...
MavlinkCameraControlInterface *pCamera = _vehicle->firmwarePlugin()
        ->createCameraControl(&info, _vehicle, message.compid, this);   // :339
```

`info.vendor_name` and `info.model_name` (each `uint8_t[32]`) and `info.cam_definition_uri`
(`char[140]`) are filled from the wire and passed unmodified.

### 2. The path-construction sink, and the over-read

```cpp
// src/Camera/VehicleCameraControl.cc:115-129
memcpy(&_mavlinkCameraInfo, info, sizeof(mavlink_camera_information_t));

_vendor = QString(reinterpret_cast<const char*>(info->vendor_name));      // :117
_modelName = QString(reinterpret_cast<const char*>(info->model_name));    // :118
_cacheFile = QString::asprintf("%s/%s_%s_%03d.xml",                       // :119
                SettingsManager::instance()->appSettings()->parameterSavePath().toStdString().c_str(),
                _vendor.toStdString().c_str(),
                _modelName.toStdString().c_str(),
                static_cast<int>(_mavlinkCameraInfo.cam_definition_version));
...
if(info->cam_definition_uri[0] != 0) {
    _handleDefinitionFile(info->cam_definition_uri);                      // :129
}
```

`:117-118` treat a 32-byte field as a NUL-terminated C string. A field that is exactly full, with no
NUL in its 32 bytes, makes the `QString` constructor scan past the array into adjacent struct memory
until it finds a zero. `:119` formats both strings into the path with no normalisation, and the base
from `parameterSavePath()` is never re-canonicalised afterwards, so any `../` survives.

### 3. The base path does not collapse `..`

```cpp
// src/Settings/AppSettings.cc:299-311
QString AppSettings::_childSavePath(const char* directory)
{
    const QString rootPath = savePath()->rawValue().toString();
    ...
    return rootDir.filePath(directory);      // :311  plain concatenation
}

// :324
QString AppSettings::parameterSavePath(void) { return _childSavePath(parameterDirectory); }
```

`QDir::filePath()` concatenates; it does not resolve or reject `..`.

### 4. Sink 1 — the MAVLink-FTP download lands at the attacker's path

```cpp
// src/Camera/VehicleCameraControl.cc:2199-2207
QString fileName = QString::asprintf("%s_%s_%03d.xml%s",
    _vendor.toStdString().c_str(),
    _modelName.toStdString().c_str(),
    ver,
    ext.toStdString().c_str());
connect(_vehicle->ftpManager(), &FTPManager::downloadComplete, this, &VehicleCameraControl::_ftpDownloadComplete);
_vehicle->ftpManager()->download(_compID, url,
    SettingsManager::instance()->appSettings()->parameterSavePath().toStdString().c_str(),
    fileName);
```

`fileName` still carries the traversal, and `FTPManager` joins it by plain concatenation:

```cpp
// src/Vehicle/FTPManager.cc:333
QString downloadFilePath = _downloadState.toDir.absoluteFilePath(_downloadState.fileName);
// src/Vehicle/FTPManager.cc:790
_downloadState.file.setFileName(_downloadState.toDir.filePath(_downloadState.fileName));
```

No parsing happens on this route, so **any** bytes land. It is gated on `!xmlFile.exists()` at
`:2193`, so on its own it can only create, never overwrite.

### 5. Sink 2 — the cache write, which truncates

```cpp
// src/Camera/VehicleCameraControl.cc:929-937
if(!_cached) {
    qCDebug(VehicleCameraControlLog) << "Saving camera definition file" << _cacheFile;
    QFile file(_cacheFile);
    if (!file.open(QIODevice::WriteOnly)) {          // :932  truncates
        qWarning() << QString("Could not save cache file %1. Error: %2").arg(_cacheFile).arg(file.errorString());
    } else {
        file.write(originalData);                    // :935  attacker XML, captured at :899
    }
}
```

### 6. Which sink fires, and why it decides create vs destroy

`_ftpDownloadComplete` sets `_cached = true` at `:2296` **before** it emits `dataReady`, so on the
MAVFTP route `:929` is never reached, `FTPManager` already wrote the file itself. Sink 2 is reachable
only via the HTTP route, where `_cached` is still false. Two consequences: the MAVFTP route needs no
valid XML at all, while sink 2 only fires if the served XML is a *loadable* camera definition
(`:919` bails on an empty `<parameters>` block, `:1012` bails on a `<parameter>` with no
`<description>` child).

| Target state | Route taken | Outcome |
|---|---|---|
| absent | `mftp://` branch at `:2193`, `FTPManager` writes | **create only**, pure MAVLink, any bytes |
| present, parses as a camera definition | `_cached = true` at `:2231` | nothing written |
| present, does not parse (a `.plan` is JSON, a `.txt` is text, documents are binary) | falls to `_httpRequest(url)` at `:2226`, then sink 2 | **truncate and replace** |
| present, but the path names an NTFS alternate data stream | `QFile::exists()` tests the *stream*, not the host file, so the gate passes | **hidden write onto a file that was already there** |

---

## Taint trace

```
[WIRE] CAMERA_INFORMATION.vendor_name[32], model_name[32], cam_definition_uri[140]
   |     (raw bytes from the vehicle, no NUL guarantee)
   v
QGCCameraManager::_mavlinkMessageReceived      QGCCameraManager.cc:157  (_initialConnectComplete gate)
   v                                                              :164-165  (sysid + camera compid gate)
QGCCameraManager::_handleCameraInfo            :321  (:324 requires the info to have been requested)
   v
mavlink_msg_camera_information_decode          :334
   v
FirmwarePlugin::createCameraControl            FirmwarePlugin.cc:339
   v
VehicleCameraControl ctor                      VehicleCameraControl.cc:115
   |-- _vendor    = QString((const char*)info->vendor_name)   :117   <- over-read if no NUL
   |-- _modelName = QString((const char*)info->model_name)    :118   <- over-read if no NUL
   '-- _cacheFile = asprintf("%s/%s_%s_%03d.xml", parameterSavePath(), ...)   :119  <- TRAVERSAL
           (parameterSavePath -> _childSavePath -> QDir::filePath, no '..' collapse, AppSettings.cc:311)
   v
_handleDefinitionFile(cam_definition_uri)      :129 -> :2187
   |
   |-- mftp:// -> FTPManager::download(toDir, fileName=asprintf("%s_%s_%03d.xml", _vendor, ...))
   |                :2199-2207 -> FTPManager.cc:333 / :790 -> TRAVERSAL, sink 1, create-only
   |
   '-- http(s):// -> _httpRequest -> _downloadFinished -> dataReady
                    -> _loadCameraDefinitionFile  :897
                       originalData(bytes)        :899   <- attacker XML captured verbatim
                       QFile(_cacheFile).open(WriteOnly); write(originalData)  :931-935
                       ===> TRUNCATES AND REPLACES at the attacker's path
```

Two attacker-controlled axes converge at the write: the **path**, via `vendor_name`/`model_name`, and
the **content**, via `cam_definition_uri`.

---

## Preconditions

Default-reachable, no non-default build flag or setting. Six gates, and three of them fail silently,
which is why this looks unreachable from source alone.

| Gate | Where | Effect |
|---|---|---|
| `sysid` matches, `compid` is autopilot or camera 100–105 | `QGCCameraManager.cc:164-165` | trivially satisfied; the attacker is on the vehicle's sysid |
| QGC must have *requested* camera info for that compid | `:324` | the attacker must first emit a `HEARTBEAT` from a camera compid, then answer the request. `CAMERA_INFORMATION` sent cold from compid 1 is dropped |
| `_initialConnectComplete` must be true | `:157` | **fails silently.** Every camera message before initial connect completes is discarded with no log at default verbosity. The PoC serves a genuine 1,387-parameter ArduCopter `@PARAM/param.pck` (31,963 bytes) purely to get past this line |
| `infoReceived` latches per component | `:328` | once accepted for a compid, no further `CAMERA_INFORMATION` is processed for it. Re-testing needs a fresh compid in 100–105 or a QGC restart |
| `parameterSavePath()` non-empty | `AppSettings.cc:299-311` | true by default after first run |
| MAVFTP replies must come from the addressed component | `FTPManager` | the camera fetch calls `download(_compID, …)`, so the XML must be served from the *camera's* compid, not the autopilot's |

---

## Impact

Zero-click creation of attacker-controlled `.xml`-suffixed files in any directory the QGC user can
write, plus hidden attacker content on any existing file via NTFS streams, plus truncation of files
matching the suffix pattern.

Beyond the write itself, a crafted definition **poisons the camera-definition cache**: QGC reads
cached definitions on subsequent connects (`:2211-2231`), and read-only, write-only and range
attributes are honoured from the XML, so the attacker shapes the camera-settings UI and the
parameters QGC exposes.

Bounding it, because the forced filename suffix is a real constraint:

| Claim | Holds? | Why |
|---|---|---|
| Arbitrary **directory** | **Yes** | `vendor_name` carries 32 bytes of traversal, and `parameterSavePath()` does not collapse `..` |
| Arbitrary **content** | **Yes** | the bytes are whatever `cam_definition_uri` serves |
| Arbitrary **filename** | **No** | `_cacheFile` is always `%s/%s_%s_%03d.xml`, so every target must end `_<model>_<NNN>.xml` |
| **Code execution** | **No** | you cannot drop `evil.bat` into Startup; it would be named `evil.bat_x_001.xml`. An ADS gives the attacker the base filename, but Windows will not execute an alternate data stream |
| **Overwrite any file** | **No** | truncation only reaches existing files already named `_<anything>_<NNN>.xml`. The run-2 victim matched because it was named to match; a real `.plan` or document does not |
| **Hidden write to any file** | **Yes** | the ADS variant works on any existing path, because `exists()` tests the stream |
| **Information disclosure** | **No** | nothing is read back to the attacker. The over-read at `:117-118` stays within the 64-byte `CAMERA_INFORMATION` tail |

On the over-read specifically: `vendor_name[32]` is immediately followed in
`mavlink_camera_information_t` by `model_name[32]`, `lens_id` and `cam_definition_uri[140]`, all
attacker-supplied. So a full `vendor_name` runs on into the attacker's own adjacent bytes rather than
leaking anything. The practical effect is that **the path component is not bounded by 32 bytes**,
which lengthens the available traversal. Derived from the generated struct layout, not separately
bench-tested.

---

## Version scope

Not a regression. The sink is present in every version checked:

| Version | File | `asprintf` cache sink | `WriteOnly` cache write |
|---|---|---|---|
| `master` `e6aeacb96` | `src/Camera/VehicleCameraControl.cc` | `:119` | `:932` |
| `v5.1.4`, `v5.1.0` | `src/Camera/VehicleCameraControl.cc` | `:119` | `:932` |
| `v5.0.8` | `src/Camera/VehicleCameraControl.cc` | `:134` | `:837` |
| `v4.4.4` | `src/Camera/QGCCameraControl.cc` | `:170` | `:850` |

The `!xmlFile.exists()` gates and the `_cached = true` latch are in the same shape in all four.

---

## Reproduction

Authorized bench only. Requires `pymavlink`.

```bash
cd poc
python3 poc_QGC01_camera_info_traversal.py --mode traversal    # create, pure MAVLink-FTP
python3 poc_QGC01_camera_info_traversal.py --mode overwrite --http   # truncate, needs an HTTP server
python3 poc_QGC01_camera_info_traversal.py --mode ads          # NTFS alternate data stream
```

`--http` writes `cam.xml` out for a stock `python3 -m http.server`. In QGroundControl, add a **TCP**
link to `127.0.0.1:5760` and Connect. Nothing else is clicked.

Two things worth knowing before you run it. `infoReceived` latches per compid, so a second run needs a
fresh camera compid or a QGC restart. And `--mode overwrite` needs the served XML to be a *loadable*
definition, including a `<parameter>` with a `<description>` child, or sink 2 returns before the write.