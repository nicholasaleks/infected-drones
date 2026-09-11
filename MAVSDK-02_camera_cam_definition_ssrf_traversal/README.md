# MAVSDK-02 — `CAMERA_INFORMATION.cam_definition_uri`: libcurl SSRF, and an `mftp://` traversal that destroys files outside the sandbox

| Field | Value |
|---|---|
| **Product** | MAVSDK (C++ SDK and `mavsdk_server`), Camera plugin |
| **Severity** | **HIGH** — traversal, CVSS 3.1 **8.2** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`. SSRF half also HIGH |
| **CWE** | CWE-22 · CWE-73 · CWE-918 |
| **Affected** | `main` and `v3.17.4`. Both halves present in each |
| **Fixed in** | nothing yet |
| **Verified** | main `34b417d45` (2026-09-01). Line numbers below are main; the file has moved ~170 lines since the original analysis |
| **Interaction** | **None.** `CAMERA_INFORMATION` is processed on receipt, and the SDK requests it after a heartbeat from any component |
| **Platform** | Cross-platform |
| **Status** | Traversal reproduced twice against the shipped `libmavsdk-dev` 3.17.4 package, most recently 2026-09-10: a 370-byte operator file outside the sandbox was renamed out of existence, zero-click. SSRF half source-verified, not reproduced |
| **Advisory** | not filed |
| **Fix** | [`fix/mavsdk-02-camdef-traversal`](https://github.com/nicholasaleks/MAVSDK/tree/fix/mavsdk-02-camdef-traversal) against `34b417d45`, no PR opened yet |

---

## Summary

MAVSDK registers a `CAMERA_INFORMATION` handler at construction and acts on the message's
`cam_definition_uri` with no allowlist. The URI's scheme prefix selects one of two sinks, and both
trust the rest of the string.

**SSRF.** An `http://` or `https://` URI is fetched with libcurl, from the GCS host, to any address
the attacker names.

**Traversal.** An `mftp://` URI has only its *scheme* removed, by a helper that does exactly that and
nothing else. The remainder, still containing `../`, is joined onto the download directory with
`operator/`, which does not normalise. `mftp://../../../../tmp/x` therefore resolves to `/tmp/x`,
outside the sandbox, and MAVSDK then calls `std::filesystem::remove()` on it and reads it.

What makes this worse than a traversal into a `remove()` is the file cache, which is enabled by
default. Before the read, `_file_cache->insert()` **renames the out-of-sandbox file into the cache**.
So the primitive is not only "delete a file on the `.xz` branch" but "move an attacker-named file out
of its location, for any extension" meaning a victim file can be renamed out of existence with no operator action at all.

There is a sanitiser in the codebase that would have stopped this. The MAVLink-FTP client applies
`.filename()` to the remote path when it builds a local path. The camera plugin builds its own path
and does not.

---

## Root cause

### 1. The handler is registered automatically

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:101-103
_system_impl->register_mavlink_message_handler(
    MAVLINK_MSG_ID_CAMERA_INFORMATION,
    [this](const mavlink_message_t& message) { process_camera_information(message); },
    this);
```

No gating, no allowlist. The SDK also actively requests `CAMERA_INFORMATION` (`:2492`) after a
heartbeat from any component id it has not seen, with no `MAV_TYPE` test and no compid filter, so
the attacker does not even have to push it unsolicited.

### 2. The scheme selects a sink, and that is the only check

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:1515
} else if (starts_with(url, "http://") || starts_with(url, "https://")) {
```

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:1594-1599
} else if (starts_with(url, "mftp://") || starts_with(url, "mavlinkftp://")) {
    LogInfo("Download file: {} using MAVLink FTP...", url);
    ...
    auto downloaded_filename = strip_prefix(strip_prefix(url, "mavlinkftp://"), "mftp://");
```

The `http(s)` branch hands the URL to libcurl with no host or address filtering — that is the SSRF.
The `mftp://` branch produces `downloaded_filename` as the URI minus its scheme and nothing else.

### 3. `strip_prefix` removes a prefix, not a path

```cpp
// cpp/src/mavsdk/core/string_utils.cpp:10-16
std::string strip_prefix(const std::string& str, const std::string& prefix)
{
    if (starts_with(str, prefix)) {
        return str.substr(prefix.size());
    }
    return str; // If no known prefix is found, return the original string
}
```

No `lexically_normal()`, no `..` rejection, no `.filename()`. `mftp://../../../../tmp/x` becomes
`../../../../tmp/x`.

### 4. The join does not normalise, and then the path is removed and read

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:1647-1674
auto downloaded_filepath = _tmp_download_path / downloaded_filename;      // :1647

LogDebug("File download finished to {}", downloaded_filepath.string());
if (downloaded_filepath.extension() == ".xz") {
    ...
    if (InflateLZMA::inflateLZMAFile(downloaded_filepath, decompressed)) {
        std::filesystem::remove(downloaded_filepath);                     // :1654
...
load_camera_definition_with_lock(                                         // :1674
    *maybe_potential_camera, downloaded_filepath);
```

`std::filesystem::operator/` with a right-hand side starting `..` does not normalise, so
`<tmpdir>/../../../../tmp/x` resolves to `/tmp/x`. `:1654` removes it on the `.xz` branch, and
`:1674` reads it.

### 5. The file cache turns the read into a second write primitive

`_file_cache` is populated by default: `init()` at `:59` resolves a cache directory from `HOME` or
`LOCALAPPDATA`, which is the normal case. Before the read, the callback inserts the downloaded file
into the cache, and `insert()` is not a copy:

```cpp
// cpp/src/mavsdk/core/file_cache.cpp:140-151
        std::filesystem::remove(file_name);
    ...
    std::filesystem::rename(file_name, data, err);
        ...
            std::filesystem::copy_file(file_name, data, err);
            ...
                std::filesystem::remove(file_name, err);
```

`file_name` here is the **traversed** path. So with the cache on, which is the default:

- the `remove()` at `:1654` still fires on the `.xz` branch, unchanged
- `insert()` **renames the out-of-sandbox file into the cache**, removing it from where it was, and
  this happens for **any** extension, not just `.xz`
- the subsequent read then reads the in-cache copy, so out-of-sandbox *content* still reaches the
  XML parser

The wording "`:1674` reads the traversed path directly" is only exact in a build with no cache
(`_file_cache == nullptr`).

### 6. Existing Sanitiser

```cpp
// cpp/src/mavsdk/core/mavlink_ftp_client.cpp:530
fs::path local_path = fs::path(item.local_folder) / fs::path(item.remote_path).filename();
```

The FTP client reduces the remote path to its filename before joining, so the FTP *write* itself is
safe. The camera plugin does not reuse that; it builds `_tmp_download_path / downloaded_filename`
from the raw string. Same repository, same join pattern, one of them sanitised.

With
`cam_definition_uri = mftp://../../root/Documents/mission-2026-08-28.plan`, the FTP client wrote the
attacker's 417 bytes to the sanitised basename inside `/tmp/mavsdk-component-metadata-<rand>/`, while
`camera_impl` rebuilt the raw traversed path and moved the operator's own 370-byte file into the
cache. Two different paths for one download: the attacker's file is sandboxed correctly and the
victim's is not.

---

## Taint trace

```
[wire]  CAMERA_INFORMATION.cam_definition_uri (char[140])
   |     handler auto-registered at camera_impl.cpp:101-103
   |     and actively requested after a heartbeat from any compid (:2492)
   v
url = cam_definition_uri
   |
   |-- starts_with "http(s)://"                      camera_impl.cpp:1515
   |     '-- libcurl GET, any host or address        ===> SSRF
   |
   '-- starts_with "mftp://" / "mavlinkftp://"       camera_impl.cpp:1594
         |-- downloaded_filename = strip_prefix(...)  camera_impl.cpp:1599
         |     scheme removed, "../" survives         string_utils.cpp:10-16
         |-- downloaded_filepath = _tmp_download_path / downloaded_filename
         |     operator/ does not normalise           camera_impl.cpp:1647
         |     <tmpdir>/../../../../tmp/x  ->  /tmp/x   OUTSIDE THE SANDBOX
         |
         |-- .xz branch: std::filesystem::remove()    camera_impl.cpp:1654   ===> DELETE
         |-- _file_cache->insert(tag, filepath)       file_cache.cpp:140-151
         |     rename/copy+remove on the traversed path  ===> MOVE, ANY EXTENSION
         '-- load_camera_definition_with_lock(...)    camera_impl.cpp:1674   ===> READ
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink link the SDK is connected to | n/a | Push. Any vehicle, component or MITM |
| Handler registered | **Yes** | At construction, unconditionally |
| Operator interaction | **None** | The message is processed on receipt |
| File cache enabled | **Yes** | `init()` resolves `HOME` / `LOCALAPPDATA`; the normal case |
| `.xz` extension | only for the `remove()` at `:1654` | The cache `insert()` move fires for any extension |
| Attacker knows the victim path | needed for targeting | Relative traversal from a temp dir makes common paths reachable |

---

## Impact

A vehicle on an unauthenticated MAVLink link, with no operator action, gets:

- **Destruction of a file of its choosing outside the sandbox.** The file is renamed into MAVSDK's
  cache, so from the operator's point of view it is gone from where it was. Reproduced against the
  shipped 3.17.4 package.
- **Out-of-sandbox file content into the XML parser**, via that cached copy.
- **SSRF from the GCS host** to any address the attacker names, including loopback, RFC1918 and
  cloud metadata endpoints. Source-verified only.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Zero-click | **Yes** | handler registered at construction, message processed on receipt |
| Traversal escapes the download directory | **Yes** | `operator/` does not normalise a `..` prefix |
| Destroys a chosen file outside the sandbox | **Yes** | reproduced on the shipped 3.17.4 package |
| Fires for any extension, not just `.xz` | **Yes** | via the cache `insert()` rename, with the cache on by default. The reproduction used a `.plan` |
| Out-of-sandbox content reaches the parser | **Yes** | the cached copy is the moved original |
| Attacker controls the destroyed file's *content* | **No** | the FTP client sanitises its own write path at `mavlink_ftp_client.cpp:530` |
| Arbitrary file *write* with attacker content | **No** | same reason |
| SSRF | **Yes by construction, not reproduced** | no host or address filtering on the libcurl branch |
| Code execution | **No** | no write primitive with attacker-controlled content |
| Recoverable | **partly** | the bytes survive inside the cache until it is evicted, but the file is gone from its path |

---

## Version scope

| Version | Layout | `mftp://` branch | `strip_prefix` | join | `remove()` |
|---|---|---|---|---|---|
| `main` `34b417d45` | `cpp/src/mavsdk/…` | `:1594` | `:1599` | `:1647` | `:1654` |
| `v3.17.4` (live-tested) | `src/mavsdk/…` | `:1422` | `:1427` | `:1474` | `:1481` |

The two trees differ structurally, not just by line drift, and `camera_impl.cpp` has grown roughly
170 lines on main since the original analysis. The behaviour is identical in both.

---

## Reproduction

Authorized bench only. Requires Docker; the image pulls the shipped
`libmavsdk-dev_3.17.4_debian12_arm64.deb` release artifact rather than building from source, so what
is under test is what users install.

`demo.sh` is split into steps so the two sides can be watched together:

```bash
./demo.sh up       # build the image from the shipped libmavsdk-dev 3.17.4 .deb
./demo.sh plant    # write /root/Documents/mission-2026-08-28.plan, the operator's file
./demo.sh before   # show it present, and the cache empty
./demo.sh vehicle  # terminal A: the attacker, cam_definition_uri = mftp://../../root/Documents/<file>
./demo.sh run      # terminal B: the operator app, whose whole body is mavsdk::Camera{system}
./demo.sh after    # show the file gone and its bytes in the cache
```

The operator app does nothing but construct a `Camera` plugin. The victim file is gone afterwards
with nothing clicked.

Check for the victim file's *absence* rather than for an error: MAVSDK logs the download as normal,
and with the cache on the file has been renamed rather than deleted, so it reappears inside the cache
directory rather than vanishing entirely.