# MAVSDK-03 — A vehicle-supplied `.xz` document is decompressed with no output ceiling

| Field | Value |
|---|---|
| **Product** | MAVSDK (C++ SDK and `mavsdk_server`), Camera plugin and component metadata |
| **Severity** | **HIGH** — CVSS 3.1 **7.5** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **CWE** | CWE-409 (data amplification) · CWE-400 · CWE-770 · CWE-459 (incomplete cleanup) |
| **Affected** | `main` and `v3.17.4` (2026-08-25), the current release. `inflate_lzma.cpp` is byte-identical in both |
| **Fixed in** | nothing yet |
| **Verified** | main `34b417d45` (2026-09-01) for the source, shipped `libmavsdk-dev` 3.17.4 package for the runs |
| **Interaction** | **None.** A heartbeat is enough. The application's only involvement is constructing one plugin |
| **Platform** | Cross-platform |
| **Status** | Reproduced on the shipped 3.17.4 package, 2026-09-10. 156,316 bytes on the wire became 1,073,741,824 bytes on disk, still present after the application exited. Reproduced again through `COMPONENT_METADATA` against an application with no Camera plugin. Three application lifetimes left 3,221,237,808 bytes cached. A run against a 256 MB filesystem left it 100% full with the partial output never removed |
| **Advisory** | not filed |
| **Fix** | [`fix/mavsdk-03-inflate-output-limit`](https://github.com/nicholasaleks/MAVSDK/tree/fix/mavsdk-03-inflate-output-limit) against `34b417d45`, submitted as [mavlink/MAVSDK#3074](https://github.com/mavlink/MAVSDK/pull/3074) |

---

## Demo

<a href="https://www.youtube.com/watch?v=9sgwLIP5-z4">
  <img src="https://img.youtube.com/vi/9sgwLIP5-z4/maxresdefault.jpg" alt="MAVSDK-03 — a vehicle-supplied .xz camera definition fills the ground station's disk" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=9sgwLIP5-z4)**

Two panes, attacker on the right and operator on the left. The vehicle states its payload up front:
312,496 bytes on the wire, 2 GiB decompressed. The operator starts an application whose entire body
is `mavsdk::Camera{system}`, and the vehicle pane shows MAVSDK asking for `CAMERA_INFORMATION` on
its own. Available disk then falls by 2 GiB while the attacker's message count stays frozen at
1,310, and the cache still holds the 2,147,483,648 bytes after the application has exited.

---

## Summary

`InflateLZMA::inflateLZMAFile` initialises its decoder with a memory limit of `UINT64_MAX` and runs
a write loop that keeps no running total, so the number of bytes it writes is whatever the sender's
stream decodes to. Two message paths reach it with a filename the vehicle chose, and in both the
`.xz` extension in that filename is what selects decompression.

The first is the Camera plugin. A MAVLink peer that heartbeats is recorded as a potential camera and
automatically asked for `CAMERA_INFORMATION`; there is no `MAV_TYPE` test and no component-ID
filter, so an ordinary autopilot on compid 1 qualifies. The reply's `cam_definition_uri` names the
file.

The second needs no Camera plugin. `COMPONENT_METADATA` carries a `uri` whose basename becomes the
local filename, and it accepts `.lzma` as well as `.xz`. Constructing `mavsdk::Events` is enough to
trigger the request, because `EventsImpl::init()` asks for the autopilot's metadata by itself.

The decompressed result is moved into a file cache that is on by default and bounded by a count of
50 entries rather than by size, so it outlives the process. Both cache tags are built from fields
the vehicle supplies, so distinct entries are the sender's to create.

A failed decode is not cheaper. Neither `inflateLZMAFile` nor the error branches in the callers
remove the partial output, so a stream truncated after a gigabyte still costs a gigabyte, and a
stream that runs the filesystem out of space leaves it out of space.

---

## Root cause

### 1. Any heartbeat makes the sender a camera candidate

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:75-78
_system_impl->register_mavlink_message_handler(
    MAVLINK_MSG_ID_HEARTBEAT,
    [this](const mavlink_message_t& message) { process_heartbeat(message); },
    this);
```

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:1178-1191
void CameraImpl::process_heartbeat(const mavlink_message_t& message)
{
    // Check for potential camera
    std::lock_guard lock(_mutex);
    auto found =
        std::any_of(_potential_cameras.begin(), _potential_cameras.end(), [&](const auto& item) {
            return item.component_id == message.compid;
        });

    if (!found) {
        _potential_cameras.emplace_back(message.compid);
        check_potential_cameras_with_lock();
    }
}
```

No `MAV_TYPE_CAMERA` test and no component-ID range check. Every distinct `compid` that heartbeats
is enqueued, which is why the reproduction works while advertising `sysid=1 compid=1`.

### 2. MAVSDK then asks for the definition by itself

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:1193-1202
void CameraImpl::check_potential_cameras_with_lock()
{
    for (auto& potential_camera : _potential_cameras) {
        // First step, get information if we don't already have it.
        if (!potential_camera.maybe_information) {
            request_camera_information(potential_camera.component_id);
            potential_camera.information_requested = true;
        }
    }
}
```

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:2489-2493
void CameraImpl::request_camera_information(uint8_t component_id)
{
    _system_impl->mavlink_request_message().request(
        MAVLINK_MSG_ID_CAMERA_INFORMATION, fixup_component_target(component_id), nullptr);
}
```

This is the zero-click property. The chain is driven entirely by inbound traffic, and the
application never asks for a download.

### 3. The `.xz` decision is made on the vehicle-supplied filename

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:1647-1653
auto downloaded_filepath = _tmp_download_path / downloaded_filename;

LogDebug("File download finished to {}", downloaded_filepath.string());
if (downloaded_filepath.extension() == ".xz") {
    auto decompressed = downloaded_filepath;
    decompressed.replace_extension(".extracted");
    if (InflateLZMA::inflateLZMAFile(downloaded_filepath, decompressed)) {
```

`downloaded_filename` is the remainder of `cam_definition_uri` after the scheme is stripped, so the
sender decides whether the decompressor runs by naming the file.

This is the `mftp://` branch specifically. The `http(s)://` branch has the same three lines at
`:1564-1567`, but they are unreachable: it builds its local path from the cache tag rather than from
the URL.

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:1491-1493, :1527
auto file_cache_tag = replace_non_ascii_and_whitespace(
    std::string("camera_definition-") + info.model_name + "_" + info.vendor_name + "-" +
    std::to_string(potential_camera.camera_definition_version) + ".xml");
...
auto download_path = _tmp_download_path / file_cache_tag;
```

The tag always ends in `.xml`, and `replace_non_ascii_and_whitespace` only substitutes `_` for
non-ASCII and whitespace bytes, so `download_path.extension()` is never `.xz`. Serving a `.xz` at an
`http://` `cam_definition_uri` puts the compressed bytes in the cache verbatim and decompresses
nothing.

### 4. The same sink, without the Camera plugin

`COMPONENT_METADATA` reaches `inflateLZMAFile` through a different file, and this path builds its
local name from the URI:

```cpp
// cpp/src/mavsdk/core/mavlink_component_metadata.cpp:212-213
const std::filesystem::path local_path =
    tmp_download_path / std::filesystem::path(download_path).filename();
```

```cpp
// cpp/src/mavsdk/core/mavlink_component_metadata.cpp:270-273
const std::string base_filename = filename_from_uri(uri);
const std::filesystem::path tmp_download_path =
    _tmp_download_path / ("http-" + std::to_string(compid) + "-" +
                          std::to_string(type) + "-" + base_filename);
```

Both forms land in `extract_and_cache_file`, which also accepts `.lzma`:

```cpp
// cpp/src/mavsdk/core/mavlink_component_metadata.cpp:352-359
if (path.extension() == ".lzma" || path.extension() == ".xz") {
    returned_path.replace_extension(".extracted");
    if (InflateLZMA::inflateLZMAFile(path, returned_path)) {
        std::filesystem::remove(path);
    } else {
        LogErr("Inflate of compressed json failed {}", path.string());
        return std::nullopt;
    }
}
```

The request is automatic for any application that constructs the `Events` plugin:

```cpp
// cpp/src/mavsdk/plugins/events/events_impl.cpp:56
_system_impl->component_metadata().request_autopilot_component();
```

### 5. The decoder has no output ceiling

```cpp
// cpp/src/mavsdk/core/inflate_lzma.cpp:27-49
// Memory usage limit is useful if it is important that the
// decompressor won't consume gigabytes of memory. The need
// for limiting depends on the application. In this example,
// no memory usage limiting is used. This is done by setting
// the limit to UINT64_MAX.
...
lzma_ret ret = lzma_stream_decoder(strm, UINT64_MAX, LZMA_CONCATENATED);
```

The file is a copy of liblzma's `02_decompress.c` example, including the comment explaining that the
example does not limit anything.

```cpp
// cpp/src/mavsdk/core/inflate_lzma.cpp:110-154
while (true) {
    ...
    lzma_ret ret = lzma_code(strm, action);

    if (strm->avail_out == 0 || ret == LZMA_STREAM_END) {
        size_t write_size = sizeof(outbuf) - strm->avail_out;

        if (fwrite(outbuf, 1, write_size, outfile) != write_size) {
```

No running total and no ceiling. `outbuf` is a fixed `BUFSIZ` stack buffer, so the cost lands on
disk rather than in memory.

### 6. The result is cached, and the cache is bounded by file count

```cpp
// cpp/src/mavsdk/plugins/camera/camera_impl.cpp:1667-1673
if (_file_cache) {
    // Cache the file (this will move/remove the temp file as well)
    downloaded_filepath =
        _file_cache->insert(file_cache_tag, downloaded_filepath)
            .value_or(downloaded_filepath);
    LogDebug("Cached path: {}", downloaded_filepath.string());
}
```

```cpp
// cpp/src/mavsdk/core/file_cache.cpp:231-235
void FileCache::remove_old_entries(const AccessCounters& access_counters) const
{
    int num_delete = static_cast<int>(access_counters.cached_files.size()) - _max_num_files;
```

`_max_num_files` is 50 for both caches (`camera_impl.cpp:61`, `mavlink_component_metadata.cpp:37-38`)
and nothing accounts for bytes. The camera tag is built from `model_name`, `vendor_name` and
`cam_definition_version`; the component metadata tag is
`compid-%03i_crc-%08x_type-%02i_trans-%i`, whose `crc` is the `file_crc` field of the
`COMPONENT_METADATA` message. Both are supplied by the vehicle, so distinct entries are the sender's
to create.

The insert happens before the document is parsed, so content that fails to parse still costs its
full size on disk.

### 7. A failed decode leaves its output behind

```cpp
// cpp/src/mavsdk/core/inflate_lzma.cpp:285-291
const bool success = decompress(&strm, lzma_filename.string().c_str(), infile, outfile);
fclose(infile);
fclose(outfile);

lzma_end(&strm);

return success;
```

The output file is closed and returned on, never removed. The callers do not remove it either: the
camera branch logs and returns, and `extract_and_cache_file` returns `std::nullopt`. A write that
fails with `ENOSPC` therefore leaves the filesystem full.

---

## Taint trace

```
[wire]  HEARTBEAT from any compid
   v
process_heartbeat -> _potential_cameras                    camera_impl.cpp:1178-1190
   |     no MAV_TYPE test, no compid range check
   v
request_camera_information(compid)                         camera_impl.cpp:1198, :2489
   v
[wire]  CAMERA_INFORMATION.cam_definition_uri (char[140])
   |
   |-- http(s):// -> download_path = _tmp_download_path / file_cache_tag
   |                 tag always ends ".xml"                camera_impl.cpp:1493, :1527
   |                 ===> the .xz branch at :1564 cannot fire
   |
   '-- mftp:// -> downloaded_filename  (scheme stripped)   camera_impl.cpp:1599
         v
       MAVLink-FTP download into _tmp_download_path        camera_impl.cpp:1601
         v
       if (downloaded_filepath.extension() == ".xz")       camera_impl.cpp:1650
             the sender named the file, so the sender chose this branch

[wire]  COMPONENT_METADATA.uri (char[100])          requested by EventsImpl::init()
   |                                                       events_impl.cpp:56
   |-- mftp:// -> tmp / path(download_path).filename()     mavlink_component_metadata.cpp:213
   '-- http(s):// -> tmp / ("http-...-" + filename_from_uri(uri))
                                                           mavlink_component_metadata.cpp:270-273
         v
       if (extension == ".lzma" || extension == ".xz")     mavlink_component_metadata.cpp:352

both reach:
InflateLZMA::inflateLZMAFile(...)
   |-- lzma_stream_decoder(strm, UINT64_MAX, ...)          inflate_lzma.cpp:49
   '-- while (true) { ... fwrite(outbuf, ...) }            inflate_lzma.cpp:110-154
         ===> output size is whatever the stream decodes to
   v
_file_cache->insert(tag, path)                             camera_impl.cpp:1670
   ===> moved to ~/.cache/mavsdk/..., outlives the process  mavlink_component_metadata.cpp:364
         cache bound is 50 entries, not bytes              file_cache.cpp:233

on failure: the partial output is never unlinked           inflate_lzma.cpp:285-291
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink link the SDK is connected to | n/a | Push. Any vehicle, component or MITM |
| Application constructs `Camera` **or** `Events` | needed | Its only involvement. It makes no calls |
| Heartbeat handler registered | **Yes** | At construction, unconditionally |
| Sender is a camera | **not required** | No `MAV_TYPE` test, no compid filter |
| Operator interaction | **None** | The chain is driven by inbound traffic |
| File cache enabled | **Yes** | `init()` resolves the user cache directory; the normal case |
| Filename ends in `.xz` | attacker's choice | It is the vehicle's own `cam_definition_uri` or `COMPONENT_METADATA.uri` |
| `mftp://` rather than `http(s)://` | for the camera route only | The HTTP camera path names its own file and cannot reach the decoder |

---

## Impact

A vehicle on an unauthenticated MAVLink link writes as much as it likes to the ground station's
disk, at a cost to itself of a few hundred kilobytes, with nothing clicked. 156,316 bytes on the
wire produced 1,073,741,824 bytes on disk, a ratio of 1:6869, and the ratio is a property of the
compressor rather than a limit: the sender picks the output size when it builds the stream.

The cost persists and accumulates. The decompressed file is moved into the user's cache directory
rather than a process temp directory, and the cache evicts on a count of 50 entries with no byte
accounting. Three application lifetimes, each presenting a different vehicle identity, left
3,221,237,808 bytes across three cache entries; a fourth run reusing the first identity was a cache
hit, which reuses the gigabyte rather than reclaiming it.

Against a small filesystem the failure mode is worse than a large file: the write fails with
`ENOSPC`, the partial output is never removed, and the filesystem stays full.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Zero-click | **Yes** | handler registered at construction; the SDK requests the document itself |
| Sender need not be a camera | **Yes** | no `MAV_TYPE` test and no compid filter; reproduced as compid 1 |
| Output size is the sender's choice | **Yes** | no ceiling in the write loop; measured 1:6869 at preset 9e |
| Reachable without the Camera plugin | **Yes** | via `COMPONENT_METADATA`; reproduced against an app whose body is `mavsdk::Events` |
| Survives application exit | **Yes** | the result is moved into the user cache directory |
| Accumulates across runs | **Yes** | measured 3 × 1 GiB over three application lifetimes, bound is 50 entries |
| Filling the disk leaves it full | **Yes** | the partial output is never unlinked; measured on a 256 MB filesystem |
| Reachable through an `http(s)://` camera definition | **No** | that branch names its file from the cache tag, which always ends `.xml`. Confirmed: the compressed bytes were cached verbatim and nothing was decompressed |
| Memory exhaustion | **No** | the output buffer is a fixed `BUFSIZ` stack buffer; this is a disk primitive |
| A large declared LZMA dictionary causes a large allocation | **No** | checked separately and not observed |
| Confidentiality or integrity impact | **No** | nothing is read or executed |

---

## Version scope

| Version | Layout | heartbeat | camera `.xz` (mftp) | metadata `.xz` / `.lzma` | decoder init | write loop |
|---|---|---|---|---|---|---|
| `main` `34b417d45` | `cpp/src/mavsdk/…` | `:1178` | `:1650` | `:352` | `inflate_lzma.cpp:49` | `:110-154` |
| `v3.17.4` (tested) | `src/mavsdk/…` | `:1008` | `:1477` | `:340` | `inflate_lzma.cpp:49` | `:110-154` |

`camera_impl.cpp` has moved roughly 170 lines between the two trees. `inflate_lzma.cpp` is
byte-identical apart from the header it includes, so the decoder configuration and the write loop
are the same code in the current release and on main.

---

## Reproduction

Authorized bench only. Requires Docker. The image installs the shipped
`libmavsdk-dev_3.17.4_debian12_arm64.deb` release artifact rather than building from source, so what
is under test is what users install.

`demo.sh` is split into steps so both sides can be watched together:

```bash
./demo.sh up               # build the image and start the container
./demo.sh vehicle 2        # terminal A: the attacker, serving a 2 GiB bomb as mftp://def.xml.xz
./demo.sh before           # terminal B: show free disk and an empty cache
./demo.sh run              # terminal B: the operator app, whose whole body is mavsdk::Camera{system}
./demo.sh cache            # terminal B: the cached file, in bytes, after the app has exited
```

`run.sh` does the same thing in one shot inside a single container, which is the easier form to
script:

```bash
./run.sh control           # ordinary definition: the app works normally
./run.sh bomb 1            # 1 GiB written to the app's disk
```

Three smaller probes cover the rest of the claims:

```bash
probe_component_metadata.py   # the COMPONENT_METADATA route, paired with events_app.cpp,
                              # whose whole body is mavsdk::Events{system}
probe_http_camdef.py          # an http(s) cam_definition_uri naming a .xz -- the negative case
persist.sh                    # four application lifetimes in one container, to show the cache
                              # accumulating and then hitting
```

Two things make a working run look like a failure. The first is that MAVSDK logs the download and
the decompression as ordinary progress, so the only visible sign is the disk; check free space and
the cache directory rather than the log. The second is that the document does not parse afterwards
— the decompressed bytes are zeros, so tinyxml2 reports an empty document and the JSON parser
reports a syntax error. That error arrives *after* the file has been cached, which is the point: the
cost is paid before the content is ever looked at.

Building the `.xz` at preset 9e takes real CPU time, around a minute for 2 GiB. `--bomb-cache PATH`
reuses a previously built payload so repeat runs are instant.
