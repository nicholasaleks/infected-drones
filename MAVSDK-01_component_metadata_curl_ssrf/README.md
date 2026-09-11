# MAVSDK-01 — `COMPONENT_METADATA.uri` reaches libcurl with no protocol allowlist

| Field | Value |
|---|---|
| **Product** | MAVSDK (C++ SDK and `mavsdk_server`), component metadata and Camera plugin |
| **Severity** | **MEDIUM** — CVSS 3.1 **5.8** `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N` |
| **CWE** | CWE-918 (SSRF) · CWE-749 (exposed dangerous method — unrestricted libcurl protocol set) |
| **Affected** | `main` and `v3.17.4` (2026-08-25), the current release |
| **Fixed in** | nothing yet |
| **Verified** | main `34b417d45` (2026-09-01) for the source, shipped `libmavsdk-dev` 3.17.4 package for the runs |
| **Interaction** | **None.** The SDK requests `COMPONENT_METADATA` by itself once the application constructs one plugin |
| **Platform** | Cross-platform |
| **Status** | Reproduced on the shipped 3.17.4 package, 2026-09-11. A service reachable only on a network the attacker had no route to was fetched by the ground station and its response written to the station's cache. A separate run read a local file through `file://` into the same cache |
| **Advisory** | not filed |
| **Fix** | none opened |

---

## Summary

MAVSDK fetches `COMPONENT_METADATA.uri` with libcurl. The URI arrives over MAVLink from whatever is
on the link, and the only thing checked about it is whether it starts with `mftp://`; anything else
is handed to `CurlWrapper`, which sets no protocol allowlist.

libcurl's default protocol set is everything the library was built with. The shipped Debian build
accepts 24 schemes, so the URI decides not only *where* the ground station connects but *how*:

- **`http://` and `https://` to any address**, including loopback, RFC1918 and cloud metadata
  endpoints. The request leaves the ground station's own network stack, so it reaches hosts the
  attacker has no route to.
- **`file://`**, which reads a local file into MAVSDK's download directory and cache.
- **`dict://`, `gopher://` and the rest**, which will speak to an arbitrary TCP service.

The response is not returned to the attacker over MAVLink. What it does is land on the victim's
disk and go into the metadata parser.

The same `CurlWrapper` serves the Camera plugin's `cam_definition_uri`, so both message paths share
this sink.

---

## Root cause

### 1. The scheme is the only thing checked

```cpp
// cpp/src/mavsdk/core/mavlink_component_metadata.cpp:202, :264-276
if (uri_is_mavlinkftp(uri, download_path, target_compid)) {
    ...
} else {
    // http(s) download
    ...
    const std::string base_filename = filename_from_uri(uri);
    const std::filesystem::path tmp_download_path =
        _tmp_download_path / ("http-" + std::to_string(compid) + "-" +
                              std::to_string(type) + "-" + base_filename);
    _http_loader.download_async(
        uri,
        tmp_download_path.string(),
```

`uri_is_mavlinkftp` tests for an `mftp://` prefix and nothing else. Everything that is not `mftp://`
goes to libcurl, including `file://`, which is why the `else` branch is not an http-only branch.

### 2. `CurlWrapper` sets no allowlist

```cpp
// cpp/src/mavsdk/core/curl_wrapper.cpp:113-121
curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 5L);
curl_easy_setopt(curl.get(), CURLOPT_XFERINFOFUNCTION, download_progress_update);
curl_easy_setopt(curl.get(), CURLOPT_PROGRESSDATA, &progress);
curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, NULL);
curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, fp);
curl_easy_setopt(curl.get(), CURLOPT_NOPROGRESS, 0L);
curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
```

No `CURLOPT_PROTOCOLS`, no `CURLOPT_REDIR_PROTOCOLS`, and none anywhere else in the tree. The same
option set, minus the file handle, appears in `download_text` at `:29-34`.

The protocol set the shipped image actually offers:

```
dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt
pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps telnet tftp
```

### 3. The request is made without the application asking

```cpp
// cpp/src/mavsdk/plugins/events/events_impl.cpp:56
_system_impl->component_metadata().request_autopilot_component();
```

```cpp
// cpp/src/mavsdk/core/mavlink_component_metadata.cpp:62-71
void MavlinkComponentMetadata::request_component(uint32_t compid)
{
    if (_mavlink_components.find(compid) == _mavlink_components.end()) {
        _mavlink_components[compid] = MavlinkComponent{};
        _system_impl.mavlink_request_message().request(
            MAVLINK_MSG_ID_COMPONENT_METADATA, compid, [this](auto&& result, auto&& message) {
                receive_component_metadata(result, message);
            });
```

Constructing `mavsdk::Events` is enough. `EventsImpl::init()` asks the autopilot for its metadata,
and the vehicle answers with whatever URI it likes.

### 4. The result is kept

```cpp
// cpp/src/mavsdk/core/mavlink_component_metadata.cpp:362-365
if (_file_cache && !file_cache_tag.empty()) {
    // Cache the file (this will move/remove the temp file as well)
    returned_path = _file_cache->insert(file_cache_tag, returned_path).value_or(returned_path);
}
```

Whatever came back is moved into `~/.cache/mavsdk/component_metadata/`, where it stays.

---

## Taint trace

```
[wire]  HEARTBEAT
   v
EventsImpl::init() -> request_autopilot_component()        events_impl.cpp:56
   v
MAV_CMD_REQUEST_MESSAGE(397)                               mavlink_component_metadata.cpp:67
   v
[wire]  COMPONENT_METADATA.uri (char[100])                 :110-113
   v
uri_is_mavlinkftp(uri, ...)                                :132-156
   |     tests for an "mftp://" prefix, nothing else
   |
   '-- everything else -> _http_loader.download_async(uri) :274
         v
       CurlWrapper::download_file_to_path                  curl_wrapper.cpp:94
         |-- CURLOPT_URL        = the wire string          :116
         |-- CURLOPT_FOLLOWLOCATION = 1                    :121
         '-- no CURLOPT_PROTOCOLS, no CURLOPT_REDIR_PROTOCOLS
               |
               |-- http(s)://<internal host>   ===> SSRF from the GCS host
               |-- file:///path                ===> local file read
               '-- dict:// gopher:// ...       ===> arbitrary TCP service
         v
       extract_and_cache_file -> _file_cache->insert(...)  :362-365
         ===> the response is kept in ~/.cache/mavsdk/component_metadata

same sink, other message: CAMERA_INFORMATION.cam_definition_uri
   http(s):// -> _http_loader->download_async(url)         camera_impl.cpp:1529
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink link the SDK is connected to | n/a | Push. Any vehicle, component or MITM |
| Application constructs `Events` (or `ComponentMetadata`, or `Camera`) | needed | Its only involvement. It makes no calls |
| Operator interaction | **None** | The SDK requests the message itself |
| Built with curl | **Yes** | `BUILD_WITHOUT_CURL` is off in the shipped packages |
| Attacker knows the internal address to name | needed for targeting | Loopback and RFC1918 ranges are guessable |
| File cache enabled | **Yes** | `init()` resolves the user cache directory |

---

## Impact

The ground station is turned into a request proxy for anything the vehicle names. The fetch leaves
the ground station's own network stack, so it reaches whatever that host can reach and the attacker
cannot: loopback services, RFC1918 hosts, cloud metadata endpoints. In the reproduction the attacker
had no route to the target at all, and the target's response still ended up on the ground station's
disk.

`file://` makes the same mechanism read local files. A URI of `file:///path` puts that file's
content into MAVSDK's download directory and then into the metadata cache.

What the attacker does not get is the content. Nothing is returned over MAVLink, so this is a blind
primitive: the attacker chooses the request, the ground station makes it, and the response goes to
the victim's own disk and parsers.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Zero-click | **Yes** | the SDK requests `COMPONENT_METADATA` itself once a plugin is constructed |
| Reaches hosts the attacker cannot | **Yes** | reproduced across a docker network the attacker was not on |
| Reads local files via `file://` | **Yes** | reproduced; the file's bytes were recovered from the victim's cache |
| Non-HTTP schemes reach a TCP service | **Yes** | `dict://` returned 362 bytes through the genuine `CurlWrapper` |
| The response is returned to the attacker | **No** | nothing goes back over MAVLink |
| Redirect from `http://` into `file://` | **No** | libcurl's default `CURLOPT_REDIR_PROTOCOLS` already excludes FILE; the attempt fails with *Unsupported protocol* |
| Fallback URI gives the attacker a success/failure oracle | **No** | the chain does not get that far, see below |
| Code execution | **No** | the response is parsed as JSON, nothing is executed |

**Chained fetches do not complete.** A metadata document that declares a second type over `http(s)`
never has that second URI fetched: `HttpLoader::work_thread` holds the work-queue lock across the
download, and the completion callback re-enters `HttpLoader::download_async`, which takes the same
non-recursive mutex. The work thread blocks there permanently. This bounds the finding — there is no
fallback-URI oracle — and it is a defect in its own right.

---

## Version scope

| Version | Layout | `uri_is_mavlinkftp` | http download | `CURLOPT_URL` | `FOLLOWLOCATION` | allowlist |
|---|---|---|---|---|---|---|
| `main` `34b417d45` | `cpp/src/mavsdk/…` | `:132` | `:274` | `curl_wrapper.cpp:116` | `:121` | absent |
| `v3.17.4` (tested) | `src/mavsdk/…` | `:128` | `:262` | `curl_wrapper.cpp:116` | `:121` | absent |

`download_text` carries the same option set at `:29-34` in both trees.

---

## Reproduction

Authorized bench only. Requires Docker. The image installs the shipped
`libmavsdk-dev_3.17.4_debian12_arm64.deb` release artifact rather than building from source.

`ssrf.sh` builds three containers on two docker networks, so the internal target is genuinely
unreachable from the attacker rather than merely notionally so:

```bash
./ssrf.sh        # prints the protocol set, proves the attacker has no route to
                 # internal-svc, then runs four cases
```

- **Case 1** hands the victim `http://internal-svc:8080/secret.json`. The attacker's own `curl` to
  that host fails; the victim fetches it and the payload appears in the victim's cache.
- **Case 2** hands it `file:///etc/mavsdk-bench-secret.txt` and recovers the file's bytes from the
  same cache.
- **Case 3** answers with a 302 into `file://` and shows libcurl refusing it.
- **Cases 4a and 4b** set a primary and a fallback URI, and show the fallback never being fetched.

The victim application is `events_app.cpp`, whose whole body is `mavsdk::Events{system}`.

Check the victim's cache rather than its log. MAVSDK logs the fetch as ordinary progress whatever
the scheme was, so the evidence is the file that appears in
`~/.cache/mavsdk/component_metadata/`.
