# MP-03 — `STATUSTEXT` markup reaches `Process.Start` with ShellExecute, on a link the attacker labels

| Field | Value |
|---|---|
| **Product** | Mission Planner (ArduPilot GCS, Windows / .NET) |
| **Severity** | **HIGH** — CVSS 3.1 **8.1** `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` |
| **CWE** | CWE-74 (injection) · CWE-601 (untrusted URL redirect) · CWE-77/88 flavour via `UseShellExecute=true` |
| **Affected** | `master` and every released Mission Planner. Latest release 1.3.83 (2025-09-10) |
| **Fixed in** | nothing yet |
| **Verified** | master `0cdb16308` (2026-09-08) |
| **Interaction** | The operator presses **Arm**, the arm is rejected, and they click the link in the failure dialog |
| **Platform** | Windows |
| **Status** | Live-tested 2026-06-30 — the "Arm failed" dialog rendered the attacker-controlled link, with a spoofed label, delivered across multiple `STATUSTEXT` frames |
| **Advisory** | [GHSA-qc8x-7mcx-cqjq](https://github.com/ArduPilot/MissionPlanner/security/advisories/GHSA-qc8x-7mcx-cqjq) |
| **Fix** | [`fix/mp-03-statustext-link-scheme`](https://github.com/nicholasaleks/MissionPlanner/tree/fix/mp-03-statustext-link-scheme) against `0cdb16308`, submitted as [ArduPilot/MissionPlanner#3776](https://github.com/ArduPilot/MissionPlanner/pull/3776) |

---

## Demo

<a href="https://www.youtube.com/watch?v=yo7rNbbAsvU">
  <img src="https://img.youtube.com/vi/yo7rNbbAsvU/maxresdefault.jpg" alt="MP-03 — STATUSTEXT markup to Process.Start with a spoofed link target" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=yo7rNbbAsvU)**

---

## Summary

When an arm attempt fails, Mission Planner concatenates every `STATUSTEXT` the vehicle emitted during
that attempt and passes the result verbatim as the body of the failure dialog. The dialog then parses
the body for a `[link;<target>;<label>]` markup, builds a clickable `LinkLabel`, and on click calls
`System.Diagnostics.Process.Start(target)`.

`Process.Start(string)` on .NET Framework defaults to `UseShellExecute = true`, so the target is
handed to the Windows shell rather than treated as a URL. There is no scheme allow-list. The shell
will resolve `http(s)` in the browser, `file://` and bare paths to local files and executables, UNC
paths like `\\host\share\file` by mounting the SMB share, and any registered protocol handler.

Two capture groups make it worse than an open redirect: group 2 is the target and group 3 is the
visible label, and nothing requires them to match. The attacker shows a real documentation URL and
points it somewhere else.

---

## Root cause

### 1. `STATUSTEXT` bytes become a string

```csharp
// ExtLibs/ArduPilot/Mavlink/MAVLinkInterface.cs:1815-1841
var sub2 = SubscribeToPacketType(MAVLINK_MSG_ID.STATUSTEXT, buffer =>
{
    if (buffer.msgid == (byte) MAVLINK_MSG_ID.STATUSTEXT)
    {
        var msg = buffer.ToStructure<mavlink_statustext_t>();
        string logdata = Encoding.UTF8.GetString(msg.text);        // :1821  attacker bytes
        ...
            MAVlist[sysid, compid].SerialString = logdata;         // :1841  stored raw
```

`msg.text` is the on-wire `STATUSTEXT.text`, a `char[50]`, fully attacker-controlled and never
validated. A second, near-identical handler exists at `:1973-1997`.

### 2. The arm-failure dialog assembles that text verbatim

```csharp
// GCSViews/FlightData.cs:1050-1062
StringBuilder sb = new StringBuilder();
var sub = MainV2.comPort.SubscribeToPacketType(MAVLink.MAVLINK_MSG_ID.STATUSTEXT, message =>
{
    sb.AppendLine(Encoding.ASCII.GetString(((MAVLink.mavlink_statustext_t) message.data).text)
        .TrimEnd('\0'));                                           // :1053  collected verbatim
    return true;
}, (byte)MainV2.comPort.sysidcurrent, (byte)MainV2.comPort.compidcurrent);
bool ans = MainV2.comPort.doARM(!isitarmed);
MainV2.comPort.UnSubscribeToPacketType(sub);
if (ans == false)
{
    if (CustomMessageBox.Show(
            action + " failed.\n" + sb.ToString() + "\nForce " + action +   // :1062  into the dialog body
```

Every `STATUSTEXT` received during the arm attempt is concatenated into `sb`. Because the attacker
controls the text, the attacker controls the markup the dialog is about to parse. The payload can be
split across several frames, since they are appended in order.

### 3. The markup parse

```csharp
// ExtLibs/Controls/CustomMessageBox.cs:87-93
Regex linkregex = new Regex(@"(\[link;([^\]]+);([^\]]+)\])", RegexOptions.IgnoreCase);
Match match = linkregex.Match(text);
if (match.Success)
{
    link = match.Groups[2].Value;        // :91  the target. No scheme allow-list
    linktext = match.Groups[3].Value;    // :92  the visible label, independent of the target
    text = text.Replace(match.Groups[1].Value, "");
```

### 4. The sink

```csharp
// ExtLibs/Controls/CustomMessageBox.cs:165-185
var linklbl = new LinkLabel
{
    ...
    Text = linktext,
    Tag = link,                          // :172  attacker target parked in .Tag
    AutoSize = true
};
linklbl.Click += (sender, args) =>
{
    try
    {
        System.Diagnostics.Process.Start(((LinkLabel)sender).Tag.ToString());   // :179  SINK
    }
    catch (Exception)
    {
        Show("Failed to open link " + ((LinkLabel)sender).Tag.ToString());
    }
};
```

`Process.Start(string)` with the .NET Framework default of `UseShellExecute = true` hands the
argument to the shell. No scheme check, no confirmation beyond the one click on a link the attacker
labelled.

### 5. The same pattern again, with ShellExecute made explicit

A second copy of the identical markup parser feeds a different sink:

```csharp
// Common.cs:351-369
var linkregex = new Regex(@"(\[link;([^\]]+);([^\]]+)\])", RegexOptions.IgnoreCase);
var match = linkregex.Match(promptText);
if (match.Success)
{
    link = match.Groups[2].Value;
    ...
    linklbl.LinkClicked += (sender, args) =>
    {
        OpenUrl(link);                                             // :369
    };
```

```csharp
// Common.cs:455-467
public static void OpenUrl(string url)
{
    try
    {
        Process.Start(url);                                        // :459
    }
    catch
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            url = url.Replace("&", "^&");
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });   // :467  explicit
        }
```

This one lives in the "show me again" dialog family rather than the arm path, so it is a sibling
sink rather than a second route to the same dialog. It is worth citing because `:467` makes the
ShellExecute semantics deliberate rather than an inherited default.

---

## Taint trace

```
[wire]  STATUSTEXT (msg 253), text = char[50], attacker-controlled
   v
operator presses Arm, the arm is rejected
   |
   |-- every STATUSTEXT during the attempt is appended    FlightData.cs:1053
   '-- concatenated into the dialog body                  FlightData.cs:1062
   v
CustomMessageBox.Show(body, ...)
   |-- [link;<target>;<label>] parsed                     CustomMessageBox.cs:87
   |-- link  = Groups[2]  (target, no scheme check)       CustomMessageBox.cs:91
   |-- label = Groups[3]  (independent of the target)     CustomMessageBox.cs:92
   '-- LinkLabel { Text = label, Tag = target }           CustomMessageBox.cs:172
   v
operator clicks the link
   v
Process.Start(Tag)  with UseShellExecute = true           CustomMessageBox.cs:179
   ===> browser, local file, executable, UNC share, or any registered protocol handler

sibling: the same markup -> Common.cs:369 -> OpenUrl -> Process.Start        Common.cs:459
         with an explicit UseShellExecute = true fallback                    Common.cs:467
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink link delivering `STATUSTEXT` | n/a | Push, no handshake. Any vehicle, component or MITM |
| MP accepts the sender's `sysid`/`compid` | **Yes** | The arm-path subscription filters on the *current* sysid/compid, which the attacker is |
| Operator presses **Arm** | **Operator action** | Routine. The attacker chooses when by rejecting the arm |
| The arm is rejected | **Attacker-controlled** | The vehicle decides whether to accept, so the attacker simply refuses |
| Operator clicks the link | **Operator action** | The label is attacker-chosen, so it can read as legitimate documentation |

The attacker controls the timing of the whole sequence: they decide when to fail the arm, and the
dialog only appears because they refused it. What they cannot do is force the click.

---

## Impact

`Process.Start` under ShellExecute is considerably more than an open redirect:

- **UNC path** `\\attacker-host\share\x` mounts an SMB share, leaking the operator's NTLM credentials
  to a host the attacker controls.
- **Local file or executable** via `file://` or a bare path, opened with whatever handler the shell
  associates with it.
- **Registered protocol handler**, including `ms-…:`, `search-ms:` and any custom application scheme
  installed on the machine.
- **Browser navigation** for `http(s)`, which is the drive-by staging case.

The label spoofing is what makes the click likely: the operator is looking at a failed arm, the
dialog offers what appears to be the relevant ArduPilot documentation link, and the target is
somewhere else entirely.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Attacker controls the link target | **Yes** | group 2 of the markup, no scheme allow-list |
| Visible label can disagree with the target | **Yes** | group 3 is independent; demonstrated with a real docs URL |
| Payload can span several frames | **Yes** | `sb.AppendLine` concatenates in order |
| Attacker controls when the dialog appears | **Yes** | by rejecting the arm |
| Attacker can force the click | **No** | the operator must click |
| Direct code execution from the click alone | **No** | it is whatever the shell does with the target. NTLM leak and handler abuse are the realistic outcomes |
| Privilege escalation | **No** | runs as the operator |

---

## Version scope

| Version | `STATUSTEXT` handler | arm-failure body | markup regex | `LinkLabel` sink | `OpenUrl` |
|---|---|---|---|---|---|
| `master` `0cdb16308` (verified) | `MAVLinkInterface.cs:1815` | `FlightData.cs:1050` | `CustomMessageBox.cs:87` | `:165` | `Common.cs:455` |
| 1.3.83 (latest release, 2025-09-10) | `:1812` | `:1038` | `:87` | `:165` | `Common.cs:393` |

The markup parser and the `LinkLabel` sink are at identical lines in both. Mission Planner publishes
rolling tags rather than per-release branches; 1.3.83 is commit `b78a7495`, and `master` has not
moved since the commit verified above.

---

## Reproduction

Authorized bench only. Requires `pymavlink`.

```bash
cd poc
python3 poc_G03_mp_statustext_link_shellexec.py --listen 0.0.0.0:5760
```

Connect Mission Planner to the harness and press **Arm**. The harness refuses the arm and emits
`STATUSTEXT` frames carrying the `[link;…;…]` markup, so the failure dialog renders the attacker's
link. Clicking it fires `Process.Start`.

The payload is split across frames deliberately, because `STATUSTEXT.text` is only 50 bytes and a
useful target plus a convincing label rarely fits in one.