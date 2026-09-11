# MP-01 — MAVLink-FTP directory-listing path traversal → `File.WriteAllBytes` → auto-compiling plugin loader = remote code execution

| Field | Value |
|---|---|
| **Product** | Mission Planner (ArduPilot GCS, Windows / .NET) |
| **Severity** | **HIGH** — CVSS 3.1 **8.8** `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-22 → CWE-94 / CWE-434 · CWE-345 |
| **Affected** | `master` and every released Mission Planner. Latest release 1.3.83 (2025-09-10) |
| **Fixed in** | nothing yet |
| **Verified** | master `0cdb16308` (2026-09-08) — every line citation below is exact at that commit |
| **Interaction** | One **Download** click in the MAVFtp window. Execution is automatic on the next MP launch |
| **Platform** | Windows. Mission Planner is a WinForms / .NET Framework application |
| **Status** | Live-tested against Mission Planner on Windows |
| **Advisory** | [GHSA-r78w-8v8p-4v5p](https://github.com/ArduPilot/MissionPlanner/security/advisories/GHSA-r78w-8v8p-4v5p) |
| **Fix** | [`fix/mp-01-mavftp-filename-traversal`](https://github.com/nicholasaleks/MissionPlanner/tree/fix/mp-01-mavftp-filename-traversal) against `0cdb16308`, no PR opened yet |

---

## Demo

<a href="https://www.youtube.com/watch?v=qHqa-1CIQwk">
  <img src="https://img.youtube.com/vi/qHqa-1CIQwk/maxresdefault.jpg" alt="MP-01 — MAVFTP listing traversal to plugin-loader RCE" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=qHqa-1CIQwk)**

---

## Summary

Mission Planner's MAVLink-FTP browser stores each vehicle-supplied directory-entry filename
**verbatim** — no sanitisation of `..`, `/`, `\`, or drive letters. When the operator clicks
**Download**, MP writes the (also vehicle-supplied) contents to
`Path.Combine(savedir, attacker_filename)`. .NET's `Path.Combine` lets a rooted or `..`-laden second
argument escape the chosen directory, so a hostile vehicle places an arbitrary file anywhere the MP
process can write — including MP's own `plugins\` folder.

On the next launch, `PluginLoader.LoadAll()` Roslyn-compiles and executes **every** `*.cs` in
`plugins\` with no signature, hash, or Authenticode check. Arbitrary write becomes arbitrary code
execution in the operator's session.

The download path is the bug because it omits the `Path.GetFileName()` call that the **upload** path
in the same file correctly applies.

---

## Root cause

### 1. Taint source — the wire filename is stored unvalidated

```csharp
// ExtLibs/ArduPilot/Mavlink/MAVFtp.cs:1310-1322
case kDirentFile:
    var filename = new StringBuilder();
    while (b != 0x0)
    {
        b = ftphead.data[offset++];          // raw MAVLink-FTP ACK payload, off the wire
        if (b != 0x0)
            filename.Append((char) b);
    }

    var items = filename.ToString().Split('\t');
    var size = ulong.Parse(items[1]);
    answer.Add(new FtpFileInfo(items[0], dir, false, size));   // items[0] stored verbatim
    break;
```

`FtpFileInfo` (`MAVFtp.cs:2363-2368`) just assigns `Name = name`. No `Path.GetFileName`, no rejection
of `..`, `/`, `\` or `C:\`.

### 2. It reaches the UI unchanged

```csharp
// Controls/MavFTPUI.cs:172-182
foreach (var file in await nodeDirInfo.GetFiles())
{
    item = new ListViewItem(file.Name, 1);   // file.Name == attacker FtpFileInfo.Name
    listView1.Items.Add(item);
```

So `listView1SelectedItem.Text` downstream **is** the raw vehicle filename.

### 3. Sink — `Path.Combine` + `File.WriteAllBytes`

```csharp
// Controls/MavFTPUI.cs:345-351   (DownloadToolStripMenuItem_Click)
var file = Path.Combine(sfd.SelectedPath, listView1SelectedItem.Text);   // traversal
int a = 0;
while (File.Exists(file))
{
    file = Path.Combine(sfd.SelectedPath, listView1SelectedItem.Text) + a++;
}
File.WriteAllBytes(file, ms.ToArray());                                  // arbitrary write
```

`Controls/MavFTPUI.cs:629-635` (`DownloadBurstToolStripMenuItem_Click`) is a byte-identical,
independently exploitable copy.

.NET's rule is *"if `path2` is an absolute path, the result is `path2`"*, and `..` segments are
preserved into the result and resolved by the filesystem at open time. So:

- `..\..\plugins\evil.cs` escapes the chosen folder into a sibling `plugins\`
- `C:\Program Files (x86)\Mission Planner\plugins\evil.cs` **ignores the operator's folder choice entirely**

### 4. The asymmetry that shows it is an omission, not a design

```csharp
// Controls/MavFTPUI.cs:392-393   (upload)
toolStripStatusLabel1.Text = "Upload " + Path.GetFileName(ofdFileName);
var fn = treeView1.SelectedNode.FullPath + "/" + Path.GetFileName(ofdFileName);
```

Upload strips directory components. Download does not — on the inbound, vehicle-controlled
direction, which is the one that matters.

### 5. RCE amplifier — the plugin loader executes anything dropped in `plugins\`

```csharp
// Plugin/PluginLoader.cs:203-254
public static void LoadAll()
{
    string path = Settings.GetRunningDirectory() + "plugins" + Path.DirectorySeparatorChar;
    ...
    String[] csFiles = Directory.GetFiles(path, "*.cs");            // :216
    foreach (var csFile in csFiles)
    {
        var content = File.ReadAllText(csFile);
        var matches = Regex.Matches(content, @"^\/\/loadassembly: (.*)$", RegexOptions.Multiline);
        foreach (Match m in matches)
            Assembly.Load(m.Groups[1].Value.Trim());                // :237  attacker-chosen assembly
        var ans = CodeGenRoslyn.BuildCode(csFile);                  // :248  Roslyn-compile attacker .cs
        InitPlugin(ans, Path.GetFileName(csFile));                  // :254  instantiate and run
    ...
String[] files = Directory.GetFiles(path, "*.dll");                 // :304  *.dll loaded too
```

`LoadAll()` runs at startup — `MainV2.cs:3195`.

`CodeGenRoslyn.BuildCode` (`ExtLibs/Utilities/CodeGen.cs:25-98`) computes an MD5 of the source, but
**only as a compile-cache key** (`md5hash + ".dll"`). There is no signature, strong-name,
hash-allowlist, or Authenticode verification before `CSharpCompilation.Create` at `:78` and the
subsequent `Assembly.Load`.

### 6. Variant B — Dokan mount re-surfaces the raw name to the whole Windows shell

```csharp
// ExtLibs/ArduPilot/MavFtpDokan.cs:351, :373
FileName = entry.Name,      // raw vehicle FtpFileInfo.Name
FileName = e.Name,
```

With **Mount as Drive** (requires Dokan installed), the unsanitised vehicle filename becomes a live
filename on an `M:\`-style drive, exposed to any process or shell operating on it.

---

## Taint trace

```
[1] MAVLink-FTP ListDirectory ACK payload         MAVFtp.cs:1314   ftphead.data[offset++]
[2] split on '\t'                                 MAVFtp.cs:1319
[3] items[0] stored verbatim as FtpFileInfo.Name  MAVFtp.cs:1321   (no sanitisation)
[4] shown in the MAVFtp ListView                  MavFTPUI.cs:174
[5] operator selects entry, clicks Download       MavFTPUI.cs:314
[6] contents fetched (also attacker-controlled)   MavFTPUI.cs:337  _mavftp.GetFile(...)
[7] dest = Combine(savedir, attacker_name)        MavFTPUI.cs:345  -> escapes savedir
[8] arbitrary file write                          MavFTPUI.cs:351  -> <install>\plugins\evil.cs
--- next Mission Planner launch ---
[9]  enumerate plugins\*.cs                       PluginLoader.cs:216
[10] //loadassembly: -> Assembly.Load             PluginLoader.cs:237
[11] Roslyn compile, no signature check           PluginLoader.cs:248 -> CodeGen.cs:78
[12] InitPlugin -> plugin code runs               PluginLoader.cs:254  ==> CODE EXECUTION

Variant B: [3] -> MavFtpDokan.cs:351/373 -> live M:\ filename
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink-FTP enabled on the link | Yes | Standard ArduPilot capability; MP uses it for params, logs, scripts |
| Attacker answers FTP as the vehicle | — | MAVLink is unauthenticated by default |
| Operator opens MAVFtp and clicks **Download** | Operator action | One click in a routine maintenance UI |
| `plugins\` exists and is writable | Usually | MP ships a `plugins\` folder; the common unzip-and-run install is user-writable |
| Plugin loader runs at startup | Yes | `MainV2.cs:3195`, unless MP is launched with Shift held |
| Roslyn/CodeGen available | Yes | Bundled |
| **Variant B only:** Dokan + Mount as Drive | No (opt-in) | The primary path needs neither |

**Honest caveats.** This is one-click, not zero-click. Execution is deferred to the next MP start.
For a per-machine `Program Files` install with restricted ACLs, writing into `plugins\` needs
elevation — but MP is very commonly run from a user-writable directory, and the absolute-path
variant can target other user-writable autorun locations instead.

The displayed list item and the write path are the **same string**, so a "flight log" cannot silently
become a `.cs` — the extension is whatever the operator sees. What the attacker can do is make the
click unremarkable: pad the name with whitespace so the traversal tail scrolls off the fixed-width
Name column, bury it among believable decoy entries, and rely on select-all → Download (the sink is a
`foreach` over `SelectedItems`). Widening the column or hovering reveals the tail. Bidi/RLO and
homoglyph tricks do **not** work here — the loader matches the true extension via
`GetFiles(path, "*.cs")` and the path needs the literal ASCII segment `plugins\`.

---

## Impact

- **Arbitrary code execution** in the MP process in the operator's security context — mission data,
  credentials, vehicle control, lateral movement.
- **Persistence.** The planted `evil.cs` re-executes on every subsequent MP launch until removed.
  The plugin folder *is* the autorun foothold.
- **Breadth.** Any MP operator who browses a hostile or MITM'd vehicle's filesystem and downloads a
  file. Variant B additionally exposes the raw filename to the entire Windows shell.

---

## Reproduction

Authorized bench only. Requires `pymavlink`.

```bash
cd poc
python3 make_payload.py                                    # generates the listing entry
python3 poc_G01_mp_mavftp_plugin_rce.py --listen 0.0.0.0:5760
```

`make_payload.py` writes the payload into `poc/ftp/` at runtime rather than it being committed. The
entry's *filename* is the exploit, and a file literally named
`log.bin<spaces>..\..\..\..\..\..\Program Files (x86)\Mission Planner\plugins\evil.cs` cannot be
checked out on Windows and trips antivirus and repository malware scanning everywhere else. The
payload *contents* are inert — the plugin writes one marker file to `%TEMP%` and exits.

In Mission Planner: add a **TCP** connection to
`127.0.0.1:5760`, Connect, open the **MAVFtp** window, select the planted entry, **Download**, pick
any folder.

Success indicators:

- `evil.cs` appears under `C:\Program Files (x86)\Mission Planner\plugins\` — *not* in the folder you
  picked. That alone proves the traversal.
- After restarting MP: `%TEMP%\mp_plugin_poc_marker.txt` exists. That proves the full chain.

---

---

## Fix scope

The branch changes one thing, at both download handlers: the vehicle-supplied entry name is reduced
with `Path.GetFileName()` before it reaches `Path.Combine()`, and an entry that cannot be represented
as a file name is logged and skipped rather than written somewhere else.

That is the same reduction the **upload** path in the same file already applies at `:392-393`, which
is the whole argument for the change: the protection exists, and the inbound direction simply does
not use it.

Two things are deliberately left out.

The **remote** path is untouched. It is built separately as
`treeView1.SelectedNode.FullPath + "/" + listView1SelectedItem.Text`, so sanitising the shared string
at its source in `MAVFtp.cs` would change which file is fetched from the vehicle, not just where it
lands. Fixing only the local side keeps download behaviour identical.

**Variant B is not fixed.** `MavFtpDokan.cs:351` and `:373` surface the same raw name on a mounted
drive. Reaching it needs the Dokan driver installed and an explicit **Mount as Drive**, and fixing it
properly means sanitising at the source, which is the change above that would alter remote paths.

Hardening the plugin loader is the other half of the chain and a much larger change:
`PluginLoader.LoadAll()` Roslyn-compiles and executes every `*.cs` in `plugins\` with no authenticity
check, and `Assembly.Load`s every `*.dll`. The MD5 in `CodeGenRoslyn.BuildCode` is a compile-cache
key, not a trust boundary. Making that trust explicit is a maintainer design decision.
