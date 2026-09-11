# MP-04 — `RALLY_TOTAL` / `FENCE_TOTAL` reach `int.Parse` outside the try, on the UI thread, on connect

| Field | Value |
|---|---|
| **Product** | Mission Planner (ArduPilot GCS, Windows / .NET) |
| **Severity** | **MEDIUM** — CVSS 3.1 **5.3** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **CWE** | CWE-248 (uncaught exception) · CWE-20 → CWE-703 · secondary CWE-1050 (excessive iteration) |
| **Affected** | `master` and every released Mission Planner. Latest release 1.3.83 (2025-09-10) |
| **Fixed in** | nothing yet |
| **Verified** | master `0cdb16308` (2026-09-08) |
| **Interaction** | **None.** Fires during the automatic post-connect sequence |
| **Platform** | Windows |
| **Status** | **Source-verified only.** PoC written; not live-confirmed against a Windows Mission Planner build. The parse path is read off the code, not observed |
| **Advisory** | not filed |
| **Fix** | [`fix/mp-04-param-total-tryparse`](https://github.com/nicholasaleks/MissionPlanner/tree/fix/mp-04-param-total-tryparse) against `0cdb16308`, no PR opened yet |

---

## Summary

When Mission Planner finishes connecting it downloads the parameter list and then runs a post-connect
block on the UI thread. That block reads `RALLY_TOTAL` and `FENCE_TOTAL` with
`int.Parse(param[...].ToString())`.

A vehicle controls both the *type* and the *value* of any parameter it reports. Reporting
`RALLY_TOTAL` as a `REAL32` whose string form is not an integer — `3.5`, `NaN`, `1E+30` — makes
`int.Parse` throw.

Two details turn that from a caught nuisance into an unhandled exception:

1. The `int.Parse` is inside the `if` **condition**, and the block's `try` opens on the line after
   the `{`. The throw happens before anything can catch it.
2. The whole block runs inside a `BeginInvokeIfRequired` lambda that has no try/catch of its own.

So the exception escapes either into `doConnect`'s catch, aborting the connection, or onto the UI
message pump as `Application.ThreadException`, producing Mission Planner's generic *"An error has
occurred … Report this Error?"* modal. Either way the operator cannot complete a connection to that
vehicle, and the rest of the post-connect setup never runs.

A second, higher-impact variant sits in the same block: if `RALLY_TOTAL` is a *valid* large integer,
Mission Planner downloads that many rally points and then computes haversine distances between
**every pair** on the UI thread.

---

## Root cause

### 1. The sinks

```csharp
// MainV2.cs:1762-1765
// get any rallypoints
if (MainV2.comPort.MAV.param.ContainsKey("RALLY_TOTAL") &&
    int.Parse(MainV2.comPort.MAV.param["RALLY_TOTAL"].ToString()) > 0 && showui)   // :1763
{
    try                                                                            // :1765
    {
```

```csharp
// MainV2.cs:1800-1804
// get any fences
if (MainV2.comPort.MAV.param.ContainsKey("FENCE_TOTAL") &&
    int.Parse(MainV2.comPort.MAV.param["FENCE_TOTAL"].ToString()) > 1 &&           // :1801
    MainV2.comPort.MAV.param.ContainsKey("FENCE_ACTION") && showui)
{
    try
    {
        FlightPlanner.GeoFencedownloadToolStripMenuItem_Click(null, null);
    }
    catch (Exception ex)
    {
        log.Warn(ex);
    }
}
```

Two things matter about the placement. The `int.Parse` is `&&`-chained in the condition, so C#
short-circuit evaluation runs it as soon as `ContainsKey` is true — **before** `showui` is even
consulted, and **before** the `try` that opens on the next line. The fence block's `catch` only logs
a warning, and it never sees this throw either.

### 2. The taint

```csharp
// ExtLibs/Mavlink/MAVLinkParam.cs:219-224
public override string ToString()
{
    if (Type == MAV_PARAM_TYPE.REAL32)
        return ((float)this).ToString();     // "3.5", "NaN", "1E+30", ...
    return Value.ToString();
}
```

Mission Planner trusts the `param_type` the vehicle reports. A vehicle sending `RALLY_TOTAL` as
`param_type = 9 (REAL32)` with `param_value = 3.5f` makes `ToString()` return `"3.5"`, and:

- `int.Parse("3.5")` → `FormatException` (the decimal point is rejected)
- `int.Parse("NaN")`, `int.Parse("1E+30")` → `FormatException`
- a valid integer string above `int.MaxValue` → `OverflowException`

### 3. Nothing catches it

```csharp
// ExtLibs/Controls/ControlHelpers.cs:101-109
public static void BeginInvokeIfRequired(this ISynchronizeInvoke control, Action action)
{
    if (control.InvokeRequired)
    {
        control.BeginInvoke(action, null);   // runs later on the UI pump -> ThreadException
    }
    else
    {
        action();                            // inline -> doConnect's catch -> forced disconnect
    }
```

The post-connect block is the body of `this.BeginInvokeIfRequired(() => { … })` starting at
`MainV2.cs:1729`, and that lambda is not wrapped in a try. Which of the two paths is taken depends
only on whether the caller is already on the UI thread.

### 4. The amplifier

```csharp
// MainV2.cs:1769-1783
double maxdist = 0;

foreach (var rally in comPort.MAV.rallypoints)
{
    foreach (var rally1 in comPort.MAV.rallypoints)
    {
        var pnt1 = new PointLatLngAlt(rally.Value.y / 10000000.0f, rally.Value.x / 10000000.0f);
        var pnt2 = new PointLatLngAlt(rally1.Value.y / 10000000.0f, rally1.Value.x / 10000000.0f);

        var dist = pnt1.GetDistance(pnt2);

        maxdist = Math.Max(maxdist, dist);
    }
}
```

A nested loop over every pair of rally points, each iteration doing a haversine distance, on the UI
thread. The count comes from `RALLY_TOTAL`, which the vehicle chose.

---

## Taint trace

```
[wire]  PARAM_VALUE: param_id="RALLY_TOTAL", param_type=9 (REAL32), param_value=3.5f
   |     carried in by the automatic post-connect parameter download
   v
MAV.param["RALLY_TOTAL"]                                  (reported type trusted verbatim)
   v
this.BeginInvokeIfRequired(() => { ... })                 MainV2.cs:1729   <- no try/catch
   v
if (ContainsKey("RALLY_TOTAL") && int.Parse(...) > 0 && showui)
   |                              ^^^^^^^^^^^^^^^         MainV2.cs:1763
   |                              runs before showui, and before the try at :1765
   |     ToString() returns "3.5"                         MAVLinkParam.cs:222
   '-- FormatException
        |
        |-- on the UI thread already -> doConnect's catch     -> connection aborted
        '-- marshalled  -> Application.ThreadException        -> "An error has occurred" modal

   same shape for FENCE_TOTAL at MainV2.cs:1801

[amplifier] RALLY_TOTAL = a valid large integer
   v  rally points downloaded, then every pair compared     MainV2.cs:1769-1783
   ===> O(n^2) haversine on the UI thread
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink link that Mission Planner connects to | n/a | Any vehicle, component or MITM |
| MP downloads parameters on connect | **Yes** | Automatic, part of the connect sequence |
| Vehicle chooses the parameter's reported type | **Yes** | `param_type` is taken from the wire with no cross-check |
| Operator interaction | **None** | The operator only connects |
| `showui` true | not required for the throw | The parse runs before `showui` is evaluated |

For the amplifier the attacker additionally has to *serve* the rally points it advertised, one
response per point, so reaching a large `n` takes sustained cooperation over the link rather than a
single message. The `int.Parse` throw needs one `PARAM_VALUE`.

---

## Impact

The operator cannot connect to the vehicle. Depending on which thread the block runs on, either the
connection is aborted outright or Mission Planner shows its generic crash-report modal, and the rest
of the post-connect setup — fence download, HUD data source, connect icon — never runs.

That is a denial of service against the ground station, delivered by the vehicle it is trying to
talk to, with no operator action beyond pressing Connect. It is availability-only: nothing is read,
written or executed.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Zero-click | **Yes** | fires in the automatic post-connect block |
| `int.Parse` is reachable before any try | **Yes** | it is in the `if` condition; the `try` opens at `:1765` |
| `showui` does not gate it | **Yes** | `&&` short-circuits left to right, and the parse comes first |
| Vehicle controls the parameter's type | **Yes** | `param_type` is trusted as reported |
| Operator is blocked from connecting | **Yes** | either path ends the post-connect sequence |
| O(n²) UI freeze | **plausible, not measured** | requires the attacker to actually deliver `n` rally points |
| Confidentiality or integrity impact | **No** | nothing is read or written |
| Persistence | **No** | reconnecting to an honest vehicle recovers |

**Not live-confirmed.** Everything above is read off the source. The PoC harness exists but has not
been run against a Windows Mission Planner build, so treat the two escape paths in §3 as reasoned
rather than observed — which of them fires depends on the calling thread at runtime.

---

## Version scope

| Version | `RALLY_TOTAL` block | `FENCE_TOTAL` block | `MAVLinkParam.ToString` | `BeginInvokeIfRequired` |
|---|---|---|---|---|
| `master` `0cdb16308` (verified) | `MainV2.cs:1762` | `MainV2.cs:1800` | `MAVLinkParam.cs:219` | `ControlHelpers.cs:101` |
| 1.3.83 (latest release, 2025-09-10) | `:1746` | `:1784` | `:219` | `:101` |

Mission Planner publishes rolling tags rather than per-release branches; 1.3.83 is commit
`b78a7495`. `master` has not moved since the commit verified above, and both parse sites sit in the
same post-connect block in each tree.

---

## Reproduction

Authorized bench only. Requires `pymavlink`.

```bash
cd poc
python3 poc_MP04_param_total_connect_dos.py --listen 0.0.0.0:5760
```

Connect Mission Planner to the harness. The harness answers the parameter download with
`RALLY_TOTAL` reported as a `REAL32` of `3.5`, so the post-connect block throws.

Expect one of two outcomes, and note which you get: the connection aborts silently, or Mission
Planner shows *"An error has occurred … Report this Error?"*. Both are the same bug; the difference
is only whether the post-connect block ran inline or was marshalled to the UI pump.