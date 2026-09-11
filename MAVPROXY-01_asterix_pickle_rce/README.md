# MAVPROXY-01 — The `asterix` module deserializes raw UDP with `pickle.loads()`

| Field | Value |
|---|---|
| **Product** | [MAVProxy](https://github.com/ArduPilot/MAVProxy) (ArduPilot ground station and proxy), `asterix` module |
| **Severity** | **HIGH** — unauthenticated code execution in the ground station process, gated on the operator loading a non-default module |
| **CWE** | CWE-502 (deserialization of untrusted data) |
| **Affected** | every released version, up to and including **v1.8.74** (2025-08-02), the latest release |
| **Fixed in** | `master` only, commit [`aeb38d3`](https://github.com/ArduPilot/MAVProxy/commit/aeb38d35404b57bfbfe5ee9d1b3a117b584997ba) (2026-08-14). **Unreleased** — no release yet carries it |
| **Verified** | vulnerable code at `f4ac15c`; fix confirmed present on `master` tip `8be070d` and absent from every tag |
| **Interaction** | The operator loads the `asterix` module. After that, one unsolicited UDP datagram |
| **Platform** | Cross-platform |
| **Status** | Source-verified, and the sink was tested with a verbatim replica of the code path: a benign marker gadget created its file |
| **Advisory** | not filed — independently reported and fixed upstream first, see below |
| **Fix** | upstream `aeb38d3`, by the original reporter |

**Credit.** This was independently discovered and reported by **jFriedli** in
[issue #1725](https://github.com/ArduPilot/MAVProxy/issues/1725) (2026-08-12) and fixed by the same
person in [PR #1728](https://github.com/ArduPilot/MAVProxy/pull/1728), merged 2026-08-14. The work
here is independent confirmation, not a priority claim. It is published because **every released
version is still affected**: the fix is on `master` and unreleased, so anyone installing MAVProxy from
PyPI or a distro package today still gets the `pickle.loads()` path.

---

## Demo

<a href="https://www.youtube.com/watch?v=7j6DIuMXQg0">
  <img src="https://img.youtube.com/vi/7j6DIuMXQg0/maxresdefault.jpg" alt="MAVPROXY-01 — asterix module pickle.loads over UDP" width="720"/>
</a>

▶ **[Watch on YouTube](https://www.youtube.com/watch?v=7j6DIuMXQg0)**

A before and after on a marker file. `ls /tmp/asterix_pwned` first returns *No such file or
directory*. The operator loads the `asterix` module, which binds UDP `0.0.0.0:45454`. A single
72-byte datagram — `b'PICKLED:'` followed by a pickled benign marker gadget — goes to that port, and
`ls /tmp/asterix_pwned` then succeeds. No authentication, no source-address check, no MAVLink link
and no prior session.

---

## Summary

MAVProxy's `asterix` module opens a UDP listener for an air-traffic feed. Datagrams that begin with
the marker `PICKLED:` have the remainder passed straight to `pickle.loads()`.

`pickle.loads` on attacker-controlled bytes is arbitrary code execution by design: the pickle format
carries object-construction instructions, and a `__reduce__` gadget names any callable to run. There
is no authentication, no source-address check and no signature on this path.

The listener binds `INADDR_ANY`, so it is reachable from any host that can route to the machine, not
only from localhost. It is not tied to MAVLink at all: the receive runs on the idle loop, so no
vehicle needs to be connected.

The cap is that `asterix` is not a default module. The operator has to load it, which is the
difference between this and a remote-root-of-every-MAVProxy bug.

---

## Root cause

### 1. The sink

```python
# MAVProxy/modules/mavproxy_asterix.py:193-210, at f4ac15c
def idle_task(self):
    '''called on idle'''
    if self.sock is None:
        return
    try:
        pkt = self.sock.recv(10240)
    except Exception:
        return
    try:
        if pkt.startswith(b'PICKLED:'):
            pkt = pkt[8:]
            # pickled packet
            try:
                amsg = [pickle.loads(pkt)]
            except pickle.UnpicklingError:
                amsg = asterix.parse(pkt)
```

`pkt` is whatever arrived on the socket. The only thing standing between the wire and `pickle.loads`
is an eight-byte prefix the attacker supplies.

### 2. The listener accepts from anywhere

```python
# MAVProxy/modules/mavproxy_asterix.py:119-127, at f4ac15c
def start_listener(self):
    '''start listening for packets'''
    if self.sock is not None:
        self.sock.close()
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind(('', self.asterix_settings.port))
    self.sock.setblocking(False)
    print("Started on port %u" % self.asterix_settings.port)
```

`bind(('', port))` is `INADDR_ANY`. No filtering follows, so any peer that can reach the port is a
valid sender.

```python
# MAVProxy/modules/mavproxy_asterix.py:63, at f4ac15c
self.asterix_settings = mp_settings.MPSettings([("port", int, 45454),
```

### 3. The module is not loaded by default

```python
# MAVProxy/mavproxy.py:1382
parser.add_option("--default-modules", default="log,signing,wp,rally,fence,ftp,param,relay,tuneopt,arm,mode,calibration,rc,auxopt,misc,cmdlong,battery,terrain,output,adsb,layout", ...)
```

`asterix` is absent from that list, so reaching any of the above requires an explicit
`module load asterix`.

### 4. The upstream fix

```python
# MAVProxy/modules/mavproxy_asterix.py:204-209, on master at aeb38d3
if pkt.startswith(b'PICKLED:'):
    ...
    decoded = json.loads(pkt.decode('utf-8'))
```

The private transport between the `genobstacles` module and this listener is now JSON, which removes
deserialization of untrusted data rather than trying to filter it.

---

## Taint trace

```
[operator] module load asterix                          <- the one required action
   v
start_listener() -> bind(('', 45454))                   mavproxy_asterix.py:125
   |     INADDR_ANY: any host with IP reach, not just localhost
   v
[wire]  one UDP datagram, unsolicited, unauthenticated
   v
idle_task(): pkt = self.sock.recv(10240)                mavproxy_asterix.py:198
   |     runs on the idle loop, so no MAVLink link is needed
   v
if pkt.startswith(b'PICKLED:')                          mavproxy_asterix.py:202
   v
pickle.loads(pkt[8:])                                   mavproxy_asterix.py:206
   ===> __reduce__ runs inside the MAVProxy process, as the operator
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| `asterix` module loaded | **No** | The operator must `module load asterix`. This is the cap on the finding |
| `asterix_decoder` PyPI package installed | needed | The module imports it at load time; without it the module fails to load and the listener never opens |
| MAVLink vehicle connected | **Not required** | `idle_task()` runs on the idle loop regardless of links |
| Network reach to port 45454 | needed | The bind is `INADDR_ANY`, so LAN and Wi-Fi peers qualify, not only localhost |
| Authentication or pairing | **None** | No auth exists on this path |

The module is a real deployed one rather than a curiosity — it is the documented path for the
ASTERIX/SDPS obstacle-avoidance use case — but it is niche, and that is the honest bound. Where it is
loaded, the exposure is total and needs nothing beyond IP reach.

---

## Impact

Code execution inside the ground station process, with the operator's privileges, from one
unsolicited UDP datagram. The gadget runs during unpickling, so nothing needs to parse as a valid
ASTERIX message afterwards.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Unauthenticated | **Yes** | no auth, no source check, no signature on this path |
| Reachable off-host | **Yes** | the bind is `INADDR_ANY` |
| Works with no vehicle connected | **Yes** | the receive is on the idle loop, independent of MAVLink |
| One packet is enough | **Yes** | 72 bytes in the tested case |
| Code execution | **Yes** | `pickle.loads` on attacker bytes; sink-tested with a benign marker gadget |
| Default configuration | **No** | `asterix` is not in `--default-modules`; the operator must load it |
| Privilege escalation | **No** | runs as the operator |
| Fixed in a release you can install | **No** | the fix is on `master` and unreleased; v1.8.74 predates it |

---

## Version scope

| Version | Date | `pickle.loads` on the UDP path |
|---|---|---|
| `master` `8be070d` | current | **no** — replaced with `json.loads` by `aeb38d3` |
| v1.8.74 (latest release) | 2025-08-02 | **yes** |
| every earlier release | — | **yes** |

The fix landed on 2026-08-14, more than a year after the latest release was cut, so no released
artifact carries it.

---

## Reproduction

Authorized bench only. Requires `asterix_decoder` and a MAVProxy checkout at or before `f4ac15c`.

```bash
# MAVProxy, no vehicle needed
mavproxy.py
# at the prompt:
module load asterix          # prints: Started on port 45454

# attacker, from anywhere that can reach the host
python3 poc/poc_G06_mavproxy_asterix_pickle_rce.py --target <host>:45454
```

The PoC sends `b'PICKLED:'` followed by a pickled object whose `__reduce__` touches
`/tmp/asterix_pwned`. Check for that file rather than for output in the MAVProxy window: the module
prints `bad packet` afterwards, because the unpickled object is not a valid ASTERIX message. The
gadget has already run by then, so the error message is what success looks like.
