# DRONEKIT-01 — Raw vehicle strings are handed to application callbacks unchanged

| Field | Value |
|---|---|
| **Product** | [DroneKit-Python](https://github.com/dronekit/dronekit-python) |
| **Severity** | **INFORMATIONAL.** There is no vulnerability in the library. The exposure is in consuming applications |
| **CWE** | CWE-20 (improper input validation, downstream). Manifests in naive consumers as CWE-22 (path traversal) and CWE-117 / CWE-134 (log and format-string injection) |
| **Affected** | `master` `243ce0a` and every release up to v2.9.2. The repository has not moved since 2024-05-20 |
| **Fixed in** | n/a — nothing to fix in DroneKit |
| **Verified** | `master` `243ce0a`, current tip |
| **Interaction** | **None** for the handoff itself |
| **Platform** | Cross-platform |
| **Status** | Source-verified. The handoff and the downstream impact were tested on loopback with `pymavlink` against a deliberately vulnerable example companion app. DroneKit itself was not exploited, because there is nothing in it to exploit |
| **Advisory** | not filed — no library defect to report |
| **Fix** | none; the guidance belongs in consuming applications |

---

## Summary

DroneKit takes two unauthenticated strings straight off the MAVLink wire — a parameter's `param_id`
and a `STATUSTEXT`'s `text` — and passes them to application-registered callbacks without
sanitisation.

DroneKit's own use of both is safe. `param_id` is only ever a dict key and an attribute name;
`STATUSTEXT.text` is only ever a logging message argument, passed in a way that stops Python's
`logging` from treating it as a format string. A repository-wide search finds no attacker-reachable
dangerous sink in the library at all.

What makes this worth writing down is where the string goes next. `notify_attribute_listeners` fans
the raw bytes out to every registered callback, and a wildcard listener receives them for every
parameter the vehicle streams. An application that uses `param_id` to build a filename, or re-logs
`STATUSTEXT.text` through a format string, is trusting a value a malicious vehicle or a MITM fully
controls.

This is published as a boundary description, not as a bug report against DroneKit.

---

## Root cause

### 1. `param_id` becomes a dict key and an attribute name

```python
# dronekit/__init__.py:1375-1379
                    self._params_set[msg.param_index] = msg

                self._params_map[msg.param_id] = msg.param_value
                self._parameters.notify_attribute_listeners(msg.param_id, msg.param_value,
                                                            cache=True)
```

At `:1377` the raw wire `char[16]` is used as a dict key — no `setattr`, no path, no `eval`. Safe
inside DroneKit. At `:1378` the same unvalidated string is forwarded as the *attribute name* to the
listener fan-out.

### 2. `STATUSTEXT.text` is logged in the safe form

```python
# dronekit/__init__.py:1100-1106
        @self.on_message('STATUSTEXT')
        def statustext_listener(self, name, m):
            # Log the STATUSTEXT on the autopilot logger, with the correct severity
            self._autopilot_logger.log(
                msg=m.text.strip(),
                level=self._mavlink_statustext_severity[m.severity]
            )
```

`m.text` goes in as the `msg=` argument with no `*args`, so `logging` never applies `%` formatting to
it and it is emitted literally. This is the correct pattern, and it is worth citing precisely because
a consumer that re-logs the same text as `logger.warning("prefix " + text)` or
`logger.warning(text % data)` reintroduces CWE-117 and CWE-134.

### 3. The fan-out is the boundary

```python
# dronekit/__init__.py:669-680
        # Notify observers.
        for fn in self._attribute_listeners.get(attr_name, []):
            try:
                fn(self, attr_name, value)
            except Exception:
                self._logger.exception('Exception in attribute handler for %s' % attr_name, exc_info=True)

        for fn in self._attribute_listeners.get('*', []):
            try:
                fn(self, attr_name, value)
            except Exception:
                self._logger.exception('Exception in attribute handler for %s' % attr_name, exc_info=True)
```

For a parameter update, `attr_name` **is** the attacker's string, and each callback receives it as its
second argument. The wildcard list at `:676` receives every attribute update, so the common
"watch all parameters" pattern gets attacker-chosen names by design.

### 4. No dangerous sink inside the library

A repository-wide search across `dronekit/` for `os.system`, `subprocess`, `eval(`, `exec(`,
`pickle`, `yaml.load`, `__import__`, `os.popen` and `setattr(` returns one match:

```python
# dronekit/mavlink.py:60
        mavutil.set_close_on_exec(self.port.fileno())
```

which sets `FD_CLOEXEC` and executes nothing. Neither `param_id` nor `STATUSTEXT.text` reaches any of
those sinks.

---

## Taint trace

```
[wire]  PARAM_VALUE.param_id (char[16]) / STATUSTEXT.text (char[50])
   |     unauthenticated, attacker-chosen bytes
   v
param_id:
   self._params_map[msg.param_id] = value              __init__.py:1377   safe: dict key only
   notify_attribute_listeners(msg.param_id, value)     __init__.py:1378
      |-- fn(self, attr_name, value)                   __init__.py:670-672
      '-- wildcard '*' listeners get every update       __init__.py:676-678
            ===== TRUST BOUNDARY =====
            the application now holds raw wire bytes as an "attribute name"

STATUSTEXT.text:
   self._autopilot_logger.log(msg=m.text.strip(), ...) __init__.py:1104
      safe here: no *args, so logging applies no % formatting
      but the same text is visible to any on_message('STATUSTEXT') handler
            ===== TRUST BOUNDARY =====

downstream, in a consumer that does not validate:
   open(os.path.join(basedir, attr_name), 'w')   ===> CWE-22 path traversal
   logger.warning(text % data)                   ===> CWE-134 format string
   logger.warning("prefix " + text)              ===> CWE-117 log injection
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink link the application connects to | n/a | Push. Any vehicle, component or MITM |
| Application registers an attribute or message listener | typical | The wildcard `'*'` form is the common "watch everything" idiom |
| Application uses the string unsafely | **application-specific** | This is the whole finding. DroneKit does not |
| Operator interaction | **None** | Parameters and `STATUSTEXT` arrive on their own |

---

## Impact

None to DroneKit. The library receives hostile strings and uses them in ways that cannot be abused.

To a consumer, the impact is whatever that consumer does with a string it assumed was well-formed.
The tested example companion demonstrated three: a `param_id` of `../../etc/x` used to build a path
escaped the intended directory; a `STATUSTEXT` containing `%s` and `%n` reached a `%`-formatted log
call; and embedded newlines forged additional log lines.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Raw wire strings reach application callbacks unchanged | **Yes** | `:1378` and `:670-672`, no validation in between |
| Wildcard listeners receive attacker-chosen names | **Yes** | `:676-678`, for every parameter the vehicle streams |
| DroneKit uses the strings safely itself | **Yes** | dict key only; `msg=` with no `*args` |
| Any dangerous sink inside DroneKit | **No** | repo-wide search returns only `set_close_on_exec` |
| Vulnerability in DroneKit | **No** | there is nothing here to fix in the library |
| Downstream traversal and log injection are reachable | **Yes** | demonstrated against a deliberately vulnerable example companion |
| Any real-world consumer was tested | **No** | the vulnerable companion is a purpose-built example, not a shipping product |

---

## Version scope

| Version | `param_id` handoff | `STATUSTEXT` log | fan-out |
|---|---|---|---|
| `master` `243ce0a` (current tip) | `:1377-1379` | `:1100-1106` | `:669-680` |

The repository's last commit is from 2024-05-20 and the latest release is v2.9.2, so the tip and the
newest release describe the same code.

---

## Reproduction

Authorized bench only, on loopback. Requires `pymavlink` and `dronekit`.

```bash
cd poc
python3 vulnerable_companion_app.py        # terminal A: the unsafe consumer
python3 attack_send.py                     # terminal B: the hostile vehicle
```

`attack_send.py` sends a `PARAM_VALUE` whose `param_id` contains traversal, and a `STATUSTEXT`
carrying format specifiers and newlines. The vulnerable companion writes outside its directory and
emits forged log lines.

```bash
python3 secure_companion_app.py            # the same app, with the boundary handled
```

The secure version takes the same traffic and does neither. The difference between the two files is
the entire point of this write-up: validate on receipt, treat an attribute name as data rather than
as a path component, and never pass wire text as a format string.
