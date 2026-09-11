# MAVROS-01 — `PARAM_VALUE.param_id` forges ROS 2 parameter events and grows an uncapped map

| Field | Value |
|---|---|
| **Product** | [mavros](https://github.com/mavlink/mavros) (ROS 2 MAVLink ↔ ROS bridge), `param` plugin |
| **Severity** | **MEDIUM** — CVSS 3.1 **6.5** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` |
| **CWE** | CWE-345 (insufficient verification of data authenticity) · CWE-770 (allocation without limits) |
| **Affected** | `ros2` branch and every 2.x release. Latest release 2.15.1; `param.cpp` is identical on the branch tip `7f7e8fdd` (2026-09-09) |
| **Fixed in** | nothing yet |
| **Verified** | 2.15.1 and branch tip `7f7e8fdd` for the source; runs were against the shipped `ros-jazzy-mavros` 2.14.0 Debian package |
| **Interaction** | **None.** No handshake, and no parameter pull needs to be in progress |
| **Platform** | Linux / ROS 2 |
| **Status** | Reproduced 2026-08-28 against `ros-jazzy-mavros 2.14.0-1noble` (arm64). Forged entries appeared on the global `/parameter_events` topic attributed to the mavros node, and **97,484** attacker-created parameters were retained, measured with mavros's own `list_parameters` service. The memory-exhaustion claim in the original analysis did **not** reproduce and is withdrawn |
| **Advisory** | not filed |
| **Fix** | none opened |

---

## Summary

mavros's `param` plugin takes `PARAM_VALUE.param_id` off the wire and uses it directly as a map key.
If the key is not already present it inserts a new entry and publishes a ROS 2 `ParameterEvent` on
`/parameter_events` — an absolute topic, visible to the whole ROS graph, attributed to the mavros
node.

Both the insert and the publish happen **before** the `param_state` check that decides whether mavros
is even expecting parameters. No pull has to be in progress and no handshake is involved; a single
`PARAM_VALUE` frame is enough.

The only admission control is the plugin filter: valid framing and a `sysid` matching the configured
`target_system_id`, which defaults to 1. There is no authentication, and no cap on how many distinct
keys a peer may create.

---

## Root cause

### 1. The wire field becomes the map key

```cpp
// mavros/src/plugins/param.cpp:592-600
void handle_param_value(
  const mavlink::mavlink_message_t * msg [[maybe_unused]],
  mavlink::common::msg::PARAM_VALUE & pmsg,
  plugin::filter::SystemAndOk filter [[maybe_unused]])
{
  lock_guard lock(mutex);

  auto lg = get_logger();
  auto param_id = mavlink::to_string(pmsg.param_id);
```

### 2. The insert is unconditional, and publishes a graph-wide event

```cpp
// mavros/src/plugins/param.cpp:641-658
// search
auto param_it = parameters.find(param_id);
if (param_it != parameters.end()) {
  // parameter exists
  auto & p = param_it->second;

  update_parameter(p, false);
  RCLCPP_DEBUG_STREAM(lg, "PR: Update param " << p.to_string());

} else {
  // insert new element
  auto pp =
    parameters.emplace(param_id, Parameter(param_id, pmsg.param_index, pmsg.param_count));
  auto & p = pp.first->second;

  update_parameter(p, true);
  RCLCPP_DEBUG_STREAM(lg, "PR: New param " << p.to_string());
}
```

`update_parameter` is where the event goes out:

```cpp
// mavros/src/plugins/param.cpp:610-621
param_event_pub->publish(p.to_event_msg());
{
  rcl_interfaces::msg::ParameterEvent evt{};
  evt.stamp = p.stamp;
  evt.node = node->get_fully_qualified_name();
  if (is_new) {
    evt.new_parameters.push_back(p.to_parameter_msg());
  } else {
    evt.changed_parameters.push_back(p.to_parameter_msg());
  }

  std_event_pub->publish(evt);
}
```

`evt.node` is mavros's own fully-qualified name, set by mavros rather than by the attacker, so a
subscriber sees a parameter event that genuinely came from the mavros node.

### 3. The topic is absolute

```cpp
// mavros/src/plugins/param.cpp:54
static constexpr const char * events = "/parameter_events";
```

```cpp
// mavros/src/plugins/param.cpp:446-449
//! Standard ROS parameter events (on /parameter_events).
std_event_pub = node->create_publisher<rcl_interfaces::msg::ParameterEvent>(
  PSN::events,
  event_qos);
```

`/parameter_events` is the standard channel every `ParameterEventHandler` in the graph watches. It is
not namespaced to mavros.

### 4. The state guard comes after both

```cpp
// mavros/src/plugins/param.cpp:660-666
if (param_state == PR::RXLIST || param_state == PR::RXPARAM ||
  param_state == PR::RXPARAM_TIMEDOUT)
{
  // we received first param. setup list timeout
  if (param_state == PR::RXLIST) {
    param_count = pmsg.param_count;
    param_state = PR::RXPARAM;
```

This block handles the parameter-pull bookkeeping. It runs at `:660`, after the insert at `:653` and
the publish at `:621`, so it gates none of them. `param_count` from the wire is recorded here but is
never used to bound the map.

### 5. The only admission control

```cpp
// mavros/include/mavros/plugin_filter.hpp:54-63
class SystemAndOk : public Filter
{
public:
  inline bool operator()(
    UASPtr uas, const mavlink::mavlink_message_t * cmsg,
    const Framing framing) override
  {
    return framing == Framing::ok && uas->is_my_target(cmsg->sysid);
  }
};
```

```cpp
// mavros/include/mavros/mavros_uas.hpp:538-541
inline bool is_my_target(uint8_t sysid)
{
  return sysid == get_tgt_system();
}
```

Valid framing plus a matching `sysid`. `tgt_system` defaults to 1 (`mavros_node.cpp:36`), which is
the stock vehicle id, so in a default single-vehicle deployment the whole bar is "send from sysid 1".

---

## Taint trace

```
[wire]  PARAM_VALUE.param_id (char[16]), param_value, param_index, param_count
   |     filter: framing ok && sysid == target_system_id (default 1)
   |                                            plugin_filter.hpp:61, mavros_uas.hpp:540
   v
param_id = mavlink::to_string(pmsg.param_id)              param.cpp:600
   v
parameters.find(param_id)                                 param.cpp:642
   |
   '-- not found -> parameters.emplace(param_id, ...)      param.cpp:653
         |     no cap, no eviction on this path
         v
       update_parameter(p, is_new = true)                 param.cpp:602
         |-- param_event_pub->publish(...)      mavros's own ~/event topic     :610
         '-- std_event_pub->publish(evt)        GLOBAL /parameter_events       :621
               evt.node = mavros's own name                                   :614
               evt.new_parameters = the attacker's name and value             :616
   v
if (param_state == RXLIST || RXPARAM || RXPARAM_TIMEDOUT)  param.cpp:660
   ===> reached only after the insert and the publish have already happened
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink link mavros is bound to | n/a | Push. `fcu_url` is commonly a UDP server, so a datagram is enough |
| `param` plugin loaded | **Yes** | Declared in `mavros_plugins.xml`; with empty allowlist and denylist every plugin is loaded |
| Attacker knows the target sysid | **Yes, it is 1** | `tgt_system` defaults to 1, matching the stock vehicle id |
| Parameter pull in progress | **No** | The insert and publish precede the `param_state` check at `:660` |
| Operator interaction | **None** | A single `PARAM_VALUE` frame |

---

## Impact

Any peer that can put a frame on mavros's link can publish arbitrary named parameter events onto the
ROS graph's standard `/parameter_events` topic, carrying a name and value of its choosing and
attributed to the mavros node. Names a downstream node would plausibly watch — `FENCE_ENABLE`,
`ARMING_CHECK`, `BATT_LOW_VOLT` — were injected and all three appeared on the topic with no handshake
and no operator action.

Separately, each unseen name adds a map entry that is never evicted on this path. 97,484
attacker-created parameters were retained in one run, counted by mavros's own `list_parameters`
service, whose response grew to 1,365,034 bytes. Every node that enumerates or queries mavros's
parameters pays that cost, and it grows without bound.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Forged parameter events, graph-wide | **Yes** | absolute topic, attacker-chosen name and value, mavros's own node attribution |
| Zero-click, no handshake | **Yes** | the insert and publish precede the `param_state` check at `:660` |
| Uncapped map growth | **Yes** | 97,484 entries confirmed through `list_parameters` |
| ROS parameter interface degradation | **Yes** | a 1.37 MB `list_parameters` response, and unbounded |
| RAM exhaustion or OOM-kill | **No** | +32 kB of RSS across 400,000 injections; the original claim is withdrawn |
| Node crash or instability | **No** | the node stayed responsive in every run |
| Other nodes *act* on the forged values | **Not shown** | `ParameterEventHandler` notifies subscribers; it does not apply values. Whether a given stack acts on a mavros parameter change is stack-specific and was not tested |
| Spoofing another node's identity | **No** | `evt.node` is mavros's own name and is not attacker-controlled |

The memory claim deserves the detail. Roughly 97,000 entries at about 150 bytes each is on the order
of 15 MB of heap, which fits inside the already-resident arena of a 27.6 MB process and never shows
as new RSS. Reaching a gigabyte would take on the order of 7 million entries, hours of uninterrupted
injection at the rates achieved, and was not demonstrated.

---

## Version scope

| Version | `param_id` read | `find` | `emplace` (sink) | `/parameter_events` publish | state guard |
|---|---|---|---|---|---|
| `ros2` tip `7f7e8fdd` | `:600` | `:642` | `:653` | `:621` | `:660` |
| 2.15.1 (latest release) | `:600` | `:642` | `:653` | `:621` | `:660` |
| 2.14.0 (tested) | `:555` | `:594` | `:605` | `:576` | `:612` |

`param.cpp` is byte-identical between 2.15.1 and the branch tip. The 2.14.0 line numbers differ, the
code does not.

---

## Reproduction

Authorized bench only. Requires Docker and `pymavlink`.

```bash
cd poc
./run.sh
```

`run.sh` brings up `ros:jazzy-ros-base` with the shipped `ros-jazzy-mavros` package, starts
`mavros_node` with a UDP server `fcu_url`, and runs the harness against it. The harness sends
`PARAM_VALUE` frames from sysid 1 and then counts what mavros retained, using mavros's own
`list_parameters` service rather than inferring from the outside.

Two things make a working run look like nothing happened. The first is rate: pushing 20,000 frames in
0.1 s produces no growth at all, because the loopback UDP socket buffer drops almost all of them —
the harness rate-limits deliberately, and the retention figures only mean anything with that in
place. The second is RSS: it does not move, which is the point of the withdrawn claim above. Count
parameters, not memory.
