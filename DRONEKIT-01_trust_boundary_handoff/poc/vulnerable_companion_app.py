#!/usr/bin/env python3
# ============================================================================
#  DELIBERATELY VULNERABLE EXAMPLE  --  DO NOT SHIP / DO NOT COPY INTO PRODUCTION
# ============================================================================
#  DRONEKIT-01 companion: demonstrates the *downstream* trust-boundary bug.
#
#  DroneKit-Python itself is SAFE: it only uses the raw vehicle string
#  `param_id` as a dict key and `STATUSTEXT.text` as a logging *message arg*
#  (see ../README.md, Root cause). The vulnerability shown here lives entirely
#  in THIS application code, which naively treats those attacker-controlled
#  strings as trusted file paths / format strings.
#
#  This script is part of an AUTHORIZED, white-box, localhost-only security
#  research dossier for a published drone-security book. Payloads are BENIGN
#  (a marker file under a writable scratch dir, and a logging call). It exists
#  to be the "victim" the fake_vehicle_harness drives so the handoff is
#  observable end-to-end.
#
#  HOW IT WORKS
#  ------------
#  A typical "auto-export parameters to disk" companion feature: for every
#  PARAM_VALUE the vehicle streams, write the value to a file *named after the
#  parameter*. The developer assumed param_id is always a tame token like
#  "THR_MIN". A hostile vehicle/MITM sends a param_id such as
#  "../../../../tmp/PWNED" (char[16] caps it, but 16 bytes of "../" is plenty to
#  escape one or two dirs) -> the app writes OUTSIDE its intended export dir.
#  We also show a '%'-format-string STATUSTEXT logging sink.
#
#  Run WITHOUT DroneKit installed: this file ships a tiny standalone shim that
#  re-implements ONLY the two relevant DroneKit handoff lines verbatim, so the
#  demo is self-contained on a machine that has pymavlink but not dronekit's
#  full dependency set (monotonic, etc.). If DroneKit IS installed, drive the
#  genuine library instead (see ../README.md, "Reproduction" section).
# ============================================================================
import logging
import os
import sys

EXPORT_DIR = os.environ.get("POC_EXPORT_DIR", "/tmp/dronekit01_export")
os.makedirs(EXPORT_DIR, exist_ok=True)

log = logging.getLogger("companion")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ---------------------------------------------------------------------------
#  THE VULNERABLE SINKS  (this is the bug -- in the APP, not in DroneKit)
# ---------------------------------------------------------------------------
def on_param_callback(_params, attr_name, value):
    """DroneKit hands us `attr_name` == the raw, attacker-controlled param_id
    string straight off the wire (dronekit/__init__.py:1378). We — the app —
    foolishly use it as a *path component*.  THIS is CWE-22 / CWE-20 downstream.
    """
    # !!! VULNERABLE: attacker-controlled string used as a filesystem path. !!!
    path = os.path.join(EXPORT_DIR, attr_name)            # <-- no validation
    with open(path, "w") as fh:                            # <-- traversal sink
        fh.write(str(value))
    log.info("exported param %r -> %s", attr_name, path)


def on_statustext(text):
    """DroneKit logs STATUSTEXT.text safely (as a msg arg). A naive app that
    re-logs it through a '%'-style format string turns attacker text into the
    format spec -> CWE-134-style log injection / potential exceptions.
    """
    # !!! VULNERABLE: attacker text used as the format string itself.        !!!
    log.warning("vehicle says: " + text)                  # log injection
    # even worse pattern some apps use:  log.warning(text % some_locals)


# ---------------------------------------------------------------------------
#  Minimal self-contained DroneKit-handoff shim (only the 2 lines that matter)
# ---------------------------------------------------------------------------
class _DroneKitHandoffShim:
    """Re-implements ONLY the trust-boundary handoff from DroneKit verbatim so
    the demo runs without installing DroneKit's full dependency stack. The two
    lines below are copied from dronekit/__init__.py @ commit 243ce0a:

        :1377  self._params_map[msg.param_id] = msg.param_value
        :1378  self._parameters.notify_attribute_listeners(msg.param_id, ...)
        :1104  msg=m.text.strip()   (passed as the *message arg*, which is safe
                                      in DroneKit; the unsafe re-log is in the app)
    """
    def __init__(self):
        self._params_map = {}
        self._param_listeners = []
        self._statustext_listeners = []

    def on_attribute(self, fn):   # mimics vehicle.parameters.on_attribute('*')
        self._param_listeners.append(fn)

    def on_statustext(self, fn):
        self._statustext_listeners.append(fn)

    def feed_param_value(self, msg):
        # ---- verbatim DroneKit handoff (param_id is ONLY a dict key here) ----
        self._params_map[msg.param_id] = msg.param_value          # :1377
        for fn in self._param_listeners:                          # :1378 ->
            fn(self, msg.param_id, msg.param_value)               #   :670/672

    def feed_statustext(self, msg):
        text = msg.text.strip()                                   # :1104
        for fn in self._statustext_listeners:
            fn(text)


def main():
    from pymavlink import mavutil

    listen = os.environ.get("POC_LISTEN", "127.0.0.1:5760")
    print("[poc] vulnerable companion: connecting to tcp:%s" % listen)
    print("[poc] export dir = %s" % EXPORT_DIR)

    shim = _DroneKitHandoffShim()
    shim.on_attribute(on_param_callback)
    shim.on_statustext(on_statustext)

    m = mavutil.mavlink_connection("tcp:" + listen)
    m.wait_heartbeat()
    print("[poc] heartbeat from sys=%d comp=%d; listening for PARAM_VALUE / STATUSTEXT"
          % (m.target_system, m.target_component))

    while True:
        msg = m.recv_match(type=["PARAM_VALUE", "STATUSTEXT"], blocking=True, timeout=30)
        if msg is None:
            print("[poc] no message in 30s; exiting")
            return
        if msg.get_type() == "PARAM_VALUE":
            # pymavlink gives param_id as str already; emulate DroneKit's intake.
            shim.feed_param_value(msg)
        else:
            shim.feed_statustext(msg)


if __name__ == "__main__":
    sys.exit(main())
