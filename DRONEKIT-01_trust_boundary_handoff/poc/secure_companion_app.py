#!/usr/bin/env python3
# ============================================================================
#  SECURE COMPANION PATTERN  --  the correct way to consume DroneKit strings
# ============================================================================
#  Companion app for DRONEKIT-01 showing the SAFE handling of the same
#  attacker-controlled vehicle strings (param_id, STATUSTEXT.text) that the
#  deliberately-vulnerable example mishandles.
#
#  Key idea: DroneKit gives you RAW, UNAUTHENTICATED wire data. Treat every
#  param_id and STATUSTEXT.text as untrusted input and:
#    1. allow-list / canonicalize before using as a path or key,
#    2. never use it as a format string,
#    3. bound its length and character set.
#
#  Authorized localhost-only research code; benign behavior only.
# ============================================================================
import logging
import os
import re
import sys

EXPORT_DIR = os.path.realpath(os.environ.get("POC_EXPORT_DIR", "/tmp/dronekit01_export_safe"))
os.makedirs(EXPORT_DIR, exist_ok=True)

log = logging.getLogger("companion-secure")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# MAVLink param_id is char[16]; valid ArduPilot param names are [A-Z0-9_].
_VALID_PARAM = re.compile(r"\A[A-Z0-9_]{1,16}\Z")


def safe_export_path(export_dir, attr_name):
    """Return a validated path, or None if the param name is hostile."""
    if not _VALID_PARAM.match(attr_name):
        return None                                   # reject ../ , slashes, etc.
    candidate = os.path.realpath(os.path.join(export_dir, attr_name))
    # Defense in depth: confirm the resolved path is still inside export_dir.
    if os.path.commonpath([candidate, export_dir]) != export_dir:
        return None
    return candidate


def on_param_callback(_params, attr_name, value):
    path = safe_export_path(EXPORT_DIR, attr_name)
    if path is None:
        log.warning("rejected hostile/invalid param_id %r", attr_name)   # %r quotes it
        return
    with open(path, "w") as fh:
        fh.write(str(value))
    log.info("exported param %r -> %s", attr_name, path)


def on_statustext(text):
    # SAFE: attacker text is a *message argument*, never the format string.
    # %r also escapes control bytes so it cannot forge log lines.
    log.info("vehicle STATUSTEXT: %r", text[:50])


def main():
    from pymavlink import mavutil

    listen = os.environ.get("POC_LISTEN", "127.0.0.1:5760")
    print("[poc] SECURE companion: connecting to tcp:%s" % listen)
    print("[poc] export dir = %s" % EXPORT_DIR)

    m = mavutil.mavlink_connection("tcp:" + listen)
    m.wait_heartbeat()
    print("[poc] heartbeat; listening for PARAM_VALUE / STATUSTEXT")

    while True:
        msg = m.recv_match(type=["PARAM_VALUE", "STATUSTEXT"], blocking=True, timeout=30)
        if msg is None:
            print("[poc] no message in 30s; exiting")
            return
        if msg.get_type() == "PARAM_VALUE":
            on_param_callback(None, msg.param_id, msg.param_value)
        else:
            on_statustext(msg.text.strip())


if __name__ == "__main__":
    sys.exit(main())
