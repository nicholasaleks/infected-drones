#!/usr/bin/env bash
# MAVSDK-03 reproduction. Runs the fake camera and a MAVSDK app in one container so
# the MAVLink link is loopback and nothing depends on host routing.
#
#   ./run.sh control        # baseline: ordinary definition, app works normally
#   ./run.sh bomb           # 1 GiB written to the app's disk
#   ./run.sh bomb 4         # 4 GiB
set -euo pipefail
MODE="${1:-bomb}"
GIB="${2:-1}"
HERE="$(cd "$(dirname "$0")" && pwd)"

docker run --rm --name mavsdk03 \
  -v "$HERE/poc_MAVSDK03_camera_definition_bomb.py:/poc/poc.py:ro" \
  mavsdk03-poc bash -lc "
set -e
mkdir -p /work && cd /work

df_used() { df -B1 --output=used /tmp | tail -1 | tr -d ' '; }
echo \"[run] MAVSDK version: \$(dpkg -query -W -f='\${Version}' libmavsdk-dev 2>/dev/null || dpkg -s libmavsdk-dev | awk '/^Version/{print \$2}')\"
echo '[run] ---- BEFORE ----'
df -h /tmp | tail -1 | awk '{print \"[run] disk: \" \$3 \" used, \" \$4 \" available\"}'
ls -lad /tmp/mavsdk-component-metadata-* 2>/dev/null || echo '[run] no temp dir yet'
BEFORE=\$(df_used)

python3 /poc/poc.py --mode $MODE --gib $GIB --listen 0.0.0.0:5760 -v > /work/harness.log 2>&1 &
HPID=\$!
# Building a 1 GiB bomb with preset 9|EXTREME takes real CPU time, so wait for the
# harness to actually be listening instead of guessing with a fixed sleep.
echo '[run] waiting for the fake vehicle to be ready (building the .xz) ...'
for i in \$(seq 1 240); do
  grep -q 'waiting for the GCS' /work/harness.log 2>/dev/null && break
  sleep 1
done
grep -qE 'waiting for the GCS' /work/harness.log || { echo '[run] harness never became ready:'; tail -20 /work/harness.log; exit 1; }
grep -E 'bomb is|that is ~|serving|cam_definition_uri' /work/harness.log | head -6

echo '[run] starting the MAVSDK app (it only creates the Camera plugin)'
timeout 300 gcs_app tcpout://127.0.0.1:5760 60 2>&1 | sed 's/^/[app] /' || true

sleep 2
AFTER=\$(df_used)
echo '[run] ---- AFTER ----'
df -h /tmp | tail -1 | awk '{print \"[run] disk: \" \$3 \" used, \" \$4 \" available\"}'
echo \"[run] disk consumed by this run: \$(( (AFTER-BEFORE) / 1048576 )) MiB\"
echo '[run] temp dir contents:'
ls -la /tmp/mavsdk-component-metadata-*/ 2>/dev/null | sed 's/^/[run]   /' || echo '[run]   (none)'
echo '[run] artifacts written by MAVSDK:'
find /tmp /root/.cache -name '*.extracted' -o -name '*.xz' -o -name '*.cache' 2>/dev/null | while read f; do
  printf '[run]   %s -> %s bytes\n' \"\$f\" \"\$(stat -c%s \"\$f\" 2>/dev/null)\"
done
echo '[run] ---- FTP exchange (harness side) ----'
grep -E 'MAVFTP|CAMERA_INFORMATION|answered|served' /work/harness.log | head -25 | sed 's/^/[run]   /'
kill \$HPID 2>/dev/null || true
"
