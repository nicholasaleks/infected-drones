#!/usr/bin/env bash
# MAVSDK-03 persistence probe, all inside one container so ~/.cache is shared
# across four separate application lifetimes.
set -e
mkdir -p /work && cd /work
cachesz() { du -sb /root/.cache/mavsdk 2>/dev/null | cut -f1 || echo 0; }
run_once() {
  local model="$1" label="$2"
  pkill -f poc.py 2>/dev/null || true; sleep 1; rm -f /work/h.log
  python3 /poc/poc.py --mode bomb --gib 1 --model "$model" \
      --bomb-cache /work/bomb.xz --listen 0.0.0.0:5760 > /work/h.log 2>&1 &
  for i in $(seq 1 300); do grep -q 'waiting for the GCS' /work/h.log 2>/dev/null && break; sleep 1; done
  grep -q 'waiting for the GCS' /work/h.log || { echo "harness not ready"; tail -5 /work/h.log; exit 1; }
  echo "--- $label (model=$model) ---"
  timeout 180 gcs_app tcpout://127.0.0.1:5760 12 2>&1 \
    | grep -Ei 'Cache (hit|miss)|Download file|download finished|Cached path|Using cached' \
    | sed 's/^/    [app] /' || true
  pkill -f poc.py 2>/dev/null || true
  echo "    cache now: $(cachesz) bytes, $(ls /root/.cache/mavsdk/camera/*.cache 2>/dev/null | wc -l) entries"
}
echo "start: cache $(cachesz) bytes"
run_once CamA "run 1, new vehicle identity"
run_once CamB "run 2, new vehicle identity"
run_once CamC "run 3, new vehicle identity"
run_once CamA "run 4, SAME identity as run 1"
echo
echo "=== final ==="
ls -la /root/.cache/mavsdk/camera/ | sed 's/^/  /'
echo "  total: $(cachesz) bytes across $(ls /root/.cache/mavsdk/camera/*.cache 2>/dev/null | wc -l) entries"
