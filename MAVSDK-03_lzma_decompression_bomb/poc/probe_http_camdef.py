"""MAVSDK-03 sink probe: camera cam_definition_uri over http(s), naming a .xz.

camera_impl.cpp:1527 builds the HTTP download path as
    _tmp_download_path / file_cache_tag
where file_cache_tag is "camera_definition-<model>_<vendor>-<version>.xml"
(:1491-1493). The url's own filename is never used. This probe serves a .xz at
an http:// url to see whether the .xz branch at :1564 can fire.
"""
import argparse, sys
sys.path.insert(0, "/poc")
import poc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:5760")
    ap.add_argument("--uri", default="http://127.0.0.1:8000/def.xml.xz")
    a = ap.parse_args()

    poc.banner("MAVSDK-03 sink probe: http(s) camera definition naming a .xz")
    v = poc.MavsdkCameraVehicle("tcpin:" + a.listen, verbose=False, cam_uri=a.uri)
    poc.observe("cam_definition_uri = %r" % a.uri)
    poc.observe("expected local path: <tmp>/camera_definition-MAVSDK03_infected-drones-1.xml")
    v.start()
    poc.observe("waiting for the GCS")
    v.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
