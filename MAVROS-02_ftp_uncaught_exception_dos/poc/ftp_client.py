#!/usr/bin/env python3
"""Minimal operator-side driver for mavros's FTP services.

Exists because `ros2 service call` would need a YAML array of 65536 integers on
the command line to start a 64 KB upload. Data is passed via a file instead.

  ftp_client.py open  PATH
  ftp_client.py write PATH FILE [OFFSET]
  ftp_client.py close PATH
"""
import sys
import rclpy
from rclpy.node import Node
from mavros_msgs.srv import FileOpen, FileWrite, FileClose


def call(node, cli, req, timeout=180.0):
    if not cli.wait_for_service(timeout_sec=20.0):
        print("SERVICE-UNAVAILABLE %s" % cli.srv_name, flush=True)
        return None
    fut = cli.call_async(req)
    rclpy.spin_until_future_complete(node, fut, timeout_sec=timeout)
    if not fut.done():
        print("TIMEOUT %s" % cli.srv_name, flush=True)
        return None
    return fut.result()


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    action, path = sys.argv[1], sys.argv[2]
    ns = "/mavros"

    rclpy.init()
    node = Node("mavros02_ftp_client")
    rc = 0
    try:
        if action == "open":
            cli = node.create_client(FileOpen, ns + "/ftp/open")
            req = FileOpen.Request()
            req.file_path = path
            req.mode = FileOpen.Request.MODE_WRITE
            res = call(node, cli, req, timeout=60.0)
            print("OPEN success=%s r_errno=%s" %
                  (getattr(res, "success", None), getattr(res, "r_errno", None)),
                  flush=True)
            rc = 0 if getattr(res, "success", False) else 1
        elif action == "write":
            data = open(sys.argv[3], "rb").read()
            off = int(sys.argv[4]) if len(sys.argv) > 4 else 0
            cli = node.create_client(FileWrite, ns + "/ftp/write")
            req = FileWrite.Request()
            req.file_path = path
            req.offset = off
            req.data = list(data)
            res = call(node, cli, req, timeout=300.0)
            print("WRITE bytes=%d success=%s r_errno=%s" %
                  (len(data), getattr(res, "success", None),
                   getattr(res, "r_errno", None)), flush=True)
            rc = 0 if getattr(res, "success", False) else 1
        elif action == "close":
            cli = node.create_client(FileClose, ns + "/ftp/close")
            req = FileClose.Request()
            req.file_path = path
            res = call(node, cli, req, timeout=60.0)
            print("CLOSE success=%s" % getattr(res, "success", None), flush=True)
        else:
            print("unknown action %r" % action)
            rc = 2
    finally:
        node.destroy_node()
        rclpy.shutdown()
    return rc


if __name__ == "__main__":
    sys.exit(main())
