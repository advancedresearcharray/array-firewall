#!/usr/bin/env python3
"""TCP honeypot sink — logs inbound probe connections redirected by nft DNAT."""
from __future__ import annotations

import json
import os
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

LOG_PATH = Path(os.environ.get("PROBE_SINK_LOG", "/var/lib/array-firewall/probe-sink-listener.jsonl"))
BIND = os.environ.get("PROBE_SINK_BIND", "0.0.0.0")
PORT = int(os.environ.get("PROBE_SINK_PORT", "39217"))


def _log(remote_ip: str, remote_port: int, local_port: int) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "local_port": local_port,
        "proto": "tcp",
        "reason": "honeypot_connect",
    }
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    print(f"[probe-sink] connect {remote_ip}:{remote_port}", flush=True)


class ProbeHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            peer = self.client_address
            _log(str(peer[0]), int(peer[1]), PORT)
        finally:
            try:
                self.request.close()
            except OSError:
                pass


class ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    with ThreadedServer((BIND, PORT), ProbeHandler) as server:
        print(f"[probe-sink] listening on {BIND}:{PORT}", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
