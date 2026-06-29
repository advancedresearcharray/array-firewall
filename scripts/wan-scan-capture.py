#!/usr/bin/env python3
"""Capture WAN port scans into AFLD (24h folded retention)."""
from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/opt/array-firewall/api")

from lib import afld  # noqa: E402

CONF = Path("/etc/array-firewall/array-firewall.conf")
GAME_TCP = {53, 80, 443, 2869, 3074}
GAME_UDP = {53, 88, 500, 3074, 3075, 3544, 4500, 9002}
SERVER_PORTS = {53, 80, 443, 88, 500, 3544, 4500, 2869, 3074, 3075, 9002}
_LINE = re.compile(
    r"IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):"
)


def _read_conf() -> dict[str, str]:
    out: dict[str, str] = {}
    if not CONF.is_file():
        return out
    for line in CONF.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        out[key.strip()] = val.strip().strip('"')
    return out


def _wan_ip(conf: dict[str, str]) -> str:
    wan_if = conf.get("WAN_IF") or "eth1"
    proc = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", wan_if],
        capture_output=True,
        text=True,
        timeout=5,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            idx = parts.index("inet") + 1
            return parts[idx].split("/")[0]
    return ""


def _wan_net(conf: dict[str, str]) -> str:
    wan_if = conf.get("WAN_IF") or "eth1"
    proc = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", wan_if],
        capture_output=True,
        text=True,
        timeout=5,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            idx = parts.index("inet") + 1
            return parts[idx]
    return ""


def _bpf_filter(wan_ip: str) -> str:
    return (
        f"dst host {wan_ip} and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
    )


def _is_private_or_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _parse_line(line: str, wan_ip: str) -> dict | None:
    if " IP " not in line:
        return None
    m = _LINE.search(line)
    if not m:
        return None
    src, sport, dst, dport = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    if dst != wan_ip or _is_private_or_local(src):
        return None

    if " UDP," in line or line.rstrip().endswith(": UDP") or " UDP " in line:
        proto = "udp"
        if dport in GAME_UDP or sport in SERVER_PORTS:
            return None
        if sport >= 1024 and dport >= 1024:
            return None
    elif " tcp" in line.lower():
        proto = "tcp"
        if "Flags [S" not in line or "Flags [S.]" in line:
            return None
        if dport in GAME_TCP:
            return None
    else:
        return None

    return {
        "ip": src,
        "port": dport,
        "sport": sport,
        "proto": proto,
        "action": "drop",
        "wan_ip": wan_ip,
        "source": "wan-scan-capture",
    }


def main() -> int:
    conf = _read_conf()
    wan_if = conf.get("WAN_IF") or "eth1"
    wan_ip = _wan_ip(conf)
    if not wan_ip:
        print("[wan-scan-capture] WAN IP not found on", wan_if, file=sys.stderr, flush=True)
        return 1
    filt = _bpf_filter(wan_ip)
    print(f"[wan-scan-capture] logging scans to AFLD on {wan_if} ({wan_ip})", flush=True)
    cmd = ["tcpdump", "-i", wan_if, "-n", "-l", "-q", filt]
    while True:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                row = _parse_line(line, wan_ip)
                if row:
                    afld.append("wan_scan", row)
            code = proc.wait()
            if code != 0:
                print(f"[wan-scan-capture] tcpdump exited {code}, restart in 5s", flush=True)
        except Exception as exc:
            print(f"[wan-scan-capture] error: {exc}", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
