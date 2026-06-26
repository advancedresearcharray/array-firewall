#!/usr/bin/env bash
# Report physical NIC link speed/duplex (ethtool) for Firewalla Gold ports eth0–eth3.
set -euo pipefail

exec python3 - <<'PY'
import json
import re
import subprocess
from datetime import datetime, timezone

PORT_MAP = {
    "eth0": "Port 1 (WAN)",
    "eth1": "Port 2",
    "eth2": "Port 3",
    "eth3": "Port 4",
}


def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        return (r.stdout or "").strip()
    except Exception as exc:
        return f"error: {exc}"


def parse_ethtool(name):
    out = run(["ethtool", name])
    if not out or out.startswith("error:"):
        return {"iface": name, "error": out or "no output"}
    info = {"iface": name, "label": PORT_MAP.get(name, name)}
    for line in out.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        kl = k.lower()
        if kl in ("speed", "duplex", "port", "link detected", "auto-negotiation"):
            info[kl.replace(" ", "_")] = v
    return info


def bridge_members():
    out = run(["ip", "-br", "link"])
    bridges = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("br"):
            bridges[parts[0]] = {"state": parts[1]}
    return bridges


ifaces = [parse_ethtool(f"eth{i}") for i in range(4)]
issues = []
for i in ifaces:
    speed = str(i.get("speed", "")).lower()
    link = str(i.get("link_detected", "")).lower()
    if link == "yes" and "100mb/s" in speed:
        issues.append(
            f"{i.get('label', i['iface'])} ({i['iface']}) linked at 100Mb/s — check cable, remote port, and SFP/adapter"
        )
    if link == "yes" and "1000mb/s" not in speed and "2500" not in speed and "10000" not in speed and "unknown" not in speed and speed:
        if "100mb/s" not in speed:
            issues.append(f"{i.get('label', i['iface'])} ({i['iface']}) unusual speed: {i.get('speed')}")

payload = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "ports": ifaces,
    "bridges": bridge_members(),
    "issues": issues,
}
print(json.dumps(payload, indent=2))
PY
