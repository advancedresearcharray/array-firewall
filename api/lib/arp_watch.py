from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from . import policies

LOG = Path("/var/lib/array-firewall/arp-watch.jsonl")
STATE = Path("/var/lib/array-firewall/arp-watch.state")
SERVICE = "array-firewall-arp-watch.service"


def _gaming() -> dict[str, Any]:
    return policies.gaming()


def status(*, tail: int = 40) -> dict[str, Any]:
    g = _gaming()
    mac = (g.get("xbox_mac") or "").lower()
    net = policies.network()
    rows: list[dict[str, Any]] = []
    if LOG.is_file():
        lines = LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-tail:]:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    last: dict[str, Any] = {}
    if STATE.is_file():
        try:
            last = json.loads(STATE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            last = {}
    active = subprocess.run(
        ["systemctl", "is-active", SERVICE],
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip()
    neigh: list[str] = []
    lan_if = net.get("lan_if") or "eth0"
    if mac:
        proc = subprocess.run(
            ["ip", "neigh", "show", "dev", lan_if],
            capture_output=True,
            text=True,
            timeout=5,
        )
        neigh = [ln for ln in proc.stdout.splitlines() if mac in ln.lower()]
    return {
        "ok": True,
        "watching": active == "active",
        "service": SERVICE,
        "service_state": active,
        "xbox_mac": mac,
        "xbox_ip": g.get("xbox_ip") or "",
        "lan_if": lan_if,
        "gateway_ip": net.get("gateway_ip") or "203.0.113.1",
        "last": last.get("last") or {},
        "updated": last.get("updated") or "",
        "neigh": neigh,
        "events": rows,
        "event_count": len(rows),
        "log_file": str(LOG),
    }
