from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from . import dhcp, devices, nft, policies

BACKUP = Path("/var/lib/array-firewall/cutover-backup.json")
CONF = Path("/etc/array-firewall/array-firewall.conf")


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out.strip()


def _iface_up(name: str) -> bool:
    p = Path(f"/sys/class/net/{name}/operstate")
    return p.is_file() and p.read_text().strip() == "up"


def preflight() -> dict[str, Any]:
    net = policies.network()
    cfg = nft._ifaces()  # noqa: SLF001
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str, *, required: bool = True) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail, "required": required})

    add("policies_file", policies.POLICIES_PATH.is_file(), str(policies.POLICIES_PATH))
    add("dnsmasq_installed", _run(["which", "dnsmasq"])[0] == 0, "dnsmasq binary")
    add("nftables", _run(["nft", "list", "ruleset"])[0] == 0, "nft rules load")
    add("api_service", _run(["systemctl", "is-active", "array-firewall-api"])[1] == "active", "array-firewall-api")
    add("admin_mac_set", bool(devices.admin_mac()), devices.admin_mac() or "set ADMIN_LAPTOP_MAC")
    add("eth0_up", _iface_up("eth0"), "eth0 link")
    add("eth1_up", _iface_up("eth1"), "eth1 link")
    add(
        "not_already_cutover",
        not policies.cutover_enabled(),
        "cutover=false (safe to proceed)" if not policies.cutover_enabled() else "ALREADY in cutover mode",
    )

    wan_if = net.get("wan_if", "eth1")
    code, route = _run(["ip", "route", "show", "default"])
    has_wan_route = "default" in route and wan_if in route if policies.cutover_enabled() else True
    add(
        "wan_default_route",
        has_wan_route or not policies.cutover_enabled(),
        route.splitlines()[0] if route else "no default route yet (expected before cutover)",
        required=False,
    )

    required_fail = [c for c in checks if c["required"] and not c["ok"]]
    return {
        "ok": len(required_fail) == 0,
        "ready": len(required_fail) == 0,
        "role": cfg.get("role"),
        "cutover": policies.cutover_enabled(),
        "lan_gateway": net.get("gateway_ip", "192.168.167.1"),
        "checks": checks,
        "warnings": [
            "Firewalla must be removed/disabled as 192.168.167.1 before cutover",
            "Physical: nic1 (eth1) → ISP/modem, nic0 (eth0) → house switch",
            "Expect brief LAN outage during reboot (~2 min)",
        ],
        "steps_doc": "/opt/array-firewall/docs/CUTOVER.md",
    }


def backup_state() -> dict[str, Any]:
    data = {
        "array_firewall_conf": CONF.read_text(encoding="utf-8") if CONF.is_file() else "",
        "policies": policies.load(),
        "devices": json.loads(devices.STORE.read_text()) if devices.STORE.is_file() else {},
        "pct_hint": {
            "ctid": 940,
            "net0": "192.168.167.241/24",
            "net1": "10.99.0.1/24",
        },
    }
    BACKUP.parent.mkdir(parents=True, exist_ok=True)
    BACKUP.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "backup": str(BACKUP)}


def status() -> dict[str, Any]:
    pf = preflight()
    return {
        "ok": True,
        "cutover": policies.cutover_enabled(),
        "role": policies.role(),
        "gateway_ip": policies.network().get("gateway_ip", "192.168.167.1"),
        "preflight": pf,
        "dhcp": {"effective": dhcp.status().get("effective"), "lease_count": dhcp.status().get("lease_count")},
        "backup_exists": BACKUP.is_file(),
        "backup_path": str(BACKUP),
    }
