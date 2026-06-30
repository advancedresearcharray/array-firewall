from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from . import dhcp, devices, nft, policies

BACKUP = Path("/var/lib/array-firewall/cutover-backup.json")
CONF = Path("/etc/array-firewall/array-firewall.conf")
EXEC_LOG = Path("/var/lib/array-firewall/cutover-exec.log")


def _run(cmd: list[str] | str, *, timeout: int = 120, shell: bool = False) -> dict[str, Any]:
    if isinstance(cmd, str):
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    else:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return {"ok": proc.returncode == 0, "exit": proc.returncode, "output": out[-2000:]}


def _run_script(path: str | Path, *args: str) -> dict[str, Any]:
    script = Path(path)
    if not script.is_file():
        return {"ok": False, "error": f"missing {script}"}
    return _run([str(script), *args])


def _set_conf_kv(key: str, value: str) -> None:
    lines: list[str] = []
    found = False
    if CONF.is_file():
        for line in CONF.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{key}="):
                lines.append(f"{key}={value}")
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f"{key}={value}")
    CONF.parent.mkdir(parents=True, exist_ok=True)
    CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _gateway_policies(lan_gw: str) -> dict[str, Any]:
    data = policies.load()
    gaming = data.setdefault("gaming", {})
    xbox_mac = str(gaming.get("xbox_mac") or os.environ.get("ARRAY_FW_XBOX_MAC") or "").strip()
    xbox_ip = str(gaming.get("xbox_ip") or "192.0.2.65").strip()
    data.setdefault("network", {}).update(
        {
            "role": "gateway",
            "cutover": True,
            "lan_if": "eth0",
            "wan_if": "eth1",
            "uplink_if": "eth1",
            "lan_cidr": "192.0.2.0/24",
            "gateway_ip": lan_gw,
            "nat": True,
        }
    )
    dhcp_cfg = data.setdefault("dhcp", {})
    dhcp_cfg.update(
        {
            "enabled": True,
            "interface": "eth0",
            "range_start": "192.0.2.50",
            "range_end": "192.0.2.200",
            "netmask": "255.255.255.0",
            "lease_time": "12h",
            "gateway": lan_gw,
            "dns": lan_gw,
            "domain": data.get("dhcp", {}).get("domain") or "array.local",
            "upstream_dns": ["1.1.1.1", "8.8.8.8"],
            "authoritative": True,
        }
    )
    if xbox_mac:
        res = dhcp_cfg.setdefault("reservations", [])
        if not any(str(r.get("mac") or "").lower() == xbox_mac.lower() for r in res if isinstance(r, dict)):
            res.append({"mac": xbox_mac, "ip": xbox_ip, "hostname": "xbox"})
    policies.save(data)
    return {"ok": True, "gateway_ip": lan_gw, "xbox_ip": xbox_ip}


def _lab_policies() -> dict[str, Any]:
    data = policies.load()
    data.setdefault("network", {}).update(
        {
            "role": "lab",
            "cutover": False,
            "lan_if": "eth1",
            "wan_if": "eth1",
            "uplink_if": "eth0",
            "lan_cidr": "198.51.100.0/24",
        }
    )
    dhcp_cfg = data.setdefault("dhcp", {})
    dhcp_cfg.update(
        {
            "enabled": True,
            "interface": "eth1",
            "range_start": "198.51.100.50",
            "range_end": "198.51.100.200",
            "gateway": "198.51.100.1",
            "dns": "198.51.100.1",
            "upstream_dns": ["192.0.2.1"],
        }
    )
    policies.save(data)
    return {"ok": True}


def _log_step(name: str, result: dict[str, Any]) -> None:
    EXEC_LOG.parent.mkdir(parents=True, exist_ok=True)
    line = {
        "ts": time.time(),
        "step": name,
        "ok": result.get("ok"),
        "detail": result.get("output") or result.get("error") or result,
    }
    with EXEC_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(line, separators=(",", ":")) + "\n")


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
    add("dnsmasq_installed", _run(["which", "dnsmasq"])["ok"], "dnsmasq binary")
    add("nftables", _run(["nft", "list", "ruleset"])["ok"], "nft rules load")
    add("api_service", _run(["systemctl", "is-active", "array-firewall-api"])["output"] == "active", "array-firewall-api")
    add("admin_mac_set", bool(devices.admin_mac()), devices.admin_mac() or "set ADMIN_LAPTOP_MAC")
    add("eth0_up", _iface_up("eth0"), "eth0 link")
    add("eth1_up", _iface_up("eth1"), "eth1 link")
    add(
        "not_already_cutover",
        not policies.cutover_enabled(),
        "cutover=false (safe to proceed)" if not policies.cutover_enabled() else "ALREADY in cutover mode",
        required=False,
    )

    wan_if = net.get("wan_if", "eth1")
    route = _run(["ip", "route", "show", "default"])
    has_wan_route = "default" in route["output"] and wan_if in route["output"] if policies.cutover_enabled() else True
    add(
        "wan_default_route",
        has_wan_route or not policies.cutover_enabled(),
        route["output"].splitlines()[0] if route["output"] else "no default route yet (expected before cutover)",
        required=False,
    )

    required_fail = [c for c in checks if c["required"] and not c["ok"]]
    return {
        "ok": len(required_fail) == 0,
        "ready": len(required_fail) == 0,
        "role": cfg.get("role"),
        "cutover": policies.cutover_enabled(),
        "lan_gateway": net.get("gateway_ip", "192.0.2.1"),
        "checks": checks,
        "warnings": [
            "Firewalla must be removed/disabled as 192.0.2.1 before cutover",
            "Physical: nic1 (eth1) → ISP/modem, nic0 (eth0) → house switch",
            "Proxmox network change still required for full migration — see docs/CUTOVER.md",
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
            "net0": "192.0.2.241/24",
            "net1": "198.51.100.1/24",
        },
    }
    BACKUP.parent.mkdir(parents=True, exist_ok=True)
    BACKUP.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "backup": str(BACKUP)}


def dry_run() -> dict[str, Any]:
    """Simulate cutover steps without changing live network role."""
    pf = preflight()
    net = policies.network()
    steps = [
        {"step": "backup_state", "would_run": True, "safe": True},
        {"step": "set_role_gateway", "would_run": True, "safe": pf.get("ok", False)},
        {"step": "enable_cutover_flag", "would_run": True, "safe": pf.get("ok", False)},
        {"step": "restart_dnsmasq", "would_run": True, "safe": pf.get("ok", False)},
        {"step": "apply_nft_gateway", "would_run": True, "safe": pf.get("ok", False)},
        {"step": "sync_sentinel", "would_run": True, "safe": True},
    ]
    return {
        "ok": pf.get("ok", False),
        "dry_run": True,
        "current_role": policies.role(),
        "cutover_enabled": policies.cutover_enabled(),
        "lan_gateway": net.get("gateway_ip"),
        "preflight": pf,
        "planned_steps": steps,
        "estimated_outage_sec": 120,
        "rollback": "POST /api/v1/cutover/rollback or cutover-rollback.sh",
    }


def execute(*, confirm: bool = False, lan_gateway: str | None = None, force: bool = False) -> dict[str, Any]:
    """In-container gateway cutover — policies, dnsmasq, nft (Proxmox wiring is separate)."""
    if not confirm:
        dr = dry_run()
        return {
            "ok": False,
            "error": "confirm=true required",
            "dry_run": dr,
            "api": "POST /api/v1/cutover/execute {\"confirm\": true}",
        }

    pf = preflight()
    if not pf.get("ok") and not force:
        return {"ok": False, "error": "preflight failed", "preflight": pf}

    lan_gw = str(lan_gateway or policies.network().get("gateway_ip") or "192.0.2.1").strip()
    steps: list[dict[str, Any]] = []

    steps.append(backup_state())
    for key, val in (
        ("ROLE", "gateway"),
        ("CUTOVER", "1"),
        ("LAN_IF", "eth0"),
        ("WAN_IF", "eth1"),
        ("UPLINK_IF", "eth1"),
        ("LAN_CIDR", "192.0.2.0/24"),
        ("LAN_GATEWAY_IP", lan_gw),
    ):
        _set_conf_kv(key, val)
    steps.append({"step": "conf_gateway", "ok": True, "gateway_ip": lan_gw})

    steps.append({"step": "policies_gateway", **_gateway_policies(lan_gw)})

    xbox_mac = str(policies.gaming().get("xbox_mac") or "").strip()
    if xbox_mac:
        try:
            devices.set_allowed(xbox_mac, True, "Xbox")
            steps.append({"step": "xbox_allow", "ok": True, "mac": xbox_mac})
        except Exception as exc:
            steps.append({"step": "xbox_allow", "ok": False, "error": str(exc)})

    for name, script in (
        ("wan_setup", "/opt/array-firewall/scripts/wan-setup.sh"),
        ("dnsmasq", "/opt/array-firewall/scripts/setup-dnsmasq.sh"),
        ("nft", "/usr/local/bin/apply-array-firewall"),
    ):
        result = _run_script(script)
        steps.append({"step": name, **result})
        _log_step(name, result)

    sync = _run_script("/opt/array-firewall/scripts/sync-sentinel-config.sh")
    steps.append({"step": "sentinel_sync", **sync})

    services = _run(["systemctl", "restart", "dnsmasq", "array-firewall-api", "warzone-lobby-sentinel"])
    steps.append({"step": "services_restart", **services})

    ok = all(s.get("ok", True) for s in steps if s.get("step") not in {"wan_setup"})
    return {
        "ok": ok,
        "cutover": True,
        "role": "gateway",
        "gateway_ip": lan_gw,
        "steps": steps,
        "proxmox_note": "Run cutover-gateway.sh on Proxmox host to re-IP CT eth0 if not already on LAN gateway",
        "verify": [
            f"curl http://{lan_gw}:8090/api/v1/cutover/status",
            "Renew DHCP on admin laptop",
            f"POST /api/v1/hardening/apply after verification",
        ],
    }


def rollback(*, confirm: bool = False, force: bool = False) -> dict[str, Any]:
    """Rollback to lab/sidecar mode inside container."""
    if not confirm:
        return {
            "ok": False,
            "error": "confirm=true required",
            "api": "POST /api/v1/cutover/rollback {\"confirm\": true}",
        }

    steps: list[dict[str, Any]] = []

    if BACKUP.is_file():
        try:
            backup = json.loads(BACKUP.read_text(encoding="utf-8"))
            if backup.get("devices"):
                devices.STORE.parent.mkdir(parents=True, exist_ok=True)
                devices.STORE.write_text(json.dumps(backup["devices"], indent=2) + "\n", encoding="utf-8")
            steps.append({"step": "restore_devices", "ok": True})
        except (json.JSONDecodeError, OSError) as exc:
            steps.append({"step": "restore_devices", "ok": False, "error": str(exc)})

    for key, val in (
        ("ROLE", "lab"),
        ("CUTOVER", "0"),
        ("LAN_IF", "eth1"),
        ("WAN_IF", "eth1"),
        ("UPLINK_IF", "eth0"),
        ("LAN_CIDR", "198.51.100.0/24"),
    ):
        _set_conf_kv(key, val)
    steps.append({"step": "conf_lab", "ok": True})
    steps.append({"step": "policies_lab", **_lab_policies()})

    for name, script in (
        ("dnsmasq", "/opt/array-firewall/scripts/setup-dnsmasq.sh"),
        ("nft", "/usr/local/bin/apply-array-firewall"),
    ):
        result = _run_script(script)
        steps.append({"step": name, **result})

    env_sentinel = Path("/etc/default/warzone-lobby-sentinel")
    if env_sentinel.is_file():
        text = env_sentinel.read_text(encoding="utf-8")
        if "WZ_FIREWALLA_API_URL=" in text:
            lines = []
            for line in text.splitlines():
                if line.startswith("WZ_FIREWALLA_API_URL="):
                    lines.append("WZ_FIREWALLA_API_URL=http://192.0.2.1:9378")
                else:
                    lines.append(line)
            env_sentinel.write_text("\n".join(lines) + "\n", encoding="utf-8")
            steps.append({"step": "sentinel_env", "ok": True})

    services = _run(["systemctl", "restart", "dnsmasq", "array-firewall-api", "warzone-lobby-sentinel"])
    steps.append({"step": "services_restart", **services})

    return {
        "ok": True,
        "cutover": False,
        "role": "lab",
        "steps": steps,
        "proxmox_note": "Run cutover-rollback.sh on Proxmox to restore CT network IPs",
    }


def status() -> dict[str, Any]:
    pf = preflight()
    return {
        "ok": True,
        "cutover": policies.cutover_enabled(),
        "role": policies.role(),
        "gateway_ip": policies.network().get("gateway_ip", "192.0.2.1"),
        "preflight": pf,
        "dhcp": {"effective": dhcp.status().get("effective"), "lease_count": dhcp.status().get("lease_count")},
        "backup_exists": BACKUP.is_file(),
        "backup_path": str(BACKUP),
        "exec_log": str(EXEC_LOG) if EXEC_LOG.is_file() else None,
    }
