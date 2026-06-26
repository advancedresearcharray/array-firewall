from __future__ import annotations

import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import policies

LEASES = Path("/var/lib/misc/dnsmasq.leases")
DNSMASQ_CONF = Path("/etc/dnsmasq.d/array-firewall.conf")
SETUP = Path("/opt/array-firewall/scripts/setup-dnsmasq.sh")

DEFAULT_DHCP: dict[str, Any] = {
    "enabled": True,
    "interface": "eth1",
    "range_start": "10.99.0.50",
    "range_end": "10.99.0.200",
    "netmask": "255.255.255.0",
    "lease_time": "12h",
    "gateway": "10.99.0.1",
    "dns": "10.99.0.1",
    "domain": "array-firewall.local",
    "upstream_dns": ["192.168.167.1"],
    "authoritative": True,
    "reservations": [],
}


def config() -> dict[str, Any]:
    data = policies.load()
    dhcp = dict(DEFAULT_DHCP)
    dhcp.update(data.get("dhcp") or {})
    return dhcp


def save_config(updates: dict[str, Any]) -> dict[str, Any]:
    data = policies.load()
    dhcp = config()
    dhcp.update(updates)
    data["dhcp"] = dhcp
    policies.save(data)
    return dhcp


def _service_active() -> bool:
    proc = subprocess.run(
        ["systemctl", "is-active", "dnsmasq"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return proc.stdout.strip() == "active"


def parse_leases() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not LEASES.is_file():
        return rows
    now = time.time()
    for line in LEASES.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        expires_raw, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]
        try:
            exp = int(expires_raw)
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
            ttl_sec = max(0, int(exp - now))
        except ValueError:
            expires_at = ""
            ttl_sec = 0
        rows.append(
            {
                "mac": mac.lower(),
                "ip": ip,
                "hostname": hostname if hostname != "*" else "",
                "expires_at": expires_at,
                "ttl_sec": ttl_sec,
                "static": expires_raw == "0",
            }
        )
    return sorted(rows, key=lambda r: r.get("ip", ""))


def read_live_conf() -> dict[str, str]:
    out: dict[str, str] = {}
    if not DNSMASQ_CONF.is_file():
        return out
    for line in DNSMASQ_CONF.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def apply() -> dict[str, Any]:
    if not SETUP.is_file():
        raise FileNotFoundError(f"missing {SETUP}")
    proc = subprocess.run([str(SETUP)], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "setup-dnsmasq failed")
    cfg = config()
    if not cfg.get("enabled", True):
        subprocess.run(["systemctl", "stop", "dnsmasq"], check=False, timeout=15)
    return status()


def status() -> dict[str, Any]:
    cfg = config()
    active = _service_active()
    enabled = bool(cfg.get("enabled", True))
    return {
        "ok": True,
        "service": "dnsmasq",
        "running": active,
        "enabled": enabled,
        "effective": active and enabled,
        "config": cfg,
        "live_conf": read_live_conf(),
        "leases": parse_leases(),
        "lease_count": len(parse_leases()),
        "conf_file": str(DNSMASQ_CONF),
    }


def update(updates: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "enabled",
        "interface",
        "range_start",
        "range_end",
        "netmask",
        "lease_time",
        "gateway",
        "dns",
        "domain",
        "upstream_dns",
        "authoritative",
        "reservations",
    }
    clean = {k: v for k, v in updates.items() if k in allowed}
    if "reservations" in clean and clean["reservations"] is not None:
        clean["reservations"] = _normalize_reservations(clean["reservations"])
    save_config(clean)
    return apply()


def _normalize_reservations(items: list[Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    mac_re = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)
    for item in items:
        if not isinstance(item, dict):
            continue
        mac = str(item.get("mac", "")).lower()
        ip = str(item.get("ip", "")).strip()
        if not mac_re.match(mac) or not ip:
            continue
        row = {"mac": mac, "ip": ip}
        if item.get("hostname"):
            row["hostname"] = str(item["hostname"])
        out.append(row)
    return out


def add_reservation(mac: str, ip: str, hostname: str | None = None) -> dict[str, Any]:
    mac = mac.lower()
    cfg = config()
    res = [r for r in cfg.get("reservations", []) if r.get("mac") != mac]
    row: dict[str, str] = {"mac": mac, "ip": ip}
    if hostname:
        row["hostname"] = hostname
    res.append(row)
    save_config({"reservations": res})
    return apply()


def remove_reservation(mac: str) -> dict[str, Any]:
    mac = mac.lower()
    cfg = config()
    res = [r for r in cfg.get("reservations", []) if r.get("mac") != mac]
    save_config({"reservations": res})
    return apply()


def sync_device(mac: str, device_entry: dict[str, Any]) -> dict[str, Any]:
    """Keep policies reservations aligned with device dhcp reserve toggle."""
    from . import devices as dev_mod

    mac = mac.lower()
    dhcp = dev_mod._dhcp_entry(device_entry)
    cfg = config()
    res = [r for r in cfg.get("reservations", []) if r.get("mac") != mac]

    if dhcp["allocate"] and dhcp["reserve"] and dhcp["ip"]:
        row: dict[str, str] = {"mac": mac, "ip": dhcp["ip"]}
        host = device_entry.get("hostname") or device_entry.get("label")
        if host:
            row["hostname"] = str(host)
        res.append(row)

    save_config({"reservations": res})
    return apply()
