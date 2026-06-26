"""Inbound NAT: port forwarding, DMZ host, UPnP (miniupnpd)."""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from . import nft, policies

UPNP_CONF = Path("/etc/miniupnpd/miniupnpd.conf")
UPNP_LEASES = Path("/var/lib/array-firewall/upnp-leases.json")
XBOX_UDP = (88, 500, 3074, 3075, 3544, 4500, 53, 9002)
XBOX_TCP = (3074, 80, 53, 443, 2869)
_PROTO_RE = re.compile(r"^(tcp|udp|both)$", re.I)
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _conf() -> dict[str, str]:
    return nft._conf()


def _ifaces() -> dict[str, str]:
    return nft._ifaces()


def _gaming() -> dict[str, Any]:
    return policies.gaming()


def _load() -> dict[str, Any]:
    return policies.load()


def _save(data: dict[str, Any]) -> None:
    policies.save(data)


def port_forwards() -> list[dict[str, Any]]:
    rows = _load().get("port_forwards") or []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(_normalize_forward(row))
    return out


def dmz() -> dict[str, Any]:
    raw = _load().get("dmz") or {}
    gaming = _gaming()
    host_ip = str(raw.get("host_ip") or gaming.get("xbox_ip") or _conf().get("XBOX_IP") or "").strip()
    host_mac = str(raw.get("host_mac") or gaming.get("xbox_mac") or "").strip().lower()
    return {
        "enabled": bool(raw.get("enabled")),
        "host_ip": host_ip,
        "host_mac": host_mac,
        "name": str(raw.get("name") or "dmz"),
    }


def upnp_config() -> dict[str, Any]:
    raw = _load().get("upnp") or {}
    return {
        "enabled": bool(raw.get("enabled", True)),
        "secure_mode": bool(raw.get("secure_mode", False)),
        "lease_seconds": int(raw.get("lease_seconds") or 3600),
        "allow_lan": bool(raw.get("allow_lan", True)),
    }


def _normalize_forward(row: dict[str, Any]) -> dict[str, Any]:
    proto = str(row.get("proto") or "tcp").lower()
    if proto not in {"tcp", "udp", "both"}:
        proto = "tcp"
    wan_port = int(row.get("wan_port") or row.get("port") or 0)
    lan_port = int(row.get("lan_port") or wan_port or 0)
    return {
        "id": str(row.get("id") or f"{proto}-{wan_port}-{row.get('lan_ip', '')}"),
        "name": str(row.get("name") or f"forward-{wan_port}"),
        "enabled": bool(row.get("enabled", True)),
        "proto": proto,
        "wan_port": wan_port,
        "lan_ip": str(row.get("lan_ip") or "").strip(),
        "lan_port": lan_port,
        "source": str(row.get("source") or "manual"),
    }


def _validate_forward(row: dict[str, Any]) -> dict[str, Any]:
    fwd = _normalize_forward(row)
    if not _IP_RE.match(fwd["lan_ip"]):
        raise ValueError("lan_ip must be IPv4")
    if fwd["wan_port"] < 1 or fwd["wan_port"] > 65535:
        raise ValueError("wan_port out of range")
    if fwd["lan_port"] < 1 or fwd["lan_port"] > 65535:
        raise ValueError("lan_port out of range")
    if not _PROTO_RE.match(fwd["proto"]):
        raise ValueError("proto must be tcp, udp, or both")
    return fwd


def add_port_forward(row: dict[str, Any]) -> dict[str, Any]:
    fwd = _validate_forward(row)
    data = _load()
    rows = [r for r in (data.get("port_forwards") or []) if str(r.get("id")) != fwd["id"]]
    rows.append(fwd)
    data["port_forwards"] = rows
    _save(data)
    nft.apply_ruleset()
    sync_services()
    return {"ok": True, "forward": fwd}


def remove_port_forward(forward_id: str) -> dict[str, Any]:
    data = _load()
    before = len(data.get("port_forwards") or [])
    rows = [r for r in (data.get("port_forwards") or []) if str(r.get("id")) != forward_id]
    data["port_forwards"] = rows
    _save(data)
    nft.apply_ruleset()
    sync_services()
    return {"ok": True, "removed": before - len(rows)}


def set_dmz(*, enabled: bool, host_ip: str | None = None, host_mac: str | None = None, name: str | None = None) -> dict[str, Any]:
    cfg = dmz()
    if host_ip:
        cfg["host_ip"] = host_ip.strip()
    if host_mac:
        cfg["host_mac"] = host_mac.strip().lower()
    if name:
        cfg["name"] = name.strip()
    cfg["enabled"] = bool(enabled)
    if cfg["enabled"] and not _IP_RE.match(cfg.get("host_ip") or ""):
        raise ValueError("DMZ host_ip required")
    data = _load()
    data["dmz"] = cfg
    _save(data)
    nft.apply_ruleset()
    sync_services()
    return {"ok": True, "dmz": cfg}


def set_upnp(*, enabled: bool | None = None, secure_mode: bool | None = None) -> dict[str, Any]:
    cfg = upnp_config()
    if enabled is not None:
        cfg["enabled"] = bool(enabled)
    if secure_mode is not None:
        cfg["secure_mode"] = bool(secure_mode)
    data = _load()
    data["upnp"] = cfg
    _save(data)
    sync_services()
    return {"ok": True, "upnp": cfg, **upnp_status()}


def xbox_preset_forwards() -> dict[str, Any]:
    gaming = _gaming()
    ip = str(gaming.get("xbox_ip") or _conf().get("XBOX_IP") or "").strip()
    if not _IP_RE.match(ip):
        raise ValueError("xbox_ip not configured")
    data = _load()
    rows = [r for r in (data.get("port_forwards") or []) if str(r.get("source")) != "xbox-preset"]
    added: list[str] = []
    for port in XBOX_UDP:
        fid = f"xbox-udp-{port}"
        rows.append(
            _validate_forward(
                {
                    "id": fid,
                    "name": f"Xbox UDP {port}",
                    "proto": "udp",
                    "wan_port": port,
                    "lan_ip": ip,
                    "lan_port": port,
                    "source": "xbox-preset",
                    "enabled": True,
                }
            )
        )
        added.append(fid)
    for port in XBOX_TCP:
        fid = f"xbox-tcp-{port}"
        rows.append(
            _validate_forward(
                {
                    "id": fid,
                    "name": f"Xbox TCP {port}",
                    "proto": "tcp",
                    "wan_port": port,
                    "lan_ip": ip,
                    "lan_port": port,
                    "source": "xbox-preset",
                    "enabled": True,
                }
            )
        )
        added.append(fid)
    data["port_forwards"] = rows
    _save(data)
    nft.apply_ruleset()
    sync_services()
    return {"ok": True, "added": len(added), "ids": added}


def enable_xbox_dmz() -> dict[str, Any]:
    gaming = _gaming()
    return set_dmz(
        enabled=True,
        host_ip=str(gaming.get("xbox_ip") or _conf().get("XBOX_IP") or ""),
        host_mac=str(gaming.get("xbox_mac") or ""),
        name="xbox",
    )


def render_prerouting_rules() -> str:
    ifaces = _ifaces()
    wan_if = ifaces["wan_if"]
    lines: list[str] = []
    dmz_cfg = dmz()
    for fwd in port_forwards():
        if not fwd.get("enabled"):
            continue
        lip, wp, lp = fwd["lan_ip"], fwd["wan_port"], fwd["lan_port"]
        target = f"{lip}:{lp}" if lp != wp else lip
        protos = ("tcp", "udp") if fwd["proto"] == "both" else (fwd["proto"],)
        for proto in protos:
            lines.append(f'    iifname "{wan_if}" {proto} dport {wp} dnat ip to {target}')
    if dmz_cfg.get("enabled") and _IP_RE.match(str(dmz_cfg.get("host_ip") or "")):
        host = dmz_cfg["host_ip"]
        lines.append(f'    iifname "{wan_if}" dnat ip to {host}')
    if not lines:
        return ""
    body = "\n".join(lines)
    return f"""
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
{body}
  }}"""


def render_forward_inbound_rules() -> str:
    ifaces = _ifaces()
    wan_if = ifaces["wan_if"]
    lan_if = ifaces["lan_if"]
    rules: list[str] = [f'    iifname "{wan_if}" oifname "{lan_if}" ct status dnat accept']
    dmz_cfg = dmz()
    if dmz_cfg.get("enabled") and _IP_RE.match(str(dmz_cfg.get("host_ip") or "")):
        host = dmz_cfg["host_ip"]
        rules.append(f'    iifname "{wan_if}" oifname "{lan_if}" ip daddr {host} accept')
    return "\n".join(rules)


def _write_upnp_conf() -> None:
    ifaces = _ifaces()
    cfg = upnp_config()
    c = _conf()
    gw = policies.network().get("gateway_ip") or c.get("LAN_GATEWAY_IP") or "192.168.167.1"
    lan_if = ifaces["lan_if"]
    secure = "yes" if cfg.get("secure_mode") else "no"
    UPNP_CONF.parent.mkdir(parents=True, exist_ok=True)
    text = f"""# Generated by array-firewall — do not edit manually
ext_ifname={ifaces['wan_if']}
listening_ip={gw}
port=1900
enable_natpmp=yes
enable_upnp=yes
secure_mode={secure}
lease_file={UPNP_LEASES}
system_uptime=yes
notify_interval=30
clean_ruleset_interval=600
allow 1024-65535 192.168.167.0/24 1024-65535
"""
    UPNP_CONF.write_text(text, encoding="utf-8")


def sync_services() -> dict[str, Any]:
    cfg = upnp_config()
    result: dict[str, Any] = {"upnp": {"enabled": cfg.get("enabled"), "running": False}}
    if not cfg.get("enabled"):
        subprocess.run(["systemctl", "stop", "miniupnpd"], capture_output=True, timeout=10)
        subprocess.run(["systemctl", "disable", "miniupnpd"], capture_output=True, timeout=10)
        return result
    _write_upnp_conf()
    subprocess.run(["systemctl", "enable", "miniupnpd"], capture_output=True, timeout=10)
    proc = subprocess.run(["systemctl", "restart", "miniupnpd"], capture_output=True, text=True, timeout=20)
    active = subprocess.run(["systemctl", "is-active", "miniupnpd"], capture_output=True, text=True, timeout=5)
    result["upnp"]["running"] = active.stdout.strip() == "active"
    if proc.returncode != 0:
        result["upnp"]["error"] = (proc.stderr or proc.stdout or "").strip()[:500]
    return result


def upnp_leases() -> list[dict[str, Any]]:
    if not UPNP_LEASES.is_file():
        return []
    try:
        data = json.loads(UPNP_LEASES.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return list(data.values())
    return []


def upnp_status() -> dict[str, Any]:
    cfg = upnp_config()
    active = subprocess.run(["systemctl", "is-active", "miniupnpd"], capture_output=True, text=True, timeout=5)
    leases = upnp_leases()
    return {
        "enabled": cfg.get("enabled"),
        "secure_mode": cfg.get("secure_mode"),
        "running": active.stdout.strip() == "active",
        "lease_count": len(leases),
        "leases": leases[:100],
    }


def status() -> dict[str, Any]:
    dmz_cfg = dmz()
    forwards = [f for f in port_forwards() if f.get("enabled")]
    return {
        "dmz": dmz_cfg,
        "port_forwards": port_forwards(),
        "port_forward_count": len(forwards),
        "upnp": upnp_status(),
        "xbox_presets": {"udp": list(XBOX_UDP), "tcp": list(XBOX_TCP)},
    }
