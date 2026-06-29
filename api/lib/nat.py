"""Inbound NAT: port forwarding, DMZ host, UPnP (miniupnpd)."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from . import nft, policies

UPNP_CONF = Path("/etc/miniupnpd/miniupnpd.conf")
UPNP_LEASES = Path("/var/lib/array-firewall/upnp.leases")
XBOX_UDP = (88, 500, 3074, 3075, 3544, 4500, 53, 9002)
XBOX_TCP = (3074, 80, 53, 443, 2869)
_PROTO_RE = re.compile(r"^(tcp|udp|both)$", re.I)
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_PUBLIC_IP_CACHE = Path("/var/lib/array-firewall/public-wan-ip.txt")


def _detect_public_ip(bind_ip: str = "") -> str:
    """Best-effort public IPv4 via STUN; cached for 10 minutes."""
    now = time.time()
    try:
        if _PUBLIC_IP_CACHE.is_file():
            age, ip = _PUBLIC_IP_CACHE.read_text(encoding="utf-8").strip().split(",", 1)
            if now - float(age) < 600 and _IP_RE.match(ip):
                return ip
    except Exception:
        pass
    try:
        import random
        import socket
        import struct

        tid = random.randbytes(12)
        req = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + tid
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if bind_ip and _IP_RE.match(bind_ip):
            s.bind((bind_ip, 0))
        s.settimeout(4)
        s.sendto(req, ("stun.l.google.com", 19302))
        data, _ = s.recvfrom(2048)
        s.close()
        off = 20
        while off + 4 <= len(data):
            attr_type, attr_len = struct.unpack("!HH", data[off : off + 4])
            off += 4
            val = data[off : off + attr_len]
            off += (attr_len + 3) & ~3
            if attr_type == 0x0020 and attr_len >= 8:
                ip = ".".join(str(b ^ 0x21) for b in val[4:8])
                if _IP_RE.match(ip):
                    _PUBLIC_IP_CACHE.parent.mkdir(parents=True, exist_ok=True)
                    _PUBLIC_IP_CACHE.write_text(f"{now},{ip}", encoding="utf-8")
                    return ip
    except Exception:
        pass
    return ""


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
        "secure_mode": bool(raw.get("secure_mode", True)),
        "xbox_only": bool(raw.get("xbox_only", False)),
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


def set_upnp(
    *,
    enabled: bool | None = None,
    secure_mode: bool | None = None,
    xbox_only: bool | None = None,
) -> dict[str, Any]:
    cfg = upnp_config()
    if enabled is not None:
        cfg["enabled"] = bool(enabled)
    if secure_mode is not None:
        cfg["secure_mode"] = bool(secure_mode)
    if xbox_only is not None:
        cfg["xbox_only"] = bool(xbox_only)
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


def enable_xbox_open_nat() -> dict[str, Any]:
    """Xbox NAT: static forwards + UPnP, default-deny WAN, outbound SNAT."""
    data = _load()
    gaming = data.setdefault("gaming", {})
    gaming["nat_open"] = False
    gaming["inbound_nat"] = True
    net = data.setdefault("network", {})
    net["unsolicited_wan"] = "deny"
    _save(data)
    preset = xbox_preset_forwards()
    upnp = enable_xbox_secure_upnp()
    nft.apply_ruleset()
    shield = Path("/opt/array-firewall/scripts/packet-shield-nft.sh")
    if shield.is_file():
        subprocess.run([str(shield), "shield", "normal"], check=False, timeout=30)
    return {
        "ok": True,
        "nat_open": False,
        "unsolicited_wan": "deny",
        "presets": preset,
        "upnp": upnp,
        **status(),
    }


def enable_xbox_secure_upnp() -> dict[str, Any]:
    """Enable UPnP restricted to Xbox IP with secure_mode."""
    gaming = _gaming()
    ip = str(gaming.get("xbox_ip") or _conf().get("XBOX_IP") or "").strip()
    if not _IP_RE.match(ip):
        raise ValueError("xbox_ip not configured")
    data = _load()
    data["upnp"] = {
        "enabled": True,
        "secure_mode": True,
        "xbox_only": True,
        "lease_seconds": int((data.get("upnp") or {}).get("lease_seconds") or 3600),
        "allow_lan": True,
    }
    _save(data)
    sync_services()
    return {"ok": True, "upnp": upnp_config(), "xbox_ip": ip, **upnp_status()}


def enable_xbox_dmz() -> dict[str, Any]:
    gaming = _gaming()
    return set_dmz(
        enabled=True,
        host_ip=str(gaming.get("xbox_ip") or _conf().get("XBOX_IP") or ""),
        host_mac=str(gaming.get("xbox_mac") or ""),
        name="xbox",
    )


def enable_xbox_wan_dmz() -> dict[str, Any]:
    """Put Xbox in array-firewall WAN DMZ (eth1 -> 192.168.5.11) with outbound SNAT."""
    result = enable_xbox_dmz()
    data = _load()
    gaming = data.setdefault("gaming", {})
    gaming["inbound_nat"] = True
    gaming["nat_open"] = False
    _save(data)
    upnp = enable_xbox_secure_upnp()
    nft.apply_ruleset()
    try:
        from . import gaming as gaming_mod

        gaming_stack = gaming_mod.apply_xbox_secure_stack(shield_level="console", buffer_profile="desync")
    except Exception as exc:
        gaming_stack = {"ok": False, "error": str(exc)}
    return {"ok": True, "dmz": result.get("dmz"), "upnp": upnp, "gaming": gaming_stack, **status()}


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
    pol = policies.network()
    role = ifaces.get("role") or policies.role()
    lan_if = ifaces["lan_if"]
    wan_if = ifaces["wan_if"]
    gw_ip = ifaces.get("gw_ip") or pol.get("gateway_ip") or c.get("LAN_GATEWAY_IP", "")
    secure = "yes" if cfg.get("secure_mode") else "no"
    gaming = _gaming()
    xbox_ip = str(gaming.get("xbox_ip") or c.get("XBOX_IP") or "").strip()
    allow_line = "allow 1024-65535 192.168.167.0/24 1024-65535"
    if cfg.get("xbox_only") and _IP_RE.match(xbox_ip):
        allow_line = f"allow 0-65535 {xbox_ip}/32 0-65535"
    elif cfg.get("secure_mode") and _IP_RE.match(xbox_ip):
        allow_line = f"allow 0-65535 {xbox_ip}/32 0-65535"
    if role == "xbox_router" and _IP_RE.match(gw_ip):
        listening_ip = gw_ip
    else:
        listening_ip = lan_if
    UPNP_CONF.parent.mkdir(parents=True, exist_ok=True)
    text = f"""# Generated by array-firewall — do not edit manually
ext_ifname={ifaces['wan_if']}
listening_ip={listening_ip}
port=1900
enable_natpmp=yes
enable_upnp=yes
secure_mode={secure}
lease_file={UPNP_LEASES}
system_uptime=yes
notify_interval=30
clean_ruleset_interval=600
{allow_line}
"""
    UPNP_CONF.write_text(text, encoding="utf-8")


_ensure_wan_nat_active = False


def _wan_nat_ok() -> bool:
    """Return True when Xbox WAN SNAT and DMZ prerouting chains are present."""
    role = policies.role()
    if role != "xbox_router" and not policies.xbox_inbound_nat_enabled():
        return True
    proc = subprocess.run(
        ["nft", "list", "chain", "ip", "nat", "postrouting"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if proc.returncode != 0:
        return False
    post = proc.stdout
    gaming = _gaming()
    xbox_ip = str(gaming.get("xbox_ip") or _conf().get("XBOX_IP") or "").strip()
    if xbox_ip and xbox_ip not in post:
        return False
    if "snat" not in post and "masquerade" not in post:
        return False
    dmz_cfg = dmz()
    if not dmz_cfg.get("enabled"):
        return True
    host = str(dmz_cfg.get("host_ip") or "").strip()
    if not _IP_RE.match(host):
        return True
    proc = subprocess.run(
        ["nft", "list", "chain", "ip", "nat", "prerouting"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return proc.returncode == 0 and host in proc.stdout


def _apply_wan_nat_rules_unlocked() -> dict[str, Any]:
    """Caller must hold nft.ruleset_lock."""
    fragment = nft.render_wan_nat_fragment()
    if not fragment.strip():
        return {"ok": False, "error": "wan nat not configured"}
    path = Path("/var/lib/array-firewall/wan-nat.nft")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"wan-nat.{os.getpid()}.tmp")
    tmp.write_text(fragment, encoding="utf-8")
    proc = nft.apply_nft_file_unlocked(tmp, timeout=10)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "wan nat apply failed").strip()
        tmp.unlink(missing_ok=True)
        return {"ok": False, "error": err[-500:]}
    tmp.replace(path)
    return {"ok": True, "path": str(path)}


def apply_wan_nat_rules() -> dict[str, Any]:
    """Restore SNAT/DMZ chains only — avoids full ruleset flush (safe during shield/QoS)."""
    with nft.ruleset_lock():
        return _apply_wan_nat_rules_unlocked()


def ensure_wan_nat() -> dict[str, Any]:
    """Restore WAN NAT if postrouting/DMZ chains were stripped (leaves only probe_blackhole)."""
    global _ensure_wan_nat_active
    with nft.ruleset_lock():
        if _ensure_wan_nat_active:
            return {"ok": True, "skipped": "in_progress"}
        if _wan_nat_ok():
            return {"ok": True, "already_ok": True}
        _ensure_wan_nat_active = True
        try:
            light = _apply_wan_nat_rules_unlocked()
            if light.get("ok") and _wan_nat_ok():
                return {"ok": True, "restored": True, "method": "wan_nat_only", "wan_nat_ok": True}
            if nft.ruleset_apply_depth() > 0:
                return {
                    "ok": False,
                    "restored": False,
                    "method": "wan_nat_only",
                    "error": light.get("error") or "wan nat incomplete during ruleset apply",
                }
            nft.apply_ruleset()
            ok = _wan_nat_ok()
            return {"ok": ok, "restored": ok, "method": "full_ruleset", "wan_nat_ok": ok}
        finally:
            _ensure_wan_nat_active = False


def sync_services() -> dict[str, Any]:
    ensure_wan_nat()
    cfg = upnp_config()
    result: dict[str, Any] = {"upnp": {"enabled": cfg.get("enabled"), "running": False}}
    if not policies.nat_enabled() and not policies.xbox_inbound_nat_enabled():
        subprocess.run(["systemctl", "stop", "miniupnpd"], capture_output=True, timeout=10)
        subprocess.run(["systemctl", "disable", "miniupnpd"], capture_output=True, timeout=10)
        result["upnp"]["enabled"] = False
        result["upnp"]["skipped"] = "nat_disabled"
        return result
    if not cfg.get("enabled"):
        subprocess.run(["systemctl", "stop", "miniupnpd"], capture_output=True, timeout=10)
        subprocess.run(["systemctl", "disable", "miniupnpd"], capture_output=True, timeout=10)
        return result
    UPNP_LEASES.parent.mkdir(parents=True, exist_ok=True)
    if not UPNP_LEASES.is_file():
        UPNP_LEASES.write_text("", encoding="utf-8")
    _write_upnp_conf()
    ifaces = _ifaces()
    c = _conf()
    wan_ip = nft._iface_ipv4(ifaces["wan_if"]) or c.get("WAN_IP", "")
    public_ip = c.get("WAN_PUBLIC_IP", "") or _detect_public_ip(wan_ip) or wan_ip
    env_path = Path("/etc/default/miniupnpd")
    if _IP_RE.match(public_ip):
        env_path.write_text(f'MiniUPnPd_OTHER_OPTIONS="-o {public_ip}"\n', encoding="utf-8")
    else:
        env_path.write_text('MiniUPnPd_OTHER_OPTIONS=""\n', encoding="utf-8")
    result["upnp"]["public_ip"] = public_ip if _IP_RE.match(public_ip) else None
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
    raw = UPNP_LEASES.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []
    if raw.startswith("{") or raw.startswith("["):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return list(data.values())
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            rows.append(
                {
                    "ext_port": parts[0],
                    "proto": parts[1],
                    "int_port": parts[2],
                    "int_client": parts[3],
                    "desc": parts[4] if len(parts) > 4 else "",
                }
            )
    return rows


def upnp_status() -> dict[str, Any]:
    cfg = upnp_config()
    active = subprocess.run(["systemctl", "is-active", "miniupnpd"], capture_output=True, text=True, timeout=5)
    leases = upnp_leases()
    return {
        "enabled": cfg.get("enabled"),
        "secure_mode": cfg.get("secure_mode"),
        "xbox_only": cfg.get("xbox_only"),
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
