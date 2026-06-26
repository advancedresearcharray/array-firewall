"""LAN zone barrier — isolate wireless (Google router) from array-firewall trusted LAN."""
from __future__ import annotations

import ipaddress
from typing import Any

from . import devices, groups, policies

DEFAULT_CFG: dict[str, Any] = {
    "enabled": True,
    "google_router_ip": "192.168.167.2",
    "wireless": {
        "groups": ["google-mesh", "wireless-infra"],
        "ip_ranges": ["192.168.167.3-192.168.167.50"],
    },
    "trusted": {
        "groups": ["infrastructure", "gaming", "laptops"],
        "ip_ranges": ["192.168.167.51-192.168.167.250"],
    },
    "bridge": {
        "groups": ["bridge", "laptops"],
        "macs": [],
    },
    "allow": {
        "gateway_dns": True,
        "wireless_internet": True,
        "trusted_internet": True,
    },
}


def config() -> dict[str, Any]:
    raw = policies.load().get("zones") or {}
    cfg = json_merge(DEFAULT_CFG, raw)
    # Admin laptop always bridged unless explicitly removed
    admin = devices.admin_mac()
    if admin:
        macs = [m.lower() for m in cfg.get("bridge", {}).get("macs") or []]
        if admin not in macs:
            cfg.setdefault("bridge", {}).setdefault("macs", []).append(admin)
    return cfg


def json_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = json_merge(out[k], v)
        else:
            out[k] = v
    return out


def _device_groups(dev: dict[str, Any], mac: str) -> list[str]:
    try:
        return groups.groups_for_mac(mac) or dev.get("groups") or []
    except Exception:
        return dev.get("groups") or []


def _ip_in_ranges(ip: str, ranges: list[str]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for spec in ranges:
        spec = spec.strip()
        if not spec:
            continue
        if "-" in spec:
            start_s, end_s = spec.split("-", 1)
            try:
                start = ipaddress.ip_address(start_s.strip())
                end = ipaddress.ip_address(end_s.strip())
                if start <= addr <= end:
                    return True
            except ValueError:
                continue
        else:
            try:
                if addr in ipaddress.ip_network(spec, strict=False):
                    return True
            except ValueError:
                continue
    return False


def classify_ip(ip: str, store: dict[str, Any] | None = None) -> str:
    """Return wireless | trusted | bridge | unknown for an IPv4 address."""
    cfg = config()
    if not ip:
        return "unknown"
    data = store or devices.load_store()
    for mac, dev in data.get("devices", {}).items():
        dip = dev.get("ip") or (dev.get("dhcp") or {}).get("ip") or ""
        if dip == ip:
            return classify_device(mac, dev, data)
    if _ip_in_ranges(ip, cfg.get("wireless", {}).get("ip_ranges") or []):
        return "wireless"
    if _ip_in_ranges(ip, cfg.get("trusted", {}).get("ip_ranges") or []):
        return "trusted"
    return "unknown"


def classify_device(mac: str, dev: dict[str, Any] | None = None, store: dict[str, Any] | None = None) -> str:
    cfg = config()
    mac = devices.norm_mac(mac)
    data = store or devices.load_store()
    entry = dev or data.get("devices", {}).get(mac) or {}
    grps = [g.lower() for g in _device_groups(entry, mac)]
    bridge_macs = [devices.norm_mac(m) for m in cfg.get("bridge", {}).get("macs") or []]
    if mac in bridge_macs:
        return "bridge"
    for g in cfg.get("bridge", {}).get("groups") or []:
        if g.lower() in grps:
            return "bridge"
    for g in cfg.get("wireless", {}).get("groups") or []:
        if g.lower() in grps:
            return "wireless"
    try:
        from . import groups as device_groups

        if device_groups.is_google_mesh(mac, entry.get("hostname", ""), entry.get("label", "")):
            return "wireless"
    except Exception:
        pass
    for g in cfg.get("trusted", {}).get("groups") or []:
        if g.lower() in grps:
            return "trusted"
    dhcp = entry.get("dhcp") or {}
    if dhcp.get("allocate") is False:
        return "wireless"
    # Default: array-firewall DHCP at .1 unless explicitly opted out
    if dhcp.get("reserve") or dhcp.get("allocate", True):
        return "trusted"
    ip = entry.get("ip") or (entry.get("dhcp") or {}).get("ip") or ""
    if _ip_in_ranges(ip, cfg.get("trusted", {}).get("ip_ranges") or []):
        return "trusted"
    if _ip_in_ranges(ip, cfg.get("wireless", {}).get("ip_ranges") or []):
        return "wireless"
    return "unknown"


def ip_sets() -> dict[str, list[str]]:
    """Build nft interval set elements for each zone."""
    cfg = config()
    data = devices.load_store()
    wireless_ranges = cfg.get("wireless", {}).get("ip_ranges") or []
    trusted_ranges = cfg.get("trusted", {}).get("ip_ranges") or []
    out: dict[str, set[str]] = {"wireless": set(), "trusted": set(), "bridge": set()}

    for spec in wireless_ranges:
        out["wireless"].add(spec.strip())
    for spec in trusted_ranges:
        out["trusted"].add(spec.strip())

    for mac, dev in data.get("devices", {}).items():
        ip = dev.get("ip") or (dev.get("dhcp") or {}).get("ip") or ""
        if not ip:
            continue
        zone = classify_device(mac, dev, data)
        if zone == "bridge":
            out["bridge"].add(ip)
        elif zone == "wireless" and not _ip_in_ranges(ip, wireless_ranges):
            # Wrong-range wireless lease (e.g. .171 from old AF DHCP)
            out["wireless"].add(ip)
        elif zone == "trusted" and not _ip_in_ranges(ip, trusted_ranges):
            out["trusted"].add(ip)

    return {k: sorted(v) for k, v in out.items()}


def nft_set_block(name: str, elements: list[str]) -> str:
    if not elements:
        return ""
    # nft interval sets: mix singles and ranges
    formatted = ", ".join(elements)
    return f"""
  set {name} {{
    type ipv4_addr
    flags interval
    elements = {{ {formatted} }}
  }}"""


def render_forward_zones(lan_if: str, gw_ip: str) -> tuple[str, str]:
    """Return (set definitions, forward hook rule) for zone barrier."""
    cfg = config()
    if not cfg.get("enabled", True):
        return "", f'    iifname "{lan_if}" oifname "{lan_if}" drop\n'

    sets = ip_sets()
    blocks = "".join(nft_set_block(f"zone_{k}", v) for k, v in sets.items() if v)
    google = cfg.get("google_router_ip") or "192.168.167.2"

    chain = f"""
  chain lan_lateral {{
    ip saddr @zone_wireless ip daddr @zone_wireless accept
    ip saddr @zone_trusted ip daddr @zone_trusted accept
    ip saddr @zone_bridge accept
    ip daddr @zone_bridge accept
    ip daddr {gw_ip} accept
    ip daddr {google} accept
    ip saddr {gw_ip} accept
    ip saddr {google} accept
    ip saddr @zone_wireless ip daddr @zone_trusted drop comment "zone-barrier"
    ip saddr @zone_trusted ip daddr @zone_wireless drop comment "zone-barrier"
    drop
  }}"""
    hook = f'    iifname "{lan_if}" oifname "{lan_if}" jump lan_lateral\n'
    return blocks + chain, hook


def render_forward_hook(lan_if: str, gw_ip: str) -> str:
    _, hook = render_forward_zones(lan_if, gw_ip)
    return hook


def status() -> dict[str, Any]:
    cfg = config()
    data = devices.load_store()
    by_zone: dict[str, list[dict[str, Any]]] = {"wireless": [], "trusted": [], "bridge": [], "unknown": []}
    for mac, dev in sorted(data.get("devices", {}).items()):
        ip = dev.get("ip") or (dev.get("dhcp") or {}).get("ip") or ""
        zone = classify_device(mac, dev, data)
        by_zone.setdefault(zone, []).append(
            {
                "mac": mac,
                "ip": ip,
                "label": dev.get("label") or mac,
                "groups": dev.get("groups") or [],
            }
        )
    return {
        "enabled": bool(cfg.get("enabled", True)),
        "google_router_ip": cfg.get("google_router_ip"),
        "config": cfg,
        "ip_sets": ip_sets(),
        "devices_by_zone": by_zone,
        "barrier": "wireless ↔ trusted blocked; bridge hosts may cross",
    }
