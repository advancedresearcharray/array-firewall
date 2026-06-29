from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

POLICIES_PATH = Path(os.environ.get("ARRAY_FW_POLICIES", "/var/lib/array-firewall/policies.json"))


def load() -> dict[str, Any]:
    if POLICIES_PATH.is_file():
        return json.loads(POLICIES_PATH.read_text(encoding="utf-8"))
    return {}


def save(data: dict[str, Any]) -> None:
    POLICIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = POLICIES_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(POLICIES_PATH)


def network() -> dict[str, Any]:
    return load().get("network", {})


def role() -> str:
    n = network()
    if n.get("role"):
        return str(n["role"])
    conf = Path("/etc/array-firewall/array-firewall.conf")
    if conf.is_file():
        for line in conf.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("ROLE="):
                val = line.split("=", 1)[1].strip()
                if val:
                    return val
    return os.environ.get("ARRAY_FW_ROLE", "lab")


def cutover_enabled() -> bool:
    n = network()
    if "cutover" in n:
        return bool(n.get("cutover"))
    conf = Path("/etc/array-firewall/array-firewall.conf")
    if conf.is_file():
        for line in conf.read_text(encoding="utf-8").splitlines():
            if line.startswith("CUTOVER="):
                return line.split("=", 1)[1].strip() in {"1", "true", "yes"}
    return False


def nat_enabled() -> bool:
    n = network()
    if role() == "xbox_router":
        return False
    if "nat" in n:
        return bool(n.get("nat"))
    return True


def xbox_inbound_nat_enabled() -> bool:
    """Allow Xbox port forwards / UPnP on the WAN side without house NAT."""
    if role() != "xbox_router":
        return nat_enabled()
    g = gaming()
    upnp = load().get("upnp") or {}
    if g.get("nat_open") or upnp.get("enabled"):
        return True
    if load().get("port_forwards") or (load().get("dmz") or {}).get("enabled"):
        return True
    return bool(g.get("inbound_nat", True))


def xbox_nat_open() -> bool:
    g = gaming()
    if "nat_open" in g:
        return bool(g.get("nat_open"))
    conf = Path("/etc/array-firewall/array-firewall.conf")
    if conf.is_file():
        for line in conf.read_text(encoding="utf-8").splitlines():
            if line.startswith("XBOX_NAT_OPEN="):
                return line.split("=", 1)[1].strip().lower() in {"1", "true", "yes", "on"}
    return False


def gateway_topology() -> bool:
    """Use gateway interface layout (LAN + WAN), not lab bench."""
    r = role()
    if r == "xbox_router":
        return True
    if r == "gateway" and (cutover_enabled() or network().get("wan_mode") == "upstream"):
        return True
    return False


def gaming() -> dict[str, Any]:
    return load().get("gaming", {})


def xbox_wan_dmz_enabled() -> bool:
    """True when Xbox is in array-firewall WAN DMZ (Open NAT path)."""
    if role() != "xbox_router":
        return False
    dmz = load().get("dmz") or {}
    xbox_ip = str(gaming().get("xbox_ip") or "").strip()
    return bool(dmz.get("enabled") and str(dmz.get("host_ip") or "") == xbox_ip)


def sentinel_tiny_only() -> bool:
    """Sentinel may only drop tiny duplicate probes — never block gameplay paths."""
    mit = gaming().get("mitigation") or {}
    explicit = mit.get("tiny_packet_only")
    if explicit is False:
        return False
    if explicit is True:
        return True
    # Default on Xbox WAN DMZ — Open NAT + dedicated servers must stay reachable.
    return xbox_wan_dmz_enabled()


def effective_shield_level(level: str) -> str:
    """Map shield levels that would block legitimate Warzone / Xbox Live traffic."""
    level = (level or "normal").lower()
    if sentinel_tiny_only():
        return "normal"
    if level == "in-match" and xbox_wan_dmz_enabled():
        return "matchmaking"
    return level


def nat_config() -> dict[str, Any]:
    data = load()
    return {
        "port_forwards": data.get("port_forwards") or [],
        "dmz": data.get("dmz") or {},
        "upnp": data.get("upnp") or {},
    }
