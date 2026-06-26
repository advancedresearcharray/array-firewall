from __future__ import annotations

import re
import time
from typing import Any

from . import devices, dhcp, nft, policies

GROUP_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")

DEFAULT_CONFIG: dict[str, Any] = {
    "internet": "allowed",
    "qos_profile": "balanced",
    "dns_filter": "off",
    "packet_shield": "off",
    "dhcp_allocate": True,
}

# Nest / Google Mesh — lease from Google router, not array-firewall DHCP
GOOGLE_MESH_OUIS = (
    "18:b4:30",
    "20:6d:31",
    "64:16:66",
    "54:60:09",
    "f4:f5:d8",
    "94:eb:2c",
)


def is_google_mesh(mac: str, hostname: str = "", label: str = "") -> bool:
    mac = mac.lower()
    text = f"{hostname} {label}".lower()
    if any(mac.startswith(o) for o in GOOGLE_MESH_OUIS):
        return True
    return any(k in text for k in ("nest", "google", "mesh", "wifi point", "google-nest"))


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _validate_id(group_id: str) -> str:
    gid = (group_id or "").strip().lower()
    if not GROUP_ID_RE.match(gid):
        raise ValueError("group id must be lowercase slug (a-z, 0-9, _, -)")
    return gid


def _groups(data: dict[str, Any] | None = None) -> dict[str, Any]:
    pol = data if data is not None else policies.load()
    return pol.setdefault("device_groups", {})


def list_groups() -> list[dict[str, Any]]:
    data = policies.load()
    groups = _groups(data)
    out: list[dict[str, Any]] = []
    for gid, grp in sorted(groups.items()):
        members = [devices.norm_mac(m) for m in grp.get("members", [])]
        out.append(
            {
                "id": gid,
                "name": grp.get("name", gid),
                "description": grp.get("description", ""),
                "members": members,
                "member_count": len(members),
                "config": {**DEFAULT_CONFIG, **(grp.get("config") or {})},
                "updated": grp.get("updated", ""),
            }
        )
    return out


def _policy_summary(cfg: dict[str, Any]) -> dict[str, Any]:
    qos = str(cfg.get("qos_profile", "balanced")).lower()
    qos_tier = "high" if qos in {"high", "gaming"} else ("low" if qos == "low" else "medium")
    qos_labels = {
        "high": "High priority — dedicated 500 Mbps up/down",
        "medium": "Medium priority — standard household traffic",
        "low": "Low priority — infrastructure / servers",
    }
    internet = str(cfg.get("internet", "allowed")).lower()
    shield = str(cfg.get("packet_shield", "off")).lower()
    dns = str(cfg.get("dns_filter", "off")).lower()
    dhcp = cfg.get("dhcp_allocate", True)
    return {
        "internet": {
            "value": internet,
            "label": "Allowed" if internet in {"allowed", "allow", "true", "1"} else "Quarantined",
            "detail": "Members can reach WAN when approved" if internet in {"allowed", "allow", "true", "1"} else "Members held in quarantine with no internet",
        },
        "qos": {
            "value": qos,
            "tier": qos_tier,
            "label": qos.replace("_", " ").title(),
            "detail": qos_labels[qos_tier],
        },
        "dns_filter": {
            "value": dns,
            "label": "Off" if dns == "off" else dns.title(),
            "detail": "No DNS filtering" if dns == "off" else f"DNS filter: {dns}",
        },
        "packet_shield": {
            "value": shield,
            "label": "Off" if shield == "off" else shield.title(),
            "detail": "No packet shield" if shield == "off" else f"Packet shield: {shield} (in-match gaming defenses)",
        },
        "dhcp_allocate": {
            "value": bool(dhcp),
            "label": "Allowed" if dhcp else "Blocked",
            "detail": "Can lease from array-firewall DHCP" if dhcp else "Ignored by array-firewall DHCP — use another router",
        },
    }


def _member_detail(mac: str, device_map: dict[str, Any], gid: str) -> dict[str, Any]:
    dev = dict(device_map.get(mac, {"mac": mac, "label": mac, "ip": ""}))
    store = devices.load_store()
    entry = store.get("devices", {}).get(mac, {})
    policy = entry.get("policy") or {}
    dev["policy"] = policy
    dev["policy_from_group"] = policy.get("source_group") == gid
    try:
        from . import qos as qos_mod

        xbox_ip = qos_mod.config().get("xbox_ip", "")
        tier = qos_mod.classify_device({**dev, **entry, "groups": dev.get("groups") or [gid]}, xbox_ip)
        dev["qos_tier"] = tier
    except Exception:
        dev["qos_tier"] = policy.get("qos_profile", "unknown")
    return dev


def get_group(group_id: str) -> dict[str, Any]:
    gid = _validate_id(group_id)
    groups = _groups()
    if gid not in groups:
        raise ValueError(f"group not found: {gid}")
    grp = groups[gid]
    members = [devices.norm_mac(m) for m in grp.get("members", [])]
    cfg = {**DEFAULT_CONFIG, **(grp.get("config") or {})}
    device_map = {d["mac"]: d for d in devices.list_devices()}
    member_details = [_member_detail(mac, device_map, gid) for mac in members]
    return {
        "id": gid,
        "name": grp.get("name", gid),
        "description": grp.get("description", ""),
        "members": members,
        "member_count": len(members),
        "member_details": member_details,
        "config": cfg,
        "policy_summary": _policy_summary(cfg),
        "updated": grp.get("updated", ""),
    }


def create_group(
    group_id: str,
    name: str,
    *,
    description: str = "",
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gid = _validate_id(group_id)
    data = policies.load()
    groups = _groups(data)
    if gid in groups:
        raise ValueError(f"group already exists: {gid}")
    groups[gid] = {
        "name": (name or gid).strip(),
        "description": (description or "").strip(),
        "members": [],
        "config": {**DEFAULT_CONFIG, **(config or {})},
        "updated": _now(),
    }
    policies.save(data)
    return get_group(gid)


def update_group(group_id: str, updates: dict[str, Any]) -> dict[str, Any]:
    gid = _validate_id(group_id)
    data = policies.load()
    groups = _groups(data)
    if gid not in groups:
        raise ValueError(f"group not found: {gid}")
    grp = groups[gid]
    if "name" in updates and updates["name"]:
        grp["name"] = str(updates["name"]).strip()
    if "description" in updates:
        grp["description"] = str(updates["description"]).strip()
    if "config" in updates and isinstance(updates["config"], dict):
        cfg = grp.setdefault("config", {})
        for key in ("internet", "qos_profile", "dns_filter", "packet_shield", "dhcp_allocate"):
            if key in updates["config"]:
                cfg[key] = updates["config"][key]
    grp["updated"] = _now()
    policies.save(data)
    return get_group(gid)


def delete_group(group_id: str) -> dict[str, Any]:
    gid = _validate_id(group_id)
    data = policies.load()
    groups = _groups(data)
    if gid not in groups:
        raise ValueError(f"group not found: {gid}")
    removed = groups.pop(gid)
    _clear_group_from_devices(gid)
    policies.save(data)
    return {"ok": True, "deleted": gid, "name": removed.get("name", gid)}


def add_member(group_id: str, mac: str, *, apply: bool = True) -> dict[str, Any]:
    gid = _validate_id(group_id)
    mac = devices.norm_mac(mac)
    data = policies.load()
    groups = _groups(data)
    if gid not in groups:
        raise ValueError(f"group not found: {gid}")
    members = groups[gid].setdefault("members", [])
    if mac not in members:
        members.append(mac)
    groups[gid]["updated"] = _now()
    policies.save(data)
    _tag_device_group(mac, gid, add=True)
    result = get_group(gid)
    if apply:
        result["apply"] = apply_group_config(gid)
    return result


def remove_member(group_id: str, mac: str) -> dict[str, Any]:
    gid = _validate_id(group_id)
    mac = devices.norm_mac(mac)
    data = policies.load()
    groups = _groups(data)
    if gid not in groups:
        raise ValueError(f"group not found: {gid}")
    members = groups[gid].setdefault("members", [])
    groups[gid]["members"] = [m for m in members if devices.norm_mac(m) != mac]
    groups[gid]["updated"] = _now()
    policies.save(data)
    _tag_device_group(mac, gid, add=False)
    return get_group(gid)


def _tag_device_group(mac: str, group_id: str, *, add: bool) -> None:
    store = devices.load_store()
    devs = store.setdefault("devices", {})
    entry = devs.setdefault(mac, {"mac": mac, "label": mac})
    groups = entry.setdefault("groups", [])
    if add and group_id not in groups:
        groups.append(group_id)
    elif not add:
        entry["groups"] = [g for g in groups if g != group_id]
    devs[mac] = entry
    devices.save_store(store)


def _clear_group_from_devices(group_id: str) -> None:
    store = devices.load_store()
    for mac, entry in store.get("devices", {}).items():
        if group_id in entry.get("groups", []):
            entry["groups"] = [g for g in entry["groups"] if g != group_id]
            entry["mac"] = mac
    devices.save_store(store)


def groups_for_mac(mac: str) -> list[str]:
    mac = devices.norm_mac(mac)
    data = policies.load()
    found: list[str] = []
    for gid, grp in _groups(data).items():
        if mac in [devices.norm_mac(m) for m in grp.get("members", [])]:
            found.append(gid)
    return sorted(found)


def apply_group_config(group_id: str) -> dict[str, Any]:
    grp = get_group(group_id)
    cfg = grp["config"]
    applied: list[dict[str, Any]] = []
    errors: list[str] = []

    for mac in grp["members"]:
        try:
            item = _apply_config_to_device(mac, cfg, group_id=grp["id"])
            applied.append(item)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{mac}: {exc}")

    shield = str(cfg.get("packet_shield", "off")).lower()
    shield_result = None
    if shield in {"normal", "strict", "shield"}:
        try:
            from . import gaming as gaming_mod

            level = "strict" if shield == "strict" else "normal"
            shield_result = gaming_mod.apply_packet_shield(level)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"packet_shield: {exc}")

    nft.apply_ruleset()
    return {
        "ok": not errors,
        "group": grp["id"],
        "applied": len(applied),
        "devices": applied,
        "errors": errors,
        "packet_shield": shield_result,
    }


def apply_all_groups() -> dict[str, Any]:
    results = []
    for grp in list_groups():
        results.append(apply_group_config(grp["id"]))
    return {"ok": True, "results": results}


def _apply_config_to_device(mac: str, cfg: dict[str, Any], *, group_id: str) -> dict[str, Any]:
    mac = devices.norm_mac(mac)
    internet = cfg.get("internet", "allowed")
    allowed = internet in {"allowed", "allow", True, "true", 1}
    dev = devices.set_allowed(mac, allowed)

    store = devices.load_store()
    entry = store.setdefault("devices", {}).setdefault(mac, {"mac": mac})
    entry["policy"] = {
        "qos_profile": cfg.get("qos_profile", "balanced"),
        "dns_filter": cfg.get("dns_filter", "off"),
        "packet_shield": cfg.get("packet_shield", "off"),
        "source_group": group_id,
        "applied_at": _now(),
    }
    groups = entry.setdefault("groups", [])
    if group_id not in groups:
        groups.append(group_id)
    store["devices"][mac] = entry
    devices.save_store(store)

    if cfg.get("dhcp_reservation"):
        res = cfg["dhcp_reservation"]
        if isinstance(res, dict) and res.get("ip"):
            dhcp.add_reservation(mac, res["ip"], res.get("hostname") or dev.get("label"))

    dhcp_allocate = cfg.get("dhcp_allocate", True)
    kw: dict[str, Any] = {"allocate": bool(dhcp_allocate)}
    if not dhcp_allocate:
        kw["reserve"] = False
    devices.set_dhcp(mac, **kw)

    try:
        from . import qos as qos_mod

        qos_mod.apply()
    except Exception:
        pass

    return {
        "mac": mac,
        "allowed": allowed,
        "label": dev.get("label"),
        "policy": entry["policy"],
        "dhcp_allocate": dhcp_allocate,
    }
