"""IDS enforcement: block/quarantine actions backed by nft sets and device quarantine."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import devices, policies

ENFORCE_FILE = Path("/var/lib/array-firewall/ids-enforcement.json")
VALID_MODES = ("log_only", "alert", "block", "quarantine")
HIGH_SIGNALS = frozenset(
    {
        "port_scan",
        "connection_spike",
        "remote_admin_port",
        "ai_elevated_risk",
        "information_flow_spike",
        "superlinear_information_flow",
        "sustained_high_flow",
    }
)


def _cfg() -> dict[str, Any]:
    base = {
        "mode": "log_only",
        "block_ttl_sec": 3600,
        "quarantine_on_high": True,
        "auto_reload": True,
    }
    base.update(policies.load().get("ids") or {})
    return base


def _now() -> float:
    return time.time()


def _load() -> dict[str, Any]:
    if not ENFORCE_FILE.is_file():
        return {"blocked_ips": {}, "quarantined_by_ids": []}
    try:
        return json.loads(ENFORCE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"blocked_ips": {}, "quarantined_by_ids": []}


def _save(state: dict[str, Any]) -> None:
    ENFORCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = ENFORCE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    tmp.replace(ENFORCE_FILE)


def _mac_for_ip(ip: str) -> str:
    if not ip:
        return ""
    for dev in devices.list_devices():
        if str(dev.get("ip") or "") == ip:
            return devices.norm_mac(str(dev.get("mac") or ""))
    return ""


def prune() -> dict[str, Any]:
    state = _load()
    now = _now()
    blocked: dict[str, float] = {}
    for ip, exp in (state.get("blocked_ips") or {}).items():
        try:
            if float(exp) > now:
                blocked[ip] = float(exp)
        except (TypeError, ValueError):
            continue
    state["blocked_ips"] = blocked
    _save(state)
    return state


def blocked_ips() -> list[str]:
    state = prune()
    return sorted(state.get("blocked_ips") or {})


def set_mode(mode: str) -> dict[str, Any]:
    mode = str(mode or "log_only").lower()
    if mode not in VALID_MODES:
        raise ValueError(f"mode must be one of: {', '.join(VALID_MODES)}")
    data = policies.load()
    ids_cfg = dict(data.get("ids") or {})
    ids_cfg["mode"] = mode
    data["ids"] = ids_cfg
    policies.save(data)
    if mode in {"block", "quarantine"}:
        from . import nft

        nft.apply_ruleset()
    return {"ok": True, "mode": mode}


def clear_blocks() -> dict[str, Any]:
    state = _load()
    state["blocked_ips"] = {}
    _save(state)
    from . import nft

    nft.apply_ruleset()
    return {"ok": True, "cleared": True}


def unblock_ip(ip: str) -> dict[str, Any]:
    state = _load()
    blocked = dict(state.get("blocked_ips") or {})
    removed = blocked.pop(ip.strip(), None) is not None
    state["blocked_ips"] = blocked
    _save(state)
    if removed:
        from . import nft

        nft.apply_ruleset()
    return {"ok": True, "removed": removed, "ip": ip}


def block_wan_ips(ips: list[str], *, ttl_sec: int = 3600, source: str = "manual") -> dict[str, Any]:
    """Block inbound WAN peer IPs at forward chain (kick tools / VPS floods)."""
    ttl = max(60, int(ttl_sec))
    state = prune()
    blocked = dict(state.get("blocked_ips") or {})
    expires = _now() + ttl
    added = 0
    for raw in ips:
        ip = str(raw).strip()
        if not ip or ip.startswith(("192.168.", "10.", "127.")):
            continue
        blocked[ip] = expires
        added += 1
    state["blocked_ips"] = blocked
    state["last_wan_block_source"] = source
    state["last_wan_block_ts"] = _now()
    _save(state)
    if added:
        from . import nft

        nft.apply_ruleset()
    try:
        from . import abuse_report as abuse_mod

        for raw in ips:
            ip = str(raw).strip()
            if ip and not ip.startswith(("192.168.", "10.", "127.")):
                abuse_mod.record_incident(ip, reason=f"ids_block:{source}", meta={"ttl_sec": ttl})
    except ImportError:
        pass
    return {"ok": True, "blocked": added, "total": len(blocked_ips()), "source": source}


def apply_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply enforcement for new high-severity events. Returns action summary."""
    cfg = _cfg()
    mode = str(cfg.get("mode") or "log_only")
    if mode == "log_only":
        return {"mode": mode, "actions": 0}

    ttl = max(60, int(cfg.get("block_ttl_sec") or 3600))
    state = prune()
    blocked = dict(state.get("blocked_ips") or {})
    quarantined: list[str] = list(state.get("quarantined_by_ids") or [])
    actions = 0
    expires = _now() + ttl

    for ev in events:
        sev = str(ev.get("severity") or "")
        signal = str(ev.get("signal") or "")
        if sev not in {"high", "critical"} and signal not in HIGH_SIGNALS:
            continue
        ip = str(ev.get("device_ip") or "").strip()
        if not ip:
            continue

        if mode == "alert":
            ev["action"] = "alert"
            actions += 1
            continue

        if mode == "block":
            blocked[ip] = expires
            ev["action"] = "blocked"
            actions += 1
            continue

        if mode == "quarantine":
            mac = _mac_for_ip(ip)
            if mac:
                devices.set_allowed(mac, False)
                if mac not in quarantined:
                    quarantined.append(mac)
                ev["action"] = "quarantined"
                actions += 1
            else:
                blocked[ip] = expires
                ev["action"] = "blocked"
                actions += 1

    state["blocked_ips"] = blocked
    state["quarantined_by_ids"] = quarantined
    state["last_enforce_ts"] = _now()
    _save(state)

    if actions and cfg.get("auto_reload", True) and mode in {"block", "quarantine"}:
        from . import nft

        nft.apply_ruleset()

    return {
        "mode": mode,
        "actions": actions,
        "blocked_ips": blocked_ips(),
        "quarantined_macs": quarantined,
    }


def render_nft() -> tuple[str, str]:
    """Return (set definition, forward drop rule)."""
    state = prune()
    blocked = state.get("blocked_ips") or {}
    if not blocked:
        return "", ""
    now = _now()
    elements: list[str] = []
    for ip, exp in blocked.items():
        try:
            remaining = max(60, int(float(exp) - now))
        except (TypeError, ValueError):
            remaining = 3600
        elements.append(f"{ip} timeout {remaining}s")
    set_def = f"""
  set ids_blocked_ips {{
    type ipv4_addr
    flags timeout
    elements = {{ {", ".join(elements)} }}
  }}"""
    rule = '    ip saddr @ids_blocked_ips drop comment "ids-block"\n'
    return set_def, rule


def status() -> dict[str, Any]:
    cfg = _cfg()
    state = prune()
    return {
        "mode": cfg.get("mode", "log_only"),
        "valid_modes": list(VALID_MODES),
        "block_ttl_sec": cfg.get("block_ttl_sec", 3600),
        "blocked_ips": blocked_ips(),
        "blocked_count": len(blocked_ips()),
        "quarantined_by_ids": state.get("quarantined_by_ids") or [],
        "last_enforce_ts": state.get("last_enforce_ts"),
    }
