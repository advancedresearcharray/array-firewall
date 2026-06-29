"""Persistent peer blocklist with TTL — feeds packet shield peer-strict mode."""
from __future__ import annotations

import json
import re
import subprocess
import time
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from . import policies

PEER_FILE = Path("/var/lib/array-firewall/peer-blocklist.json")
PEER_EXPORT = Path("/var/lib/array-firewall/persistent-peers.txt")
SHIELD_STATE = Path("/var/lib/array-firewall/packet-shield.state")
SHIELD_SCRIPT = Path("/opt/array-firewall/scripts/packet-shield-nft.sh")
MM_ALLOWLIST = Path("/opt/array-firewall/config/matchmaking-allowlist.json")
IN_MATCH_ALLOWLIST = Path("/opt/array-firewall/config/in-match-allowlist.json")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_allowlist_nets_cache: list[Any] | None = None


def _cfg() -> dict[str, Any]:
    gaming = policies.gaming()
    base = {
        "enabled": True,
        "peer_ttl_sec": 86400,
        "repeat_offender_hits": 3,
        "repeat_offender_ttl_sec": 604800,
        "max_peers": 256,
    }
    base.update(gaming.get("mitigation") or {})
    return base


def _now() -> float:
    return time.time()


def _load() -> dict[str, Any]:
    if not PEER_FILE.is_file():
        return {"peers": {}, "updated": 0}
    try:
        return json.loads(PEER_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"peers": {}, "updated": 0}


def _save(data: dict[str, Any]) -> None:
    PEER_FILE.parent.mkdir(parents=True, exist_ok=True)
    data["updated"] = _now()
    tmp = PEER_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(PEER_FILE)


def _valid_ip(ip: str) -> bool:
    ip = ip.strip()
    if not _IP_RE.match(ip):
        return False
    parts = [int(p) for p in ip.split(".")]
    return all(0 <= p <= 255 for p in parts) and not ip.startswith(("0.", "127.", "255."))


def _allowlist_networks() -> list[Any]:
    global _allowlist_nets_cache
    if _allowlist_nets_cache is not None:
        return _allowlist_nets_cache
    nets: list[Any] = []
    for path in (MM_ALLOWLIST, IN_MATCH_ALLOWLIST):
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for cidr in data.get("cidrs") or []:
            try:
                nets.append(ip_network(str(cidr).strip(), strict=False))
            except ValueError:
                continue
    _allowlist_nets_cache = nets
    return nets


def in_game_allowlist(ip: str) -> bool:
    """True when IP is a known Xbox/CoD/Azure backend (never block for sentinel/VPS heuristics)."""
    if not _valid_ip(ip):
        return False
    try:
        addr = ip_address(ip.strip())
    except ValueError:
        return False
    return any(addr in net for net in _allowlist_networks())


def prune() -> dict[str, Any]:
    data = _load()
    now = _now()
    peers: dict[str, Any] = {}
    for ip, meta in (data.get("peers") or {}).items():
        try:
            exp = float((meta or {}).get("expires") or 0)
        except (TypeError, ValueError):
            continue
        if exp > now and _valid_ip(ip):
            peers[ip] = meta
    data["peers"] = peers
    _save(data)
    return data


def active_ips() -> list[str]:
    return sorted(prune().get("peers") or {})


def _ttl_for_entry(entry: dict[str, Any], cfg: dict[str, Any], default_ttl: int) -> int:
    hits = int(entry.get("hits") or 0)
    repeat_threshold = int(cfg.get("repeat_offender_hits") or 3)
    repeat_ttl = int(cfg.get("repeat_offender_ttl_sec") or 604800)
    if hits >= repeat_threshold:
        entry["repeat_offender"] = True
        return max(default_ttl, repeat_ttl)
    return default_ttl


def add_peers(
    ips: list[str],
    *,
    reason: str = "sentinel",
    ttl_sec: int | None = None,
    hits: int = 1,
) -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "added": 0, "enabled": False}

    default_ttl = max(300, int(ttl_sec or cfg.get("peer_ttl_sec") or 86400))
    max_peers = max(32, int(cfg.get("max_peers") or 256))
    data = prune()
    peers: dict[str, Any] = dict(data.get("peers") or {})
    now = _now()
    added = 0
    repeat_extended = 0

    try:
        from . import abuse_report as abuse_mod

        abuse_enabled = True
    except ImportError:
        abuse_mod = None
        abuse_enabled = False

    for raw in ips:
        ip = str(raw).strip()
        if not _valid_ip(ip):
            continue
        if in_game_allowlist(ip):
            continue
        entry = peers.get(ip) or {"reason": reason, "hits": 0, "first_seen": now}
        entry["hits"] = int(entry.get("hits") or 0) + hits
        entry["last_seen"] = now
        entry["reason"] = reason
        ttl = _ttl_for_entry(entry, cfg, default_ttl)
        if entry.get("repeat_offender"):
            repeat_extended += 1
        entry["expires"] = max(float(entry.get("expires") or 0), now + ttl)
        entry["ttl_sec"] = ttl
        peers[ip] = entry
        added += 1
        if abuse_enabled and abuse_mod:
            abuse_mod.record_incident(ip, reason=reason, meta={"hits": entry["hits"], "ttl_sec": ttl})

    if len(peers) > max_peers:
        ranked = sorted(
            peers.items(),
            key=lambda kv: (float(kv[1].get("hits") or 0), float(kv[1].get("last_seen") or 0)),
        )
        peers = dict(ranked[-max_peers:])

    data["peers"] = peers
    _save(data)
    export_peers()
    return {
        "ok": True,
        "added": added,
        "total": len(peers),
        "repeat_offender_extended": repeat_extended,
        "peers": active_ips(),
    }


def prune_allowlisted() -> dict[str, Any]:
    """Drop allowlisted game-server IPs mistakenly blocked by sentinel/VPS heuristics."""
    data = prune()
    peers: dict[str, Any] = dict(data.get("peers") or {})
    removed: list[str] = []
    for ip in list(peers):
        if in_game_allowlist(ip):
            peers.pop(ip, None)
            removed.append(ip)
    if removed:
        data["peers"] = peers
        _save(data)
        export_peers()
    return {"ok": True, "removed": len(removed), "ips": removed[:32]}


def export_peers() -> list[str]:
    ips = active_ips()
    PEER_EXPORT.parent.mkdir(parents=True, exist_ok=True)
    if ips:
        PEER_EXPORT.write_text("\n".join(ips) + "\n", encoding="utf-8")
    elif PEER_EXPORT.is_file():
        PEER_EXPORT.unlink(missing_ok=True)
    return ips


def remove_peers(ips: list[str]) -> dict[str, Any]:
    data = prune()
    peers: dict[str, Any] = dict(data.get("peers") or {})
    removed = 0
    for raw in ips:
        ip = str(raw).strip()
        if ip in peers:
            del peers[ip]
            removed += 1
    data["peers"] = peers
    _save(data)
    export_peers()
    return {"ok": True, "removed": removed, "total": len(peers), "peers": active_ips()}


def clear_all() -> dict[str, Any]:
    _save({"peers": {}, "updated": _now()})
    export_peers()
    return {"ok": True, "cleared": True}


def decay_stale(*, max_age_sec: int = 86400, keep_repeat: bool = True) -> dict[str, Any]:
    """Shorten TTL on low-hit peers after clean sessions — outcome-calibrated learning."""
    data = prune()
    now = _now()
    peers: dict[str, Any] = dict(data.get("peers") or {})
    decayed = 0
    removed = 0
    for ip, meta in list(peers.items()):
        if keep_repeat and meta.get("repeat_offender"):
            continue
        hits = int(meta.get("hits") or 0)
        if hits >= 3:
            continue
        exp = float(meta.get("expires") or 0)
        if hits <= 1 and exp - now > max_age_sec / 4:
            peers.pop(ip, None)
            removed += 1
        elif hits <= 2 and exp > now:
            meta["expires"] = now + max(300, max_age_sec // 8)
            peers[ip] = meta
            decayed += 1
    data["peers"] = peers
    _save(data)
    export_peers()
    return {"ok": True, "decayed": decayed, "removed": removed, "remaining": len(peers)}


def _current_shield_level() -> str:
    if not SHIELD_STATE.is_file():
        return "normal"
    level = "normal"
    for line in SHIELD_STATE.read_text(encoding="utf-8").splitlines():
        if line.startswith("level="):
            level = line.split("=", 1)[1].strip() or "normal"
    return level


def sync_shield(*, level: str | None = None, extra_peers: list[str] | None = None) -> dict[str, Any]:
    """Re-apply packet shield merging persistent + session peers."""
    prune_allowlisted()
    if not SHIELD_SCRIPT.is_file():
        return {"ok": False, "error": "packet shield script missing"}

    tiny_only = policies.sentinel_tiny_only()
    shield_level = policies.effective_shield_level(level or _current_shield_level() or "normal")
    if shield_level in {"off", "relax", "inactive"}:
        shield_level = "normal"
    if tiny_only:
        shield_level = "normal"

    peers = [] if tiny_only else [ip for ip in active_ips() if not in_game_allowlist(ip)]
    session_file = Path("/var/lib/array-firewall/suspicious-peers.txt")
    if session_file.is_file():
        for line in session_file.read_text(encoding="utf-8").splitlines():
            ip = line.strip().split("#", 1)[0].strip()
            if _valid_ip(ip) and ip not in peers and not in_game_allowlist(ip):
                peers.append(ip)
    for ip in extra_peers or []:
        ip = str(ip).strip()
        if _valid_ip(ip) and ip not in peers and not in_game_allowlist(ip):
            peers.append(ip)

    args = ["shield", shield_level, *peers]
    proc = subprocess.run(
        [str(SHIELD_SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    result = {
        "ok": proc.returncode == 0,
        "level": shield_level,
        "peer_count": len(peers),
        "stdout": (proc.stdout or "").strip()[-400:],
        "stderr": (proc.stderr or "").strip()[-400:],
    }
    if proc.returncode == 0:
        try:
            from . import nat as nat_mod

            result["wan_nat"] = nat_mod.ensure_wan_nat()
        except Exception as exc:
            result["wan_nat"] = {"ok": False, "error": str(exc)}
    return result


def status() -> dict[str, Any]:
    cfg = _cfg()
    data = prune()
    peers = data.get("peers") or {}
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "peer_ttl_sec": cfg.get("peer_ttl_sec", 86400),
        "repeat_offender_hits": cfg.get("repeat_offender_hits", 3),
        "repeat_offender_ttl_sec": cfg.get("repeat_offender_ttl_sec", 604800),
        "count": len(peers),
        "peers": [
            {
                "ip": ip,
                "reason": meta.get("reason"),
                "hits": meta.get("hits"),
                "repeat_offender": bool(meta.get("repeat_offender")),
                "ttl_sec": meta.get("ttl_sec"),
                "expires": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime(float(meta.get("expires") or 0)),
                ),
            }
            for ip, meta in sorted(peers.items(), key=lambda kv: float(kv[1].get("last_seen") or 0), reverse=True)[:64]
        ],
    }
