"""Narrow gaming IDS enforce — VPS probe storms only (safe under tiny_packet_only)."""
from __future__ import annotations

from typing import Any

from . import ids_enforce, peer_blocklist, policies, wan_scan_block


def _cfg() -> dict[str, Any]:
    gaming = policies.gaming()
    mit = dict(gaming.get("mitigation") or {})
    base = {
        "enabled": True,
        "min_identical": 10,
        "require_vps_probe": True,
        "block_ttl_sec": 3600,
        "max_blocks_per_tick": 6,
    }
    base.update(mit.get("gaming_probe_ids") or {})
    return base


def enforce_from_peers(peers: list[dict[str, Any]], *, phase: str = "") -> dict[str, Any]:
    """Block WAN probe sources even when full IDS block mode is off."""
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "skipped": True, "reason": "disabled"}
    if phase not in {"matchmaking", "in-match"}:
        return {"ok": True, "skipped": True, "reason": "not_gaming_phase"}

    targets: list[str] = []
    for row in peers:
        ip = str(row.get("ip") or row.get("remote") or "").split(":")[0].strip()
        if not ip or peer_blocklist.in_game_allowlist(ip):
            continue
        identical = int(row.get("identical_count") or row.get("max_burst") or 0)
        vps = bool(row.get("vps_probe"))
        if cfg.get("require_vps_probe", True) and not vps:
            continue
        if identical < int(cfg.get("min_identical") or 10):
            continue
        targets.append(ip)

    targets = list(dict.fromkeys(targets))[: int(cfg.get("max_blocks_per_tick") or 6)]
    if not targets:
        return {"ok": True, "blocked": 0, "ips": []}

    blocked = 0
    results: list[dict[str, Any]] = []
    ttl = int(cfg.get("block_ttl_sec") or 3600)
    for ip in targets:
        try:
            res = wan_scan_block.block_scanner(ip, reason="gaming_probe_ids", port=None, proto="udp")
        except Exception:
            res = ids_enforce.block_wan_ips([ip], ttl_sec=ttl, source="gaming_probe_ids")
        if res.get("ok") or res.get("blocked"):
            blocked += 1
        results.append({"ip": ip, "result": res})

    return {"ok": True, "blocked": blocked, "ips": targets, "results": results}


def status() -> dict[str, Any]:
    return {"ok": True, "config": _cfg(), "tiny_packet_only": policies.sentinel_tiny_only()}
