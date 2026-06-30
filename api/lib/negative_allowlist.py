"""ASVI-derived negative allowlist — CIDRs that must never be treated as in-match safe."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import policies

NEG_FILE = Path("/var/lib/array-firewall/negative-allowlist.json")


def _load() -> dict[str, Any]:
    if not NEG_FILE.is_file():
        return {"cidrs": [], "sources": {}}
    try:
        return json.loads(NEG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"cidrs": [], "sources": {}}


def _save(data: dict[str, Any]) -> None:
    NEG_FILE.parent.mkdir(parents=True, exist_ok=True)
    NEG_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def add_void_prefix(prefix: str, *, reason: str, session_hex: str | None = None) -> dict[str, Any]:
    prefix = prefix.strip()
    if not prefix:
        return {"ok": False, "error": "empty prefix"}
    data = _load()
    cidrs = list(data.get("cidrs") or [])
    if prefix not in cidrs:
        cidrs.append(prefix)
    sources = dict(data.get("sources") or {})
    sources[prefix] = {"reason": reason, "session_hex": session_hex, "ts": time.time()}
    data["cidrs"] = cidrs[-512:]
    data["sources"] = sources
    _save(data)
    return {"ok": True, "added": prefix, "count": len(cidrs)}


def ingest_asvi_voids(voids: list[dict[str, Any]], *, session_hex: str | None = None) -> dict[str, Any]:
    cfg = policies.load().get("ai_ops") or {}
    if not cfg.get("negative_allowlist_enabled", True):
        return {"ok": True, "skipped": True}
    added = 0
    for void in voids:
        if void.get("smst") != "act":
            continue
        prefix = str(void.get("prefix") or void.get("void_prefix") or "").strip()
        if prefix:
            add_void_prefix(prefix, reason="asvi_act_void", session_hex=session_hex)
            added += 1
    return {"ok": True, "added": added}


def is_negative(ip: str) -> bool:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    for cidr in _load().get("cidrs") or []:
        try:
            if addr in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def list_cidrs() -> list[str]:
    return list(_load().get("cidrs") or [])


def status() -> dict[str, Any]:
    data = _load()
    return {"ok": True, "count": len(data.get("cidrs") or []), "cidrs": list_cidrs()[:32]}


def enforce_negative_peers(
    candidates: dict[str, Any],
    *,
    min_confidence: float = 0.72,
) -> list[dict[str, Any]]:
    """Block peers landing in negative CIDR space (proactive deny, stay-in-lobby)."""
    from . import peer_blocklist

    blocked: list[dict[str, Any]] = []
    for ip, row in candidates.items():
        if not is_negative(str(ip)):
            continue
        score = float(row.get("score") or 0)
        if score < min_confidence and not row.get("vps_probe"):
            continue
        if peer_blocklist.in_game_allowlist(str(ip)):
            continue
        result = peer_blocklist.add_peers(
            [str(ip)],
            reason="negative_allowlist",
            ttl_sec=604800,
        )
        blocked.append({"ip": ip, "result": result, "score": score})
    return blocked

