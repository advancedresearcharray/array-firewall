"""Learn dedicated-server CIDRs from conn-lite traffic during matches."""
from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from . import conn_lite_db, policies, session_events

ALLOWLIST_PATH = Path("/opt/array-firewall/config/in-match-allowlist.json")
STAGING_PATH = Path("/var/lib/array-firewall/in-match-allowlist.learned.json")
LEARN_TYPES = frozenset({"dedicated-server", "warzone-game"})


def _cfg() -> dict[str, Any]:
    gaming = policies.gaming()
    base = {
        "enabled": True,
        "prefix_len": 24,
        "min_hits": 3,
        "min_ips_per_prefix": 1,
        "max_new_cidrs": 8,
        "auto_apply_in_match": False,
    }
    base.update(gaming.get("allowlist_learn") or {})
    return base


def _load_allowlist() -> dict[str, Any]:
    if not ALLOWLIST_PATH.is_file():
        return {"description": "In-match allowlist", "cidrs": []}
    try:
        data = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"description": "In-match allowlist", "cidrs": []}
    if not isinstance(data, dict):
        return {"description": "In-match allowlist", "cidrs": []}
    data.setdefault("cidrs", [])
    return data


def _existing_networks(cidrs: list[str]) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError:
            continue
    return nets


def _ip_to_prefix(ip: str, prefix_len: int) -> str | None:
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
        return str(net)
    except ValueError:
        return None


def analyze(
    *,
    session_hex: str | None = None,
    since_ts: float | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    cfg = _cfg()
    prefix_len = max(16, min(int(cfg.get("prefix_len") or 24), 28))
    min_hits = max(1, int(cfg.get("min_hits") or 3))

    q = conn_lite_db.query(
        session_hex=session_hex,
        conn_type="dedicated-server",
        limit=limit,
        offset=0,
    )
    rows = q.get("rows") or []
    if not rows:
        q = conn_lite_db.query(session_hex=session_hex, limit=limit, offset=0)
        rows = [
            r
            for r in (q.get("rows") or [])
            if str(r.get("conn_type") or "") in LEARN_TYPES
        ]

    prefix_stats: dict[str, dict[str, Any]] = {}
    for row in rows:
        if since_ts and float(row.get("last_seen") or 0) < since_ts:
            continue
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        prefix = _ip_to_prefix(ip, prefix_len)
        if not prefix:
            continue
        bucket = prefix_stats.setdefault(
            prefix,
            {"hits": 0, "ips": set(), "last_seen": 0.0},
        )
        bucket["hits"] += int(row.get("hit_count") or 1)
        bucket["ips"].add(ip)
        bucket["last_seen"] = max(float(bucket["last_seen"]), float(row.get("last_seen") or 0))

    ip_hits = {
        ip: {"hits": meta["hits"], "last_seen": meta["last_seen"]}
        for meta in prefix_stats.values()
        for ip in meta["ips"]
    }
    try:
        from . import rqd

        candidates = rqd.discover_prefixes(
            ip_hits,
            prefix_len=prefix_len,
            min_hits=min_hits,
            max_candidates=max(0, int(cfg.get("max_new_cidrs") or 8)),
        )
    except Exception:
        candidates = []

    current = _load_allowlist()
    existing = _existing_networks(list(current.get("cidrs") or []))

    if not candidates:
        candidates = []
        for prefix, stats in prefix_stats.items():
            if stats["hits"] < min_hits:
                continue
            try:
                net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if any(net.subnet_of(e) or e.subnet_of(net) for e in existing):
                continue
            candidates.append(
                {
                    "cidr": prefix,
                    "hits": stats["hits"],
                    "ip_count": len(stats["ips"]),
                    "sample_ips": sorted(stats["ips"])[:5],
                    "last_seen": stats["last_seen"],
                }
            )
        candidates.sort(key=lambda x: (-x["hits"], -x["last_seen"]))
        max_new = max(0, int(cfg.get("max_new_cidrs") or 8))
        candidates = candidates[:max_new]
    else:
        filtered: list[dict[str, Any]] = []
        for row in candidates:
            try:
                net = ipaddress.ip_network(str(row.get("cidr") or ""), strict=False)
            except ValueError:
                continue
            if any(net.subnet_of(e) or e.subnet_of(net) for e in existing):
                continue
            filtered.append(row)
        candidates = filtered

    asvi_scan: dict[str, Any] = {}
    try:
        from . import asvi

        asvi_scan = asvi.scan_session(session_hex=session_hex, limit=limit)
        void_cidrs = asvi.void_boost_candidates(asvi_scan.get("voids") or [])
        seen = {str(c.get("cidr") or "") for c in candidates}
        for prefix in void_cidrs:
            if prefix in seen:
                continue
            try:
                net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if any(net.subnet_of(e) or e.subnet_of(net) for e in existing):
                continue
            candidates.append(
                {
                    "cidr": prefix,
                    "hits": 0,
                    "ip_count": 0,
                    "sample_ips": [],
                    "last_seen": time.time(),
                    "source": "asvi_void",
                }
            )
            seen.add(prefix)
    except Exception:
        pass

    staging = {
        "updated_at": time.time(),
        "session_hex": session_hex,
        "prefix_len": prefix_len,
        "asvi": asvi_scan if asvi_scan else None,
        "candidates": candidates,
        "existing_count": len(existing),
    }
    STAGING_PATH.parent.mkdir(parents=True, exist_ok=True)
    STAGING_PATH.write_text(json.dumps(staging, indent=2), encoding="utf-8")

    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "session_hex": session_hex,
        "candidates": candidates,
        "staging_path": str(STAGING_PATH),
        "existing_cidrs": len(existing),
    }


def apply_learned(*, merge: bool = True, reload_shield: bool = False) -> dict[str, Any]:
    cfg = _cfg()
    if not STAGING_PATH.is_file():
        return {"ok": False, "error": "no learned staging file — run analyze first"}

    try:
        staging = json.loads(STAGING_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"invalid staging: {exc}"}

    candidates = staging.get("candidates") or []
    if not candidates:
        return {"ok": True, "added": [], "message": "no new CIDR candidates"}

    current = _load_allowlist()
    cidrs = list(current.get("cidrs") or [])
    existing = set(str(c).strip() for c in cidrs)
    added: list[str] = []

    for row in candidates:
        cidr = str(row.get("cidr") or "").strip()
        if not cidr or cidr in existing:
            continue
        cidrs.append(cidr)
        existing.add(cidr)
        added.append(cidr)

    if not added:
        return {"ok": True, "added": [], "message": "all candidates already present"}

    current["cidrs"] = cidrs
    current["learned_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    current["learned_cidrs"] = list(dict.fromkeys([*(current.get("learned_cidrs") or []), *added]))
    ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    ALLOWLIST_PATH.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")

    session_events.append(
        "allowlist.learned",
        session_hex=str(staging.get("session_hex") or ""),
        detail=f"added {len(added)} CIDR(s)",
        meta={"added": added},
    )

    shield = None
    if reload_shield:
        from . import gaming

        shield = gaming.apply_packet_shield(policies.effective_shield_level("in-match"))

    return {
        "ok": True,
        "added": added,
        "total_cidrs": len(cidrs),
        "allowlist_path": str(ALLOWLIST_PATH),
        "shield": shield,
    }


def status() -> dict[str, Any]:
    cfg = _cfg()
    staging = None
    if STAGING_PATH.is_file():
        try:
            staging = json.loads(STAGING_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            staging = None
    current = _load_allowlist()
    return {
        "ok": True,
        "config": cfg,
        "allowlist_path": str(ALLOWLIST_PATH),
        "cidr_count": len(current.get("cidrs") or []),
        "learned_cidrs": current.get("learned_cidrs") or [],
        "staging": staging,
    }


def auto_learn_in_match(*, session_hex: str | None = None, phase: str | None = None) -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("enabled", True) or phase != "in-match":
        return {"ok": True, "skipped": True, "reason": "disabled_or_not_in_match"}
    result = analyze(session_hex=session_hex, since_ts=time.time() - 900)
    candidates = result.get("candidates") or []
    if not candidates:
        return {"ok": True, "skipped": True, "reason": "no_candidates", "analyze": result}
    if cfg.get("auto_apply_in_match"):
        applied = apply_learned(reload_shield=False)
        return {"ok": True, "analyze": result, "apply": applied}
    return {"ok": True, "analyze": result, "staged": True}
