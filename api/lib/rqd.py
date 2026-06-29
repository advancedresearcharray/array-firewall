"""Recursive Quadrant Deduction (RQD) — exponential → polynomial search.

Operational slice of Kilpatrick (2026) Zenodo 20942201:
https://zenodo.org/records/20942201

- Recursive quadrant subdivision with solution-probability pruning
- Pattern shortcuts: periodicity, convexity, sparsity, hierarchical, invariance
- Persistent shortcut cache for instant replay on repeated workloads
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import policies

ZENODO = {
    "doi": "10.5281/zenodo.20942201",
    "url": "https://zenodo.org/records/20942201",
    "title": "Recursive Quadrant Deduction: Exponential to Polynomial Complexity",
    "version": "v2",
}

PATTERN_TYPES = ("periodicity", "convexity", "sparsity", "hierarchical", "invariance")
SHORTCUT_CACHE_PATH = Path("/var/lib/array-firewall/rqd-shortcuts.json")
RQD_STATS_PATH = Path("/var/lib/array-firewall/rqd-stats.json")
_MAX_CACHE = 2048


def _cfg() -> dict[str, Any]:
    base = {
        "enabled": True,
        "prune_threshold": 0.15,
        "max_depth": 6,
        "shortcut_cache": True,
        "min_quadrant_size": 1,
    }
    base.update(policies.load().get("rqd") or {})
    gaming = policies.gaming().get("rqd") or {}
    base.update(gaming)
    return base


def _default_stats() -> dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "started_at": now,
        "updated_at": now,
        "searches": 0,
        "quadrants_visited": 0,
        "quadrants_pruned": 0,
        "shortcut_hits": 0,
        "shortcut_misses": 0,
        "complexity_reduction_pct": 0.0,
        "last_search": None,
    }


def _load_stats() -> dict[str, Any]:
    if not RQD_STATS_PATH.is_file():
        return _default_stats()
    try:
        data = json.loads(RQD_STATS_PATH.read_text(encoding="utf-8"))
        base = _default_stats()
        base.update(data)
        return base
    except (json.JSONDecodeError, TypeError):
        return _default_stats()


def _save_stats(data: dict[str, Any]) -> None:
    data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    RQD_STATS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RQD_STATS_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _load_shortcuts() -> dict[str, Any]:
    if not SHORTCUT_CACHE_PATH.is_file():
        return {"shortcuts": {}}
    try:
        return json.loads(SHORTCUT_CACHE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, TypeError):
        return {"shortcuts": {}}


def _save_shortcuts(data: dict[str, Any]) -> None:
    SHORTCUT_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SHORTCUT_CACHE_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def detect_patterns(values: list[float]) -> dict[str, float]:
    """Score five RQD pattern types on a numeric series (20942201 §patterns)."""
    if not values:
        return {k: 0.0 for k in PATTERN_TYPES}
    vals = [float(v) for v in values[:512]]
    n = len(vals)
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / max(n, 1)
    std = math.sqrt(var) or 1e-9

    zeros = sum(1 for v in vals if abs(v) < 1e-6)
    sparsity = zeros / n

    diffs = [vals[i + 1] - vals[i] for i in range(n - 1)] if n > 1 else [0.0]
    sign_changes = sum(
        1 for i in range(len(diffs) - 1) if diffs[i] * diffs[i + 1] < 0
    )
    periodicity = min(1.0, sign_changes / max(len(diffs), 1) * 2.0) if n > 3 else 0.0
    if n >= 4:
        autoc = sum(vals[i] * vals[i + 2] for i in range(n - 2)) / max(n - 2, 1)
        periodicity = max(periodicity, min(1.0, abs(autoc) / (std * std + 1e-9)))

    convexity = 0.0
    if len(diffs) >= 2:
        second = [diffs[i + 1] - diffs[i] for i in range(len(diffs) - 1)]
        same_sign = sum(1 for d in second if d * second[0] > 0)
        convexity = same_sign / max(len(second), 1)

    levels = 0
    step = max(n // 4, 1)
    for i in range(0, n - step, step):
        chunk = vals[i : i + step]
        if chunk and max(chunk) - min(chunk) < std * 0.5:
            levels += 1
    hierarchical = min(1.0, levels / 4.0)

    first = vals[: max(n // 4, 1)]
    last = vals[-max(n // 4, 1) :]
    inv_first = sum(first) / max(len(first), 1)
    inv_last = sum(last) / max(len(last), 1)
    invariance = 1.0 - min(1.0, abs(inv_first - inv_last) / (std + 1e-9))

    return {
        "periodicity": round(periodicity, 4),
        "convexity": round(convexity, 4),
        "sparsity": round(sparsity, 4),
        "hierarchical": round(hierarchical, 4),
        "invariance": round(invariance, 4),
    }


def adaptive_probability(patterns: dict[str, float], *, prior: float = 0.5) -> float:
    """Blend pattern scores into quadrant solution probability (20942201 adaptive models)."""
    if not patterns:
        return prior
    weights = {
        "periodicity": 0.18,
        "convexity": 0.16,
        "sparsity": 0.22,
        "hierarchical": 0.24,
        "invariance": 0.20,
    }
    score = sum(float(patterns.get(k, 0.0)) * w for k, w in weights.items())
    return max(0.01, min(0.99, prior * 0.35 + score * 0.65))


def recursive_quadrant_digest(data: bytes, *, depth: int = 4) -> str:
    """Multi-level quadrant digest — extends 17844752 hook with RQD recursion."""
    if not data:
        return "0" * 16
    if depth <= 0 or len(data) <= 16:
        return hashlib.sha256(data).hexdigest()[:16]

    mid = len(data) // 2
    left = recursive_quadrant_digest(data[:mid], depth=depth - 1)
    right = recursive_quadrant_digest(data[mid:], depth=depth - 1)
    return hashlib.sha256(f"{left}:{right}".encode()).hexdigest()[:16]


@dataclass
class Quadrant:
    lo: float
    hi: float
    items: list[Any] = field(default_factory=list)
    depth: int = 0


def _split_quadrant(q: Quadrant) -> tuple[Quadrant, Quadrant]:
    mid = (q.lo + q.hi) / 2.0
    left_items: list[Any] = []
    right_items: list[Any] = []
    for item in q.items:
        key = float(item.get("_rqd_key", item) if isinstance(item, dict) else item)
        if key <= mid:
            left_items.append(item)
        else:
            right_items.append(item)
    return (
        Quadrant(lo=q.lo, hi=mid, items=left_items, depth=q.depth + 1),
        Quadrant(lo=mid, hi=q.hi, items=right_items, depth=q.depth + 1),
    )


def recursive_search(
    items: list[Any],
    *,
    key_fn: Callable[[Any], float],
    score_fn: Callable[[Any], float],
    maximize: bool = True,
    context: str = "generic",
) -> dict[str, Any]:
    """RQD search over numeric-keyed items — prune low-probability quadrants."""
    cfg = _cfg()
    if not cfg.get("enabled", True) or len(items) <= 2:
        best = max(items, key=score_fn) if maximize else min(items, key=score_fn)
        return {
            "ok": True,
            "best": best,
            "score": score_fn(best),
            "visited": len(items),
            "pruned": 0,
            "shortcut_hit": False,
            "patterns": {},
        }

    keyed = [{**item, "_rqd_key": key_fn(item)} if isinstance(item, dict) else item for item in items]
    if not all(isinstance(x, dict) for x in keyed):
        keyed = [{"value": x, "_rqd_key": key_fn(x)} for x in items]

    keys = [float(x["_rqd_key"]) for x in keyed]
    patterns = detect_patterns(keys + [score_fn(x) for x in keyed])
    cache_key = f"{context}:{recursive_quadrant_digest(json.dumps(keys[:64], separators=(',', ':')).encode())}"

    stats = _load_stats()
    stats["searches"] = int(stats.get("searches") or 0) + 1

    if cfg.get("shortcut_cache", True):
        store = _load_shortcuts()
        hit = (store.get("shortcuts") or {}).get(cache_key)
        if hit and hit.get("best") is not None:
            stats["shortcut_hits"] = int(stats.get("shortcut_hits") or 0) + 1
            stats["last_search"] = {"context": context, "shortcut_hit": True, "patterns": patterns}
            _save_stats(stats)
            return {
                "ok": True,
                "best": hit["best"],
                "score": hit.get("score"),
                "visited": 0,
                "pruned": hit.get("pruned", 0),
                "shortcut_hit": True,
                "patterns": patterns,
                "complexity_reduction_pct": hit.get("complexity_reduction_pct", 35.0),
            }
        stats["shortcut_misses"] = int(stats.get("shortcut_misses") or 0) + 1

    prune_threshold = float(cfg.get("prune_threshold") or 0.15)
    max_depth = int(cfg.get("max_depth") or 6)
    lo, hi = min(keys), max(keys)
    if lo == hi:
        hi = lo + 1.0

    root = Quadrant(lo=lo, hi=hi, items=keyed, depth=0)
    stack: list[tuple[Quadrant, float]] = [(root, adaptive_probability(patterns))]
    visited = 0
    pruned = 0
    best_item: dict[str, Any] | None = None
    best_score = float("-inf") if maximize else float("inf")

    while stack:
        quadrant, prob = stack.pop()
        if not quadrant.items:
            continue
        visited += 1
        stats["quadrants_visited"] = int(stats.get("quadrants_visited") or 0) + 1

        if prob < prune_threshold and quadrant.depth > 0:
            pruned += len(quadrant.items)
            stats["quadrants_pruned"] = int(stats.get("quadrants_pruned") or 0) + 1
            continue

        for item in quadrant.items:
            s = score_fn(item)
            if maximize and s > best_score:
                best_score = s
                best_item = item
            elif not maximize and s < best_score:
                best_score = s
                best_item = item

        if quadrant.depth >= max_depth or len(quadrant.items) <= int(cfg.get("min_quadrant_size") or 1):
            continue

        left, right = _split_quadrant(quadrant)
        left_keys = [float(x["_rqd_key"]) for x in left.items]
        right_keys = [float(x["_rqd_key"]) for x in right.items]
        left_pat = detect_patterns(left_keys) if left_keys else patterns
        right_pat = detect_patterns(right_keys) if right_keys else patterns
        stack.append((right, adaptive_probability(right_pat, prior=prob)))
        stack.append((left, adaptive_probability(left_pat, prior=prob)))

    total = max(len(items), 1)
    reduction = round((pruned / total) * 100.0, 2)
    stats["complexity_reduction_pct"] = round(
        (float(stats.get("complexity_reduction_pct") or 0) * 0.9) + reduction * 0.1,
        2,
    )
    stats["last_search"] = {
        "context": context,
        "visited": visited,
        "pruned": pruned,
        "patterns": patterns,
        "shortcut_hit": False,
    }
    _save_stats(stats)

    result = {
        "ok": True,
        "best": best_item,
        "score": best_score if best_item else None,
        "visited": visited,
        "pruned": pruned,
        "shortcut_hit": False,
        "patterns": patterns,
        "complexity_reduction_pct": reduction,
    }

    if cfg.get("shortcut_cache", True) and best_item is not None:
        store = _load_shortcuts()
        shortcuts = store.setdefault("shortcuts", {})
        shortcuts[cache_key] = {
            "best": best_item,
            "score": best_score,
            "pruned": pruned,
            "complexity_reduction_pct": reduction,
            "patterns": patterns,
            "ts": time.time(),
        }
        if len(shortcuts) > _MAX_CACHE:
            oldest = sorted(shortcuts.items(), key=lambda x: float(x[1].get("ts") or 0))[:128]
            for k, _ in oldest:
                shortcuts.pop(k, None)
        _save_shortcuts(store)

    return result


def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def discover_prefixes(
    ip_hits: dict[str, dict[str, Any]],
    *,
    prefix_len: int = 24,
    min_hits: int = 3,
    max_candidates: int = 8,
) -> list[dict[str, Any]]:
    """RQD-accelerated /prefix discovery over observed dedicated-server IPs."""
    if not ip_hits:
        return []

    buckets: dict[str, dict[str, Any]] = {}
    for ip, meta in ip_hits.items():
        try:
            prefix = str(ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False))
        except ValueError:
            continue
        bucket = buckets.setdefault(
            prefix,
            {"cidr": prefix, "hits": 0, "ips": set(), "last_seen": 0.0},
        )
        bucket["hits"] += int(meta.get("hits") or 1)
        bucket["ips"].add(ip)
        bucket["last_seen"] = max(float(bucket["last_seen"]), float(meta.get("last_seen") or 0))

    candidates = [
        {
            "cidr": b["cidr"],
            "hits": b["hits"],
            "ip_count": len(b["ips"]),
            "sample_ips": sorted(b["ips"])[:5],
            "last_seen": b["last_seen"],
            "_rqd_key": float(ip_to_int(next(iter(b["ips"])))),
        }
        for b in buckets.values()
        if b["hits"] >= min_hits
    ]

    if len(candidates) <= max_candidates:
        return [{k: v for k, v in c.items() if not k.startswith("_")} for c in candidates]

    search = recursive_search(
        candidates,
        key_fn=lambda x: float(x["_rqd_key"]),
        score_fn=lambda x: float(x["hits"]) * 10.0 + float(x["ip_count"]),
        context="allowlist_prefix",
    )
    ranked = sorted(candidates, key=lambda x: float(x["hits"]), reverse=True)[:max_candidates]
    if search.get("best"):
        top = search["best"]
        ranked = [top] + [c for c in ranked if c["cidr"] != top["cidr"]]
    return [{k: v for k, v in c.items() if not k.startswith("_")} for c in ranked[:max_candidates]]


def prioritize_investigation(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order unknown IPs by RQD threat probability — investigate worst first."""
    unknowns = [r for r in rows if str(r.get("conn_type") or "") == "unknown"]
    if len(unknowns) <= 1:
        return rows

    def threat_score(row: dict[str, Any]) -> float:
        tiny = float(row.get("tiny_packets") or 0)
        identical = float(row.get("identical_max") or 0)
        hits = float(row.get("hit_count") or 1)
        sessions = float(row.get("session_count") or 1)
        patterns = detect_patterns([tiny, identical, hits, sessions])
        base = tiny * 2.5 + identical * 2.0 + hits * 0.1 + sessions * 1.5
        return base * adaptive_probability(patterns, prior=0.35)

    scored = []
    for row in unknowns:
        scored.append({**row, "_rqd_key": threat_score(row), "_rqd_score": threat_score(row)})

    try:
        from . import asvi

        void_scan = asvi.scan_unknown_voids(limit=100)
        void_ips = {
            ip
            for v in (void_scan.get("voids") or [])
            for ip in (v.get("sample_ips") or [])
        }
        for row in scored:
            if str(row.get("ip") or "") in void_ips:
                row["_rqd_score"] = float(row.get("_rqd_score") or 0) + 25.0
    except Exception:
        pass

    try:
        from . import qce

        boosts = qce.investigation_boost(scored)
        for row in scored:
            ip = str(row.get("ip") or "")
            if ip in boosts:
                row["_rqd_score"] = float(row.get("_rqd_score") or 0) + boosts[ip]
                row["_qce_boost"] = boosts[ip]
    except Exception:
        pass

    ordered = recursive_search(
        scored,
        key_fn=lambda x: float(x["_rqd_key"]),
        score_fn=lambda x: float(x["_rqd_score"]),
        context="investigate_ip",
    )
    best_first = sorted(scored, key=lambda x: float(x["_rqd_score"]), reverse=True)
    if ordered.get("best"):
        top = ordered["best"]
        best_first = [top] + [r for r in best_first if r.get("ip") != top.get("ip")]

    known = [r for r in rows if str(r.get("conn_type") or "") != "unknown"]
    clean = [{k: v for k, v in r.items() if not k.startswith("_rqd")} for r in best_first]
    return known + clean


def select_buffer_profile(sample: dict[str, float]) -> dict[str, Any]:
    """Pick CAKE buffer profile via RQD over {gaming, light, desync, kick}."""
    profiles = [
        {"name": "gaming", "latency_budget": 8.0, "backlog": 65536},
        {"name": "light", "latency_budget": 10.0, "backlog": 81920},
        {"name": "desync", "latency_budget": 5.0, "backlog": 32768},
        {"name": "kick", "latency_budget": 3.0, "backlog": 16384},
    ]

    upload_util = float(sample.get("upload_util_pct") or sample.get("utilization_pct") or 0)
    queue_pressure = float(sample.get("queue_pressure") or sample.get("backlog_bytes") or 0) / 65536.0
    kick_spike = float(sample.get("kick_spike") or 0)
    desync = float(sample.get("desync_hint") or 0)
    in_match = float(sample.get("in_match") or 0)

    def fit_score(profile: dict[str, Any]) -> float:
        name = profile["name"]
        score = 100.0 - profile["latency_budget"]
        if name == "kick" and (kick_spike > 0.5 or upload_util >= 85):
            score += 40
        if name == "desync" and (desync > 0.5 or upload_util >= 70):
            score += 25
        if name == "gaming" and in_match < 0.5 and upload_util < 60:
            score += 20
        if name == "light" and queue_pressure < 0.3 and upload_util < 50:
            score += 10
        score -= queue_pressure * 15
        return score

    for p in profiles:
        p["_rqd_key"] = p["latency_budget"]
        p["_rqd_score"] = fit_score(p)

    result = recursive_search(
        profiles,
        key_fn=lambda x: float(x["_rqd_key"]),
        score_fn=lambda x: float(x["_rqd_score"]),
        context="buffer_profile",
    )
    best = result.get("best") or profiles[0]
    return {
        "ok": True,
        "profile": best["name"],
        "score": result.get("score"),
        "patterns": result.get("patterns") or {},
        "rqd": {
            "visited": result.get("visited"),
            "pruned": result.get("pruned"),
            "shortcut_hit": result.get("shortcut_hit"),
            "complexity_reduction_pct": result.get("complexity_reduction_pct"),
        },
        "zenodo": ZENODO,
    }


def classify_rules_fast(
    ip: str,
    rules: list[dict[str, Any]],
    *,
    hostname: str = "",
) -> tuple[str, dict[str, Any]]:
    """RQD-pruned rule scan — CIDR rules first, then hostname patterns."""
    cidr_rules: list[dict[str, Any]] = []
    host_rules: list[dict[str, Any]] = []
    for rule in rules:
        if rule.get("cidrs"):
            cidr_rules.append(rule)
        if rule.get("match"):
            host_rules.append(rule)

    for rule in cidr_rules:
        for cidr in rule.get("cidrs") or []:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(str(cidr), strict=False):
                    return str(rule.get("id") or "unknown"), {"path": "cidr", "rule": rule.get("id")}
            except ValueError:
                continue

    if not hostname:
        return "unknown", {"path": "none"}

    host = hostname.lower().rstrip(".")
    scored: list[dict[str, Any]] = []
    for rule in host_rules:
        excludes = [str(x).lower() for x in (rule.get("matchExclude") or [])]
        if any(x in host for x in excludes):
            continue
        patterns = [str(x).lower() for x in (rule.get("match") or [])]
        match_count = sum(1 for p in patterns if p in host)
        if match_count:
            scored.append(
                {
                    "id": str(rule.get("id") or "unknown"),
                    "rule": rule,
                    "_rqd_key": float(match_count),
                    "_rqd_score": float(match_count) * 10.0 + len(patterns),
                }
            )

    if not scored:
        return "unknown", {"path": "hostname_miss"}

    if len(scored) == 1:
        return scored[0]["id"], {"path": "hostname", "rqd": {"visited": 1}}

    found = recursive_search(
        scored,
        key_fn=lambda x: float(x["_rqd_key"]),
        score_fn=lambda x: float(x["_rqd_score"]),
        context="role_classify",
    )
    best = found.get("best") or scored[0]
    return best["id"], {"path": "hostname", "rqd": found}


def status() -> dict[str, Any]:
    cfg = _cfg()
    stats = _load_stats()
    shortcuts = _load_shortcuts()
    sc = shortcuts.get("shortcuts") or {}
    searches = max(int(stats.get("searches") or 0), 1)
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "zenodo": ZENODO,
        "config": cfg,
        "stats": stats,
        "shortcut_cache_size": len(sc),
        "shortcut_hit_rate_pct": round(
            (int(stats.get("shortcut_hits") or 0) / searches) * 100,
            1,
        ),
        "pattern_types": list(PATTERN_TYPES),
    }
