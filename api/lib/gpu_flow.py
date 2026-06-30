"""GPU-assisted traffic flow — peer-vector scoring every mitigate tick (stay in lobby)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

LAST_FILE = Path("/var/lib/array-firewall/gpu-flow-last.json")


def peers_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for path in (
        ("peer_tracker", "peers"),
        ("packet_analysis", "metrics", "inbound_identical_peers"),
        ("packets", "metrics", "inbound_identical_peers"),
        ("metrics", "inbound_identical_peers"),
    ):
        cur: Any = payload
        for part in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(part)
        if isinstance(cur, list):
            return [p for p in cur if isinstance(p, dict)]
    return []


def metrics_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    for key in ("packet_analysis", "packets"):
        block = payload.get(key)
        if isinstance(block, dict):
            m = block.get("metrics")
            if isinstance(m, dict):
                return m
    return {}


def analyze_payload(payload: dict[str, Any], *, phase: str = "") -> dict[str, Any]:
    from . import perf, policies

    mit = dict(policies.gaming().get("mitigation") or {})
    if not mit.get("gpu_flow_enabled", True):
        return {"ok": True, "skipped": True, "reason": "disabled"}
    peers = peers_from_payload(payload)
    min_peers = int(mit.get("gpu_flow_min_peers") or 2)
    if len(peers) < min_peers:
        return {"ok": True, "skipped": True, "reason": "insufficient_peers", "peer_count": len(peers)}

    metrics = metrics_from_payload(payload)
    analysis = perf.analyze_peers_gpu(peers, phase=phase or str(payload.get("phase") or ""), metrics=metrics)
    analysis["phase"] = phase or str(payload.get("phase") or "")
    analysis["analyzed_at"] = time.time()
    analysis["peer_count"] = len(peers)

    LAST_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_FILE.write_text(json.dumps(analysis, indent=2) + "\n", encoding="utf-8")
    return analysis


def shield_peer_hints(analysis: dict[str, Any]) -> tuple[list[str], list[str]]:
    strict = list(analysis.get("strict_ips") or [])
    throttle = list(analysis.get("throttle_ips") or [])
    return strict, throttle


def status() -> dict[str, Any]:
    last = {}
    if LAST_FILE.is_file():
        try:
            last = json.loads(LAST_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            last = {}
    from . import perf

    return {"ok": True, "gpu": perf.gpu_status(), "last": last}
