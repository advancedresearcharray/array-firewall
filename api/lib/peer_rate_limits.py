"""Dynamic per-peer nft throttle from identical-burst / low-spread probe signatures."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

ANALYSIS_FILE = Path("/var/lib/array-firewall/peer-rate-analysis.json")
OVERRIDE_FILE = Path("/var/lib/array-firewall/peer-rate-overrides.json")


def _spread(peer: dict[str, Any]) -> float | None:
    sizes = peer.get("sizes") or peer.get("packet_sizes") or []
    if not isinstance(sizes, list) or len(sizes) < 2:
        identical = int(peer.get("identical_count") or peer.get("max_burst") or 0)
        if identical >= 12:
            return 0.0
        return None
    try:
        nums = [float(s) for s in sizes]
        return max(nums) - min(nums)
    except (TypeError, ValueError):
        return None


def analyze(peers: list[dict[str, Any]], *, phase: str = "") -> dict[str, Any]:
    throttle: list[dict[str, Any]] = []
    strict: list[dict[str, Any]] = []
    for row in peers:
        ip = str(row.get("ip") or row.get("remote") or "").split(":")[0].strip()
        if not ip or ip.startswith(("10.", "192.168.", "127.")):
            continue
        identical = int(row.get("identical_count") or row.get("max_burst") or 0)
        vps = bool(row.get("vps_probe"))
        spread = _spread(row)
        score = 0.0
        if vps:
            score += 0.45
        if identical >= 20:
            score += 0.35
        elif identical >= 8:
            score += 0.2
        if spread is not None and spread <= 4.0:
            score += 0.25
        if spread == 0.0 and identical >= 6:
            score += 0.15
        entry = {
            "ip": ip,
            "score": round(score, 3),
            "identical": identical,
            "vps_probe": vps,
            "size_spread": spread,
            "per_src_udp_rate": 120 if score >= 0.65 else (220 if score >= 0.4 else None),
            "conn_cap": 12 if score >= 0.65 else (24 if score >= 0.4 else None),
        }
        if score >= 0.65 or (vps and identical >= 10):
            strict.append(entry)
        elif score >= 0.4:
            throttle.append(entry)

    result = {
        "ok": True,
        "phase": phase,
        "analyzed_at": time.time(),
        "throttle_peers": throttle[:32],
        "strict_peers": strict[:24],
        "throttle_ips": [e["ip"] for e in throttle],
        "strict_ips": [e["ip"] for e in strict],
    }
    ANALYSIS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ANALYSIS_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def apply_to_shield(peers: list[dict[str, Any]], *, phase: str = "", sync_nft: bool = True) -> dict[str, Any]:
    """Return merged peer list for shield sync — strict peers prioritized."""
    analysis = analyze(peers, phase=phase)
    strict = analysis.get("strict_ips") or []
    throttle = analysis.get("throttle_ips") or []
    merged: list[str] = []
    for ip in strict + throttle:
        if ip not in merged:
            merged.append(ip)
    overrides = {
        "updated_at": time.time(),
        "phase": phase,
        "peers": {e["ip"]: e for e in (analysis.get("strict_peers") or []) + (analysis.get("throttle_peers") or [])},
    }
    OVERRIDE_FILE.write_text(json.dumps(overrides, indent=2) + "\n", encoding="utf-8")
    sync = {"ok": True, "skipped": True}
    if sync_nft and merged:
        from . import nft

        sync = nft.sync_shield_peers(merged)
    return {"ok": True, "analysis": analysis, "merged_peers": merged, "nft_sync": sync}


def status() -> dict[str, Any]:
    analysis = {}
    if ANALYSIS_FILE.is_file():
        try:
            analysis = json.loads(ANALYSIS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            analysis = {}
    return {"ok": True, "analysis": analysis}
