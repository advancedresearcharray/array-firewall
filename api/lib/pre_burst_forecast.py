"""Lobby risk forecast — matchmaking and in-match pre-burst (stay in lobby)."""
from __future__ import annotations

from typing import Any


def _peer_rows(context: dict[str, Any]) -> list[dict[str, Any]]:
    payload = context.get("_payload") or {}
    pt = payload.get("peer_tracker") or {}
    peers = pt.get("peers") or payload.get("peers") or []
    if isinstance(peers, list):
        return peers
    return []


def forecast(context: dict[str, Any]) -> dict[str, Any]:
    """Score 0–1 for forming probe activity; drives shield-first autopilot."""
    phase = str(context.get("phase") or "")
    if phase not in {"matchmaking", "in-match"}:
        return {"ok": True, "skipped": True, "reason": "not_gaming_phase"}

    score = 0.0
    factors: list[str] = []
    qce = context.get("qce") or {}
    entropy = float(qce.get("entanglement_entropy") or 0)
    unknown = int(qce.get("unknown_count") or 0)
    if entropy >= 0.45:
        score += min(0.25, entropy * 0.35)
        factors.append(f"entropy_slope:{entropy:.2f}")
    if unknown >= 4:
        score += min(0.2, unknown * 0.04)
        factors.append(f"unknown_inbound:{unknown}")

    offenders = context.get("offenders") or []
    overlap = len(offenders)
    if overlap >= 2:
        score += min(0.25, overlap * 0.06)
        factors.append(f"offender_overlap:{overlap}")

    vps_mesh = 0
    forming = 0
    low_spread = 0
    for _ip, row in (context.get("candidates") or {}).items():
        if row.get("vps_probe"):
            vps_mesh += 1
    for peer in _peer_rows(context):
        identical = int(peer.get("identical_count") or peer.get("max_burst") or 0)
        if 6 <= identical <= 19:
            forming += 1
        sizes = peer.get("sizes") or peer.get("packet_sizes") or []
        if isinstance(sizes, list) and len(sizes) >= 2:
            try:
                nums = [float(s) for s in sizes]
                if max(nums) - min(nums) <= 4:
                    low_spread += 1
            except (TypeError, ValueError):
                pass
    if vps_mesh >= 2:
        score += min(0.3, vps_mesh * 0.08)
        factors.append(f"vps_mesh:{vps_mesh}")
    if forming >= 2:
        score += min(0.2, forming * 0.05)
        factors.append(f"identical_forming:{forming}")
    if phase == "in-match" and low_spread >= 2:
        score += min(0.22, low_spread * 0.06)
        factors.append(f"in_match_low_spread:{low_spread}")

    gs = context.get("game_state") or {}
    if gs.get("recent_kick"):
        score += 0.18
        factors.append("game_state:kick")
    if float(context.get("game_fusion_score") or 0) >= 0.2:
        score += 0.1
        factors.append("game_fusion")

    pkt = context.get("packets") or {}
    metrics = pkt.get("metrics") if isinstance(pkt, dict) else {}
    if isinstance(metrics, dict):
        wan_jitter = metrics.get("wan_jitter") or metrics.get("server_jitter")
        if wan_jitter and float(wan_jitter) >= 0.35:
            score += 0.08
            factors.append("server_jitter")

    signals = list(context.get("signals") or [])
    if any("pre_burst" in s for s in signals):
        score += 0.15
        factors.append("identical_forming")

    score = round(min(1.0, score), 3)
    band = "low"
    if score >= 0.65:
        band = "high"
    elif score >= 0.38:
        band = "medium"

    headline = (
        "Probe formation likely — shield-first mitigation (stay in lobby)"
        if score >= 0.38
        else ("In-match stable — monitoring probes" if phase == "in-match" else "Queue forming normally")
    )

    return {
        "ok": True,
        "forecast_score": score,
        "band": band,
        "phase": phase,
        "factors": factors,
        "recommend_shield": score >= 0.38,
        "recommend_block": score >= 0.80,
        "headline": headline,
    }
