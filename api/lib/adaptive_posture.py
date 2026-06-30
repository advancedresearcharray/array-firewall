"""Adaptive shield + buffer posture from fusion, QCE, and RQD (stay in lobby)."""
from __future__ import annotations

from typing import Any


def recommend(context: dict[str, Any]) -> dict[str, Any]:
    """Map fused verdict + signals → shield level and buffer profile."""
    verdict = str(context.get("fused_verdict") or "clean")
    phase = str(context.get("phase") or "")
    gaming = phase in {"matchmaking", "in-match"}
    signals = list(context.get("signals") or [])
    qce = context.get("qce") or {}
    gpu = context.get("gpu") or {}
    cheater = str(context.get("cheater_label") or "")
    top_score = 0.0
    candidates = context.get("candidates") or {}
    if candidates:
        top_score = float(next(iter(candidates.values()), {}).get("score") or 0)

    shield = "normal"
    buffer_profile = "gaming"
    headline = "Monitoring — no escalation needed"

    if not gaming:
        return {
            "ok": True,
            "shield_level": shield,
            "buffer_profile": buffer_profile,
            "headline": "Idle — autopilot standby",
            "posture": "stay_and_mitigate",
            "verdict": verdict,
            "phase": phase,
        }

    if verdict == "hostile" or top_score >= 0.85 or cheater in {"LIKELY", "USER_BAD"}:
        shield = "matchmaking" if phase == "matchmaking" else "in-match"
        buffer_profile = "kick" if "kick_spike" in str(signals) else "desync"
        headline = "Hostile fusion — maximum mitigation, stay in lobby"
    elif verdict == "suspicious" or top_score >= 0.55 or cheater == "POSSIBLE":
        shield = "peer-strict" if phase == "matchmaking" else "in-match"
        buffer_profile = "desync"
        headline = "Suspicious lobby — shield tightening, continue playing"
    elif any("pre_burst" in s for s in signals):
        shield = "peer-strict"
        buffer_profile = "light"
        headline = "Pre-burst forecast — early shield before identical spikes"
    elif qce.get("peak_entropy_band"):
        shield = "peer-strict"
        buffer_profile = "desync"
        headline = "QCE entropy peak — RQD buffer + peer-strict shield"

    flood = float(gpu.get("flood_score") or 0)
    if flood >= 0.35 or any("gpu_flood" in s for s in signals):
        shield = "strict" if phase == "in-match" else "peer-strict"
        buffer_profile = "kick" if flood >= 0.5 else "desync"
        headline = "GPU flood signal — probe storm mitigation active"

    try:
        from . import rqd

        sample = {
            "upload_util_pct": float((context.get("telemetry") or {}).get("upload_util_pct") or 0),
            "kick_spike": 1.0 if "kick_spike" in str(signals) else 0.0,
            "desync_hint": 1.0 if buffer_profile == "desync" else 0.0,
            "in_match": 1.0 if phase == "in-match" else 0.0,
        }
        rec = rqd.select_buffer_profile(sample)
        if rec.get("profile"):
            buffer_profile = str(rec["profile"])
    except Exception:
        pass

    return {
        "ok": True,
        "shield_level": shield,
        "buffer_profile": buffer_profile,
        "headline": headline,
        "posture": "stay_and_mitigate",
        "verdict": verdict,
        "phase": phase,
        "top_fusion_score": round(top_score, 3),
        "signal_count": len(signals),
    }
