"""Lobby risk forecast at matchmaking T+ — act before identical table spikes."""
from __future__ import annotations

from typing import Any


def forecast(context: dict[str, Any]) -> dict[str, Any]:
    """Score 0–1 for forming probe activity; drives shield-first autopilot."""
    phase = str(context.get("phase") or "")
    if phase != "matchmaking":
        return {"ok": True, "skipped": True, "reason": "not_matchmaking"}

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
    for _ip, row in (context.get("candidates") or {}).items():
        if row.get("vps_probe"):
            vps_mesh += 1
    if vps_mesh >= 2:
        score += min(0.3, vps_mesh * 0.08)
        factors.append(f"vps_mesh:{vps_mesh}")

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

    return {
        "ok": True,
        "forecast_score": score,
        "band": band,
        "factors": factors,
        "recommend_shield": score >= 0.38,
        "recommend_block": score >= 0.80,
        "headline": (
            "Probe formation likely — shield-first mitigation (stay in lobby)"
            if score >= 0.38
            else "Queue forming normally"
        ),
    }
