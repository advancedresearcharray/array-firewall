"""In-lobby playability score — mitigation health, not leave/requeue advice."""
from __future__ import annotations

from typing import Any


def assess(
    *,
    context: dict[str, Any],
    plan: dict[str, Any],
    execution: dict[str, Any],
    shield_level: str | None = None,
) -> dict[str, Any]:
    """Return playability 0-100 and mitigation status for staying in the lobby."""
    verdict = str(context.get("fused_verdict") or plan.get("verdict") or "clean")
    phase = str(context.get("phase") or "")
    gaming = phase in {"matchmaking", "in-match"}
    cheater = str(context.get("cheater_label") or "")
    signals = list(context.get("signals") or [])
    executed = execution.get("executed") or []
    skipped = execution.get("skipped") or []

    score = 88.0
    if verdict == "hostile":
        score -= 28
    elif verdict == "suspicious":
        score -= 14
    if cheater in {"LIKELY", "USER_BAD"}:
        score -= 12
    elif cheater == "POSSIBLE":
        score -= 6
    score -= min(15, len(signals) * 2)
    score += min(12, len(executed) * 3)
    if any(ex.get("type") == "shield" for ex in executed):
        score += 8
    if any(ex.get("type") == "buffer_tune" for ex in executed):
        score += 5
    score = max(5.0, min(100.0, round(score, 1)))

    if score >= 72:
        band = "playable"
        headline = "Lobby playable — defenses absorbing cheater noise"
        posture = "stay_and_mitigate"
    elif score >= 48:
        band = "strained"
        headline = "Lobby strained — autopilot tightening shield and blocks"
        posture = "stay_and_mitigate"
    else:
        band = "under_attack"
        headline = "Heavy probe activity — maximum mitigation active (stay in lobby)"
        posture = "stay_and_mitigate"

    mitigations: list[str] = []
    for ex in executed:
        typ = ex.get("type")
        if typ == "shield":
            mitigations.append(f"Shield → {ex.get('level')}")
        elif typ == "block_peer":
            mitigations.append(f"Blocked probe {ex.get('ip')}")
        elif typ == "block_subnet":
            mitigations.append(f"Blocked subnet from {ex.get('ip')}")
        elif typ == "buffer_tune":
            mitigations.append(f"Buffer → {ex.get('profile')}")
        elif typ == "investigate_ip":
            mitigations.append(f"Intel on {ex.get('ip')}")
    if not mitigations and gaming:
        mitigations.append("Monitoring — no blocks needed yet")

    return {
        "ok": True,
        "playability_score": score,
        "band": band,
        "headline": headline,
        "posture": posture,
        "phase": phase,
        "verdict": verdict,
        "shield_level": shield_level,
        "mitigations_active": mitigations,
        "actions_executed": len(executed),
        "actions_skipped": len(skipped),
        "recommendation": _recommendation(band, mitigations, gaming),
    }


def _recommendation(band: str, mitigations: list[str], gaming: bool) -> str:
    if not gaming:
        return "Idle — autopilot standby until next queue."
    if band == "playable":
        return "Continue playing. Sentinel + autopilot are holding probe traffic off your path."
    if band == "strained":
        return "Continue playing. Shield and peer blocks are reducing desync and tiny-packet hits."
    return "Continue playing if you can — autopilot is blocking VPS mesh and tuning buffers to preserve hit reg."
