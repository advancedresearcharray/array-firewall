"""Fuse Overwolf/Xbox companion game_state into ai_ops (kick = ground truth)."""
from __future__ import annotations

from typing import Any, Callable


def fuse(
    ctx: dict[str, Any],
    payload: dict[str, Any],
    *,
    bump: Callable[..., None] | None = None,
    weights: dict[str, Any] | None = None,
) -> dict[str, Any]:
    weights = weights or {}
    gs = payload.get("game_state") or {}
    if not isinstance(gs, dict):
        return {"ok": True, "skipped": True}

    events = list(gs.get("events") or [])
    summary = {
        "playlist": gs.get("playlist"),
        "recent_kick": bool(gs.get("recent_kick")),
        "kick_age_sec": gs.get("kick_age_sec"),
        "flagged_players": int(gs.get("flagged_players") or 0),
        "event_count": len(events),
    }
    ctx["game_state"] = summary

    if summary["recent_kick"]:
        ctx["signals"].append("game_state:kick")
        age = float(summary["kick_age_sec"] or 0)
        ctx["game_fusion_score"] = float(ctx.get("game_fusion_score") or 0) + float(
            weights.get("game_kick", 0.35)
        )
        if age < 60:
            ctx["signals"].append("game_state:kick_fresh")

    cheat_events = {"prefire", "snap", "wallhack", "cheater", "killcam_result"}
    for ev in events[:12]:
        if not isinstance(ev, dict):
            continue
        et = str(ev.get("type") or "").lower()
        if et in cheat_events:
            ctx["signals"].append(f"game_state:{et}")
            ctx["game_fusion_score"] = float(ctx.get("game_fusion_score") or 0) + float(
                weights.get("game_cheat_event", 0.12)
            )
        player = str(ev.get("player") or "").strip()
        if player and bump and et in cheat_events:
            bump(player, float(weights.get("game_player_flag", 0.08)), f"game_state:{et}")

    if summary["flagged_players"] >= 2:
        ctx["signals"].append(f"game_state:flags:{summary['flagged_players']}")

    score = float(ctx.get("game_fusion_score") or 0)
    if score >= 0.25:
        ctx["fused_game_verdict"] = "hostile_signal"
    elif score >= 0.1:
        ctx["fused_game_verdict"] = "suspicious_signal"
    else:
        ctx["fused_game_verdict"] = "clean"

    return {"ok": True, "summary": summary, "fusion_score": round(score, 3)}
