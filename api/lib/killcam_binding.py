"""Bind game-state killcam/cheat events to peer_tracker burst windows."""
from __future__ import annotations

import time
from typing import Any


def bind(payload: dict[str, Any]) -> dict[str, Any]:
    gs = payload.get("game_state") or {}
    if not isinstance(gs, dict):
        return {"ok": True, "skipped": True}

    events = list(gs.get("events") or [])
    cheat_types = {"prefire", "snap", "wallhack", "cheater", "killcam_result"}
    cheat_events = [e for e in events if isinstance(e, dict) and str(e.get("type") or "").lower() in cheat_types]
    if not cheat_events:
        return {"ok": True, "bindings": [], "cheat_event_count": 0}

    peers = _peer_rows(payload)
    if not peers:
        return {"ok": True, "bindings": [], "cheat_event_count": len(cheat_events)}

    ranked = sorted(
        peers,
        key=lambda p: int(p.get("identical_count") or p.get("max_burst") or 0),
        reverse=True,
    )
    bindings: list[dict[str, Any]] = []
    for ev in cheat_events[:6]:
        et = str(ev.get("type") or "").lower()
        player = str(ev.get("player") or "").strip()
        best = ranked[0] if ranked else None
        if not best:
            continue
        ip = str(best.get("ip") or best.get("remote") or "").split(":")[0].strip()
        bindings.append(
            {
                "event_type": et,
                "player": player or None,
                "bound_ip": ip,
                "identical": int(best.get("identical_count") or best.get("max_burst") or 0),
                "vps_probe": bool(best.get("vps_probe")),
                "confidence": 0.55 if player else 0.35,
                "method": "top_burst_peer",
            }
        )

    return {
        "ok": True,
        "cheat_event_count": len(cheat_events),
        "bindings": bindings,
        "bound_at": time.time(),
    }


def apply_to_context(ctx: dict[str, Any], payload: dict[str, Any], *, bump) -> dict[str, Any]:
    result = bind(payload)
    for row in result.get("bindings") or []:
        ip = str(row.get("bound_ip") or "").strip()
        if not ip:
            continue
        bump(ip, float(row.get("confidence") or 0.35) * 0.25, f"killcam:{row.get('event_type')}")
        ctx.setdefault("signals", []).append(f"killcam_bind:{row.get('event_type')}")
    ctx["killcam_bindings"] = result
    return result


def _peer_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for path in (
        ("peer_tracker", "peers"),
        ("packets", "metrics", "inbound_identical_peers"),
        ("packet_analysis", "metrics", "inbound_identical_peers"),
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
