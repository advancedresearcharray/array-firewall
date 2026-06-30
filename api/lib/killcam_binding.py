"""Bind game-state killcam/cheat events to peer_tracker burst windows."""
from __future__ import annotations

import re
import time
from typing import Any

CHEAT_TYPES = frozenset({"prefire", "snap", "wallhack", "cheater", "killcam_result"})


def bind(payload: dict[str, Any]) -> dict[str, Any]:
    gs = payload.get("game_state") or {}
    if not isinstance(gs, dict):
        return {"ok": True, "skipped": True}

    events = [e for e in (gs.get("events") or []) if isinstance(e, dict)]
    cheat_events = [e for e in events if str(e.get("type") or "").lower() in CHEAT_TYPES]
    if not cheat_events:
        return {"ok": True, "bindings": [], "cheat_event_count": 0}

    peers = _peer_rows(payload)
    if not peers:
        return {"ok": True, "bindings": [], "cheat_event_count": len(cheat_events)}

    now = time.time()
    bindings: list[dict[str, Any]] = []
    for ev in cheat_events[:8]:
        binding = _bind_event(ev, peers, now=now)
        if binding:
            bindings.append(binding)

    return {
        "ok": True,
        "cheat_event_count": len(cheat_events),
        "bindings": bindings,
        "bound_at": now,
    }


def _event_ts(ev: dict[str, Any], *, now: float) -> float | None:
    for key in ("ts", "timestamp", "event_ts"):
        val = ev.get(key)
        if val is None:
            continue
        try:
            ts = float(val)
            if ts > 1e12:
                ts /= 1000.0
            return ts
        except (TypeError, ValueError):
            pass
    offset = ev.get("offset_ms") or ev.get("age_ms")
    if offset is not None:
        try:
            return now - float(offset) / 1000.0
        except (TypeError, ValueError):
            pass
    return None


def _player_tokens(player: str) -> set[str]:
    player = player.strip().lower()
    if not player:
        return set()
    tokens = {player}
    tokens.update(re.findall(r"[a-z0-9]{3,}", player))
    return tokens


def _peer_player_match(peer: dict[str, Any], tokens: set[str]) -> bool:
    if not tokens:
        return False
    hay = " ".join(
        str(peer.get(k) or "")
        for k in ("player", "gamertag", "name", "role", "roleId", "label", "vendor")
    ).lower()
    return any(tok in hay for tok in tokens)


def _score_peer(peer: dict[str, Any], ev: dict[str, Any], *, event_ts: float | None, now: float) -> tuple[float, dict[str, Any]]:
    ip = str(peer.get("ip") or peer.get("remote") or "").split(":")[0].strip()
    identical = int(peer.get("identical_count") or peer.get("max_burst") or 0)
    vps = bool(peer.get("vps_probe"))
    player = str(ev.get("player") or "").strip()
    tokens = _player_tokens(player)
    victim_ip = str(ev.get("victim_ip") or ev.get("attacker_ip") or "").split(":")[0].strip()

    score = 0.0
    reasons: list[str] = []

    if victim_ip and ip == victim_ip:
        score += 0.55
        reasons.append("victim_ip")
    if _peer_player_match(peer, tokens):
        score += 0.35
        reasons.append("player_match")
    if identical >= 20:
        score += 0.25
        reasons.append("identical_high")
    elif identical >= 8:
        score += 0.15
        reasons.append("identical_mid")
    if vps:
        score += 0.12
        reasons.append("vps_probe")

    last_seen = peer.get("last_seen") or peer.get("last_burst_ts")
    if event_ts is not None and last_seen is not None:
        try:
            delta = abs(float(last_seen) - float(event_ts))
            if delta <= 8.0:
                score += 0.22
                reasons.append("burst_window")
            elif delta <= 20.0:
                score += 0.1
                reasons.append("burst_near")
        except (TypeError, ValueError):
            pass
    elif identical >= 10:
        score += 0.08
        reasons.append("active_burst")

    method = "fusion"
    if "victim_ip" in reasons:
        method = "victim_ip"
    elif "player_match" in reasons:
        method = "player_match"
    elif "burst_window" in reasons:
        method = "burst_window"
    elif score < 0.2:
        method = "weak_signal"

    return round(min(1.0, score), 3), {
        "ip": ip,
        "identical": identical,
        "vps_probe": vps,
        "reasons": reasons,
        "method": method,
    }


def _bind_event(ev: dict[str, Any], peers: list[dict[str, Any]], *, now: float) -> dict[str, Any] | None:
    et = str(ev.get("type") or "").lower()
    player = str(ev.get("player") or "").strip()
    event_ts = _event_ts(ev, now=now)
    ranked: list[tuple[float, dict[str, Any]]] = []
    for peer in peers:
        ip = str(peer.get("ip") or peer.get("remote") or "").split(":")[0].strip()
        if not ip or ip.startswith(("10.", "192.168.", "127.")):
            continue
        score, meta = _score_peer(peer, ev, event_ts=event_ts, now=now)
        if score >= 0.18:
            ranked.append((score, meta))
    if not ranked:
        top = sorted(
            peers,
            key=lambda p: int(p.get("identical_count") or p.get("max_burst") or 0),
            reverse=True,
        )[0]
        ip = str(top.get("ip") or top.get("remote") or "").split(":")[0].strip()
        if not ip:
            return None
        return {
            "event_type": et,
            "player": player or None,
            "bound_ip": ip,
            "identical": int(top.get("identical_count") or top.get("max_burst") or 0),
            "vps_probe": bool(top.get("vps_probe")),
            "confidence": 0.25,
            "method": "top_burst_peer_fallback",
        }

    ranked.sort(key=lambda row: row[0], reverse=True)
    best_score, meta = ranked[0]
    return {
        "event_type": et,
        "player": player or None,
        "bound_ip": meta["ip"],
        "identical": meta["identical"],
        "vps_probe": meta["vps_probe"],
        "confidence": best_score,
        "method": meta["method"],
        "reasons": meta["reasons"],
        "candidates": len(ranked),
    }


def apply_to_context(ctx: dict[str, Any], payload: dict[str, Any], *, bump) -> dict[str, Any]:
    result = bind(payload)
    for row in result.get("bindings") or []:
        ip = str(row.get("bound_ip") or "").strip()
        if not ip:
            continue
        conf = float(row.get("confidence") or 0.35)
        bump(ip, conf * 0.45, f"killcam:{row.get('event_type')}:{row.get('method')}")
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
