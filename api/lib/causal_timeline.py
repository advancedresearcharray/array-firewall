"""Causal session waterfall — probe → shield → block chains (stay-in-lobby audit)."""
from __future__ import annotations

import time
from typing import Any

from . import autopilot_audit, probe_intel, session_timeline


def _kind_bucket(kind: str, action_type: str = "") -> str:
    k = str(kind or action_type or "").lower()
    if "probe" in k:
        return "probe"
    if "shield" in k:
        return "shield"
    if "block" in k or "subnet" in k or "negative" in k:
        return "block"
    if "buffer" in k:
        return "buffer"
    if "upload" in k or "boost" in k:
        return "upload"
    if "conn" in k:
        return "conn"
    if "game_state" in k:
        return "game_state"
    return "other"


def _normalize_event(row: dict[str, Any], *, source: str) -> dict[str, Any]:
    ts = float(row.get("ts") or 0)
    kind = str(row.get("kind") or row.get("action_type") or "event")
    return {
        "id": f"{source}:{int(ts * 1000)}:{kind}",
        "ts": ts,
        "ts_iso": row.get("ts_iso") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "kind": kind,
        "bucket": _kind_bucket(kind, str(row.get("action_type") or "")),
        "detail": str(row.get("detail") or row.get("title") or ""),
        "phase": row.get("phase"),
        "source": source,
        "meta": row.get("meta") or {},
        "caused_by": None,
        "causal_label": None,
    }


def _link_causality(events: list[dict[str, Any]], *, window_sec: float = 90.0) -> None:
    """Link probe → shield → block within time window."""
    for i, ev in enumerate(events):
        if ev["bucket"] != "shield":
            continue
        best_probe = None
        best_dt = window_sec + 1
        for j in range(i - 1, -1, -1):
            prev = events[j]
            dt = float(ev["ts"]) - float(prev["ts"])
            if dt > window_sec:
                break
            if prev["bucket"] == "probe":
                if dt < best_dt:
                    best_dt = dt
                    best_probe = prev
        if best_probe:
            ev["caused_by"] = best_probe["id"]
            ev["causal_label"] = f"shield after probe ({int(best_dt)}s)"

    for i, ev in enumerate(events):
        if ev["bucket"] != "block":
            continue
        for j in range(i - 1, -1, -1):
            prev = events[j]
            dt = float(ev["ts"]) - float(prev["ts"])
            if dt > window_sec:
                break
            if prev["bucket"] in {"shield", "probe"}:
                ev["caused_by"] = prev["id"]
                ev["causal_label"] = f"block after {prev['bucket']} ({int(dt)}s)"
                break


def build(session_hex: str, *, limit: int = 150) -> dict[str, Any]:
    session_hex = str(session_hex or "").strip()
    if not session_hex:
        return {"ok": False, "error": "session_hex required"}

    base = session_timeline.build(session_hex, limit=limit * 2)
    events: list[dict[str, Any]] = []

    for row in base.get("events") or []:
        events.append(_normalize_event(row, source=str(row.get("source") or "session")))

    for row in autopilot_audit.recent(limit=limit, session_hex=session_hex):
        ts = float(row.get("ts") or 0)
        events.append(
            _normalize_event(
                {
                    "ts": ts,
                    "ts_iso": row.get("ts_iso"),
                    "kind": f"autopilot.{row.get('action_type')}",
                    "detail": row.get("detail"),
                    "phase": row.get("phase"),
                    "meta": row.get("meta") or {},
                    "action_type": row.get("action_type"),
                },
                source="autopilot",
            )
        )

    for row in probe_intel.session_peers(session_hex, limit=32):
        ts = float(row.get("last_seen") or 0)
        spread = row.get("size_spread")
        detail = f"{row.get('ip')} identical={row.get('identical_max')} vps={row.get('vps_probe')}"
        if spread is not None:
            detail += f" spread={spread}"
        events.append(
            _normalize_event(
                {
                    "ts": ts,
                    "kind": "probe_intel.indexed",
                    "detail": detail,
                    "meta": row,
                },
                source="probe_intel",
            )
        )

    events.sort(key=lambda e: float(e.get("ts") or 0))
    if len(events) > limit:
        events = events[-limit:]
    _link_causality(events)

    chains: list[dict[str, Any]] = []
    for ev in events:
        if ev.get("causal_label"):
            chains.append(
                {
                    "effect_id": ev["id"],
                    "cause_id": ev.get("caused_by"),
                    "label": ev.get("causal_label"),
                    "kind": ev.get("kind"),
                }
            )

    return {
        "ok": True,
        "session_hex": session_hex,
        "session": base.get("session"),
        "event_count": len(events),
        "events": events,
        "causal_chains": chains,
        "posture": "stay_and_mitigate",
        "state": base.get("state"),
    }
