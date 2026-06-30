"""Build per-session timeline from events, conn DB, probe sink, and state files."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import conn_lite_db, probe_sink, session_events

STATE_FILES = {
    "shield": Path("/var/lib/array-firewall/packet-shield.state"),
    "buffer": Path("/var/lib/array-firewall/buffer-tune.state"),
    "upload_boost": Path("/var/lib/array-firewall/upload-boost.state"),
    "download_boost": Path("/var/lib/array-firewall/download-boost.state"),
    "route_pref": Path("/var/lib/array-firewall/gaming-route.state"),
}


def _parse_kv(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _session_meta(session_hex: str) -> dict[str, Any] | None:
    sessions = conn_lite_db.list_sessions(limit=200).get("sessions") or []
    for row in sessions:
        if str(row.get("session_hex") or "") == session_hex:
            return row
    return None


def _conn_milestones(session_hex: str, *, started_at: float | None) -> list[dict[str, Any]]:
    q = conn_lite_db.query(session_hex=session_hex, limit=200, offset=0)
    rows = q.get("rows") or []
    events: list[dict[str, Any]] = []
    type_first: dict[str, float] = {}
    for row in rows:
        ctype = str(row.get("conn_type") or "unknown")
        ts = float(row.get("first_seen") or row.get("last_seen") or 0)
        if started_at and ts < started_at - 60:
            continue
        if ctype not in type_first or ts < type_first[ctype]:
            type_first[ctype] = ts
    for ctype, ts in sorted(type_first.items(), key=lambda x: x[1]):
        events.append(
            {
                "ts": ts,
                "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
                "kind": "conn.first",
                "detail": f"first {ctype}",
                "meta": {"conn_type": ctype},
            }
        )
    block_rows = [r for r in rows if str(r.get("policy") or "") == "block"]
    if block_rows:
        events.append(
            {
                "ts": max(float(r.get("last_seen") or 0) for r in block_rows),
                "ts_iso": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime(max(float(r.get("last_seen") or 0) for r in block_rows)),
                ),
                "kind": "conn.blocked",
                "detail": f"{len(block_rows)} blocked IP(s) in session",
                "meta": {"count": len(block_rows)},
            }
        )
    return events


def _probe_events(session_hex: str, *, since_ts: float | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ev in probe_sink.recent_events(limit=300):
        meta = ev.get("meta") or {}
        if str(meta.get("session_hex") or "") != session_hex:
            continue
        ts_str = str(ev.get("ts") or "")
        try:
            ts = time.mktime(time.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S"))
        except (ValueError, TypeError):
            ts = time.time()
        if since_ts and ts < since_ts:
            continue
        out.append(
            {
                "ts": ts,
                "ts_iso": ts_str,
                "kind": "probe",
                "detail": f"{ev.get('ip')}:{ev.get('port')} {ev.get('reason')}",
                "meta": ev,
            }
        )
    return out


def build(session_hex: str, *, limit: int = 150) -> dict[str, Any]:
    session_hex = session_hex.strip()
    if not session_hex:
        return {"ok": False, "error": "session_hex required"}

    meta = _session_meta(session_hex)
    started_at = float(meta.get("started_at") or 0) if meta else None
    since_ts = (started_at - 120) if started_at else None

    events: list[dict[str, Any]] = []

    for row in session_events.recent(session_hex=session_hex, limit=limit):
        events.append(
            {
                "ts": float(row.get("ts") or 0),
                "ts_iso": row.get("ts_iso"),
                "kind": row.get("kind"),
                "detail": row.get("detail"),
                "phase": row.get("phase"),
                "meta": row.get("meta") or {},
                "source": "session_events",
            }
        )

    events.extend(_conn_milestones(session_hex, started_at=started_at))
    events.extend(_probe_events(session_hex, since_ts=since_ts))

    # Snapshot current subsystem state as timeline tail markers
    now = time.time()
    shield = _parse_kv(STATE_FILES["shield"])
    if shield.get("mode") == "shield":
        events.append(
            {
                "ts": now,
                "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "kind": "state.shield",
                "detail": f"level={shield.get('level', '?')}",
                "meta": shield,
                "source": "state",
            }
        )
    buffer = _parse_kv(STATE_FILES["buffer"])
    if buffer.get("profile"):
        events.append(
            {
                "ts": now,
                "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "kind": "state.buffer",
                "detail": f"profile={buffer.get('profile')}",
                "meta": buffer,
                "source": "state",
            }
        )
    upload = _parse_kv(STATE_FILES["upload_boost"])
    if upload.get("active") == "1" or upload.get("mode") == "boost":
        events.append(
            {
                "ts": now,
                "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "kind": "state.upload_boost",
                "detail": "upload assist active",
                "meta": upload,
                "source": "state",
            }
        )

    events.sort(key=lambda e: float(e.get("ts") or 0))
    if len(events) > limit:
        events = events[-limit:]

    return {
        "ok": True,
        "session_hex": session_hex,
        "session": meta,
        "event_count": len(events),
        "events": events,
        "state": {name: _parse_kv(path) for name, path in STATE_FILES.items()},
    }
