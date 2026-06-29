"""Append-only session event log for match timeline and ops audit."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

EVENT_LOG = Path("/var/lib/array-firewall/session-events.jsonl")
MAX_LINES = 5000


def _now() -> float:
    return time.time()


def _iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts or _now()))


def append(
    kind: str,
    *,
    session_hex: str | None = None,
    phase: str | None = None,
    detail: str | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "ts": _now(),
        "ts_iso": _iso(),
        "kind": str(kind or "event").strip() or "event",
        "session_hex": (session_hex or "").strip() or None,
        "phase": (phase or "").strip() or None,
        "detail": (detail or "").strip() or None,
        "meta": meta or {},
    }
    with EVENT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, separators=(",", ":")) + "\n")
    _trim_log()
    return row


def _trim_log() -> None:
    if not EVENT_LOG.is_file():
        return
    try:
        lines = EVENT_LOG.read_text(encoding="utf-8").splitlines()
        if len(lines) <= MAX_LINES:
            return
        tail = lines[-MAX_LINES:]
        EVENT_LOG.write_text("\n".join(tail) + "\n", encoding="utf-8")
    except OSError:
        pass


def recent(
    *,
    session_hex: str | None = None,
    kind_prefix: str | None = None,
    since_ts: float | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    if not EVENT_LOG.is_file():
        return []
    limit = max(1, min(int(limit or 200), 1000))
    lines = EVENT_LOG.read_text(encoding="utf-8").splitlines()
    out: list[dict[str, Any]] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if session_hex and str(row.get("session_hex") or "") != session_hex.strip():
            continue
        if since_ts and float(row.get("ts") or 0) < since_ts:
            continue
        if kind_prefix and not str(row.get("kind") or "").startswith(kind_prefix):
            continue
        out.append(row)
        if len(out) >= limit:
            break
    return out
