"""Autopilot action timeline and one-tick undo (playability-safe rollback)."""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from . import ids_enforce, peer_blocklist, session_events

TIMELINE_FILE = Path("/var/lib/array-firewall/autopilot-timeline.jsonl")
UNDO_STACK_FILE = Path("/var/lib/array-firewall/autopilot-undo-stack.json")
MAX_TIMELINE = 500


def _now() -> float:
    return time.time()


def _iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts or _now()))


def append_event(
    *,
    tick_id: str,
    source: str,
    action_type: str,
    detail: str,
    session_hex: str | None = None,
    phase: str | None = None,
    meta: dict[str, Any] | None = None,
    reversible: bool = False,
    undo: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "ts": _now(),
        "ts_iso": _iso(),
        "tick_id": tick_id,
        "source": source,
        "action_type": action_type,
        "detail": detail,
        "session_hex": session_hex,
        "phase": phase,
        "meta": meta or {},
        "reversible": reversible,
        "undo": undo,
    }
    TIMELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with TIMELINE_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, separators=(",", ":")) + "\n")
    _trim()
    session_events.append(
        f"autopilot.{action_type}",
        session_hex=session_hex,
        phase=phase,
        detail=detail,
        meta={"tick_id": tick_id, **(meta or {})},
    )
    return row


def record_tick(
    *,
    source: str,
    session_hex: str | None,
    phase: str | None,
    executed: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> str:
    tick_id = uuid.uuid4().hex[:12]
    undo_ops: list[dict[str, Any]] = []
    for ex in executed:
        typ = str(ex.get("type") or "")
        detail = typ
        meta = {"result": ex.get("result")}
        undo_spec: dict[str, Any] | None = None
        rev = False

        if typ == "block_peer":
            ip = ex.get("ip") or ""
            detail = f"block peer {ip}"
            undo_spec = {"op": "unblock_peer", "ip": ip}
            rev = True
        elif typ == "block_subnet":
            ip = ex.get("ip") or ""
            res = ex.get("result") or {}
            cidrs = res.get("blocked") or res.get("cidrs") or []
            detail = f"block subnet from {ip}"
            undo_spec = {"op": "unblock_subnet", "cidrs": cidrs, "ip": ip}
            rev = bool(cidrs or ip)
        elif typ == "ids_block":
            ips = ex.get("ips") or []
            detail = f"ids block {len(ips)} ip(s)"
            undo_spec = {"op": "ids_unblock", "ips": ips}
            rev = bool(ips)
        elif typ == "shield":
            level = ex.get("level") or "?"
            prev = (context or {}).get("prev_shield_level") or "normal"
            detail = f"shield → {level}"
            undo_spec = {"op": "shield_restore", "level": prev}
            rev = True
        elif typ == "buffer_tune":
            profile = ex.get("profile") or "?"
            prev = (context or {}).get("prev_buffer_profile") or "gaming"
            detail = f"buffer → {profile}"
            undo_spec = {"op": "buffer_restore", "profile": prev}
            rev = True
        else:
            detail = typ

        append_event(
            tick_id=tick_id,
            source=source,
            action_type=typ,
            detail=detail,
            session_hex=session_hex,
            phase=phase,
            meta=meta,
            reversible=rev,
            undo=undo_spec,
        )
        if rev and undo_spec:
            undo_ops.append(undo_spec)

    if undo_ops:
        stack = _load_stack()
        stack.insert(
            0,
            {
                "tick_id": tick_id,
                "ts": _now(),
                "source": source,
                "session_hex": session_hex,
                "ops": undo_ops,
            },
        )
        _save_stack(stack[:5])
    return tick_id


def _load_stack() -> list[dict[str, Any]]:
    if not UNDO_STACK_FILE.is_file():
        return []
    try:
        return list(json.loads(UNDO_STACK_FILE.read_text(encoding="utf-8")).get("stack") or [])
    except (json.JSONDecodeError, OSError):
        return []


def _save_stack(stack: list[dict[str, Any]]) -> None:
    UNDO_STACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    UNDO_STACK_FILE.write_text(json.dumps({"stack": stack}, indent=2) + "\n", encoding="utf-8")


def undo_last() -> dict[str, Any]:
    stack = _load_stack()
    if not stack:
        return {"ok": False, "error": "nothing to undo"}
    entry = stack.pop(0)
    results: list[dict[str, Any]] = []
    for op in entry.get("ops") or []:
        kind = op.get("op")
        if kind == "unblock_peer" and op.get("ip"):
            results.append(peer_blocklist.remove_peers([str(op["ip"])]))
        elif kind == "unblock_subnet":
            try:
                from . import subnet_blocklist as sb

                cidrs = op.get("cidrs") or []
                if not cidrs and op.get("ip"):
                    r = sb.block_from_ips([str(op["ip"])], reason="undo_lookup", source="undo")
                    cidrs = r.get("blocked") or []
                for c in cidrs:
                    results.append(sb.remove_subnet(str(c)))
            except ImportError:
                results.append({"ok": False, "error": "subnet_blocklist missing"})
        elif kind == "ids_unblock":
            for ip in op.get("ips") or []:
                results.append(ids_enforce.unblock_ip(str(ip)))
        elif kind == "shield_restore":
            results.append(peer_blocklist.sync_shield(level=str(op.get("level") or "normal")))
        elif kind == "buffer_restore":
            try:
                from . import qos

                results.append(qos.buffer_tune_apply(str(op.get("profile") or "gaming")))
            except Exception as exc:
                results.append({"ok": False, "error": str(exc)})
    _save_stack(stack)
    append_event(
        tick_id=entry.get("tick_id") or "undo",
        source="undo",
        action_type="undo",
        detail=f"Reverted tick {entry.get('tick_id')}",
        session_hex=entry.get("session_hex"),
        meta={"ops": len(entry.get("ops") or [])},
    )
    return {"ok": True, "reverted_tick": entry.get("tick_id"), "results": results}


def recent(*, limit: int = 40, session_hex: str | None = None) -> list[dict[str, Any]]:
    if not TIMELINE_FILE.is_file():
        return []
    lines = TIMELINE_FILE.read_text(encoding="utf-8").splitlines()
    out: list[dict[str, Any]] = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if session_hex and str(row.get("session_hex") or "") != session_hex:
            continue
        out.append(row)
        if len(out) >= limit:
            break
    return out


def _trim() -> None:
    if not TIMELINE_FILE.is_file():
        return
    try:
        lines = TIMELINE_FILE.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_TIMELINE:
            TIMELINE_FILE.write_text("\n".join(lines[-MAX_TIMELINE:]) + "\n")
    except OSError:
        pass


def status() -> dict[str, Any]:
    stack = _load_stack()
    return {
        "ok": True,
        "undo_available": bool(stack),
        "last_undo_tick": stack[0].get("tick_id") if stack else None,
        "recent": recent(limit=15),
    }
