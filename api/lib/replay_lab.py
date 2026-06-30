"""Offline fusion replay lab — tune thresholds without live Xbox traffic."""
from __future__ import annotations

import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import ai_ops, policies

SESSION_ROOTS = (
    Path("/var/lib/warzone-sentinel/sessions"),
    Path("/opt/warzone-lobby-sentinel/logs/sessions"),
)


@contextmanager
def _ai_ops_mode(mode: str) -> Iterator[str | None]:
    """Temporarily set ai_ops.mode without persisting unrelated policy edits."""
    data = policies.load()
    ai = dict(data.get("ai_ops") or {})
    saved = ai.get("mode")
    ai["mode"] = mode
    ai["ollama_planner"] = False
    ai["auto_ids_scan"] = False
    data["ai_ops"] = ai
    policies.save(data)
    try:
        yield saved
    finally:
        data = policies.load()
        ai = dict(data.get("ai_ops") or {})
        if saved is None:
            ai.pop("mode", None)
        else:
            ai["mode"] = saved
        data["ai_ops"] = ai
        policies.save(data)


def _load_peers_from_path(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    doc = json.loads(path.read_text(encoding="utf-8"))
    if "detail" in doc and isinstance(doc["detail"], dict):
        return doc["detail"]
    if "peers" in doc:
        return doc
    if "files" in doc:
        for f in doc["files"]:
            data = f.get("data") or {}
            if data.get("peers"):
                return data
    raise ValueError(f"no peers in {path}")


def list_sources(*, limit: int = 40) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in SESSION_ROOTS:
        if not root.is_dir():
            continue
        for meta in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime if p.is_dir() else 0, reverse=True):
            if not meta.is_dir():
                continue
            hex_id = meta.name
            if hex_id in seen:
                continue
            seen.add(hex_id)
            peers_path = meta / "peers.latest.json"
            row = {
                "session_hex": hex_id,
                "path": str(peers_path if peers_path.is_file() else meta),
                "mtime": meta.stat().st_mtime,
            }
            if peers_path.is_file():
                try:
                    doc = json.loads(peers_path.read_text(encoding="utf-8"))
                    row["peer_count"] = len(doc.get("peers") or [])
                except (json.JSONDecodeError, OSError):
                    row["peer_count"] = 0
            out.append(row)
            if len(out) >= limit:
                return out
    return out


def replay_payload(payload: dict[str, Any], *, mode: str = "observe") -> dict[str, Any]:
    """Replay a session payload dict through fusion (golden-session CI)."""
    with _ai_ops_mode(mode):
        tick = ai_ops.tick(sentinel_payload=payload, source="replay_lab", force=True)
    plan = tick.get("plan") or {}
    return {
        "ok": True,
        "mode": mode,
        "verdict": plan.get("verdict"),
        "execution": tick.get("execution") or {},
        "plan": plan,
        "context": tick.get("context") or {},
    }


def replay_path(path: Path, *, mode: str = "observe", restore_mode: str | None = None) -> dict[str, Any]:
    peers_doc = _load_peers_from_path(path)
    payload = {
        "peer_tracker": {"peers": peers_doc.get("peers") or [], "session_hex": peers_doc.get("session_hex")},
        "phase": peers_doc.get("phase") or "matchmaking",
        "session_hex": peers_doc.get("session_hex"),
    }
    effective_mode = mode
    with _ai_ops_mode(effective_mode):
        result = ai_ops.tick(sentinel_payload=payload, force=True, source=f"replay:{path.name}")
    return {
        "ok": True,
        "path": str(path),
        "mode": effective_mode,
        "restored_mode": restore_mode,
        "replay_at": time.time(),
        "tick": result,
    }


def replay_session_hex(session_hex: str, *, mode: str = "observe") -> dict[str, Any]:
    hex_id = session_hex.strip()
    for root in SESSION_ROOTS:
        cand = root / hex_id / "peers.latest.json"
        if cand.is_file():
            return replay_path(cand, mode=mode)
        export = root / hex_id / "export.json"
        if export.is_file():
            return replay_path(export, mode=mode)
    raise FileNotFoundError(f"session {hex_id} not found")


def batch_replay(sessions: list[str], *, mode: str = "observe") -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for hex_id in sessions[:20]:
        try:
            results.append(replay_session_hex(hex_id, mode=mode))
        except Exception as exc:
            errors.append({"session_hex": hex_id, "error": str(exc)})
    planned = sum(len((r.get("tick") or {}).get("plan", {}).get("actions") or []) for r in results)
    executed = sum(
        len((r.get("tick") or {}).get("execution", {}).get("executed") or []) for r in results
    )
    return {
        "ok": True,
        "replayed": len(results),
        "errors": errors,
        "total_planned_actions": planned,
        "total_executed_actions": executed,
        "results": results,
    }


def status() -> dict[str, Any]:
    cfg = policies.load().get("ai_ops") or {}
    sources = list_sources(limit=5)
    return {
        "ok": True,
        "enabled": cfg.get("replay_lab_enabled", True),
        "session_roots": [str(p) for p in SESSION_ROOTS if p.is_dir()],
        "recent_sessions": sources,
        "count": len(list_sources(limit=200)),
    }
