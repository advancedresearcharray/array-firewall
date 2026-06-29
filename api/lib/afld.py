"""AFLD — Array-Firewall Log Dimensional storage (24h retention, Zenodo fold compression).

Uses ``folding.compress_json_store`` / 8196→32D fold + BLSB + gzip stack
(see https://zenodo.org/records/18102374).
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from . import folding, policies

AFLD_ROOT = Path("/var/lib/array-firewall/afld")
HOT_LOG = AFLD_ROOT / "hot.jsonl"
SEG_DIR = AFLD_ROOT / "segments"
INDEX_PATH = AFLD_ROOT / "index.json"
_LOCK = threading.Lock()

DEFAULT_RETENTION_SEC = 86400
DEFAULT_ROLLUP_BYTES = 8192


def _cfg() -> dict[str, Any]:
    gaming = policies.gaming()
    base = {
        "enabled": True,
        "retention_sec": DEFAULT_RETENTION_SEC,
        "rollup_min_bytes": DEFAULT_ROLLUP_BYTES,
        "kinds": ["wan_scan", "probe_sink", "honeypot"],
    }
    base.update(gaming.get("afld") or {})
    base.update(policies.load().get("afld") or {})
    return base


def _now() -> float:
    return time.time()


def _iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts or _now()))


def _load_index() -> dict[str, Any]:
    if not INDEX_PATH.is_file():
        return {"segments": [], "updated": 0}
    try:
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"segments": [], "updated": 0}


def _save_index(data: dict[str, Any]) -> None:
    AFLD_ROOT.mkdir(parents=True, exist_ok=True)
    data["updated"] = _now()
    tmp = INDEX_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(INDEX_PATH)


def _maybe_block_scanner(kind: str, row: dict[str, Any]) -> dict[str, Any] | None:
    """Block inbound port scanners as soon as AFLD records them."""
    if kind not in {"wan_scan", "probe_sink", "honeypot"}:
        return None
    ip = str(row.get("ip") or row.get("src") or "").strip()
    if not ip:
        return None
    try:
        from . import wan_scan_block

        return wan_scan_block.block_scanner(
            ip,
            reason=str(kind),
            port=row.get("port"),
            proto=row.get("proto"),
        )
    except Exception:
        return None


def append(
    kind: str,
    row: dict[str, Any],
    *,
    ts: float | None = None,
) -> dict[str, Any]:
    """Append one log row to the hot buffer."""
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": False, "skipped": True, "reason": "afld_disabled"}
    stamp = ts if ts is not None else _now()
    entry = {
        "ts": stamp,
        "ts_iso": _iso(stamp),
        "kind": str(kind or "event").strip() or "event",
        **{k: v for k, v in row.items() if k not in {"ts", "ts_iso", "kind"}},
    }
    AFLD_ROOT.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        with HOT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        hot_bytes = HOT_LOG.stat().st_size if HOT_LOG.is_file() else 0
    out: dict[str, Any] = {"ok": True, "appended": entry, "hot_bytes": hot_bytes}
    blocked = _maybe_block_scanner(kind, entry)
    if blocked:
        out["blocked"] = blocked
    min_bytes = int(cfg.get("rollup_min_bytes") or DEFAULT_ROLLUP_BYTES)
    if hot_bytes >= min_bytes:
        out["rollup"] = rollup()
    return out


def _read_hot(*, since_ts: float | None = None) -> list[dict[str, Any]]:
    if not HOT_LOG.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in HOT_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if since_ts and float(row.get("ts") or 0) < since_ts:
            continue
        rows.append(row)
    return rows


def rollup(*, force: bool = False) -> dict[str, Any]:
    """Roll hot JSONL into a folded segment and clear hot buffer."""
    cfg = _cfg()
    if not HOT_LOG.is_file():
        return {"ok": True, "rolled": 0, "reason": "hot_empty"}
    hot_bytes = HOT_LOG.stat().st_size
    min_bytes = int(cfg.get("rollup_min_bytes") or DEFAULT_ROLLUP_BYTES)
    if not force and hot_bytes < min_bytes:
        return {"ok": True, "rolled": 0, "reason": "below_threshold", "hot_bytes": hot_bytes}

    with _LOCK:
        lines = HOT_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        rows: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if not rows:
            HOT_LOG.unlink(missing_ok=True)
            return {"ok": True, "rolled": 0, "reason": "no_parseable_rows"}

        seg_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        folded = folding.compress_json_store(rows)
        SEG_DIR.mkdir(parents=True, exist_ok=True)
        seg_path = SEG_DIR / f"{seg_id}.afld.json"
        segment = {
            "segment_id": seg_id,
            "count": len(rows),
            "ts_start": min(float(r.get("ts") or 0) for r in rows),
            "ts_end": max(float(r.get("ts") or 0) for r in rows),
            "kinds": sorted({str(r.get("kind") or "") for r in rows if r.get("kind")}),
            "folded": folded,
        }
        seg_path.write_text(json.dumps(segment, indent=2) + "\n", encoding="utf-8")
        HOT_LOG.unlink(missing_ok=True)

        idx = _load_index()
        idx.setdefault("segments", []).append(
            {
                "segment_id": seg_id,
                "path": str(seg_path),
                "count": len(rows),
                "ts_start": segment["ts_start"],
                "ts_end": segment["ts_end"],
                "kinds": segment["kinds"],
                "orig_size": folded.get("orig_size"),
                "compressed_size": folded.get("compressed_size"),
                "ratio": folded.get("ratio"),
            }
        )
        _save_index(idx)

    prune_result = prune()
    return {
        "ok": True,
        "rolled": len(rows),
        "segment_id": seg_id,
        "orig_size": folded.get("orig_size"),
        "compressed_size": folded.get("compressed_size"),
        "ratio": folded.get("ratio"),
        "prune": prune_result,
    }


def prune(*, retention_sec: int | None = None) -> dict[str, Any]:
    """Drop segments and hot rows older than retention window (default 24h)."""
    cfg = _cfg()
    retain = int(retention_sec or cfg.get("retention_sec") or DEFAULT_RETENTION_SEC)
    cutoff = _now() - retain
    removed = 0
    idx = _load_index()
    kept: list[dict[str, Any]] = []
    for seg in idx.get("segments") or []:
        if float(seg.get("ts_end") or 0) < cutoff:
            path = Path(str(seg.get("path") or ""))
            if path.is_file():
                path.unlink(missing_ok=True)
            removed += 1
        else:
            kept.append(seg)
    idx["segments"] = kept
    _save_index(idx)

    hot_kept = 0
    if HOT_LOG.is_file():
        rows = _read_hot(since_ts=cutoff)
        hot_kept = len(rows)
        if hot_kept != len(_read_hot()):
            with HOT_LOG.open("w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, separators=(",", ":")) + "\n")

    return {"ok": True, "removed_segments": removed, "retention_sec": retain, "hot_rows": hot_kept}


def _load_segment_rows(seg_meta: dict[str, Any]) -> list[dict[str, Any]]:
    path = Path(str(seg_meta.get("path") or ""))
    if not path.is_file():
        return []
    try:
        segment = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    folded = segment.get("folded") or {}
    if not folded.get("_folded"):
        return segment.get("rows") or []
    try:
        data = folding.decompress_json_store(folded)
    except Exception:
        return []
    return data if isinstance(data, list) else []


def query(
    *,
    kind: str | None = None,
    ip: str | None = None,
    since_ts: float | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Query hot buffer + decompressed segments within retention."""
    cfg = _cfg()
    retain = int(cfg.get("retention_sec") or DEFAULT_RETENTION_SEC)
    since = since_ts if since_ts is not None else (_now() - retain)
    limit = max(1, min(int(limit or 500), 5000))
    rows: list[dict[str, Any]] = []

    for row in _read_hot(since_ts=since):
        if kind and str(row.get("kind") or "") != kind:
            continue
        if ip and str(row.get("ip") or "") != ip.strip():
            continue
        rows.append(row)

    idx = _load_index()
    for seg in reversed(idx.get("segments") or []):
        if float(seg.get("ts_end") or 0) < since:
            continue
        if kind and kind not in (seg.get("kinds") or []):
            continue
        for row in _load_segment_rows(seg):
            if float(row.get("ts") or 0) < since:
                continue
            if kind and str(row.get("kind") or "") != kind:
                continue
            if ip and str(row.get("ip") or "") != ip.strip():
                continue
            rows.append(row)

    rows.sort(key=lambda r: float(r.get("ts") or 0), reverse=True)
    return rows[:limit]


def scanner_summary(*, hours: float = 24, limit: int = 200) -> list[dict[str, Any]]:
    """Aggregate WAN scan events by source IP."""
    since = _now() - (float(hours) * 3600.0)
    rows = query(kind="wan_scan", since_ts=since, limit=10000)
    by_ip: dict[str, dict[str, Any]] = {}
    for row in rows:
        sip = str(row.get("ip") or "").strip()
        if not sip:
            continue
        slot = by_ip.setdefault(
            sip,
            {
                "ip": sip,
                "attempts": 0,
                "ports": set(),
                "protos": set(),
                "actions": set(),
                "first_seen": row.get("ts_iso"),
                "last_seen": row.get("ts_iso"),
                "last_ts": float(row.get("ts") or 0),
            },
        )
        slot["attempts"] += 1
        port = row.get("port")
        if port is not None:
            slot["ports"].add(int(port))
        proto = row.get("proto")
        if proto:
            slot["protos"].add(str(proto))
        action = row.get("action")
        if action:
            slot["actions"].add(str(action))
        ts = float(row.get("ts") or 0)
        if ts >= slot["last_ts"]:
            slot["last_ts"] = ts
            slot["last_seen"] = row.get("ts_iso")
        if row.get("ts_iso") and (not slot.get("first_seen") or ts < float(row.get("first_ts") or ts)):
            slot["first_seen"] = row.get("ts_iso")

    out: list[dict[str, Any]] = []
    for sip, slot in by_ip.items():
        out.append(
            {
                "ip": sip,
                "attempts": slot["attempts"],
                "ports": sorted(slot["ports"])[:24],
                "port_count": len(slot["ports"]),
                "protos": sorted(slot["protos"]),
                "actions": sorted(slot["actions"]),
                "first_seen": slot["first_seen"],
                "last_seen": slot["last_seen"],
            }
        )
    out.sort(key=lambda r: (-r["attempts"], r["ip"]))
    return out[: max(1, min(int(limit or 200), 1000))]


def status() -> dict[str, Any]:
    cfg = _cfg()
    idx = _load_index()
    hot_bytes = HOT_LOG.stat().st_size if HOT_LOG.is_file() else 0
    hot_rows = len(_read_hot())
    segs = idx.get("segments") or []
    compressed_total = sum(int(s.get("compressed_size") or 0) for s in segs)
    orig_total = sum(int(s.get("orig_size") or 0) for s in segs)
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "retention_sec": int(cfg.get("retention_sec") or DEFAULT_RETENTION_SEC),
        "retention_hours": round(int(cfg.get("retention_sec") or DEFAULT_RETENTION_SEC) / 3600, 1),
        "hot_bytes": hot_bytes,
        "hot_rows": hot_rows,
        "segment_count": len(segs),
        "segments_orig_bytes": orig_total,
        "segments_compressed_bytes": compressed_total,
        "compression_ratio": round(orig_total / max(compressed_total, 1), 2) if compressed_total else None,
        "zenodo": "https://zenodo.org/records/18102374",
        "pipeline": ["pattern_rle", "fold8196→32", "blsb", "gzip"],
        "kinds": cfg.get("kinds") or [],
        "root": str(AFLD_ROOT),
    }
