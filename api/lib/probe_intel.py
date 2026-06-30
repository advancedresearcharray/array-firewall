"""Parallel probe/VPS peer index — not dropped like conn-lite SKIP_CONN_TYPES."""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

DB_PATH = Path("/var/lib/array-firewall/probe-intel.db")
_LOCK = threading.Lock()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS probe_peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_hex TEXT NOT NULL,
            ip TEXT NOT NULL,
            identical_max INTEGER NOT NULL DEFAULT 0,
            vps_probe INTEGER NOT NULL DEFAULT 0,
            size_spread REAL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            hit_count INTEGER NOT NULL DEFAULT 1,
            UNIQUE(session_hex, ip)
        );
        CREATE INDEX IF NOT EXISTS idx_probe_session ON probe_peers(session_hex, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_probe_ip ON probe_peers(ip, last_seen DESC);
        """
    )
    return conn


def ingest_session_peers(session_hex: str, peers: list[dict[str, Any]]) -> dict[str, Any]:
    session_hex = str(session_hex or "").strip()
    if not session_hex or not peers:
        return {"ok": True, "ingested": 0}
    now = time.time()
    ingested = 0
    with _LOCK:
        conn = _connect()
        try:
            for row in peers:
                ip = str(row.get("ip") or row.get("remote") or "").split(":")[0].strip()
                if not ip or ip.startswith(("10.", "192.168.", "127.")):
                    continue
                identical = int(row.get("identical_count") or row.get("max_burst") or 0)
                vps = 1 if row.get("vps_probe") else 0
                sizes = row.get("sizes") or row.get("packet_sizes") or []
                spread = None
                if isinstance(sizes, list) and len(sizes) >= 2:
                    try:
                        nums = [float(s) for s in sizes]
                        spread = max(nums) - min(nums)
                    except (TypeError, ValueError):
                        spread = None
                if identical < 4 and not vps and (spread is None or spread > 8):
                    continue
                conn.execute(
                    """
                    INSERT INTO probe_peers (session_hex, ip, identical_max, vps_probe, size_spread,
                        first_seen, last_seen, hit_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(session_hex, ip) DO UPDATE SET
                        identical_max = MAX(identical_max, excluded.identical_max),
                        vps_probe = MAX(vps_probe, excluded.vps_probe),
                        size_spread = COALESCE(excluded.size_spread, size_spread),
                        last_seen = excluded.last_seen,
                        hit_count = hit_count + 1
                    """,
                    (session_hex, ip, identical, vps, spread, now, now),
                )
                ingested += 1
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "ingested": ingested, "session_hex": session_hex}


def session_peers(session_hex: str, *, limit: int = 64) -> list[dict[str, Any]]:
    session_hex = str(session_hex or "").strip()
    if not session_hex:
        return []
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT ip, identical_max, vps_probe, size_spread, first_seen, last_seen, hit_count
            FROM probe_peers WHERE session_hex = ? ORDER BY last_seen DESC LIMIT ?
            """,
            (session_hex, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def ip_history(ip: str, *, limit: int = 32) -> list[dict[str, Any]]:
    ip = str(ip or "").strip().split(":")[0]
    if not ip:
        return []
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT session_hex, identical_max, vps_probe, size_spread, first_seen, last_seen, hit_count
            FROM probe_peers WHERE ip = ? ORDER BY last_seen DESC LIMIT ?
            """,
            (ip, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def lookup_ip(ip: str) -> dict[str, Any]:
    ip = str(ip or "").strip().split(":")[0]
    if not ip:
        return {"ok": False, "error": "ip required"}
    conn = _connect()
    try:
        row = conn.execute(
            """
            SELECT ip,
                COUNT(DISTINCT session_hex) AS session_count,
                MAX(identical_max) AS identical_max,
                MAX(vps_probe) AS vps_probe,
                MIN(first_seen) AS first_seen,
                MAX(last_seen) AS last_seen,
                SUM(hit_count) AS hit_count
            FROM probe_peers WHERE ip = ? GROUP BY ip
            """,
            (ip,),
        ).fetchone()
        if not row:
            return {"ok": True, "ip": ip, "session_count": 0, "history": []}
        out = dict(row)
        out["ok"] = True
        out["history"] = ip_history(ip, limit=12)
        return out
    finally:
        conn.close()


def repeat_offenders(*, min_sessions: int = 2, limit: int = 24) -> list[dict[str, Any]]:
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT ip,
                COUNT(DISTINCT session_hex) AS session_count,
                MAX(identical_max) AS identical_max,
                MAX(vps_probe) AS vps_probe,
                MAX(last_seen) AS last_seen,
                SUM(hit_count) AS hit_count
            FROM probe_peers
            GROUP BY ip
            HAVING session_count >= ?
            ORDER BY session_count DESC, identical_max DESC, last_seen DESC
            LIMIT ?
            """,
            (max(1, int(min_sessions)), limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def status() -> dict[str, Any]:
    conn = _connect()
    try:
        n = conn.execute("SELECT COUNT(*) AS c FROM probe_peers").fetchone()
        offenders = repeat_offenders(min_sessions=2, limit=8)
        return {
            "ok": True,
            "row_count": int(n["c"]) if n else 0,
            "repeat_offenders": offenders,
            "repeat_offender_count": len(offenders),
        }
    finally:
        conn.close()
