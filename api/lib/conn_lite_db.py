"""Lite SQLite store for inbound connections keyed by game session — query + protect/block."""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from . import peer_blocklist

DB_PATH = Path("/var/lib/array-firewall/connections-lite.db")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_LOCK = threading.Lock()
VALID_POLICIES = frozenset({"none", "protect", "block"})
VALID_ACTIONS = frozenset({"protect", "block", "none", "remove"})
# P2P-shaped UDP heuristics — not verified lobby players; drop at firewall, skip DB/intel.
SKIP_CONN_TYPES = frozenset({"vps-probe", "game-peer"})
# In-match: only Warzone + Xbox Live (+ LAN) are logged/processed.
IN_MATCH_CONN_TYPES = frozenset({"warzone-game", "xbox-live", "lan-local", "lan-gateway"})


def _now() -> float:
    return time.time()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS game_sessions (
            session_hex TEXT PRIMARY KEY,
            phase TEXT,
            xbox_ip TEXT,
            started_at REAL NOT NULL,
            ended_at REAL,
            last_seen REAL NOT NULL,
            poll_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS conn_rows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_hex TEXT NOT NULL,
            ip TEXT NOT NULL,
            conn_type TEXT NOT NULL DEFAULT 'unknown',
            label TEXT,
            direction TEXT,
            proto TEXT,
            remote TEXT,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            hit_count INTEGER NOT NULL DEFAULT 1,
            total_packets INTEGER NOT NULL DEFAULT 0,
            tiny_packets INTEGER NOT NULL DEFAULT 0,
            identical_max INTEGER NOT NULL DEFAULT 0,
            vps_probe INTEGER NOT NULL DEFAULT 0,
            suspicious INTEGER NOT NULL DEFAULT 0,
            UNIQUE(session_hex, ip, conn_type)
        );

        CREATE TABLE IF NOT EXISTS ip_policy (
            ip TEXT PRIMARY KEY,
            policy TEXT NOT NULL DEFAULT 'none',
            reason TEXT,
            updated_at REAL NOT NULL,
            expires_at REAL
        );

        CREATE INDEX IF NOT EXISTS idx_conn_session ON conn_rows(session_hex, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_conn_ip ON conn_rows(ip, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_conn_type ON conn_rows(conn_type, last_seen DESC);
        """
    )


def _valid_ip(ip: str) -> bool:
    ip = ip.strip()
    if not _IP_RE.match(ip):
        return False
    parts = [int(p) for p in ip.split(".")]
    return all(0 <= p <= 255 for p in parts) and not ip.startswith(("0.", "127.", "255.", "192.168.", "10.", "172.16."))


def _extract_ip(remote: str) -> str:
    remote = str(remote or "").strip()
    if not remote:
        return ""
    if remote.startswith("[") and "]" in remote:
        return remote.split("]", 1)[0][1:]
    host = remote.rsplit(":", 1)[0] if remote.count(":") == 1 else remote
    return host.strip()


def _conn_type(item: dict[str, Any]) -> str:
    for key in ("conn_type", "roleId", "role", "type"):
        val = item.get(key)
        if val:
            return str(val).strip() or "unknown"
    return "unknown"


def _row_from_connection(item: dict[str, Any], *, ts: float) -> dict[str, Any] | None:
    ip = str(item.get("ip") or _extract_ip(str(item.get("remote") or ""))).strip()
    if not _valid_ip(ip):
        return None
    direction = str(item.get("direction") or item.get("dir") or "in").lower()
    if direction not in ("in", "out"):
        direction = "in"
    return {
        "ip": ip,
        "conn_type": _conn_type(item),
        "label": str(item.get("label") or item.get("vendor") or item.get("hostname") or "")[:120],
        "direction": direction,
        "proto": str(item.get("proto") or item.get("protocol") or "")[:8],
        "remote": str(item.get("remote") or f"{ip}:{item.get('port') or ''}")[:80],
        "total_packets": int(item.get("total_packets") or item.get("packets") or item.get("count") or 1),
        "tiny_packets": int(item.get("tiny_packets") or item.get("tiny") or 0),
        "identical_max": int(item.get("identical_count") or item.get("identical_max") or item.get("max_burst") or 0),
        "vps_probe": 1 if item.get("vps_probe") else 0,
        "suspicious": 1 if item.get("suspicious") else 0,
        "ts": ts,
    }


def _upsert_session(conn: sqlite3.Connection, *, session_hex: str, phase: str, xbox_ip: str | None, ts: float) -> None:
    conn.execute(
        """
        INSERT INTO game_sessions (session_hex, phase, xbox_ip, started_at, last_seen, poll_count)
        VALUES (?, ?, ?, ?, ?, 1)
        ON CONFLICT(session_hex) DO UPDATE SET
            phase = excluded.phase,
            xbox_ip = COALESCE(excluded.xbox_ip, game_sessions.xbox_ip),
            last_seen = excluded.last_seen,
            poll_count = game_sessions.poll_count + 1,
            ended_at = NULL
        """,
        (session_hex, phase, xbox_ip, ts, ts),
    )


def _upsert_row(conn: sqlite3.Connection, *, session_hex: str, row: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO conn_rows (
            session_hex, ip, conn_type, label, direction, proto, remote,
            first_seen, last_seen, hit_count, total_packets, tiny_packets,
            identical_max, vps_probe, suspicious
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
        ON CONFLICT(session_hex, ip, conn_type) DO UPDATE SET
            label = COALESCE(NULLIF(excluded.label, ''), conn_rows.label),
            direction = excluded.direction,
            proto = COALESCE(NULLIF(excluded.proto, ''), conn_rows.proto),
            remote = COALESCE(NULLIF(excluded.remote, ''), conn_rows.remote),
            last_seen = excluded.last_seen,
            hit_count = conn_rows.hit_count + 1,
            total_packets = conn_rows.total_packets + excluded.total_packets,
            tiny_packets = conn_rows.tiny_packets + excluded.tiny_packets,
            identical_max = MAX(conn_rows.identical_max, excluded.identical_max),
            vps_probe = MAX(conn_rows.vps_probe, excluded.vps_probe),
            suspicious = MAX(conn_rows.suspicious, excluded.suspicious)
        """,
        (
            session_hex,
            row["ip"],
            row["conn_type"],
            row.get("label") or "",
            row.get("direction") or "in",
            row.get("proto") or "",
            row.get("remote") or "",
            row["ts"],
            row["ts"],
            row.get("total_packets") or 0,
            row.get("tiny_packets") or 0,
            row.get("identical_max") or 0,
            row.get("vps_probe") or 0,
            row.get("suspicious") or 0,
        ),
    )


def ingest(
    *,
    session_hex: str,
    phase: str = "",
    xbox_ip: str | None = None,
    snapshot: dict[str, Any] | None = None,
    peers: list[dict[str, Any]] | None = None,
    connections: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    session_hex = str(session_hex or "").strip()
    if len(session_hex) < 8:
        return {"ok": False, "error": "session_hex required"}

    ts = _now()
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []

    def add_item(item: dict[str, Any]) -> None:
        parsed = _row_from_connection(item, ts=ts)
        if not parsed:
            return
        if parsed["conn_type"] in SKIP_CONN_TYPES:
            return
        if phase == "in-match" and parsed["conn_type"] not in IN_MATCH_CONN_TYPES:
            return
        key = (parsed["ip"], parsed["conn_type"])
        if key in seen:
            return
        seen.add(key)
        rows.append(parsed)

    snap = snapshot or {}
    for item in connections or []:
        if isinstance(item, dict):
            add_item(item)

    conn_items = (snap.get("connections") or {}).get("items") or []
    if isinstance(conn_items, list):
        for item in conn_items:
            if isinstance(item, dict):
                scope = str(item.get("scope") or "").lower()
                direction = str(item.get("direction") or item.get("dir") or "in").lower()
                if scope == "lan" and direction != "in":
                    continue
                add_item(item)

    for flow in snap.get("recentFlows") or []:
        if not isinstance(flow, dict):
            continue
        direction = str(flow.get("direction") or flow.get("dir") or "").lower()
        if direction and direction != "in":
            continue
        add_item(
            {
                "ip": flow.get("ip") or flow.get("remote"),
                "remote": flow.get("remote") or flow.get("hostname"),
                "roleId": flow.get("roleId") or flow.get("role"),
                "label": flow.get("label") or flow.get("hostname"),
                "direction": "in",
                "proto": flow.get("proto"),
                "count": flow.get("count") or flow.get("packets") or 1,
            }
        )

    for peer in peers or []:
        if isinstance(peer, dict):
            peer_item = dict(peer)
            peer_item.setdefault("conn_type", peer.get("role") or "game-peer")
            peer_item.setdefault("roleId", peer.get("role") or "game-peer")
            add_item(peer_item)

    with _LOCK:
        conn = _connect()
        try:
            _init_db(conn)
            _upsert_session(conn, session_hex=session_hex, phase=phase, xbox_ip=xbox_ip, ts=ts)
            for row in rows:
                _upsert_row(conn, session_hex=session_hex, row=row)
            conn.commit()
        finally:
            conn.close()

    _queue_unknown_investigations(rows)
    return {"ok": True, "session_hex": session_hex, "ingested": len(rows), "phase": phase}


def _queue_unknown_investigations(rows: list[dict[str, Any]]) -> None:
    try:
        from . import unknown_investigator

        unknown_investigator.queue_from_conn_rows(rows)
    except Exception:
        pass


def end_session(session_hex: str) -> dict[str, Any]:
    session_hex = str(session_hex or "").strip()
    if not session_hex:
        return {"ok": False, "error": "session_hex required"}
    ts = _now()
    with _LOCK:
        conn = _connect()
        try:
            _init_db(conn)
            conn.execute(
                "UPDATE game_sessions SET ended_at = ?, last_seen = ? WHERE session_hex = ?",
                (ts, ts, session_hex),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "session_hex": session_hex, "ended_at": ts}


def list_sessions(*, limit: int = 40) -> dict[str, Any]:
    limit = max(1, min(int(limit or 40), 200))
    with _LOCK:
        conn = _connect()
        try:
            _init_db(conn)
            rows = conn.execute(
                """
                SELECT s.*,
                    (SELECT COUNT(*) FROM conn_rows c WHERE c.session_hex = s.session_hex) AS conn_count
                FROM game_sessions s
                ORDER BY s.last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        finally:
            conn.close()
    return {"ok": True, "sessions": [_session_row(r) for r in rows]}


def query(
    *,
    session_hex: str | None = None,
    ip: str | None = None,
    conn_type: str | None = None,
    policy: str | None = None,
    min_sessions: int | None = None,
    offenders_only: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    clauses: list[str] = []
    params: list[Any] = []

    if session_hex:
        clauses.append("c.session_hex = ?")
        params.append(session_hex.strip())
    if ip:
        clauses.append("c.ip LIKE ?")
        params.append(f"%{ip.strip()}%")
    if conn_type:
        clauses.append("c.conn_type = ?")
        params.append(conn_type.strip())
    if policy:
        pol = policy.strip().lower()
        if pol in VALID_POLICIES:
            clauses.append("COALESCE(p.policy, 'none') = ?")
            params.append(pol)
    if min_sessions and int(min_sessions) > 1:
        clauses.append(
            "(SELECT COUNT(DISTINCT c2.session_hex) FROM conn_rows c2 WHERE c2.ip = c.ip) >= ?"
        )
        params.append(int(min_sessions))
    elif offenders_only:
        clauses.append(
            "(SELECT COUNT(DISTINCT c2.session_hex) FROM conn_rows c2 WHERE c2.ip = c.ip) >= 2"
        )

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    sql = f"""
        SELECT
            c.*,
            s.phase AS session_phase,
            s.started_at AS session_started,
            s.ended_at AS session_ended,
            COALESCE(p.policy, 'none') AS policy,
            p.reason AS policy_reason,
            p.updated_at AS policy_updated,
            (SELECT COUNT(DISTINCT c2.session_hex) FROM conn_rows c2 WHERE c2.ip = c.ip) AS session_count
        FROM conn_rows c
        LEFT JOIN game_sessions s ON s.session_hex = c.session_hex
        LEFT JOIN ip_policy p ON p.ip = c.ip
        {where}
        ORDER BY c.last_seen DESC, c.identical_max DESC, c.tiny_packets DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    with _LOCK:
        conn = _connect()
        try:
            _init_db(conn)
            rows = conn.execute(sql, params).fetchall()
            total = conn.execute(
                f"SELECT COUNT(*) FROM conn_rows c LEFT JOIN ip_policy p ON p.ip = c.ip {where}",
                params[:-2] if params else [],
            ).fetchone()[0]
        finally:
            conn.close()

    out_rows = [_conn_row(r) for r in rows]
    try:
        from . import unknown_investigator

        out_rows = [unknown_investigator.enrich_query_row(row) for row in out_rows]
    except Exception:
        pass

    return {
        "ok": True,
        "total": total,
        "limit": limit,
        "offset": offset,
        "rows": out_rows,
    }


def offenders(*, min_sessions: int = 2, limit: int = 50) -> dict[str, Any]:
    min_sessions = max(2, int(min_sessions or 2))
    limit = max(1, min(int(limit or 50), 200))
    with _LOCK:
        conn = _connect()
        try:
            _init_db(conn)
            rows = conn.execute(
                """
                SELECT
                    c.ip,
                    COUNT(DISTINCT c.session_hex) AS session_count,
                    MAX(c.last_seen) AS last_seen,
                    MIN(c.first_seen) AS first_seen,
                    SUM(c.hit_count) AS hit_count,
                    SUM(c.total_packets) AS total_packets,
                    SUM(c.tiny_packets) AS tiny_packets,
                    MAX(c.identical_max) AS identical_max,
                    MAX(c.vps_probe) AS vps_probe,
                    MAX(c.suspicious) AS suspicious,
                    GROUP_CONCAT(DISTINCT c.conn_type) AS conn_types,
                    MAX(c.label) AS label,
                    COALESCE(p.policy, 'none') AS policy,
                    p.reason AS policy_reason
                FROM conn_rows c
                LEFT JOIN ip_policy p ON p.ip = c.ip
                GROUP BY c.ip
                HAVING session_count >= ?
                ORDER BY session_count DESC, identical_max DESC, last_seen DESC
                LIMIT ?
                """,
                (min_sessions, limit),
            ).fetchall()
        finally:
            conn.close()
    return {"ok": True, "offenders": [_offender_row(r) for r in rows], "min_sessions": min_sessions}


def apply_action(
    *,
    ips: list[str],
    action: str,
    session_hex: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    action = str(action or "").strip().lower()
    if action not in VALID_ACTIONS:
        return {"ok": False, "error": f"action must be one of {sorted(VALID_ACTIONS)}"}

    clean_ips = [ip.strip() for ip in ips if _valid_ip(str(ip).strip())]
    if not clean_ips:
        return {"ok": False, "error": "no valid IPs"}

    ts = _now()
    tag = session_hex or "manual"
    base_reason = reason or f"conn-lite:{action}:{tag}"
    block_result: dict[str, Any] | None = None
    shield_result: dict[str, Any] | None = None
    removed_rows = 0

    if action == "protect":
        block_result = peer_blocklist.add_peers(clean_ips, reason=base_reason, ttl_sec=86_400)
        shield_result = peer_blocklist.sync_shield(level="peer-strict", extra_peers=clean_ips)
        _set_policies(clean_ips, "protect", base_reason, ts, block_result)
    elif action == "block":
        block_result = peer_blocklist.add_peers(clean_ips, reason=base_reason, ttl_sec=604_800)
        shield_result = peer_blocklist.sync_shield(level="peer-strict", extra_peers=clean_ips)
        _set_policies(clean_ips, "block", base_reason, ts, block_result)
    elif action == "none":
        block_result = peer_blocklist.remove_peers(clean_ips)
        shield_result = peer_blocklist.sync_shield(level="peer-strict", extra_peers=[])
        _set_policies(clean_ips, "none", base_reason, ts, None)
    elif action == "remove":
        removed_rows = _delete_rows(clean_ips, session_hex=session_hex)

    return {
        "ok": True,
        "action": action,
        "ips": clean_ips,
        "blocklist": block_result,
        "shield": shield_result,
        "removed_rows": removed_rows,
    }


def _set_policies(
    ips: list[str],
    policy: str,
    reason: str,
    ts: float,
    block_result: dict[str, Any] | None,
) -> None:
    with _LOCK:
        conn = _connect()
        try:
            _init_db(conn)
            for ip in ips:
                expires = None
                if block_result and isinstance(block_result.get("peers"), list):
                    pass
                if policy == "protect":
                    expires = ts + 86_400
                elif policy == "block":
                    expires = ts + 604_800
                conn.execute(
                    """
                    INSERT INTO ip_policy (ip, policy, reason, updated_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        policy = excluded.policy,
                        reason = excluded.reason,
                        updated_at = excluded.updated_at,
                        expires_at = excluded.expires_at
                    """,
                    (ip, policy, reason, ts, expires),
                )
            conn.commit()
        finally:
            conn.close()


def _delete_rows(ips: list[str], *, session_hex: str | None) -> int:
    with _LOCK:
        conn = _connect()
        try:
            _init_db(conn)
            if session_hex:
                cur = conn.execute(
                    "DELETE FROM conn_rows WHERE ip IN ({}) AND session_hex = ?".format(
                        ",".join("?" * len(ips))
                    ),
                    [*ips, session_hex],
                )
            else:
                cur = conn.execute(
                    "DELETE FROM conn_rows WHERE ip IN ({})".format(",".join("?" * len(ips))),
                    ips,
                )
            conn.commit()
            return int(cur.rowcount)
        finally:
            conn.close()


def _session_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "session_hex": row["session_hex"],
        "phase": row["phase"],
        "xbox_ip": row["xbox_ip"],
        "started_at": row["started_at"],
        "ended_at": row["ended_at"],
        "last_seen": row["last_seen"],
        "poll_count": row["poll_count"],
        "conn_count": row["conn_count"],
    }


def _conn_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "session_hex": row["session_hex"],
        "ip": row["ip"],
        "conn_type": row["conn_type"],
        "label": row["label"],
        "direction": row["direction"],
        "proto": row["proto"],
        "remote": row["remote"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "hit_count": row["hit_count"],
        "total_packets": row["total_packets"],
        "tiny_packets": row["tiny_packets"],
        "identical_max": row["identical_max"],
        "vps_probe": bool(row["vps_probe"]),
        "suspicious": bool(row["suspicious"]),
        "session_phase": row["session_phase"],
        "session_started": row["session_started"],
        "session_ended": row["session_ended"],
        "policy": row["policy"],
        "policy_reason": row["policy_reason"],
        "session_count": row["session_count"],
    }


def _offender_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "ip": row["ip"],
        "session_count": row["session_count"],
        "last_seen": row["last_seen"],
        "first_seen": row["first_seen"],
        "hit_count": row["hit_count"],
        "total_packets": row["total_packets"],
        "tiny_packets": row["tiny_packets"],
        "identical_max": row["identical_max"],
        "vps_probe": bool(row["vps_probe"]),
        "suspicious": bool(row["suspicious"]),
        "conn_types": (row["conn_types"] or "").split(","),
        "label": row["label"],
        "policy": row["policy"],
        "policy_reason": row["policy_reason"],
    }
