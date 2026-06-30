"""Cross-session IP reputation — boosts mitigation for repeat cheater-network peers."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

GRAPH_FILE = Path("/var/lib/array-firewall/reputation-graph.json")
DECAY_DAYS = 14


def _now() -> float:
    return time.time()


def _load() -> dict[str, Any]:
    if not GRAPH_FILE.is_file():
        return {"ips": {}}
    try:
        return json.loads(GRAPH_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"ips": {}}


def _save(data: dict[str, Any]) -> None:
    GRAPH_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = GRAPH_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(GRAPH_FILE)


def _decay_factor(last_seen: float) -> float:
    age_days = max(0.0, (_now() - last_seen) / 86400.0)
    return max(0.1, 1.0 - age_days / DECAY_DAYS)


def touch_ip(
    ip: str,
    *,
    session_hex: str | None = None,
    bad: bool = False,
    clean: bool = False,
    identical_max: int = 0,
    vps_probe: bool = False,
) -> None:
    ip = ip.strip()
    if not ip:
        return
    data = _load()
    ips: dict[str, Any] = data.setdefault("ips", {})
    row = dict(ips.get(ip) or {})
    row["last_seen"] = _now()
    row["sessions_seen"] = int(row.get("sessions_seen") or 0) + 1
    if session_hex and session_hex not in (row.get("sessions") or []):
        sess = list(row.get("sessions") or [])[-20:]
        sess.append(session_hex)
        row["sessions"] = sess
    if bad:
        row["bad_hits"] = int(row.get("bad_hits") or 0) + 1
    if clean:
        row["clean_hits"] = int(row.get("clean_hits") or 0) + 1
    if identical_max:
        row["identical_max"] = max(int(row.get("identical_max") or 0), identical_max)
    if vps_probe:
        row["vps_probe"] = True
    ips[ip] = row
    _save(data)


def touch_peers_from_payload(payload: dict[str, Any], *, bad: bool = False, clean: bool = False) -> None:
    session_hex = str(payload.get("session_hex") or "").strip() or None
    for peer in _peer_rows(payload):
        ip = str(peer.get("ip") or peer.get("remote") or "").split(":")[0].strip()
        if not ip:
            continue
        touch_ip(
            ip,
            session_hex=session_hex,
            bad=bad,
            clean=clean,
            identical_max=int(peer.get("identical_count") or peer.get("max_burst") or 0),
            vps_probe=bool(peer.get("vps_probe")),
        )


def _peer_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for path in (
        ("peer_tracker", "peers"),
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


def score(ip: str) -> float:
    """0..1 reputation risk (higher = more likely cheater infrastructure)."""
    data = _load()
    row = (data.get("ips") or {}).get(ip.strip())
    if not row:
        return 0.0
    decay = _decay_factor(float(row.get("last_seen") or 0))
    bad = int(row.get("bad_hits") or 0)
    clean = int(row.get("clean_hits") or 0)
    sess = int(row.get("sessions_seen") or 0)
    base = bad * 0.25 - clean * 0.08 + min(sess, 6) * 0.04
    if row.get("vps_probe"):
        base += 0.2
    if int(row.get("identical_max") or 0) >= 30:
        base += 0.15
    return round(max(0.0, min(1.0, base * decay)), 4)


def top_risk(*, limit: int = 16) -> list[dict[str, Any]]:
    data = _load()
    rows = []
    for ip, row in (data.get("ips") or {}).items():
        s = score(ip)
        if s < 0.15:
            continue
        rows.append({"ip": ip, "score": s, **row})
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:limit]


def status() -> dict[str, Any]:
    data = _load()
    return {"ok": True, "ip_count": len(data.get("ips") or {}), "top_risk": top_risk(limit=12)}
