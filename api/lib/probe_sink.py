"""Probe sink event log and honeypot hit tracking."""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from . import peer_blocklist, policies

try:
    from . import afld
except ImportError:
    afld = None  # type: ignore[assignment]

EVENT_LOG = Path("/var/lib/array-firewall/probe-sink.jsonl")
COUNTER_STATE = Path("/var/lib/array-firewall/probe-sink-counters.json")
HONEYPOT_PORTS = (23, 21, 445, 135, 139, 3389, 5900, 8080, 8443, 31337, 4444, 5555, 6667)


def _cfg() -> dict[str, Any]:
    gaming = policies.gaming()
    base = {
        "honeypot_enabled": True,
        "sink_port": 39217,
        "auto_block_on_probe": True,
        "probe_block_ttl_sec": 86400,
    }
    base.update(gaming.get("mitigation") or {})
    return base


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def record_probe(
    ip: str,
    *,
    port: int | None = None,
    proto: str = "tcp",
    reason: str = "honeypot",
    meta: dict[str, Any] | None = None,
    session_hex: str | None = None,
) -> dict[str, Any]:
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    meta = dict(meta or {})
    if session_hex:
        meta["session_hex"] = str(session_hex).strip()
    row = {
        "ts": _now(),
        "ip": ip.strip(),
        "port": port,
        "proto": proto,
        "reason": reason,
        "meta": meta,
    }
    with EVENT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")

    if afld is not None:
        afld.append(
            "probe_sink",
            {
                "ip": row["ip"],
                "port": port,
                "proto": proto,
                "reason": reason,
                "action": "logged",
            },
        )

    cfg = _cfg()
    blocked = None
    if cfg.get("auto_block_on_probe", True) and row["ip"]:
        try:
            from . import wan_scan_block

            blocked = wan_scan_block.block_scanner(
                row["ip"],
                reason=f"probe_sink:{reason}",
                port=port,
                proto=proto,
            )
        except Exception:
            blocked = peer_blocklist.add_peers(
                [row["ip"]],
                reason=f"probe_sink:{reason}",
                ttl_sec=int(cfg.get("probe_block_ttl_sec") or 86400),
            )
    return {"ok": True, "recorded": row, "blocked": blocked}


def recent_events(*, limit: int = 100) -> list[dict[str, Any]]:
    if not EVENT_LOG.is_file():
        return []
    lines = EVENT_LOG.read_text(encoding="utf-8").splitlines()
    out: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(out))


def _read_nft_counter(name: str) -> int:
    try:
        raw = subprocess.check_output(
            ["nft", "-j", "list", "counter", "inet", "gaming", name],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(raw)
        nftables = data.get("nftables") or []
        for item in nftables:
            counter = item.get("counter") or item.get("elem") or {}
            if isinstance(counter, dict):
                val = counter.get("packets") or counter.get("val", {}).get("packets")
                if val is not None:
                    return int(val)
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError, ValueError):
        pass
    return 0


def poll_counters() -> dict[str, Any]:
    """Track nft probe counter totals (IPs captured via honeypot listener)."""
    counters = {
        "probe_tcp_rst": _read_nft_counter("probe_tcp_rst"),
        "probe_udp_sink": _read_nft_counter("probe_udp_sink"),
        "wan_scan_drop": _read_nft_counter("wan_scan_drop"),
    }
    prev: dict[str, int] = {}
    if COUNTER_STATE.is_file():
        try:
            prev = json.loads(COUNTER_STATE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            prev = {}

    delta_total = sum(max(0, counters[k] - int(prev.get(k) or 0)) for k in counters)
    COUNTER_STATE.write_text(json.dumps(counters, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "counters": counters, "delta_since_last": delta_total}


def ingest_listener_log(*, limit: int = 200) -> dict[str, Any]:
    """Process probe-sink listener JSONL and auto-block sources."""
    listener_log = Path("/var/lib/array-firewall/probe-sink-listener.jsonl")
    if not listener_log.is_file():
        return {"ok": True, "ingested": 0}
    state_file = Path("/var/lib/array-firewall/probe-sink-listener.offset")
    offset = 0
    if state_file.is_file():
        try:
            offset = int(state_file.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            offset = 0
    raw = listener_log.read_bytes()
    if offset > len(raw):
        offset = 0
    chunk = raw[offset:].decode("utf-8", errors="replace")
    ingested = 0
    for line in chunk.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = str(row.get("remote_ip") or row.get("ip") or "").strip()
        if not ip or ip.startswith("127."):
            continue
        record_probe(
            ip,
            port=row.get("local_port") or row.get("port"),
            proto=str(row.get("proto") or "tcp"),
            reason="honeypot_connect",
            meta=row,
        )
        if afld is not None:
            afld.append(
                "honeypot",
                {
                    "ip": ip,
                    "port": row.get("local_port") or row.get("port"),
                    "sport": row.get("remote_port"),
                    "proto": str(row.get("proto") or "tcp"),
                    "action": "sink",
                    "reason": "honeypot_connect",
                },
            )
        ingested += 1
    state_file.write_text(str(len(raw)), encoding="utf-8")
    return {"ok": True, "ingested": ingested}


def status() -> dict[str, Any]:
    cfg = _cfg()
    listener_active = subprocess.run(
        ["systemctl", "is-active", "array-firewall-probe-sink"],
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip() == "active"
    return {
        "ok": True,
        "enabled": bool(cfg.get("honeypot_enabled", True)),
        "sink_port": cfg.get("sink_port", 39217),
        "honeypot_ports": list(HONEYPOT_PORTS),
        "listener_active": listener_active,
        "recent_events": recent_events(limit=20),
        "event_count": len(EVENT_LOG.read_text(encoding="utf-8").splitlines()) if EVENT_LOG.is_file() else 0,
    }


def tag_session_on_recent_probes(session_hex: str, *, window_sec: float = 300.0) -> dict[str, Any]:
    """Persist session_hex onto recent probe JSONL rows for causal timeline."""
    session_hex = str(session_hex or "").strip()
    if not session_hex or not EVENT_LOG.is_file():
        return {"ok": True, "tagged": 0}
    now = time.time()
    lines = EVENT_LOG.read_text(encoding="utf-8").splitlines()
    tagged = 0
    out_lines: list[str] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            out_lines.append(line)
            continue
        meta = dict(row.get("meta") or {})
        if meta.get("session_hex"):
            out_lines.append(json.dumps(row, separators=(",", ":")))
            continue
        ts_str = str(row.get("ts") or "")
        try:
            ts = time.mktime(time.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S"))
        except (ValueError, TypeError):
            ts = now
        if now - ts <= window_sec:
            meta["session_hex"] = session_hex
            row["meta"] = meta
            tagged += 1
        out_lines.append(json.dumps(row, separators=(",", ":")))
    if tagged:
        EVENT_LOG.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return {"ok": True, "session_hex": session_hex, "tagged": tagged}


def correlate_session(session_hex: str) -> dict[str, Any]:
    """Tag recent probe hits with the active game session hex and persist to JSONL."""
    session_hex = str(session_hex or "").strip()
    if not session_hex:
        return {"ok": False, "error": "session_hex required"}
    tag_result = tag_session_on_recent_probes(session_hex)
    recent = recent_events(limit=40)
    correlated = int(tag_result.get("tagged") or 0)
    for row in recent:
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        meta = row.get("meta") or {}
        if str(meta.get("session_hex") or "") != session_hex:
            continue
        try:
            from . import wan_scan_block

            wan_scan_block.block_scanner(
                ip,
                reason=f"probe_sink:{session_hex[:8]}",
                port=row.get("port"),
                proto=row.get("proto"),
            )
        except Exception:
            peer_blocklist.add_peers(
                [ip],
                reason=f"probe_sink:{session_hex[:8]}",
                ttl_sec=int(_cfg().get("probe_block_ttl_sec") or 86400),
            )
    return {
        "ok": True,
        "session_hex": session_hex,
        "correlated": correlated,
        "tagged_persisted": correlated,
        "recent_probes": len(recent),
    }
