"""Immediate WAN port-scanner blocking — nft timeout set + persisted state."""
from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from . import peer_blocklist, policies

STATE_PATH = Path("/var/lib/array-firewall/wan-scanners.json")
TABLE = "inet"
CHAIN_TABLE = "gaming"
SET_NAME = "wan_scanners"
_LOCK = threading.Lock()


def _cfg() -> dict[str, Any]:
    gaming = policies.gaming()
    mit = dict(gaming.get("mitigation") or {})
    base = {
        "enabled": True,
        "ttl_sec": 86400,
        "block_on_first_probe": True,
    }
    base.update(mit.get("wan_scan_block") or {})
    if mit.get("auto_block_wan_scanners") is False:
        base["enabled"] = False
    return base


def _now() -> float:
    return time.time()


def _load() -> dict[str, Any]:
    if not STATE_PATH.is_file():
        return {"scanners": {}, "updated": 0}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"scanners": {}, "updated": 0}


def _save(data: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data["updated"] = _now()
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(STATE_PATH)


def _valid_scanner_ip(ip: str) -> bool:
    ip = str(ip or "").strip()
    if not ip or ip.startswith(("0.", "127.", "255.")):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= o <= 255 for o in octets):
        return False
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                      "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        return False
    if peer_blocklist.in_game_allowlist(ip):
        return False
    return True


def _nft_add_timeout(ip: str, ttl_sec: int) -> bool:
    ttl_sec = max(60, int(ttl_sec))
    proc = subprocess.run(
        [
            "nft",
            "add",
            "element",
            TABLE,
            CHAIN_TABLE,
            SET_NAME,
            "{",
            f"{ip} timeout {ttl_sec}s",
            "}",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return proc.returncode == 0


def block_scanner(
    ip: str,
    *,
    reason: str = "wan_scan",
    ttl_sec: int | None = None,
    port: int | None = None,
    proto: str | None = None,
) -> dict[str, Any]:
    """Block inbound scanner IP immediately (nft timeout set + 24h state)."""
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "skipped": True, "reason": "wan_scan_block_disabled"}

    ip = str(ip or "").strip()
    if not _valid_scanner_ip(ip):
        return {"ok": True, "skipped": True, "reason": "not_blockable", "ip": ip}

    ttl = max(300, int(ttl_sec or cfg.get("ttl_sec") or 86400))
    now = _now()
    nft_ok = False
    added = False

    with _LOCK:
        data = _load()
        scanners: dict[str, Any] = dict(data.get("scanners") or {})
        entry = scanners.get(ip) or {"hits": 0, "first_seen": now}
        entry["hits"] = int(entry.get("hits") or 0) + 1
        entry["last_seen"] = now
        entry["reason"] = reason
        entry["expires"] = max(float(entry.get("expires") or 0), now + ttl)
        if port is not None:
            ports = set(entry.get("ports") or [])
            ports.add(int(port))
            entry["ports"] = sorted(ports)[:64]
        if proto:
            entry["proto"] = proto
        was_active = float(entry.get("expires") or 0) > now and entry.get("hits", 0) > 1
        scanners[ip] = entry
        data["scanners"] = scanners
        _save(data)
        added = not was_active
        nft_ok = _nft_add_timeout(ip, ttl)

    try:
        from . import session_events

        session_events.append(
            "wan_scan.block",
            detail=f"blocked {ip}",
            meta={"reason": reason, "port": port, "proto": proto, "ttl_sec": ttl},
        )
    except ImportError:
        pass

    return {
        "ok": True,
        "ip": ip,
        "blocked": True,
        "nft_applied": nft_ok,
        "new_block": added,
        "ttl_sec": ttl,
        "reason": reason,
    }


def prune() -> dict[str, Any]:
    data = _load()
    now = _now()
    kept: dict[str, Any] = {}
    removed = 0
    for ip, meta in (data.get("scanners") or {}).items():
        if float((meta or {}).get("expires") or 0) > now:
            kept[ip] = meta
        else:
            removed += 1
    data["scanners"] = kept
    _save(data)
    return {"ok": True, "removed": removed, "active": len(kept), "scanners": kept}


def active_scanners() -> list[dict[str, Any]]:
    prune()
    data = _load()
    out: list[dict[str, Any]] = []
    for ip, meta in sorted((data.get("scanners") or {}).items()):
        row = dict(meta or {})
        row["ip"] = ip
        out.append(row)
    return out


def render_nft_elements() -> str:
    """Elements clause for packet-shield restore."""
    prune()
    data = _load()
    now = _now()
    parts: list[str] = []
    for ip, meta in (data.get("scanners") or {}).items():
        remaining = max(60, int(float(meta.get("expires") or 0) - now))
        parts.append(f"{ip} timeout {remaining}s")
    return ", ".join(parts)


def status() -> dict[str, Any]:
    cfg = _cfg()
    active = active_scanners()
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "ttl_sec": int(cfg.get("ttl_sec") or 86400),
        "active_count": len(active),
        "active": active[:100],
        "state_path": str(STATE_PATH),
        "set": f"{TABLE} {CHAIN_TABLE} {SET_NAME}",
    }
