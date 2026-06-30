"""Session-adaptive honeypot ports — rotate decoys from recent probe hits."""
from __future__ import annotations

import json
import random
import time
from collections import Counter
from pathlib import Path
from typing import Any

from . import policies

STATE_FILE = Path("/var/lib/array-firewall/adaptive-honeypot.json")
BASE_PORTS = (23, 21, 445, 135, 139, 3389, 5900, 8080, 8443, 31337, 4444, 5555, 6667, 39217)


def _cfg() -> dict[str, Any]:
    mit = dict(policies.gaming().get("mitigation") or {})
    base = {"enabled": True, "rotate_every_sec": 900, "active_ports": 6}
    base.update(mit.get("adaptive_honeypot") or {})
    return base


def _load() -> dict[str, Any]:
    if not STATE_FILE.is_file():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def ingest_probe_hits(hits: list[dict[str, Any]], *, session_hex: str = "") -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "skipped": True}
    counts: Counter[int] = Counter()
    for row in hits:
        port = row.get("port")
        if port is not None:
            try:
                counts[int(port)] += 1
            except (TypeError, ValueError):
                pass
    state = _load()
    merged: Counter[int] = Counter({int(k): v for k, v in (state.get("port_hits") or {}).items()})
    merged.update(counts)
    top = [p for p, _ in merged.most_common(12)]
    pool = list(dict.fromkeys([*top, *BASE_PORTS]))
    active_n = max(4, int(cfg.get("active_ports") or 6))
    active = pool[:active_n]
    if len(active) < active_n:
        active.extend(random.sample(list(BASE_PORTS), min(active_n - len(active), len(BASE_PORTS))))
    sink_port = active[0] if active else int(policies.gaming().get("mitigation", {}).get("sink_port") or 39217)
    out = {
        "updated_at": time.time(),
        "session_hex": session_hex,
        "port_hits": dict(merged.most_common(32)),
        "active_ports": active,
        "sink_port": sink_port,
    }
    _save(out)
    return {"ok": True, **out}


def maybe_rotate(*, force: bool = False) -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "skipped": True}
    state = _load()
    now = time.time()
    interval = max(300, int(cfg.get("rotate_every_sec") or 900))
    last = float(state.get("updated_at") or 0)
    if not force and last and (now - last) < interval:
        return {"ok": True, "skipped": True, "active_ports": state.get("active_ports"), "sink_port": state.get("sink_port")}
    hits = [{"port": p} for p in (state.get("port_hits") or {}).keys()]
    return ingest_probe_hits(hits, session_hex=str(state.get("session_hex") or ""))


def status() -> dict[str, Any]:
    state = _load()
    return {"ok": True, "config": _cfg(), "state": state}
