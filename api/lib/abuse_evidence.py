"""Abuse evidence bundles attached to subnet blocks (provider reports)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

EVIDENCE_DIR = Path("/var/lib/array-firewall/abuse-evidence")


def _now() -> float:
    return time.time()


def build_bundle(
    *,
    session_hex: str | None,
    trigger_ip: str,
    reason: str,
    peers: list[dict[str, Any]] | None = None,
    cheater_label: str | None = None,
    signals: list[str] | None = None,
    autopilot_summary: str | None = None,
) -> dict[str, Any]:
    bundle = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "format": "array-firewall-abuse-v1",
        "session_hex": session_hex,
        "trigger_ip": trigger_ip,
        "reason": reason,
        "cheater_label": cheater_label,
        "signals": signals or [],
        "autopilot_summary": autopilot_summary,
        "peers": peers or [],
        "intent": "mitigate_in_lobby_playability — block probe infrastructure, player stays in match",
    }
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    slug = (session_hex or "manual")[:16]
    path = EVIDENCE_DIR / f"abuse-{slug}-{int(_now())}.json"
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    bundle["path"] = str(path)
    return bundle


def list_bundles(*, limit: int = 20) -> list[dict[str, Any]]:
    if not EVIDENCE_DIR.is_dir():
        return []
    files = sorted(EVIDENCE_DIR.glob("abuse-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    out: list[dict[str, Any]] = []
    for path in files[:limit]:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            doc["filename"] = path.name
            out.append(doc)
        except (json.JSONDecodeError, OSError):
            continue
    return out
