"""Fleet blocklist export/import for multi-node array-firewall sync."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from . import peer_blocklist, policies

EXPORT_FILE = Path("/var/lib/array-firewall/fleet-blocklist-export.json")
IMPORT_DIR = Path("/var/lib/array-firewall/fleet-import")


def _now() -> float:
    return time.time()


def export_bundle() -> dict[str, Any]:
    try:
        from . import subnet_blocklist as sb

        subnets = sb.active_subnets()
    except ImportError:
        subnets = []
    peers = peer_blocklist.status().get("peers") or []
    bundle = {
        "exported_at": _now(),
        "format": "array-firewall-fleet-v1",
        "node": (policies.load().get("network") or {}).get("hostname") or "array-firewall",
        "peers": peers,
        "subnets": subnets,
    }
    raw = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    bundle["sha256"] = hashlib.sha256(raw.encode()).hexdigest()
    EXPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    EXPORT_FILE.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "path": str(EXPORT_FILE), "peer_count": len(peers), "subnet_count": len(subnets), "sha256": bundle["sha256"]}


def import_bundle(doc: dict[str, Any], *, merge: bool = True) -> dict[str, Any]:
    cfg = policies.load().get("ai_ops") or {}
    if not cfg.get("fleet_sync_enabled", True):
        return {"ok": False, "error": "fleet_sync disabled"}
    peer_added = 0
    subnet_added = 0
    for row in doc.get("peers") or []:
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        if merge and peer_blocklist.in_game_allowlist(ip):
            continue
        peer_blocklist.add_peers([ip], reason="fleet_sync", ttl_sec=int(row.get("ttl_sec") or 604800))
        peer_added += 1
    try:
        from . import subnet_blocklist as sb

        for row in doc.get("subnets") or []:
            cidr = str(row.get("cidr") or row.get("prefix") or "").strip()
            if not cidr:
                continue
            sb.add_subnet(cidr, reason="fleet_sync", source="fleet_import")
            subnet_added += 1
    except ImportError:
        pass
    IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = int(_now())
    (IMPORT_DIR / f"import-{stamp}.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "peers_merged": peer_added, "subnets_merged": subnet_added}


def pull_from_url(url: str) -> dict[str, Any]:
    import urllib.request

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        doc = json.loads(resp.read().decode())
    return import_bundle(doc)


def status() -> dict[str, Any]:
    cfg = policies.load().get("ai_ops") or {}
    exp = {}
    if EXPORT_FILE.is_file():
        try:
            exp = json.loads(EXPORT_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            exp = {}
    return {
        "ok": True,
        "enabled": cfg.get("fleet_sync_enabled", True),
        "export_url": cfg.get("fleet_export_url"),
        "pull_url": cfg.get("fleet_pull_url"),
        "last_export": exp.get("exported_at"),
        "sha256": exp.get("sha256"),
    }
