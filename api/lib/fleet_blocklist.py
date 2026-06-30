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


def pull_from_url(url: str, *, merge: bool = True) -> dict[str, Any]:
    import urllib.request

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        doc = json.loads(resp.read().decode())
    return import_bundle(doc, merge=merge)


def scheduled_pull(url: str, *, merge_policy: str = "merge") -> dict[str, Any]:
    """Pull fleet bundle with merge policy: merge | prefer_local | prefer_remote."""
    import urllib.request

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        doc = json.loads(resp.read().decode())
    expected = doc.get("sha256")
    if expected:
        raw = json.dumps({k: v for k, v in doc.items() if k != "sha256"}, sort_keys=True, separators=(",", ":"))
        if hashlib.sha256(raw.encode()).hexdigest() != expected:
            return {"ok": False, "error": "sha256 mismatch", "url": url}
    if merge_policy == "prefer_local":
        return {"ok": True, "skipped": True, "reason": "prefer_local", "url": url}
    merge = merge_policy != "prefer_remote"
    result = import_bundle(doc, merge=merge)
    result["merge_policy"] = merge_policy
    result["url"] = url
    return result


def push_to_url(url: str, *, timeout: float = 20.0) -> dict[str, Any]:
    """HTTP PUT/POST fleet bundle to peer node."""
    import urllib.error
    import urllib.request

    export = export_bundle()
    path = Path(export.get("path") or EXPORT_FILE)
    if not path.is_file():
        return {"ok": False, "error": "export missing"}
    body = path.read_bytes()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Array-Fleet-Format": "array-firewall-fleet-v1",
    }
    token = (policies.load().get("ai_ops") or {}).get("fleet_export_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, method="PUT", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            detail = resp.read(4096).decode("utf-8", errors="replace")
        return {"ok": True, "url": url, "status": resp.status, "sha256": export.get("sha256"), "detail": detail[:500]}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "url": url, "error": str(exc), "status": exc.code}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "url": url, "error": str(exc)}


def sync_cycle() -> dict[str, Any]:
    """Export, optional push, optional pull — used by systemd timer."""
    cfg = policies.load().get("ai_ops") or {}
    if not cfg.get("fleet_sync_enabled", True):
        return {"ok": True, "skipped": True, "reason": "fleet_sync disabled"}
    out: dict[str, Any] = {"ok": True, "export": export_bundle()}
    export_url = str(cfg.get("fleet_export_url") or "").strip()
    if export_url:
        out["push"] = push_to_url(export_url)
    pull_url = str(cfg.get("fleet_pull_url") or "").strip()
    if pull_url:
        out["pull"] = scheduled_pull(pull_url, merge_policy=str(cfg.get("fleet_merge_policy") or "merge"))
    return out


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
