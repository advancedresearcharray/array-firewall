"""Federated bad-lobby intel — export/import offender IPs and fold fingerprints."""
from __future__ import annotations

import base64
import json
import struct
import time
from pathlib import Path
from typing import Any

from . import conn_lite_db, peer_blocklist, policies

INTEL_FILE = Path("/var/lib/array-firewall/lobby-intel-import.json")
FOLD_DIM = 32


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _fold_to_b64(fold: list[float]) -> str:
    vals = (float(x) for x in fold[:FOLD_DIM])
    packed = struct.pack(f"<{FOLD_DIM}f", *vals)
    return base64.b64encode(packed).decode("ascii")


def _fold_from_b64(payload: str) -> list[float]:
    raw = base64.b64decode(payload.encode("ascii"))
    if len(raw) < FOLD_DIM * 4:
        return []
    return list(struct.unpack(f"<{FOLD_DIM}f", raw[: FOLD_DIM * 4]))


def export_intel(*, include_offenders: bool = True, fold_limit: int = 64) -> dict[str, Any]:
    """Build portable intel blob from local peer blocklist + conn-lite repeat offenders."""
    peers = peer_blocklist.status()
    offender_ips: list[str] = []
    if include_offenders:
        off = conn_lite_db.offenders(min_sessions=2, limit=fold_limit)
        offender_ips = [str(r.get("ip") or "") for r in off.get("offenders") or [] if r.get("ip")]

    peer_entries = []
    for row in peers.get("peers") or []:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        peer_entries.append(
            {
                "ip": ip,
                "reason": row.get("reason"),
                "hits": row.get("hits"),
                "repeat_offender": bool(row.get("repeat_offender")),
            }
        )

    return {
        "ok": True,
        "version": 1,
        "exported_at": _now(),
        "source": policies.gaming().get("xbox_ip") or "array-firewall",
        "peer_blocks": peer_entries[:fold_limit],
        "offender_ips": offender_ips[:fold_limit],
        "fold_dim": FOLD_DIM,
    }


def import_intel(payload: dict[str, Any], *, merge_peers: bool = True) -> dict[str, Any]:
    """Merge remote intel — block repeat offender IPs with extended TTL."""
    cfg = policies.gaming()
    default_ttl = int((cfg.get("mitigation") or {}).get("repeat_offender_ttl_sec") or 604800)
    imported_peers = 0
    imported_offenders = 0

    if merge_peers:
        ips: list[str] = []
        for row in payload.get("peer_blocks") or []:
            if isinstance(row, dict):
                ip = str(row.get("ip") or "").strip()
                if ip:
                    ips.append(ip)
        for ip in payload.get("offender_ips") or []:
            ip = str(ip).strip()
            if ip and ip not in ips:
                ips.append(ip)
        if ips:
            result = peer_blocklist.add_peers(
                ips,
                reason="federated_intel",
                ttl_sec=default_ttl,
                hits=2,
            )
            imported_peers = int(result.get("added") or 0)
            imported_offenders = len(payload.get("offender_ips") or [])

    INTEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    INTEL_FILE.write_text(
        json.dumps(
            {
                "imported_at": _now(),
                "source": payload.get("source"),
                "peer_blocks": len(payload.get("peer_blocks") or []),
                "offender_ips": len(payload.get("offender_ips") or []),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "ok": True,
        "imported_peers": imported_peers,
        "imported_offender_ips": imported_offenders,
        "merged_at": _now(),
    }


def status() -> dict[str, Any]:
    meta: dict[str, Any] = {}
    if INTEL_FILE.is_file():
        try:
            meta = json.loads(INTEL_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            meta = {}
    return {"ok": True, "last_import": meta, "export_ready": True}
