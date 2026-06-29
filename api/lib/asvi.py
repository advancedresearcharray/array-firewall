"""ASVI + SMST — Adaptive Shell-Margin Void Index (Zenodo 18770016).

Detects coverage voids in shield allowlists and connection classification shells.
SMST provides balanced-risk class labels: monitor | stage | act.

https://zenodo.org/records/18770016
"""
from __future__ import annotations

import ipaddress
import json
import math
import time
from pathlib import Path
from typing import Any

from . import conn_lite_db, policies

ZENODO = {
    "doi": "10.5281/zenodo.18770016",
    "url": "https://zenodo.org/records/18770016",
    "title": "ASVI: Adaptive Shell-Margin Void Index and SMST",
    "version": "v1",
}

ALLOWLIST_PATH = Path("/opt/array-firewall/config/in-match-allowlist.json")
SCAN_STATE = Path("/var/lib/array-firewall/asvi-scan.json")

SMST_LABELS = ("monitor", "stage", "act")


def _cfg() -> dict[str, Any]:
    base = {
        "enabled": True,
        "prefix_len": 24,
        "stage_threshold": 0.35,
        "act_threshold": 0.65,
        "min_hits": 2,
        "auto_stage_allowlist": False,
    }
    base.update(policies.load().get("asvi") or {})
    base.update(policies.gaming().get("asvi") or {})
    return base


def _load_allowlist_cidrs() -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    if not ALLOWLIST_PATH.is_file():
        return nets
    try:
        data = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
        for c in data.get("cidrs") or []:
            try:
                nets.append(ipaddress.ip_network(str(c).strip(), strict=False))
            except ValueError:
                continue
    except (json.JSONDecodeError, OSError):
        pass
    return nets


def _prefix_key(ip: str, prefix_len: int) -> str | None:
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False))
    except ValueError:
        return None


def _is_covered(ip: str, allowlist: list[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in allowlist)


def build_void_complex(
    rows: list[dict[str, Any]],
    *,
    allowlist: list[ipaddress.IPv4Network] | None = None,
    prefix_len: int = 24,
) -> dict[str, dict[str, Any]]:
    """Binary cubical complex: cells keyed by /prefix with traffic weight."""
    allowlist = allowlist if allowlist is not None else _load_allowlist_cidrs()
    cells: dict[str, dict[str, Any]] = {}
    for row in rows:
        ip = str(row.get("ip") or "").strip()
        if not ip or ip.startswith(("192.168.", "10.", "172.16.")):
            continue
        key = _prefix_key(ip, prefix_len)
        if not key:
            continue
        covered = _is_covered(ip, allowlist)
        cell = cells.setdefault(
            key,
            {
                "prefix": key,
                "covered": covered,
                "hits": 0,
                "ips": set(),
                "conn_types": set(),
                "suspicious": 0,
                "void": not covered,
            },
        )
        cell["hits"] += int(row.get("hit_count") or 1)
        cell["ips"].add(ip)
        ct = str(row.get("conn_type") or "unknown")
        cell["conn_types"].add(ct)
        if row.get("suspicious") or row.get("vps_probe"):
            cell["suspicious"] += 1
    return cells


def _shell_margin_voids(cells: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Cells on the shell margin: void cells adjacent to covered shell."""
    covered_keys = {k for k, v in cells.items() if v.get("covered")}
    margin_voids: list[dict[str, Any]] = []
    for key, cell in cells.items():
        if not cell.get("void"):
            continue
        # margin = void cell with traffic while shell exists elsewhere
        if covered_keys and cell.get("hits", 0) > 0:
            margin_voids.append(cell)
    return margin_voids


def compute_asvi(cell: dict[str, Any], *, total_hits: int) -> float:
    """Adaptive Shell-Margin Void Index for one cell (0..1)."""
    hits = float(cell.get("hits") or 0)
    ip_count = float(len(cell.get("ips") or []))
    suspicious = float(cell.get("suspicious") or 0)
    share = hits / max(total_hits, 1.0)
    type_bonus = 0.15 if "dedicated-server" in (cell.get("conn_types") or set()) else 0.0
    type_penalty = 0.2 if "game-peer" in (cell.get("conn_types") or set()) else 0.0
    raw = (
        0.35 * min(1.0, share * 4.0)
        + 0.25 * min(1.0, ip_count / 8.0)
        + 0.20 * min(1.0, suspicious / max(hits, 1.0))
        + type_bonus
        - type_penalty
    )
    return round(max(0.0, min(1.0, raw)), 4)


def smst_classify(asvi: float, cfg: dict[str, Any] | None = None) -> str:
    """Shell-Margin Separation Theorem — balanced-risk label."""
    cfg = cfg or _cfg()
    stage = float(cfg.get("stage_threshold") or 0.35)
    act = float(cfg.get("act_threshold") or 0.65)
    if asvi >= act:
        return "act"
    if asvi >= stage:
        return "stage"
    return "monitor"


def scan_session(
    *,
    session_hex: str | None = None,
    limit: int = 300,
) -> dict[str, Any]:
    """Scan conn-lite traffic for allowlist voids and SMST labels."""
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "skipped": True, "reason": "disabled"}

    prefix_len = max(16, min(int(cfg.get("prefix_len") or 24), 28))
    q = conn_lite_db.query(session_hex=session_hex, limit=limit, offset=0)
    rows = q.get("rows") or []
    allowlist = _load_allowlist_cidrs()
    cells = build_void_complex(rows, allowlist=allowlist, prefix_len=prefix_len)
    total_hits = sum(int(c.get("hits") or 0) for c in cells.values())

    voids: list[dict[str, Any]] = []
    for key, cell in cells.items():
        if not cell.get("void") or int(cell.get("hits") or 0) < int(cfg.get("min_hits") or 2):
            continue
        asvi = compute_asvi(cell, total_hits=total_hits)
        voids.append(
            {
                "prefix": key,
                "asvi": asvi,
                "smst": smst_classify(asvi, cfg),
                "hits": cell["hits"],
                "ip_count": len(cell["ips"]),
                "sample_ips": sorted(cell["ips"])[:5],
                "conn_types": sorted(cell["conn_types"]),
                "suspicious": cell["suspicious"],
            }
        )

    voids.sort(key=lambda x: (-x["asvi"], -x["hits"]))
    margin = _shell_margin_voids(cells)
    max_asvi = max((v["asvi"] for v in voids), default=0.0)

    result = {
        "ok": True,
        "zenodo": ZENODO,
        "session_hex": session_hex,
        "prefix_len": prefix_len,
        "allowlist_cidrs": len(allowlist),
        "cells_total": len(cells),
        "void_count": len(voids),
        "margin_void_count": len(margin),
        "max_asvi": max_asvi,
        "smst_summary": {
            "monitor": sum(1 for v in voids if v["smst"] == "monitor"),
            "stage": sum(1 for v in voids if v["smst"] == "stage"),
            "act": sum(1 for v in voids if v["smst"] == "act"),
        },
        "voids": voids[:32],
        "scanned_at": time.time(),
    }

    SCAN_STATE.parent.mkdir(parents=True, exist_ok=True)
    SCAN_STATE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def scan_unknown_voids(*, limit: int = 200) -> dict[str, Any]:
    """Find classification voids — unknown conn_types with high traffic."""
    q = conn_lite_db.query(conn_type="unknown", limit=limit, offset=0)
    rows = q.get("rows") or []
    if not rows:
        return {"ok": True, "void_count": 0, "voids": []}

    cells = build_void_complex(rows, allowlist=[], prefix_len=24)
    total = sum(int(c.get("hits") or 0) for c in cells.values())
    voids = []
    for cell in cells.values():
        asvi = compute_asvi(cell, total_hits=total)
        if asvi < float(_cfg().get("stage_threshold") or 0.35):
            continue
        voids.append(
            {
                "prefix": cell["prefix"],
                "asvi": asvi,
                "smst": smst_classify(asvi),
                "hits": cell["hits"],
                "sample_ips": sorted(cell["ips"])[:5],
            }
        )
    voids.sort(key=lambda x: -x["asvi"])
    return {"ok": True, "void_count": len(voids), "voids": voids[:24], "zenodo": ZENODO}


def status() -> dict[str, Any]:
    cfg = _cfg()
    last = None
    if SCAN_STATE.is_file():
        try:
            last = json.loads(SCAN_STATE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            last = None
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "zenodo": ZENODO,
        "config": cfg,
        "smst_labels": list(SMST_LABELS),
        "last_scan": last,
    }


def void_boost_candidates(voids: list[dict[str, Any]]) -> list[str]:
    """Return CIDR prefixes worth staging from ASVI stage/act voids."""
    out: list[str] = []
    for v in voids:
        if v.get("smst") in ("stage", "act") and v.get("prefix"):
            out.append(str(v["prefix"]))
    return out
