"""Mesh-cluster reputation — co-burst peer cliques share infrastructure score."""
from __future__ import annotations

import ipaddress
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

MESH_FILE = Path("/var/lib/array-firewall/mesh-reputation.json")


def _prefix24(ip: str) -> str:
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net.network_address) + "/24"
    except ValueError:
        return ""


def analyze_peers(peers: list[dict[str, Any]], *, session_hex: str = "") -> dict[str, Any]:
    """Group peers that co-burst with low size spread into mesh cliques."""
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in peers:
        ip = str(row.get("ip") or row.get("remote") or "").split(":")[0].strip()
        if not ip or ip.startswith(("10.", "192.168.", "127.")):
            continue
        identical = int(row.get("identical_count") or row.get("max_burst") or 0)
        if identical < 6 and not row.get("vps_probe"):
            continue
        key = f"{_prefix24(ip)}:{identical // 5}"
        buckets[key].append({**row, "ip": ip, "identical": identical})

    cliques: list[dict[str, Any]] = []
    ip_scores: dict[str, float] = {}
    for key, members in buckets.items():
        if len(members) < 2:
            continue
        vps_n = sum(1 for m in members if m.get("vps_probe"))
        score = round(min(1.0, 0.35 + len(members) * 0.08 + vps_n * 0.12), 3)
        clique_id = f"mesh:{key}:{len(members)}"
        cliques.append(
            {
                "clique_id": clique_id,
                "prefix": key.split(":")[0],
                "member_count": len(members),
                "vps_count": vps_n,
                "mesh_score": score,
                "ips": [m["ip"] for m in members[:16]],
            }
        )
        for m in members:
            ip_scores[m["ip"]] = max(ip_scores.get(m["ip"], 0.0), score)

    result = {
        "ok": True,
        "session_hex": session_hex,
        "analyzed_at": time.time(),
        "clique_count": len(cliques),
        "cliques": cliques[:24],
        "ip_scores": ip_scores,
    }
    if cliques:
        MESH_FILE.parent.mkdir(parents=True, exist_ok=True)
        prev = {}
        if MESH_FILE.is_file():
            try:
                prev = json.loads(MESH_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                prev = {}
        history = list(prev.get("recent") or [])[-40:]
        history.append(result)
        MESH_FILE.write_text(
            json.dumps({"updated_at": time.time(), "recent": history, "last": result}, indent=2) + "\n",
            encoding="utf-8",
        )
    return result


def cliques_for_subnet_block(mesh: dict[str, Any]) -> list[dict[str, Any]]:
    """Cliques eligible for automatic /24 subnet blocks."""
    out: list[dict[str, Any]] = []
    for clique in mesh.get("cliques") or []:
        if int(clique.get("member_count") or 0) >= 2 and int(clique.get("vps_count") or 0) >= 1:
            out.append(clique)
    return out


def mesh_score(ip: str) -> float:
    if not MESH_FILE.is_file():
        return 0.0
    try:
        data = json.loads(MESH_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0.0
    last = data.get("last") or {}
    return float((last.get("ip_scores") or {}).get(ip.strip()) or 0.0)


def status() -> dict[str, Any]:
    if not MESH_FILE.is_file():
        return {"ok": True, "clique_count": 0}
    try:
        data = json.loads(MESH_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"ok": True, "clique_count": 0}
    last = data.get("last") or {}
    return {
        "ok": True,
        "clique_count": last.get("clique_count", 0),
        "last_session": last.get("session_hex"),
        "cliques": (last.get("cliques") or [])[:8],
    }
