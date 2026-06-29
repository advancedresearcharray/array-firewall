"""Built-in agent: investigate unknown WAN connections (PTR, WHOIS, behavior → label + purpose)."""
from __future__ import annotations

import ipaddress
import json
import queue
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from . import abuse_report

ROLES_FILE = Path("/opt/warzone-lobby-sentinel/data/server-roles.json")
ROLES_FALLBACK = Path(__file__).resolve().parents[3] / "warzone-lobby-sentinel/data/server-roles.json"
INTEL_FILE = Path("/var/lib/array-firewall/ip-intel.json")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_VULTR_PREFIXES = ("45.76.", "45.77.", "66.42.", "108.61.", "149.28.", "155.138.", "207.148.", "140.82.")
_WORKER: threading.Thread | None = None
_QUEUE: queue.Queue[str] = queue.Queue()
_LOCK = threading.Lock()

VPS_ORG_KEYS = (
    "vultr",
    "choopa",
    "linode",
    "digitalocean",
    "hetzner",
    "ovh",
    "contabo",
    "amazon",
    "google cloud",
    "microsoft",
    "azure",
)


def _now() -> float:
    return time.time()


def _valid_wan_ip(ip: str) -> bool:
    ip = ip.strip()
    if not _IP_RE.match(ip):
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


def _load_roles() -> list[dict[str, Any]]:
    for path in (ROLES_FILE, ROLES_FALLBACK):
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return list(data.get("rules") or [])
            except (json.JSONDecodeError, OSError):
                continue
    return []


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def classify_hostname(hostname: str) -> str:
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return "unknown"
    try:
        from . import rqd

        role, _meta = rqd.classify_rules_fast("", _load_roles(), hostname=host)
        if role != "unknown":
            return role
    except Exception:
        pass
    for rule in _load_roles():
        excludes = [str(x).lower() for x in (rule.get("matchExclude") or [])]
        if any(x in host for x in excludes):
            continue
        patterns = [str(x).lower() for x in (rule.get("match") or [])]
        if any(p in host for p in patterns):
            return str(rule.get("id") or "unknown")
    return "unknown"


def classify_ip_cidr(ip: str) -> str:
    try:
        from . import rqd

        role, _meta = rqd.classify_rules_fast(ip, _load_roles())
        if role != "unknown":
            return role
    except Exception:
        pass
    for rule in _load_roles():
        for cidr in rule.get("cidrs") or []:
            if _ip_in_cidr(ip, str(cidr)):
                return str(rule.get("id") or "unknown")
    return "unknown"


def reverse_ptr(ip: str) -> str:
    try:
        raw = subprocess.check_output(
            ["dig", "+short", "+time=1", "+tries=1", "-x", ip, "@1.1.1.1"],
            text=True,
            timeout=4,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return ""
    return (raw.splitlines()[0] if raw.splitlines() else "").strip().rstrip(".").lower()


def _vps_label(org: str, ip: str) -> str:
    blob = (org or "").lower()
    if "vultr" in blob or "choopa" in blob or ip.startswith(_VULTR_PREFIXES):
        return "Vultr VPS"
    if "linode" in blob or "akamai" in blob:
        return "Linode VPS"
    if "digitalocean" in blob:
        return "DigitalOcean"
    if "amazon" in blob or "aws" in blob:
        return "AWS"
    if "google" in blob:
        return "Google Cloud"
    if "microsoft" in blob or "azure" in blob:
        return "Azure"
    if "hetzner" in blob:
        return "Hetzner VPS"
    if "ovh" in blob:
        return "OVH"
    if any(k in blob for k in ("vps", "hosting", "cloud", "datacenter", "server")):
        return "Cloud/VPS host"
    return ""


def _behavior_summary(*, proto: str, direction: str, port: int | None, tiny: int, identical: int, total: int) -> str:
    parts: list[str] = []
    p = (proto or "udp").lower()
    d = (direction or "in").lower()
    if d == "in":
        parts.append("inbound to Xbox")
    else:
        parts.append("outbound from Xbox")
    if port:
        parts.append(f"{p}/{port}")
    elif p:
        parts.append(p)
    if tiny >= 4:
        parts.append(f"{tiny} tiny packets (≤79B) — likely probe/flood")
    elif tiny >= 1:
        parts.append(f"{tiny} small packets")
    if identical >= 6:
        parts.append(f"identical burst ×{identical} — scripted traffic")
    elif identical >= 2:
        parts.append(f"repeated size ×{identical}")
    if total >= 20:
        parts.append(f"{total} packets total — sustained contact")
    return " · ".join(parts) if parts else "WAN socket — role not in allowlist"


def _parse_port(remote: str) -> int | None:
    remote = str(remote or "")
    if remote.count(":") == 1 and "." in remote:
        try:
            return int(remote.rsplit(":", 1)[1])
        except ValueError:
            return None
    return None


def investigate_ip(ip: str, *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run built-in investigation for one WAN IP."""
    ip = ip.strip()
    if not _valid_wan_ip(ip):
        return {"ok": False, "error": "invalid or non-WAN IP", "ip": ip}

    ctx = context or {}
    ptr = reverse_ptr(ip)
    whois = abuse_report.lookup_ip(ip)
    org = str(whois.get("org") or "unknown")
    country = str(whois.get("country") or "")
    provider = whois.get("provider") or {}

    hostname = ptr or ""
    conn_type = "unknown"
    if hostname:
        conn_type = classify_hostname(hostname)
    if conn_type == "unknown":
        conn_type = classify_ip_cidr(ip)
    if conn_type == "unknown" and hostname:
        conn_type = classify_hostname(hostname.split(".")[0])

    proto = str(ctx.get("proto") or "udp")
    direction = str(ctx.get("direction") or "in")
    port = ctx.get("port")
    if port is None:
        port = _parse_port(str(ctx.get("remote") or ""))
    tiny = int(ctx.get("tiny_packets") or 0)
    identical = int(ctx.get("identical_max") or ctx.get("identical_count") or 0)
    total = int(ctx.get("total_packets") or ctx.get("hit_count") or 0)

    label = _vps_label(org, ip)
    purpose_parts: list[str] = []

    if conn_type == "unknown":
        if proto.lower() == "udp" and port and int(port) >= 1024 and direction == "in":
            conn_type = "game-peer"
            purpose_parts.append("High-port inbound UDP — classified as P2P/game-peer by port heuristic")
        elif tiny >= 3 and direction == "in":
            conn_type = "game-peer"
            purpose_parts.append("Tiny inbound packets — typical kick/probe pattern")

    if not label and hostname:
        label = hostname.split(".")[0]
    if not label:
        label = _vps_label(org, ip) or org[:48] or "Unknown host"

    behavior = _behavior_summary(
        proto=proto,
        direction=direction,
        port=int(port) if port else None,
        tiny=tiny,
        identical=identical,
        total=total,
    )
    purpose_parts.append(behavior)
    if org and org != "unknown":
        loc = f" ({country})" if country else ""
        purpose_parts.append(f"WHOIS: {org}{loc}")
    if ptr:
        purpose_parts.append(f"PTR: {ptr}")
    if provider:
        purpose_parts.append(f"Provider: {provider.get('name', '')}")

    is_vps = bool(_vps_label(org, ip)) or any(k in org.lower() for k in VPS_ORG_KEYS)
    suspicious = is_vps and conn_type == "game-peer" and (tiny >= 2 or identical >= 2)

    status = "resolved" if conn_type != "unknown" else "partial"
    if conn_type == "unknown" and not ptr and org == "unknown":
        status = "unknown"

    result = {
        "ok": True,
        "ip": ip,
        "status": status,
        "conn_type": conn_type,
        "label": label,
        "purpose": " — ".join(purpose_parts),
        "ptr": ptr,
        "org": org,
        "country": country,
        "provider": provider,
        "is_vps": is_vps,
        "suspicious": suspicious,
        "investigated_at": _now(),
        "context": ctx,
    }
    _save_intel(ip, result)
    return result


def _save_intel(ip: str, data: dict[str, Any]) -> None:
    with _LOCK:
        cache: dict[str, Any] = {}
        if INTEL_FILE.is_file():
            try:
                cache = json.loads(INTEL_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                cache = {}
        cache[ip] = data
        INTEL_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = INTEL_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
        tmp.replace(INTEL_FILE)


def get_intel(ip: str) -> dict[str, Any] | None:
    if not INTEL_FILE.is_file():
        return None
    try:
        cache = json.loads(INTEL_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    row = cache.get(ip)
    return row if isinstance(row, dict) else None


def list_intel(*, limit: int = 100) -> dict[str, Any]:
    if not INTEL_FILE.is_file():
        return {"ok": True, "entries": []}
    try:
        cache = json.loads(INTEL_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"ok": True, "entries": []}
    items = sorted(
        cache.values(),
        key=lambda x: float(x.get("investigated_at") or 0),
        reverse=True,
    )[: max(1, min(limit, 500))]
    return {"ok": True, "entries": items}


def apply_intel_to_db(ip: str, intel: dict[str, Any]) -> dict[str, Any]:
    """Update conn_lite_db rows after investigation."""
    from . import conn_lite_db

    conn_type = str(intel.get("conn_type") or "unknown")
    label = str(intel.get("label") or "")
    purpose = str(intel.get("purpose") or "")
    suspicious = 1 if intel.get("suspicious") else 0
    vps_probe = 1 if intel.get("is_vps") and conn_type == "game-peer" else 0

    with conn_lite_db._LOCK:  # noqa: SLF001
        conn = conn_lite_db._connect()  # noqa: SLF001
        try:
            conn_lite_db._init_db(conn)  # noqa: SLF001
            conn.execute(
                """
                UPDATE conn_rows SET
                    conn_type = CASE WHEN conn_type = 'unknown' AND ? != 'unknown' THEN ? ELSE conn_type END,
                    label = CASE WHEN ? != '' THEN ? ELSE label END,
                    suspicious = MAX(suspicious, ?),
                    vps_probe = MAX(vps_probe, ?)
                WHERE ip = ?
                """,
                (conn_type, conn_type, label, label, suspicious, vps_probe, ip),
            )
            conn.commit()
            updated = conn.execute(
                "SELECT COUNT(*) FROM conn_rows WHERE ip = ?", (ip,)
            ).fetchone()[0]
        finally:
            conn.close()

    return {
        "ok": True,
        "ip": ip,
        "updated_rows": updated,
        "conn_type": conn_type,
        "label": label,
        "purpose": purpose,
    }


def queue_ip(ip: str) -> None:
    if not _valid_wan_ip(ip):
        return
    existing = get_intel(ip)
    if existing and (_now() - float(existing.get("investigated_at") or 0)) < 3600:
        return
    _QUEUE.put(ip)
    _ensure_worker()


def queue_from_conn_rows(rows: list[dict[str, Any]]) -> int:
    queued = 0
    for row in rows:
        if str(row.get("conn_type") or "") != "unknown":
            continue
        ip = str(row.get("ip") or "").strip()
        if not _valid_wan_ip(ip):
            continue
        queue_ip(ip)
        queued += 1
    return queued


def _ensure_worker() -> None:
    global _WORKER
    if _WORKER and _WORKER.is_alive():
        return

    def run() -> None:
        from . import conn_lite_db

        while True:
            try:
                ip = _QUEUE.get(timeout=30)
            except queue.Empty:
                continue
            ctx: dict[str, Any] = {}
            with conn_lite_db._LOCK:  # noqa: SLF001
                conn = conn_lite_db._connect()  # noqa: SLF001
                try:
                    conn_lite_db._init_db(conn)  # noqa: SLF001
                    row = conn.execute(
                        """
                        SELECT * FROM conn_rows WHERE ip = ?
                        ORDER BY last_seen DESC LIMIT 1
                        """,
                        (ip,),
                    ).fetchone()
                    if row:
                        ctx = dict(row)
                finally:
                    conn.close()
            try:
                intel = investigate_ip(ip, context=ctx)
                apply_intel_to_db(ip, intel)
            except Exception as exc:  # noqa: BLE001
                _save_intel(
                    ip,
                    {
                        "ok": False,
                        "ip": ip,
                        "status": "error",
                        "error": str(exc),
                        "investigated_at": _now(),
                    },
                )
            finally:
                _QUEUE.task_done()

    _WORKER = threading.Thread(target=run, name="unknown-investigator", daemon=True)
    _WORKER.start()


def run_pending(*, limit: int = 20) -> dict[str, Any]:
    from . import conn_lite_db

    with conn_lite_db._LOCK:  # noqa: SLF001
        conn = conn_lite_db._connect()  # noqa: SLF001
        try:
            conn_lite_db._init_db(conn)  # noqa: SLF001
            rows = conn.execute(
                """
                SELECT DISTINCT ip FROM conn_rows
                WHERE conn_type = 'unknown'
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (max(1, min(limit, 100)),),
            ).fetchall()
        finally:
            conn.close()

    ip_rows = [{"ip": row["ip"]} for row in rows]
    try:
        from . import rqd

        ctx_rows = []
        for item in ip_rows:
            ctx_row = conn_lite_db.query(ip=item["ip"], limit=1).get("rows") or []
            ctx_rows.append(ctx_row[0] if ctx_row else item)
        ordered = rqd.prioritize_investigation(ctx_rows)
        ip_order = [str(r.get("ip") or "") for r in ordered if r.get("ip")]
        row_map = {row["ip"]: row for row in rows}
        rows = [row_map[ip] for ip in ip_order if ip in row_map]
    except Exception:
        pass

    results = []
    for row in rows:
        ip = row["ip"]
        ctx_row = conn_lite_db.query(ip=ip, limit=1).get("rows") or []
        ctx = ctx_row[0] if ctx_row else {}
        intel = investigate_ip(ip, context=ctx)
        applied = apply_intel_to_db(ip, intel)
        results.append(applied)

    return {"ok": True, "investigated": len(results), "results": results}


def enrich_query_row(row: dict[str, Any]) -> dict[str, Any]:
    intel = get_intel(str(row.get("ip") or ""))
    if intel:
        row["intel"] = {
            "status": intel.get("status"),
            "purpose": intel.get("purpose"),
            "ptr": intel.get("ptr"),
            "org": intel.get("org"),
            "investigated_at": intel.get("investigated_at"),
        }
        if row.get("conn_type") == "unknown" and intel.get("conn_type") not in (None, "unknown"):
            row["conn_type"] = intel.get("conn_type")
        if not row.get("label") and intel.get("label"):
            row["label"] = intel.get("label")
    elif row.get("conn_type") == "unknown":
        row["intel"] = {"status": "pending", "purpose": "Investigation queued…"}
        queue_ip(str(row.get("ip") or ""))
    return row
