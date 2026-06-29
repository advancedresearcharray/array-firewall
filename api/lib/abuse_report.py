"""Upstream abuse reporting — log VPS attackers and generate provider reports."""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from . import policies

REPORT_FILE = Path("/var/lib/array-firewall/abuse-reports.json")
WHOIS_CACHE = Path("/var/lib/array-firewall/whois-cache.json")

# Provider hints from org/_descr substrings → abuse portal + mailto template
PROVIDERS: dict[str, dict[str, str]] = {
    "vultr": {
        "name": "Vultr",
        "url": "https://www.vultr.com/report-abuse/",
        "email": "abuse@vultr.com",
    },
    "choopa": {
        "name": "Vultr (Choopa)",
        "url": "https://www.vultr.com/report-abuse/",
        "email": "abuse@vultr.com",
    },
    "ovh": {
        "name": "OVH",
        "url": "https://www.ovh.com/abuse/",
        "email": "abuse@ovh.net",
    },
    "hetzner": {
        "name": "Hetzner",
        "url": "https://www.hetzner.com/abuse",
        "email": "abuse@hetzner.com",
    },
    "linode": {
        "name": "Linode (Akamai)",
        "url": "https://www.linode.com/legal-abuse/",
        "email": "abuse@linode.com",
    },
    "akamai": {
        "name": "Akamai/Linode",
        "url": "https://www.linode.com/legal-abuse/",
        "email": "abuse@linode.com",
    },
    "digitalocean": {
        "name": "DigitalOcean",
        "url": "https://www.digitalocean.com/community/pages/abuse",
        "email": "abuse@digitalocean.com",
    },
    "amazon": {
        "name": "AWS",
        "url": "https://repost.aws/knowledge-center/report-aws-abuse",
        "email": "abuse@amazonaws.com",
    },
    "microsoft": {
        "name": "Microsoft Azure",
        "url": "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/30",
        "email": "abuse@microsoft.com",
    },
    "google": {
        "name": "Google Cloud",
        "url": "https://support.google.com/code/go/report-abuse",
        "email": "abuse@google.com",
    },
    "contabo": {
        "name": "Contabo",
        "url": "https://contabo.com/en/abuse/",
        "email": "abuse@contabo.com",
    },
}


def _cfg() -> dict[str, Any]:
    gaming = policies.gaming()
    base = {"auto_record": True, "min_hits_for_report": 2}
    base.update(gaming.get("mitigation") or {})
    return base


def _now() -> float:
    return time.time()


def _load() -> dict[str, Any]:
    if not REPORT_FILE.is_file():
        return {"incidents": {}, "reports": []}
    try:
        return json.loads(REPORT_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"incidents": {}, "reports": []}


def _save(data: dict[str, Any]) -> None:
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    data["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tmp = REPORT_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(REPORT_FILE)


def _load_whois_cache() -> dict[str, Any]:
    if not WHOIS_CACHE.is_file():
        return {}
    try:
        return json.loads(WHOIS_CACHE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_whois_cache(cache: dict[str, Any]) -> None:
    WHOIS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    WHOIS_CACHE.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")


def lookup_ip(ip: str) -> dict[str, Any]:
    cache = _load_whois_cache()
    if ip in cache and (_now() - float(cache[ip].get("cached_at") or 0)) < 86400 * 7:
        return cache[ip]

    org = ""
    descr = ""
    country = ""
    netname = ""
    try:
        raw = subprocess.check_output(["whois", ip], text=True, timeout=12, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        raw = ""

    for line in raw.splitlines():
        low = line.lower()
        if not org and re.match(r"^(orgname|org-name|organisation|organization)\s*:", low):
            org = line.split(":", 1)[-1].strip()
        if not descr and re.match(r"^(descr|netname)\s*:", low):
            val = line.split(":", 1)[-1].strip()
            if low.startswith("netname"):
                netname = val
            else:
                descr = val
        if not country and re.match(r"^country\s*:", low):
            country = line.split(":", 1)[-1].strip()

    blob = " ".join([org, descr, netname]).lower()
    provider_key = ""
    provider = {}
    for key, info in PROVIDERS.items():
        if key in blob:
            provider_key = key
            provider = info
            break

    result = {
        "ip": ip,
        "org": org or descr or netname or "unknown",
        "country": country,
        "provider_key": provider_key,
        "provider": provider,
        "cached_at": _now(),
    }
    cache[ip] = result
    _save_whois_cache(cache)
    return result


def record_incident(
    ip: str,
    *,
    reason: str = "gaming_attack",
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("auto_record", True):
        return {"ok": True, "skipped": True}

    data = _load()
    incidents: dict[str, Any] = dict(data.get("incidents") or {})
    now = _now()
    entry = incidents.get(ip) or {
        "ip": ip,
        "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "hits": 0,
        "reasons": [],
    }
    entry["hits"] = int(entry.get("hits") or 0) + 1
    entry["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    if reason not in (entry.get("reasons") or []):
        entry.setdefault("reasons", []).append(reason)
    if meta:
        events = list(entry.get("events") or [])
        events.append({"ts": entry["last_seen"], "reason": reason, "meta": meta})
        entry["events"] = events[-50:]
    if not entry.get("whois"):
        entry["whois"] = lookup_ip(ip)
    incidents[ip] = entry
    data["incidents"] = incidents
    _save(data)
    return {"ok": True, "incident": entry}


def generate_report(ip: str) -> dict[str, Any]:
    data = _load()
    incident = (data.get("incidents") or {}).get(ip)
    if not incident:
        incident = record_incident(ip, reason="manual_report").get("incident")

    whois = incident.get("whois") or lookup_ip(ip)
    provider = whois.get("provider") or {}
    hostname = policies.network().get("hostname") or "array-firewall"
    body = (
        f"Abuse report — unauthorized network attack targeting home gaming console\n\n"
        f"Reporter network: {hostname} (residential gateway)\n"
        f"Attacker IP: {ip}\n"
        f"Organization: {whois.get('org', 'unknown')}\n"
        f"Country: {whois.get('country', 'unknown')}\n"
        f"First seen: {incident.get('first_seen', 'unknown')}\n"
        f"Last seen: {incident.get('last_seen', 'unknown')}\n"
        f"Observed incidents: {incident.get('hits', 1)}\n"
        f"Reasons: {', '.join(incident.get('reasons') or ['udp/tcp flood to gaming console'])}\n\n"
        f"Evidence: Inbound tiny-packet / kick-tool flood detected by edge firewall IDS.\n"
        f"Action requested: Investigate and suspend abusive VPS/host if confirmed.\n\n"
        f"— Automated report from array-firewall gaming mitigation\n"
    )

    report = {
        "ip": ip,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "provider": provider,
        "whois": whois,
        "incident": incident,
        "subject": f"Abuse report: network attack from {ip}",
        "body": body,
        "submit_url": provider.get("url"),
        "submit_email": provider.get("email"),
    }

    reports = list(data.get("reports") or [])
    reports.append(report)
    data["reports"] = reports[-200:]
    _save(data)
    return {"ok": True, "report": report}


def list_incidents(*, min_hits: int = 1, limit: int = 100) -> dict[str, Any]:
    cfg = _cfg()
    min_hits = max(min_hits, int(cfg.get("min_hits_for_report") or 1))
    data = _load()
    incidents = data.get("incidents") or {}
    rows = [
        v
        for v in incidents.values()
        if int(v.get("hits") or 0) >= min_hits
    ]
    rows.sort(key=lambda r: (int(r.get("hits") or 0), r.get("last_seen") or ""), reverse=True)
    return {
        "ok": True,
        "count": len(rows),
        "incidents": rows[:limit],
        "providers": {k: v["url"] for k, v in PROVIDERS.items()},
    }


def status() -> dict[str, Any]:
    data = _load()
    incidents = data.get("incidents") or {}
    pending = [ip for ip, row in incidents.items() if int(row.get("hits") or 0) >= 2]
    return {
        "ok": True,
        "incident_count": len(incidents),
        "pending_report_count": len(pending),
        "pending_ips": pending[:32],
        "recent_reports": (data.get("reports") or [])[-10:],
    }
