"""AI-assisted IDS: NIST-aligned detection, log-only mode, traffic priority hints."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import devices, information_flow, ids_enforce, policies, qos

EVENTS_FILE = Path("/var/lib/array-firewall/ids-events.json")
STATE_FILE = Path("/var/lib/array-firewall/ids-state.json")
SNAPSHOT_FILE = Path("/var/lib/array-firewall/ids-flow-snapshot.json")
MAX_EVENTS = 500

# NIST SP 800-53 Rev 5 / CSF-aligned detection catalog (log-only enforcement).
NIST_RULES: list[dict[str, Any]] = [
    {
        "id": "SI-4",
        "framework": "NIST 800-53",
        "title": "System Monitoring",
        "description": "Detect anomalous traffic patterns and connection spikes.",
        "signals": ["connection_spike", "egress_flood", "new_device_burst"],
    },
    {
        "id": "SC-7",
        "framework": "NIST 800-53",
        "title": "Boundary Protection",
        "description": "Suspicious outbound connections and port scanning.",
        "signals": ["port_scan", "unusual_egress_port", "wan_probe"],
    },
    {
        "id": "AC-17",
        "framework": "NIST 800-53",
        "title": "Remote Access",
        "description": "Remote admin ports accessed from LAN devices.",
        "signals": ["remote_admin_port", "rdp_ssh_outbound"],
    },
    {
        "id": "CM-7",
        "framework": "NIST 800-53",
        "title": "Least Functionality",
        "description": "Legacy or risky protocol use on the LAN.",
        "signals": ["legacy_protocol", "telnet_ftp"],
    },
    {
        "id": "AU-6",
        "framework": "NIST 800-53",
        "title": "Audit Review",
        "description": "Traffic anomalies warranting operator review.",
        "signals": ["ai_elevated_risk", "priority_mismatch"],
    },
    {
        "id": "SI-4-IFC",
        "framework": "Information Flow Complexity",
        "title": "Dynamic State Monitoring",
        "description": "Shannon flow H(State_t|State_{t-1}) spikes and super-linear transitions (Zenodo 17373031).",
        "signals": [
            "information_flow_spike",
            "superlinear_information_flow",
            "sustained_high_flow",
        ],
    },
]

SUSPICIOUS_PORTS = {
    23: "telnet",
    21: "ftp",
    445: "smb",
    3389: "rdp",
    5900: "vnc",
    1433: "mssql",
    3306: "mysql",
    6379: "redis",
    11211: "memcached",
    53: "dns",
}

REMOTE_ADMIN_PORTS = {22, 3389, 5900, 5985, 5986}


def _cfg() -> dict[str, Any]:
    data = policies.load()
    base = {
        "enabled": True,
        "mode": "log_only",
        "scan_interval_sec": 30,
        "ai_enabled": True,
        "ollama_url": os.environ.get("IDS_OLLAMA_URL", "http://192.0.2.62:11434"),
        "ollama_model": os.environ.get("IDS_OLLAMA_MODEL", "llama3.2:1b"),
        "ollama_timeout_sec": 30,
        "connection_spike_threshold": 80,
        "port_scan_threshold": 12,
        "block_ttl_sec": 3600,
    }
    base.update(data.get("ids") or {})
    return base


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _load_events() -> list[dict[str, Any]]:
    if not EVENTS_FILE.is_file():
        return []
    try:
        data = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
        return list(data.get("events") or [])
    except (json.JSONDecodeError, OSError):
        return []


def _save_events(events: list[dict[str, Any]]) -> None:
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "updated": _now(), "events": events[-MAX_EVENTS:]}
    tmp = EVENTS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(EVENTS_FILE)


def _load_state() -> dict[str, Any]:
    if not STATE_FILE.is_file():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_state(state: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    tmp.replace(STATE_FILE)


def _device_label(ip: str) -> str:
    for dev in devices.list_devices():
        if str(dev.get("ip") or "") == ip:
            return devices.display_name(dev)
    return ip


def _parse_flows() -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    try:
        raw = subprocess.check_output(
            ["conntrack", "-L"],
            text=True,
            timeout=10,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return flows

    for line in raw.splitlines():
        src_m = re.search(r"\bsrc=([\d.]+)", line)
        dst_m = re.search(r"\bdst=([\d.]+)", line)
        sport_m = re.search(r"\bsport=(\d+)", line)
        dport_m = re.search(r"\bdport=(\d+)", line)
        proto_m = re.search(r"^(tcp|udp|icmp)", line, re.I)
        if not src_m or not dst_m:
            continue
        flows.append(
            {
                "src": src_m.group(1),
                "dst": dst_m.group(1),
                "sport": int(sport_m.group(1)) if sport_m else 0,
                "dport": int(dport_m.group(1)) if dport_m else 0,
                "proto": (proto_m.group(1).lower() if proto_m else "unknown"),
            }
        )
    return flows


def _is_lan(ip: str) -> bool:
    return ip.startswith("192.0.2.") or ip.startswith("198.51.100.")


def _is_wan(ip: str) -> bool:
    return bool(ip) and not _is_lan(ip) and not ip.startswith("127.")


def _emit(
    events: list[dict[str, Any]],
    *,
    severity: str,
    signal: str,
    nist_id: str,
    title: str,
    detail: str,
    device_ip: str = "",
    meta: dict[str, Any] | None = None,
) -> None:
    rule = next((r for r in NIST_RULES if r["id"] == nist_id), {})
    events.append(
        {
            "id": f"{signal}-{int(time.time() * 1000)}",
            "ts": _now(),
            "severity": severity,
            "signal": signal,
            "nist_id": nist_id,
            "nist_title": rule.get("title", nist_id),
            "title": title,
            "detail": detail,
            "device_ip": device_ip,
            "device_label": _device_label(device_ip) if device_ip else "",
            "action": "logged",
            "meta": meta or {},
        }
    )


def _heuristic_scan(flows: list[dict[str, Any]], cfg: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    ports_by_src: dict[str, set[int]] = defaultdict(set)
    conns_by_src: dict[str, int] = defaultdict(int)
    wan_dsts_by_src: dict[str, set[str]] = defaultdict(set)

    for f in flows:
        src, dst = f["src"], f["dst"]
        if not _is_lan(src):
            continue
        conns_by_src[src] += 1
        if f["dport"]:
            ports_by_src[src].add(f["dport"])
        if _is_wan(dst):
            wan_dsts_by_src[src].add(dst)
            dport = f["dport"]
            if dport in SUSPICIOUS_PORTS and dport not in (53, 443, 80):
                _emit(
                    events,
                    severity="medium",
                    signal="unusual_egress_port",
                    nist_id="SC-7",
                    title=f"Unusual egress: {SUSPICIOUS_PORTS[dport]}",
                    detail=f"{_device_label(src)} ({src}) → {dst}:{dport} ({SUSPICIOUS_PORTS[dport]})",
                    device_ip=src,
                    meta={"port": dport, "dst": dst},
                )
            if dport in REMOTE_ADMIN_PORTS:
                _emit(
                    events,
                    severity="high",
                    signal="remote_admin_port",
                    nist_id="AC-17",
                    title=f"Remote admin port {dport}",
                    detail=f"{_device_label(src)} ({src}) outbound to {dst}:{dport}",
                    device_ip=src,
                    meta={"port": dport, "dst": dst},
                )
            if dport in (23, 21):
                _emit(
                    events,
                    severity="medium",
                    signal="legacy_protocol",
                    nist_id="CM-7",
                    title=f"Legacy protocol {SUSPICIOUS_PORTS.get(dport, dport)}",
                    detail=f"{_device_label(src)} ({src}) → {dst}:{dport}",
                    device_ip=src,
                )

    spike_thr = int(cfg.get("connection_spike_threshold") or 80)
    scan_thr = int(cfg.get("port_scan_threshold") or 12)

    for src, count in conns_by_src.items():
        if count >= spike_thr:
            _emit(
                events,
                severity="high" if count >= spike_thr * 2 else "medium",
                signal="connection_spike",
                nist_id="SI-4",
                title="Connection spike",
                detail=f"{_device_label(src)} ({src}) has {count} active flows",
                device_ip=src,
                meta={"connections": count},
            )

    for src, ports in ports_by_src.items():
        if len(ports) >= scan_thr:
            _emit(
                events,
                severity="high",
                signal="port_scan",
                nist_id="SC-7",
                title="Possible port scan",
                detail=f"{_device_label(src)} ({src}) touched {len(ports)} distinct destination ports",
                device_ip=src,
                meta={"unique_ports": len(ports)},
            )

    for src, dsts in wan_dsts_by_src.items():
        if len(dsts) >= 25:
            _emit(
                events,
                severity="medium",
                signal="egress_flood",
                nist_id="SI-4",
                title="Wide egress fan-out",
                detail=f"{_device_label(src)} ({src}) connected to {len(dsts)} external hosts",
                device_ip=src,
                meta={"external_hosts": len(dsts)},
            )

    return events


def _ollama_reachable(url: str, timeout: float = 3.0) -> bool:
    try:
        req = urllib.request.Request(f"{url.rstrip('/')}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _ai_assess(new_events: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    if not cfg.get("ai_enabled", True) or not new_events:
        return {"ok": False, "skipped": True, "reason": "no_events_or_disabled"}

    url = str(cfg.get("ollama_url", "")).rstrip("/")
    model = str(cfg.get("ollama_model", "qwen2.5-coder:7b"))
    timeout = max(30, int(cfg.get("ollama_timeout_sec") or 90))
    if not _ollama_reachable(url):
        return {"ok": False, "reachable": False, "error": "Ollama API unreachable at " + url}

    highlights = [
        f"- [{e['severity']}] {e['title']}: {e['detail']} (NIST {e['nist_id']})"
        for e in new_events[:8]
    ]
    prompt = (
        "You are a network IDS analyst aligned with NIST CSF/800-53. "
        "Review these firewall log-only alerts. Reply JSON only:\n"
        '{"risk_score":0-100,"verdict":"low|medium|high","summary":"one sentence",'
        '"recommendations":["..."],"priority_notes":"traffic priority guidance"}\n\n'
        "Alerts:\n" + "\n".join(highlights)
    )
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"num_predict": 128, "temperature": 0.2},
        }
    ).encode()
    req = urllib.request.Request(
        f"{url}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        text = (data.get("response") or "").strip()
        parsed = json.loads(text) if text.startswith("{") else {"summary": text[:400]}
        return {"ok": True, "reachable": True, "model": model, "assessment": parsed}
    except TimeoutError:
        return {
            "ok": False,
            "reachable": True,
            "error": "inference_timeout",
            "detail": f"Ollama reachable but GPU queue busy (>{timeout}s) — gh-inbox fleet may be using .221",
        }
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if "timed out" in str(reason).lower():
            return {
                "ok": False,
                "reachable": True,
                "error": "inference_timeout",
                "detail": f"Ollama reachable but inference timed out after {timeout}s (GPU likely busy)",
            }
        return {"ok": False, "reachable": False, "error": str(reason)}
    except (json.JSONDecodeError, OSError) as exc:
        return {"ok": False, "reachable": True, "error": str(exc)}


def analyze(*, force: bool = False) -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "enabled": False, "skipped": True}

    state = _load_state()
    now = time.time()
    interval = max(10, int(cfg.get("scan_interval_sec") or 30))
    if not force and state.get("last_scan_ts") and (now - float(state["last_scan_ts"])) < interval:
        return summary()

    flows = _parse_flows()
    new_events = _heuristic_scan(flows, cfg)

    try:
        information_flow.analyze_step()
        for sig in information_flow.ids_signals():
            _emit(
                new_events,
                severity=str(sig.get("severity") or "medium"),
                signal=str(sig.get("signal") or "information_flow_spike"),
                nist_id="SI-4-IFC",
                title=str(sig.get("title") or "Information flow anomaly"),
                detail=str(sig.get("detail") or ""),
                meta=sig.get("meta") if isinstance(sig.get("meta"), dict) else {},
            )
    except OSError:
        pass
    ai = _ai_assess(new_events, cfg) if new_events else {"ok": False, "skipped": True}

    if ai.get("ok") and isinstance(ai.get("assessment"), dict):
        score = int(ai["assessment"].get("risk_score") or 0)
        if score >= 70:
            new_events.append(
                {
                    "id": f"ai-{int(now * 1000)}",
                    "ts": _now(),
                    "severity": "high" if score >= 85 else "medium",
                    "signal": "ai_elevated_risk",
                    "nist_id": "AU-6",
                    "nist_title": "Audit Review",
                    "title": "AI elevated risk assessment",
                    "detail": str(ai["assessment"].get("summary") or "AI flagged elevated risk"),
                    "device_ip": "",
                    "device_label": "",
                    "action": "logged",
                    "meta": {"risk_score": score},
                }
            )

    existing = _load_events()
    # Dedupe by signal+device in last 5 minutes
    recent_keys = {
        f"{e.get('signal')}:{e.get('device_ip')}"
        for e in existing
        if e.get("ts", "") > time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 300))
    }
    merged = existing
    added_for_enforce: list[dict[str, Any]] = []
    for ev in new_events:
        key = f"{ev.get('signal')}:{ev.get('device_ip')}"
        if key not in recent_keys:
            merged.append(ev)
            added_for_enforce.append(ev)
            recent_keys.add(key)

    enforce_result = ids_enforce.apply_events(added_for_enforce)

    _save_events(merged)
    SNAPSHOT_FILE.write_text(
        json.dumps({"ts": _now(), "flow_count": len(flows)}, indent=2) + "\n",
        encoding="utf-8",
    )

    priority = qos.priority_summary()
    state.update(
        {
            "last_scan_ts": now,
            "last_scan": _now(),
            "flow_count": len(flows),
            "new_events": len(new_events),
            "total_events": len(merged),
            "ai": ai,
            "priority": priority,
            "mode": cfg.get("mode", "log_only"),
        }
    )
    _save_state(state)

    return {
        "ok": True,
        "scanned_at": state["last_scan"],
        "flow_count": len(flows),
        "new_events": len(new_events),
        "highlights": highlights(limit=12),
        "ai": ai,
        "priority": priority,
        "mode": cfg.get("mode", "log_only"),
        "enforcement": enforce_result,
    }


def highlights(*, limit: int = 20, severity: str | None = None) -> list[dict[str, Any]]:
    events = _load_events()
    if severity:
        events = [e for e in events if e.get("severity") == severity]
    events.sort(key=lambda e: e.get("ts", ""), reverse=True)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    events.sort(key=lambda e: (order.get(str(e.get("severity", "info")), 9), e.get("ts", "")), reverse=True)
    return events[:limit]


def summary() -> dict[str, Any]:
    cfg = _cfg()
    state = _load_state()
    events = _load_events()
    sev_counts: dict[str, int] = defaultdict(int)
    for e in events:
        sev_counts[str(e.get("severity", "info"))] += 1

    recent = highlights(limit=8)
    priority = qos.priority_summary()
    mode = cfg.get("mode", "log_only")
    mode_labels = {
        "log_only": "Log only — suspicious activity recorded, not blocked",
        "alert": "Alert — elevated events flagged for review",
        "block": "Block — high-severity sources blocked at firewall",
        "quarantine": "Quarantine — high-severity devices denied internet",
    }

    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "mode": mode,
        "mode_label": mode_labels.get(str(mode), str(mode)),
        "valid_modes": list(ids_enforce.VALID_MODES),
        "enforcement": ids_enforce.status(),
        "nist_rules": len(NIST_RULES),
        "nist_catalog": NIST_RULES,
        "last_scan": state.get("last_scan"),
        "flow_count": state.get("flow_count", 0),
        "event_counts": dict(sev_counts),
        "total_events": len(events),
        "highlights": recent,
        "ai": state.get("ai") or {},
        "priority": priority,
        "scan_interval_sec": cfg.get("scan_interval_sec", 30),
        "information_flow": information_flow.status(),
    }


def events(limit: int = 100, severity: str | None = None) -> dict[str, Any]:
    evs = highlights(limit=min(limit, MAX_EVENTS), severity=severity)
    return {"ok": True, "events": evs, "count": len(evs)}


def nist_catalog() -> dict[str, Any]:
    return {"ok": True, "rules": NIST_RULES, "mode": _cfg().get("mode", "log_only")}


def set_mode(mode: str) -> dict[str, Any]:
    return ids_enforce.set_mode(mode)


def clear_enforcement() -> dict[str, Any]:
    return ids_enforce.clear_blocks()
