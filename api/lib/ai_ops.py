"""AI Autopilot — fuses Sentinel, IDS/Ollama, QCE, ASVI, RQD, and GPU signals into automatic firewall actions.

Modes:
  observe  — record fused threat graph and planned actions only
  assist   — shield sync, investigate, buffer tune (safe with tiny_packet_only)
  enforce  — block peers/subnets/IDS when confidence thresholds met
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import ids, peer_blocklist, policies, sentinel
from . import ai_learning, autopilot_audit, negative_allowlist, playability, reputation_graph
from . import adaptive_posture, pre_burst_forecast

STATE_FILE = Path("/var/lib/array-firewall/ai-ops.json")
LOG_FILE = Path("/var/lib/array-firewall/ai-ops-log.jsonl")
MAX_LOG = 200

HOSTILE_LABELS = frozenset({"LIKELY", "USER_BAD", "POSSIBLE"})
VPS_ORG_HINTS = ("vultr", "linode", "digitalocean", "hetzner", "choopa", "ovh", "contabo")


def _cfg() -> dict[str, Any]:
    base = {
        "enabled": True,
        "mode": "assist",
        "tick_interval_sec": 5,
        "ollama_planner": True,
        "ollama_url": "",
        "ollama_model": "",
        "ollama_timeout_sec": 45,
        "min_confidence_shield": 0.45,
        "min_confidence_block": 0.72,
        "min_confidence_subnet": 0.80,
        "override_tiny_packet_only": False,
        "auto_ids_on_hostile": True,
        "auto_buffer_on_spike": True,
        "max_blocks_per_tick": 8,
        "max_subnets_per_tick": 2,
        "fuse_weights": {
            "sentinel_likely": 0.35,
            "vps_probe": 0.40,
            "identical_burst": 0.25,
            "asvi_act": 0.30,
            "qce_peak": 0.25,
            "ids_ai_high": 0.30,
            "repeat_offender": 0.20,
            "gpu_flood": 0.20,
            "reputation_bad": 0.35,
            "pre_burst": 0.30,
        },
        "pre_burst_identical_min": 6,
        "pre_burst_identical_max": 19,
        "fleet_sync_enabled": True,
        "fleet_export_every_ticks": 60,
        "negative_allowlist_enabled": True,
        "learning_rate": 0.04,
    }
    ids_cfg = policies.load().get("ids") or {}
    base["ollama_url"] = base["ollama_url"] or ids_cfg.get("ollama_url") or ""
    base["ollama_model"] = base["ollama_model"] or ids_cfg.get("ollama_model") or "llama3.2:1b"
    base.update(policies.load().get("ai_ops") or {})
    return base


def _now() -> float:
    return time.time()


def _load_state() -> dict[str, Any]:
    if not STATE_FILE.is_file():
        return {"ticks": 0, "last_tick_ts": 0, "last_verdict": "idle"}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"ticks": 0, "last_tick_ts": 0, "last_verdict": "idle"}


def _save_state(state: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    tmp.replace(STATE_FILE)


def _append_log(entry: dict[str, Any]) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if LOG_FILE.is_file():
        try:
            lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
    lines.append(json.dumps(entry, separators=(",", ":")))
    if len(lines) > MAX_LOG:
        lines = lines[-MAX_LOG:]
    LOG_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _ollama_reachable(url: str, timeout: float = 3.0) -> bool:
    if not url:
        return False
    try:
        req = urllib.request.Request(f"{url.rstrip('/')}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _extract_peer_rows(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not payload:
        return []
    for path in (
        ("peer_tracker", "peers"),
        ("packet_analysis", "metrics", "inbound_identical_peers"),
        ("packets", "metrics", "inbound_identical_peers"),
        ("metrics", "inbound_identical_peers"),
    ):
        cur: Any = payload
        for part in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(part)
        if isinstance(cur, list):
            return [p for p in cur if isinstance(p, dict)]
    return []


def _cheater_label(payload: dict[str, Any] | None) -> str:
    if not payload:
        return ""
    for key in ("cheater_label",):
        if payload.get(key):
            return str(payload[key]).upper()
    cl = payload.get("cheater_lobby") or {}
    if isinstance(cl, dict) and cl.get("label"):
        return str(cl["label"]).upper()
    ca = payload.get("cheater_answer") or {}
    if isinstance(ca, dict) and ca.get("label"):
        return str(ca["label"]).upper()
    return ""


def _fuse_context(*, sentinel_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collect multi-engine telemetry into one threat graph."""
    cfg = _cfg()
    weights = ai_learning.fuse_weights()
    ctx: dict[str, Any] = {
        "ts": _now(),
        "tiny_packet_only": policies.sentinel_tiny_only(),
        "phase": "",
        "session_hex": "",
        "cheater_label": "",
        "ids_ai_score": 0,
        "ids_mode": (policies.load().get("ids") or {}).get("mode", "log_only"),
        "qce": {},
        "asvi": {},
        "gpu": {},
        "offenders": [],
        "candidates": {},
        "signals": [],
    }

    dash = {}
    try:
        dash = sentinel.dashboard_data() or {}
    except Exception:
        dash = {}
    payload = dict(sentinel_payload or dash)
    pt = payload.get("peer_tracker") or {}
    ctx["phase"] = str(payload.get("phase") or pt.get("phase") or "")
    ctx["session_hex"] = str(payload.get("session_hex") or pt.get("session_hex") or "")
    ctx["cheater_label"] = _cheater_label(payload)

    if ctx["cheater_label"] in HOSTILE_LABELS:
        ctx["signals"].append(f"sentinel:{ctx['cheater_label']}")

    scores: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"ip": "", "score": 0.0, "reasons": [], "vps_probe": False}
    )

    def bump(ip: str, amount: float, reason: str, **meta: Any) -> None:
        ip = ip.strip()
        if not ip or ip.startswith(("10.", "192.168.", "127.", "198.18.")):
            return
        row = scores[ip]
        row["ip"] = ip
        row["score"] = round(float(row["score"]) + amount, 4)
        row["reasons"].append(reason)
        for k, v in meta.items():
            row[k] = v

    for peer in _extract_peer_rows(payload):
        ip = str(peer.get("ip") or peer.get("remote") or "").split(":")[0].strip()
        if not ip:
            continue
        identical = int(peer.get("identical_count") or peer.get("max_burst") or 0)
        vps = bool(peer.get("vps_probe"))
        if vps:
            bump(ip, float(weights.get("vps_probe", 0.4)), "vps_probe", vps_probe=True)
        if identical >= 20:
            bump(ip, float(weights.get("identical_burst", 0.25)), f"identical:{identical}")
        elif ctx.get("phase") in {"matchmaking", "in-match"}:
            imin = int(cfg.get("pre_burst_identical_min") or 6)
            imax = int(cfg.get("pre_burst_identical_max") or 19)
            if cfg.get("pre_burst_enabled", True) and imin <= identical <= imax and (
                vps or ctx["cheater_label"] in HOSTILE_LABELS
            ):
                bump(ip, float(weights.get("pre_burst", 0.30)), f"pre_burst:{identical}")
                ctx["signals"].append("pre_burst:forming")
        if ctx["cheater_label"] in HOSTILE_LABELS and identical >= 6:
            bump(ip, float(weights.get("sentinel_likely", 0.35)), f"sentinel:{ctx['cheater_label']}")
        rep = reputation_graph.score(ip)
        if rep >= 0.2:
            bump(ip, rep * float(weights.get("reputation_bad", 0.35)), f"reputation:{rep}")
        if negative_allowlist.is_negative(ip):
            bump(ip, 0.25, "negative_allowlist")

    try:
        from . import asvi

        if asvi._cfg().get("enabled", True):  # noqa: SLF001
            scan = asvi.scan_session(session_hex=ctx["session_hex"] or None, limit=200)
            ctx["asvi"] = {
                "void_count": scan.get("void_count"),
                "max_asvi": scan.get("max_asvi"),
                "smst_summary": scan.get("smst_summary"),
            }
            for void in scan.get("voids") or []:
                if void.get("smst") != "act":
                    continue
                sample = str(void.get("sample_ip") or void.get("ip") or "").strip()
                if sample:
                    bump(
                        sample,
                        float(weights.get("asvi_act", 0.30)),
                        "asvi_act_void",
                        void_prefix=void.get("prefix"),
                    )
                    ctx["signals"].append("asvi:act_void")
    except Exception:
        pass

    try:
        from . import qce

        if qce._cfg().get("enabled", True):  # noqa: SLF001
            qm = qce.measure_session(session_hex=ctx["session_hex"] or None, limit=200)
            ctx["qce"] = {
                "entanglement_entropy": qm.get("entanglement_entropy"),
                "consciousness_score": qm.get("consciousness_score"),
                "peak_entropy_band": qm.get("peak_entropy_band"),
                "unknown_count": qm.get("unknown_count"),
            }
            if qm.get("peak_entropy_band") and int(qm.get("unknown_count") or 0) >= 3:
                ctx["signals"].append("qce:peak_entropy")
                try:
                    qrows = conn_lite_db.query(
                        session_hex=ctx["session_hex"] or None, limit=50, offset=0
                    ).get("rows") or []
                    boosts = qce.investigation_boost(
                        [r for r in qrows if str(r.get("conn_type") or "") == "unknown"]
                    )
                    for ip, boost in sorted(boosts.items(), key=lambda kv: kv[1], reverse=True)[:8]:
                        bump(ip, float(weights.get("qce_peak", 0.25)), f"qce_boost:{boost}")
                except Exception:
                    pass
    except Exception:
        pass

    try:
        from . import conn_lite_db

        off = conn_lite_db.offenders(min_sessions=2, limit=12)
        ctx["offenders"] = off.get("offenders") or []
        for row in ctx["offenders"]:
            ip = str(row.get("ip") or "").strip()
            if not ip:
                continue
            sess = int(row.get("session_count") or 0)
            if sess >= 3 or row.get("vps_probe"):
                bump(
                    ip,
                    float(weights.get("repeat_offender", 0.20)) * min(sess, 5) / 3,
                    f"repeat_offender:{sess}",
                    session_count=sess,
                )
    except Exception:
        pass

    try:
        ids_sum = ids.summary()
        ai = ids_sum.get("ai") or {}
        assessment = ai.get("assessment") or {}
        score = int(assessment.get("risk_score") or 0)
        ctx["ids_ai_score"] = score
        if score >= 70:
            ctx["signals"].append(f"ids_ai:{score}")
            for ev in ids.highlights(limit=6, severity="high"):
                ip = str(ev.get("device_ip") or "").strip()
                if ip:
                    bump(ip, float(weights.get("ids_ai_high", 0.30)), f"ids_ai:{score}")
    except Exception:
        pass

    pkt = payload.get("packet_analysis") or payload.get("packets") or {}
    metrics = pkt.get("metrics") if isinstance(pkt, dict) else {}
    if isinstance(metrics, dict):
        tiny = int(metrics.get("tiny_inbound") or metrics.get("tiny_packets") or 0)
        inbound = int(metrics.get("inbound_packets") or metrics.get("total_inbound") or 0)
        if inbound > 0 and tiny / max(inbound, 1) >= 0.35:
            ctx["signals"].append(f"packet_tiny_flood:{tiny}/{inbound}")
            ctx["gpu"] = {"flood_score": round(tiny / inbound, 3), "source": "sentinel_packets"}
            bump_amt = float(weights.get("gpu_flood", 0.20)) * min(1.0, tiny / max(inbound, 1))
            for peer in _extract_peer_rows(payload):
                if peer.get("vps_probe"):
                    ip = str(peer.get("ip") or "").split(":")[0].strip()
                    if ip:
                        bump(ip, bump_amt, "gpu_flood_proxy")

    try:
        from . import perf

        recs = (metrics or {}).get("recent_packets") or []
        if perf.gpu_enabled() and isinstance(recs, list) and recs:
            gpu = perf.analyze_packets_gpu(recs[:256])
            ctx["gpu"] = {**(ctx.get("gpu") or {}), **gpu}
            flood = float(gpu.get("flood_score") or 0)
            if flood >= 35:
                ctx["signals"].append(f"gpu_flood:{flood}")
    except Exception:
        pass

    try:
        from . import asvi as asvi_mod

        scan_for_neg = ctx.get("asvi") or {}
        if scan_for_neg.get("void_count"):
            voids = asvi_mod.scan_session(session_hex=ctx["session_hex"] or None, limit=100).get("voids") or []
            negative_allowlist.ingest_asvi_voids(voids, session_hex=ctx["session_hex"] or None)
    except Exception:
        pass

    ctx["candidates"] = dict(
        sorted(scores.items(), key=lambda kv: kv[1]["score"], reverse=True)[:32]
    )
    if cfg.get("pre_burst_enabled", True) and ctx.get("phase") == "matchmaking":
        ctx["pre_burst_forecast"] = pre_burst_forecast.forecast(ctx)
        pbf = ctx["pre_burst_forecast"]
        if pbf.get("recommend_shield"):
            ctx["signals"].append(f"pre_burst_forecast:{pbf.get('forecast_score')}")
    top = next(iter(ctx["candidates"].values()), None)
    if top and float(top.get("score") or 0) >= 0.85:
        ctx["fused_verdict"] = "hostile"
    elif top and float(top.get("score") or 0) >= 0.55:
        ctx["fused_verdict"] = "suspicious"
    else:
        ctx["fused_verdict"] = "clean"
    return ctx


def _heuristic_plan(context: dict[str, Any]) -> dict[str, Any]:
    cfg = _cfg()
    actions: list[dict[str, Any]] = []
    phase = str(context.get("phase") or "")
    gaming = phase in {"matchmaking", "in-match"}
    verdict = str(context.get("fused_verdict") or "clean")
    tiny = bool(context.get("tiny_packet_only"))

    block_ips: list[str] = []
    subnet_ips: list[str] = []
    investigate_ips: list[str] = []

    for ip, row in (context.get("candidates") or {}).items():
        score = float(row.get("score") or 0)
        if score >= float(cfg.get("min_confidence_block", 0.72)):
            if row.get("vps_probe") or "vps_probe" in row.get("reasons", []):
                block_ips.append(ip)
            elif verdict == "hostile" and gaming:
                block_ips.append(ip)
            elif score >= 0.9:
                block_ips.append(ip)
        elif score >= float(cfg.get("min_confidence_shield", 0.45)):
            investigate_ips.append(ip)

        if row.get("void_prefix") and score >= float(cfg.get("min_confidence_subnet", 0.80)):
            subnet_ips.append(ip)

    vps_blocks = [ip for ip in block_ips if (context.get("candidates") or {}).get(ip, {}).get("vps_probe")]
    if len(vps_blocks) >= 2:
        subnet_ips.extend(vps_blocks[:6])

    if gaming and verdict in {"suspicious", "hostile"}:
        top_score = float(next(iter((context.get("candidates") or {}).values()), {}).get("score") or 0)
        posture = adaptive_posture.recommend(context) if cfg.get("adaptive_shield_enabled", True) else {}
        if posture.get("shield_level"):
            level = str(posture["shield_level"])
        elif verdict == "hostile" and phase == "in-match":
            level = "in-match" if not tiny else "matchmaking"
        elif verdict == "hostile" or top_score >= 0.85:
            level = "strict" if phase == "in-match" else "matchmaking"
        elif any("pre_burst" in s for s in (context.get("signals") or [])):
            level = "peer-strict"
        else:
            level = "peer-strict"
        pbf = context.get("pre_burst_forecast") or {}
        conf = 0.55 if pbf.get("recommend_shield") else (
            0.55 if any("pre_burst" in s for s in (context.get("signals") or [])) else (
                0.6 if verdict == "suspicious" else 0.85
            )
        )
        actions.append(
            {
                "type": "shield",
                "level": level,
                "confidence": conf,
                "reason": posture.get("headline") or f"fused_verdict:{verdict}",
            }
        )
        if posture.get("buffer_profile") and cfg.get("auto_buffer_on_spike"):
            actions.append(
                {
                    "type": "buffer_tune",
                    "profile": posture["buffer_profile"],
                    "confidence": conf,
                    "reason": "adaptive_posture",
                }
            )

    max_blocks = int(cfg.get("max_blocks_per_tick") or 8)
    for ip in block_ips[:max_blocks]:
        conf = float((context.get("candidates") or {}).get(ip, {}).get("score") or 0.72)
        actions.append(
            {
                "type": "block_peer",
                "target": ip,
                "confidence": conf,
                "reason": "fusion_block",
                "ttl_sec": 604800 if (context.get("candidates") or {}).get(ip, {}).get("vps_probe") else 86400,
            }
        )

    max_subnets = int(cfg.get("max_subnets_per_tick") or 2)
    seen_prefix: set[str] = set()
    for ip in subnet_ips:
        if len(seen_prefix) >= max_subnets:
            break
        actions.append(
            {
                "type": "block_subnet",
                "target": ip,
                "confidence": float(cfg.get("min_confidence_subnet", 0.80)),
                "reason": "vps_mesh_or_asvi_void",
            }
        )
        seen_prefix.add(ip)

    if context.get("signals") and "qce:peak_entropy" in context["signals"]:
        actions.append(
            {
                "type": "investigate_rqd",
                "confidence": 0.55,
                "reason": "qce_peak_entropy",
                "limit": 12,
            }
        )

    if cfg.get("auto_buffer_on_spike") and gaming and verdict != "clean":
        if not any(a.get("type") == "buffer_tune" for a in actions):
            actions.append(
                {
                    "type": "buffer_tune",
                    "confidence": 0.5,
                    "reason": f"lobby_{verdict}",
                }
            )

    if cfg.get("auto_ids_on_hostile") and verdict == "hostile" and block_ips:
        actions.append(
            {
                "type": "ids_block",
                "targets": block_ips[:max_blocks],
                "confidence": 0.75,
                "reason": "hostile_fusion",
            }
        )

    for ip in investigate_ips[:12]:
        if ip not in block_ips:
            actions.append(
                {
                    "type": "investigate_ip",
                    "target": ip,
                    "confidence": float((context.get("candidates") or {}).get(ip, {}).get("score") or 0.5),
                    "reason": "fusion_investigate",
                }
            )

    return {
        "planner": "heuristic",
        "verdict": verdict,
        "summary": f"Fusion {verdict} — {len(block_ips)} block candidate(s), phase={phase or 'idle'}",
        "actions": actions,
    }


def _ollama_plan(context: dict[str, Any], heuristic: dict[str, Any]) -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("ollama_planner", True):
        return {"ok": False, "skipped": True}

    url = str(cfg.get("ollama_url") or "").rstrip("/")
    if not url or not _ollama_reachable(url):
        return {"ok": False, "skipped": True, "reason": "ollama_unreachable"}

    top_peers = []
    for ip, row in list((context.get("candidates") or {}).items())[:8]:
        top_peers.append(f"{ip} score={row.get('score')} reasons={row.get('reasons')}")

    prompt = (
        "You are an autonomous gaming firewall operator. Given fused telemetry, output JSON only:\n"
        '{"verdict":"clean|suspicious|hostile","summary":"one line",'
        '"actions":[{"type":"shield|block_peer|block_subnet|investigate|buffer_tune|none",'
        '"target":"ip or empty","level":"normal|peer-strict|matchmaking|in-match","confidence":0.0-1.0,"reason":"..."}]}\n'
        "Prefer shield and buffer tuning — player stays in lobby. Block VPS probes when confidence>=0.75. Never suggest leaving.\n\n"
        f"Phase: {context.get('phase')}\n"
        f"Cheater label: {context.get('cheater_label')}\n"
        f"Fused verdict: {context.get('fused_verdict')}\n"
        f"Signals: {context.get('signals')}\n"
        f"IDS AI score: {context.get('ids_ai_score')}\n"
        f"Top peers:\n" + "\n".join(top_peers) + "\n"
        f"Heuristic plan summary: {heuristic.get('summary')}\n"
    )
    body = json.dumps(
        {
            "model": str(cfg.get("ollama_model") or "llama3.2:1b"),
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"num_predict": 256, "temperature": 0.15},
        }
    ).encode()
    timeout = max(20, int(cfg.get("ollama_timeout_sec") or 45))
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
        parsed = json.loads(text) if text.startswith("{") else {}
        actions = parsed.get("actions") if isinstance(parsed.get("actions"), list) else []
        return {
            "ok": True,
            "planner": "ollama",
            "verdict": str(parsed.get("verdict") or heuristic.get("verdict") or "suspicious"),
            "summary": str(parsed.get("summary") or heuristic.get("summary") or ""),
            "actions": [a for a in actions if isinstance(a, dict)],
            "raw": parsed,
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def _merge_plans(heuristic: dict[str, Any], ollama: dict[str, Any]) -> dict[str, Any]:
    if not ollama.get("ok"):
        return heuristic
    merged_actions = list(heuristic.get("actions") or [])
    seen = {f"{a.get('type')}:{a.get('target', '')}" for a in merged_actions}
    for act in ollama.get("actions") or []:
        if str(act.get("type") or "") == "none":
            continue
        key = f"{act.get('type')}:{act.get('target', '')}"
        if key not in seen:
            merged_actions.append(act)
            seen.add(key)
    return {
        "planner": "fusion+ollama",
        "verdict": ollama.get("verdict") or heuristic.get("verdict"),
        "summary": ollama.get("summary") or heuristic.get("summary"),
        "actions": merged_actions,
        "ollama": {"ok": True, "verdict": ollama.get("verdict")},
    }


def _can_block(tiny: bool, cfg: dict[str, Any]) -> bool:
    if not tiny:
        return True
    return bool(cfg.get("override_tiny_packet_only"))


def _prev_shield_level() -> str:
    path = Path("/var/lib/array-firewall/packet-shield.state")
    if not path.is_file():
        return "normal"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("level="):
            return line.split("=", 1)[1].strip() or "normal"
    return "normal"


def _prev_buffer_profile() -> str:
    path = Path("/var/lib/array-firewall/buffer-tune.state")
    if not path.is_file():
        return "gaming"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("profile="):
            return line.split("=", 1)[1].strip() or "gaming"
    return "gaming"


def _execute_plan(plan: dict[str, Any], context: dict[str, Any], *, mode: str) -> dict[str, Any]:
    cfg = _cfg()
    tiny = bool(context.get("tiny_packet_only"))
    executed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    exec_ctx = {
        "prev_shield_level": _prev_shield_level(),
        "prev_buffer_profile": _prev_buffer_profile(),
    }

    if mode == "observe":
        return {"mode": mode, "executed": [], "skipped": plan.get("actions") or [], "dry_run": True}

    for act in plan.get("actions") or []:
        typ = str(act.get("type") or "")
        conf = float(act.get("confidence") or 0)
        reason = str(act.get("reason") or "ai_ops")

        if typ == "shield":
            if conf < float(cfg.get("min_confidence_shield", 0.45)):
                skipped.append({**act, "why": "low_confidence"})
                continue
            if mode == "observe":
                skipped.append({**act, "why": "observe_mode"})
                continue
            level = str(act.get("level") or "peer-strict")
            peers = [
                ip
                for ip, row in (context.get("candidates") or {}).items()
                if float(row.get("score") or 0) >= float(cfg.get("min_confidence_shield", 0.45))
            ]
            result = peer_blocklist.sync_shield(level=level, extra_peers=peers[:24])
            executed.append({"type": typ, "level": level, "result": result})
            continue

        if typ in {"block_peer", "block_subnet", "ids_block"}:
            if mode != "enforce":
                skipped.append({**act, "why": "needs_enforce_mode"})
                continue
            if not _can_block(tiny, cfg):
                skipped.append({**act, "why": "tiny_packet_only"})
                continue

        if typ == "block_peer":
            if conf < float(cfg.get("min_confidence_block", 0.72)):
                skipped.append({**act, "why": "low_confidence"})
                continue
            ip = str(act.get("target") or "").strip()
            if not ip or peer_blocklist.in_game_allowlist(ip):
                skipped.append({**act, "why": "allowlisted"})
                continue
            ttl = int(act.get("ttl_sec") or 86400)
            result = peer_blocklist.add_peers([ip], reason=f"ai_ops:{reason}", ttl_sec=ttl)
            executed.append({"type": typ, "ip": ip, "result": result})
            continue

        if typ == "block_subnet":
            if conf < float(cfg.get("min_confidence_subnet", 0.80)):
                skipped.append({**act, "why": "low_confidence"})
                continue
            ip = str(act.get("target") or "").strip()
            if not ip:
                skipped.append({**act, "why": "no_target"})
                continue
            try:
                from . import subnet_blocklist as sb

                result = sb.block_from_ips([ip], reason=f"ai_ops:{reason}", source="ai_ops")
                try:
                    from . import abuse_evidence

                    cidr = result.get("results", [{}])[0].get("cidr") if result.get("results") else result.get("cidr")
                    abuse_evidence.build_bundle(
                        session_hex=str(context.get("session_hex") or "") or None,
                        trigger_ip=ip,
                        reason=reason,
                        peers=list(_extract_peer_rows(context)),
                        cheater_label=str(context.get("cheater_label") or ""),
                        signals=list(context.get("signals") or []),
                        autopilot_summary=str(plan.get("summary") or ""),
                    )
                    if cidr:
                        result["evidence_cidr"] = cidr
                except ImportError:
                    pass
                executed.append({"type": typ, "ip": ip, "result": result})
            except ImportError:
                skipped.append({**act, "why": "subnet_module_missing"})
            continue

        if typ == "ids_block":
            targets = act.get("targets") or []
            if isinstance(act.get("target"), str):
                targets = [act["target"]]
            ips = [str(t).strip() for t in targets if str(t).strip()]
            if not ips:
                skipped.append({**act, "why": "no_targets"})
                continue
            from . import ids_enforce

            result = ids_enforce.block_wan_ips(ips, ttl_sec=3600, source="ai_ops")
            executed.append({"type": typ, "ips": ips, "result": result})
            continue

        if typ == "investigate_rqd":
            if mode == "observe":
                skipped.append({**act, "why": "observe_mode"})
                continue
            try:
                from . import conn_lite_db, qce, unknown_investigator

                lim = int(act.get("limit") or 12)
                rows = conn_lite_db.query(
                    session_hex=str(context.get("session_hex") or "") or None,
                    limit=80,
                    offset=0,
                ).get("rows") or []
                unknowns = [r for r in rows if str(r.get("conn_type") or "") == "unknown"]
                from . import rqd

                ordered_rows = rqd.prioritize_investigation(rows)
                unknown_ordered = [r for r in ordered_rows if str(r.get("conn_type") or "") == "unknown"]
                if not unknown_ordered:
                    unknown_ordered = unknowns
                blocked: list[str] = []
                for row in unknown_ordered[:lim]:
                    ip = str(row.get("ip") or "").strip()
                    if not ip:
                        continue
                    intel = unknown_investigator.investigate_ip(ip)
                    label = str(intel.get("label") or intel.get("purpose") or "").lower()
                    if any(k in label for k in ("vps", "probe", "abuse", "scanner", "vultr", "hosting")):
                        if mode == "enforce" and _can_block(tiny, cfg):
                            peer_blocklist.add_peers([ip], reason="rqd_investigate", ttl_sec=604800)
                            blocked.append(ip)
                executed.append({"type": typ, "investigated": lim, "blocked": blocked})
            except Exception as exc:
                skipped.append({**act, "why": str(exc)})
            continue

        if typ == "investigate":
            try:
                from . import unknown_investigator

                pending = unknown_investigator.run_pending(limit=int(act.get("limit") or 15))
                executed.append({"type": typ, "result": pending})
            except ImportError:
                skipped.append({**act, "why": "investigator_missing"})
            continue

        if typ == "investigate_ip":
            ip = str(act.get("target") or "").strip()
            if not ip:
                continue
            try:
                from . import unknown_investigator

                unknown_investigator.queue_ip(ip)
                intel = unknown_investigator.investigate_ip(ip)
                executed.append({"type": typ, "ip": ip, "intel": intel.get("label")})
            except ImportError:
                skipped.append({**act, "why": "investigator_missing"})
            continue

        if typ == "buffer_tune":
            if mode == "observe":
                skipped.append({**act, "why": "observe_mode"})
                continue
            try:
                from . import qos

                profile = act.get("profile")
                if profile:
                    applied = qos.buffer_tune_apply(
                        str(profile),
                        auto_rqd=True,
                        phase=str(context.get("phase") or ""),
                        session_hex=str(context.get("session_hex") or "") or None,
                    )
                    executed.append({"type": typ, "profile": profile, "result": applied})
                else:
                    rec = qos.rqd_buffer_recommendation()
                    if rec.get("profile"):
                        applied = qos.buffer_tune_apply(
                            str(rec["profile"]),
                            auto_rqd=True,
                            phase=str(context.get("phase") or ""),
                            session_hex=str(context.get("session_hex") or "") or None,
                        )
                        executed.append({"type": typ, "profile": rec["profile"], "result": applied})
                    else:
                        skipped.append({**act, "why": "no_profile"})
            except Exception as exc:
                skipped.append({**act, "why": str(exc)})

    return {"mode": mode, "executed": executed, "skipped": skipped}


def tick(
    *,
    force: bool = False,
    sentinel_payload: dict[str, Any] | None = None,
    source: str = "timer",
) -> dict[str, Any]:
    """Run one AI Autopilot cycle — fuse, plan, optionally execute."""
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "enabled": False, "skipped": True}

    state = _load_state()
    now = _now()
    interval = max(5, int(cfg.get("tick_interval_sec") or 5))
    if not force and state.get("last_tick_ts") and (now - float(state["last_tick_ts"])) < interval:
        return {
            "ok": True,
            "skipped": True,
            "reason": "rate_limited",
            "next_in_sec": max(0, int(interval - (now - float(state["last_tick_ts"])))),
            "last": state,
        }

    context = _fuse_context(sentinel_payload=sentinel_payload)
    context["adaptive_posture"] = adaptive_posture.recommend(context)

    ids_scan = {}
    if cfg.get("auto_ids_scan", True):
        try:
            ids_scan = ids.analyze(force=force)
        except Exception as exc:
            ids_scan = {"ok": False, "error": str(exc)}

    heuristic = _heuristic_plan(context)
    ollama = _ollama_plan(context, heuristic)
    plan = _merge_plans(heuristic, ollama)
    mode = str(cfg.get("mode") or "assist").lower()
    if mode not in {"observe", "assist", "enforce"}:
        mode = "assist"

    execution = _execute_plan(plan, context, mode=mode)
    if cfg.get("negative_allowlist_enabled", True) and mode == "enforce":
        neg_blocks = negative_allowlist.enforce_negative_peers(
            context.get("candidates") or {},
            min_confidence=float(cfg.get("min_confidence_block", 0.72)),
        )
        if neg_blocks:
            execution.setdefault("executed", []).extend(
                [{"type": "negative_allowlist", "ip": b["ip"], "result": b["result"]} for b in neg_blocks]
            )
    tick_id = autopilot_audit.record_tick(
        source=source,
        session_hex=str(context.get("session_hex") or "") or None,
        phase=str(context.get("phase") or "") or None,
        executed=execution.get("executed") or [],
        context={
            "prev_shield_level": _prev_shield_level(),
            "prev_buffer_profile": _prev_buffer_profile(),
        },
    )
    reputation_graph.touch_peers_from_payload(
        dict(sentinel_payload or {}),
        bad=str(context.get("fused_verdict") or "") == "hostile",
    )
    play = playability.assess(
        context=context,
        plan=plan,
        execution=execution,
        shield_level=next(
            (ex.get("level") for ex in execution.get("executed") or [] if ex.get("type") == "shield"),
            None,
        ),
    )
    state = _load_state()
    state["last_playability"] = play
    state["last_adaptive_posture"] = context.get("adaptive_posture")
    state["last_pre_burst_forecast"] = context.get("pre_burst_forecast")
    state["last_tick_id"] = tick_id

    fleet_result = None
    ticks = int(state.get("ticks") or 0) + 1
    fleet_interval = max(60, int(cfg.get("fleet_sync_interval_sec") or 300))
    export_every = max(1, int(cfg.get("fleet_export_every_ticks") or max(1, fleet_interval // interval)))
    last_fleet = float(state.get("last_fleet_sync_ts") or 0)
    if cfg.get("fleet_sync_enabled") and (
        ticks % export_every == 0 or (now - last_fleet) >= fleet_interval
    ):
        try:
            from . import fleet_blocklist as fb

            fleet_result = fb.export_bundle()
            pull = cfg.get("fleet_pull_url")
            if pull:
                fleet_result["pull"] = fb.pull_from_url(str(pull))
            state["last_fleet_sync_ts"] = now
        except Exception as exc:
            fleet_result = {"ok": False, "error": str(exc)}

    entry = {
        "ts": now,
        "source": source,
        "mode": mode,
        "verdict": plan.get("verdict"),
        "summary": plan.get("summary"),
        "signals": context.get("signals"),
        "top_candidates": list((context.get("candidates") or {}).values())[:5],
        "planned_actions": len(plan.get("actions") or []),
        "executed": len(execution.get("executed") or []),
        "skipped": len(execution.get("skipped") or []),
        "planner": plan.get("planner"),
    }
    _append_log(entry)

    state.update(
        {
            "ticks": int(state.get("ticks") or 0) + 1,
            "last_tick_ts": now,
            "last_verdict": plan.get("verdict"),
            "last_summary": plan.get("summary"),
            "last_mode": mode,
            "last_source": source,
            "last_executed": execution.get("executed"),
            "last_planned": len(plan.get("actions") or []),
            "fused_signals": context.get("signals"),
            "top_candidates": list((context.get("candidates") or {}).values())[:8],
        }
    )
    _save_state(state)

    return {
        "ok": True,
        "mode": mode,
        "source": source,
        "context": {
            "phase": context.get("phase"),
            "session_hex": context.get("session_hex"),
            "cheater_label": context.get("cheater_label"),
            "fused_verdict": context.get("fused_verdict"),
            "signals": context.get("signals"),
            "tiny_packet_only": context.get("tiny_packet_only"),
        },
        "plan": plan,
        "execution": execution,
        "ollama": ollama if ollama.get("ok") else {"ok": False, "skipped": ollama.get("skipped", True)},
        "ids_scan": ids_scan,
        "playability": play,
        "fleet": fleet_result,
        "tick_id": tick_id,
        "state": state,
    }


def execute_ai_actions(payload: dict[str, Any]) -> dict[str, Any]:
    """Apply structured ai_actions from Sentinel (stay-in-lobby mitigation)."""
    actions = payload.get("ai_actions") or []
    if not isinstance(actions, list) or not actions:
        return {"ok": True, "skipped": True, "count": 0}
    cfg = _cfg()
    mode = str(cfg.get("mode") or "assist")
    ctx = _fuse_context(sentinel_payload=payload)
    plan = {"verdict": ctx.get("fused_verdict"), "summary": "sentinel_ai_actions", "actions": actions}
    execution = _execute_plan(plan, ctx, mode=mode)
    autopilot_audit.record_tick(
        source="sentinel_ai_actions",
        session_hex=str(payload.get("session_hex") or "") or None,
        phase=str(payload.get("phase") or "") or None,
        executed=execution.get("executed") or [],
        context={},
    )
    return {"ok": True, "execution": execution, "count": len(actions)}


def record_outcome_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Learn from session feedback without leaving the lobby."""
    bad = payload.get("bad_lobby")
    if bad is None:
        cl = payload.get("cheater_lobby") or {}
        if isinstance(cl, dict) and cl.get("label"):
            label = str(cl["label"]).upper()
            bad = label in {"LIKELY", "USER_BAD", "POSSIBLE"}
    verdict = "bad" if bad else ("clean" if bad is False else str(payload.get("verdict") or "mitigated"))
    if payload.get("kicked"):
        verdict = "kicked"
    result = ai_learning.record_outcome(
        session_hex=str(payload.get("session_hex") or "") or None,
        verdict=verdict,
        bad_lobby=bad if isinstance(bad, bool) else None,
        cheater_label=_cheater_label(payload),
        signals=list(payload.get("signals") or []) if isinstance(payload.get("signals"), list) else [],
        autopilot_actions=list(payload.get("actions") or []),
        peer_ips=[str(p.get("ip") or "") for p in _extract_peer_rows(payload)],
        note=str(payload.get("note") or ""),
    )
    reputation_graph.touch_peers_from_payload(payload, bad=bad is True, clean=bad is False)
    return result


def set_mode(mode: str) -> dict[str, Any]:
    mode = str(mode or "assist").lower()
    if mode not in {"observe", "assist", "enforce"}:
        raise ValueError("mode must be observe, assist, or enforce")
    data = policies.load()
    ai = dict(data.get("ai_ops") or {})
    ai["mode"] = mode
    data["ai_ops"] = ai
    policies.save(data)
    return {"ok": True, "mode": mode}


def recent_log(*, limit: int = 20) -> list[dict[str, Any]]:
    if not LOG_FILE.is_file():
        return []
    try:
        lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(out))


def status() -> dict[str, Any]:
    cfg = _cfg()
    state = _load_state()
    return {
        "ok": True,
        "enabled": cfg.get("enabled", True),
        "mode": cfg.get("mode", "assist"),
        "valid_modes": ["observe", "assist", "enforce"],
        "tick_interval_sec": cfg.get("tick_interval_sec", 30),
        "ollama_planner": cfg.get("ollama_planner", True),
        "ollama_url": cfg.get("ollama_url"),
        "tiny_packet_only": policies.sentinel_tiny_only(),
        "override_tiny_packet_only": cfg.get("override_tiny_packet_only", False),
        "thresholds": {
            "shield": cfg.get("min_confidence_shield", 0.45),
            "block": cfg.get("min_confidence_block", 0.72),
            "subnet": cfg.get("min_confidence_subnet", 0.80),
        },
        "playability": state.get("last_playability"),
        "adaptive_posture": state.get("last_adaptive_posture"),
        "pre_burst_forecast": state.get("last_pre_burst_forecast"),
        "learning": ai_learning.status(),
        "reputation": reputation_graph.status(),
        "timeline": autopilot_audit.status(),
        "negative_allowlist": negative_allowlist.status(),
        "state": state,
        "recent": recent_log(limit=8),
    }
