"""Sentinel-driven gaming mitigation — peer blocks, IDS escalation, shield sync."""
from __future__ import annotations

import time
from typing import Any

from . import ids_enforce, peer_blocklist, policies

try:
    from . import abuse_report, allowlist_learn, asvi, nft, probe_sink, session_events
except ImportError:
    abuse_report = None  # type: ignore[assignment]
    allowlist_learn = None  # type: ignore[assignment]
    asvi = None  # type: ignore[assignment]
    nft = None  # type: ignore[assignment]
    probe_sink = None  # type: ignore[assignment]
    session_events = None  # type: ignore[assignment]

HIGH_LABELS = frozenset({"LIKELY", "USER_BAD", "POSSIBLE"})
ATTACK_SIGNALS = frozenset(
    {
        "inbound_flood",
        "inbound_attack",
        "packet_storm",
        "tiny_packet_flood",
        "packet_cheat",
        "inbound_elevated",
        "unknown_inbound",
        "unknown_inbound_fanout",
        "unknown_inbound_packets",
        "peer_tiny_flood",
        "peer_micro_burst",
        "suspicious_peer",
    }
)
PEER_SIGNALS = frozenset({"peer_tiny_flood", "peer_micro_burst", "suspicious_peer"})
FLOW_SIGNALS = frozenset(
    {
        "superlinear_flow",
        "info_flow_spike",
        "prg_like_traffic",
        "byte_flow_entropy",
    }
)

_LAST_MITIGATE = 0.0


def _cfg() -> dict[str, Any]:
    gaming = policies.gaming()
    tiny_only = policies.sentinel_tiny_only()
    base = {
        "auto_block_peers": not tiny_only,
        "auto_ids_block": not tiny_only,
        "peer_ttl_sec": 86400,
        "ids_block_ttl_sec": 3600,
        "auto_shield_sync": True,
        "matchmaking_allowlist": True,
        "min_mitigate_interval_sec": 15,
        "repeat_offender_hits": 3,
        "repeat_offender_ttl_sec": 604800,
        "auto_block_vps_peers": True,
        "auto_block_vultr_only": False,
        "vps_peer_ttl_sec": 604800,
        "auto_route_pref_in_match": not tiny_only,
        "lobby_reputation_gate": not tiny_only,
        "tiny_packet_only": tiny_only,
    }
    base.update(gaming.get("mitigation") or {})
    if tiny_only:
        base["auto_block_peers"] = False
        base["auto_ids_block"] = False
        base["auto_route_pref_in_match"] = False
        base["lobby_reputation_gate"] = False
    return base


def _extract_signals(payload: dict[str, Any]) -> dict[str, float]:
    raw = payload.get("signals") or {}
    out: dict[str, float] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            try:
                out[str(k)] = float(v)
            except (TypeError, ValueError):
                continue
    return out


def _extract_peer_ips(payload: dict[str, Any]) -> list[str]:
    ips: list[str] = []
    ips.extend(_extract_vps_game_peer_ips(payload))
    for key in ("suspicious_peers", "peer_ips", "vps_peer_ips"):
        block = payload.get(key)
        if isinstance(block, list):
            for item in block:
                if isinstance(item, str):
                    ips.append(item)
                elif isinstance(item, dict):
                    ip = str(item.get("ip") or "").strip()
                    if ip:
                        ips.append(ip)
    for path in (
        ("packet_analysis", "metrics", "suspicious_peers"),
        ("packets", "metrics", "suspicious_peers"),
        ("metrics", "suspicious_peers"),
    ):
        cur: Any = payload
        for part in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(part)
        if isinstance(cur, list):
            for item in cur:
                if isinstance(item, str):
                    ips.append(item)
                elif isinstance(item, dict):
                    ip = str(item.get("ip") or "").strip()
                    if ip:
                        ips.append(ip)
    seen: set[str] = set()
    ordered: list[str] = []
    for ip in ips:
        ip = ip.strip()
        if ip and ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def _is_vultr_vps_row(item: dict[str, Any]) -> bool:
    if not item.get("vps_probe"):
        return False
    label = str(item.get("label") or item.get("vendor") or "").lower()
    role = str(item.get("role") or item.get("roleId") or "").lower()
    ip = str(item.get("ip") or item.get("remote") or "").strip().split(":")[0]
    return role in {"vps-probe", "game-peer"} or "vultr" in label or ip.startswith(
        ("45.76.", "45.77.", "66.42.", "96.30.", "108.61.", "149.28.", "155.138.", "207.148.", "140.82.", "144.202.")
    )


def _is_vps_game_peer_row(item: dict[str, Any]) -> bool:
    if not isinstance(item, dict):
        return False
    if not item.get("vps_probe"):
        return False
    role = str(item.get("role") or item.get("roleId") or "").lower()
    return role in {"vps-probe", "game-peer"}


def _extract_vps_game_peer_ips(payload: dict[str, Any]) -> list[str]:
    """Inbound identical peers flagged as VPS / Vultr game-peer — auto-block targets."""
    cfg = _cfg()
    if not cfg.get("auto_block_vps_peers", True):
        return []
    vultr_only = bool(cfg.get("auto_block_vultr_only", False))
    ips: list[str] = []
    for path in (
        ("packet_analysis", "metrics", "inbound_identical_peers"),
        ("packets", "metrics", "inbound_identical_peers"),
        ("metrics", "inbound_identical_peers"),
        ("packet_analysis", "metrics", "vps_game_peers"),
        ("packets", "metrics", "vps_game_peers"),
    ):
        cur: Any = payload
        for part in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(part)
        if not isinstance(cur, list):
            continue
        for item in cur:
            if not isinstance(item, dict):
                continue
            if vultr_only:
                if not _is_vultr_vps_row(item):
                    continue
            elif not _is_vps_game_peer_row(item):
                continue
            ip = str(item.get("ip") or "").strip()
            if not ip and item.get("remote"):
                ip = str(item.get("remote")).strip().split(":")[0]
            if ip:
                ips.append(ip)
    return ips


def _extract_peer_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
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


def _cheater_label(payload: dict[str, Any]) -> str:
    for key in ("cheater_label",):
        if payload.get(key):
            return str(payload[key]).upper()
    cl = payload.get("cheater_lobby") or {}
    if isinstance(cl, dict):
        return str(cl.get("label") or "").upper()
    return ""


def _has_attack(signals: dict[str, float]) -> bool:
    return any(signals.get(sig, 0) >= 0.35 for sig in ATTACK_SIGNALS)


def _has_peer_attack(signals: dict[str, float]) -> bool:
    return any(signals.get(sig, 0) >= 0.25 for sig in PEER_SIGNALS)


def _has_flow_spike(signals: dict[str, float]) -> bool:
    return any(signals.get(sig, 0) >= 0.35 for sig in FLOW_SIGNALS)


def _lobby_reputation_gate(payload: dict[str, Any]) -> bool:
    rep = payload.get("lobby_reputation") or {}
    if isinstance(rep, dict) and rep.get("gate"):
        return True
    ng = payload.get("network_guard") or {}
    if isinstance(ng, dict) and ng.get("lobby_reputation_gate"):
        return True
    return False


def _identical_peer_spike(payload: dict[str, Any]) -> bool:
    for path in (
        ("packet_analysis", "metrics", "inbound_identical_peers"),
        ("packets", "metrics", "inbound_identical_peers"),
    ):
        cur: Any = payload
        for part in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(part)
        if isinstance(cur, list) and len(cur) >= 3:
            return True
    return False


def _game_state_kick(payload: dict[str, Any]) -> bool:
    gs = payload.get("game_state") or {}
    return isinstance(gs, dict) and bool(gs.get("recent_kick"))


def _shield_level(payload: dict[str, Any], signals: dict[str, float], *, kick_spike: bool = False) -> str:
    if policies.sentinel_tiny_only():
        return "normal"
    phase = str(payload.get("phase") or "").lower()
    label = _cheater_label(payload)
    cfg = _cfg()
    kick_spike = kick_spike or _game_state_kick(payload)

    if _lobby_reputation_gate(payload) and phase == "matchmaking":
        return "peer-strict"

    if phase == "in-match" and cfg.get("console_mode", True):
        if policies.role() == "xbox_router":
            dmz = (policies.load().get("dmz") or {})
            xbox_ip = str(policies.gaming().get("xbox_ip") or "").strip()
            if dmz.get("enabled") and str(dmz.get("host_ip") or "") == xbox_ip:
                return "matchmaking"
        return policies.effective_shield_level("in-match")

    if _has_peer_attack(signals) or _extract_peer_ips(payload) or _identical_peer_spike(payload):
        return "peer-strict"

    if _has_flow_spike(signals) and label in HIGH_LABELS:
        return "strict"

    if phase == "matchmaking" and cfg.get("matchmaking_allowlist", True):
        if label in HIGH_LABELS or _has_attack(signals) or kick_spike or _has_flow_spike(signals):
            return "matchmaking"

    if phase == "matchmaking":
        return "console"

    if kick_spike or _has_attack(signals) or _has_flow_spike(signals):
        return "strict"
    if label in HIGH_LABELS:
        return "normal"
    return "normal"


def _sync_shield(level: str, peer_ips: list[str], cfg: dict[str, Any]) -> dict[str, Any]:
    if cfg.get("nft_fast_path", True) and nft is not None:
        merged = list(dict.fromkeys([*peer_blocklist.active_ips(), *peer_ips]))
        fast = nft.sync_shield_fast(level=level, peers=merged)
        if fast.get("ok"):
            return fast
    return peer_blocklist.sync_shield(level=level, extra_peers=peer_ips)


def mitigate(payload: dict[str, Any]) -> dict[str, Any]:
    """Apply closed-loop mitigation from sentinel session risk."""
    global _LAST_MITIGATE
    cfg = _cfg()
    now = time.time()
    interval = max(5, int(cfg.get("min_mitigate_interval_sec") or 15))
    if now - _LAST_MITIGATE < interval:
        return {"ok": True, "skipped": True, "reason": "rate_limited"}
    _LAST_MITIGATE = now

    signals = _extract_signals(payload)
    phase = str(payload.get("phase") or "")
    label = _cheater_label(payload)
    tiny_only = policies.sentinel_tiny_only()
    peer_ips = [] if tiny_only else _extract_peer_ips(payload)
    kick_spike = bool(payload.get("kick_spike")) or _game_state_kick(payload)
    session_hex = str(payload.get("session_hex") or "").strip()

    if phase not in {"matchmaking", "in-match"} and not peer_ips and not tiny_only:
        return {"ok": True, "skipped": True, "reason": "not_gaming_phase"}

    result: dict[str, Any] = {
        "ok": True,
        "phase": phase,
        "cheater_label": label,
        "peer_ips": peer_ips,
        "tiny_packet_only": tiny_only,
        "lobby_reputation_gate": _lobby_reputation_gate(payload),
        "actions": [],
    }

    if (
        cfg.get("lobby_reputation_gate", True)
        and _lobby_reputation_gate(payload)
        and phase == "matchmaking"
        and peer_ips
    ):
        gate_result = peer_blocklist.add_peers(
            peer_ips,
            reason="lobby_reputation_gate",
            ttl_sec=int(cfg.get("repeat_offender_ttl_sec") or 604800),
            hits=2,
        )
        result["lobby_gate"] = gate_result
        result["actions"].append(f"lobby_gate:{gate_result.get('added', 0)}")

    if cfg.get("auto_block_vps_peers", True):
        vps_ips = [ip for ip in _extract_vps_game_peer_ips(payload) if not peer_blocklist.in_game_allowlist(ip)]
        if vps_ips:
            vps_result = peer_blocklist.add_peers(
                vps_ips,
                reason="vultr_vps_game_peer",
                ttl_sec=int(cfg.get("vps_peer_ttl_sec") or cfg.get("repeat_offender_ttl_sec") or 604800),
                hits=2,
            )
            result["vps_peer_blocklist"] = vps_result
            result["actions"].append(f"vps_blocked:{vps_result.get('added', 0)}")
            subnet_cfg = dict((policies.gaming().get("mitigation") or {}).get("subnet_block") or {})
            if subnet_cfg.get("auto_block_on_vps_mesh", True):
                try:
                    from . import subnet_blocklist as sb

                    subnet_result = sb.block_from_ips(
                        vps_ips,
                        reason="vultr_vps_game_peer",
                        source="sentinel_mitigate",
                    )
                    result["subnet_blocklist"] = subnet_result
                    result["actions"].append(
                        f"subnet_blocked:{subnet_result.get('nft_applied', 0)}"
                    )
                except ImportError:
                    pass

    if cfg.get("auto_block_peers", True) and peer_ips:
        peer_ips = [ip for ip in peer_ips if not peer_blocklist.in_game_allowlist(ip)]
    if cfg.get("auto_block_peers", True) and peer_ips:
        peer_result = peer_blocklist.add_peers(
            peer_ips,
            reason=f"sentinel:{label or phase}",
            ttl_sec=int(cfg.get("peer_ttl_sec") or 86400),
        )
        result["peer_blocklist"] = peer_result
        result["actions"].append(f"blocked_peers:{peer_result.get('added', 0)}")
        if session_events and peer_result.get("added"):
            session_events.append(
                "peer.block",
                session_hex=session_hex or None,
                phase=phase,
                detail=f"added {peer_result.get('added', 0)} peer(s)",
                meta={"reason": f"sentinel:{label or phase}"},
            )

    escalate = (
        cfg.get("auto_ids_block", True)
        and (
            label in {"LIKELY", "USER_BAD"}
            or _lobby_reputation_gate(payload)
            or _has_flow_spike(signals)
        )
        and (_has_attack(signals) or _has_peer_attack(signals) or kick_spike)
    )
    if escalate and peer_ips:
        ids_result = ids_enforce.block_wan_ips(
            peer_ips,
            ttl_sec=int(cfg.get("ids_block_ttl_sec") or 3600),
            source="sentinel",
        )
        result["ids_block"] = ids_result
        result["actions"].append(f"ids_blocked:{ids_result.get('blocked', 0)}")

    if cfg.get("auto_shield_sync", True):
        level = _shield_level(payload, signals, kick_spike=kick_spike)
        shield_peers = list(peer_ips)
        peer_rows = _extract_peer_rows(payload)
        gpu_strict: list[str] = []
        gpu_throttle: list[str] = []
        if peer_rows and phase in {"matchmaking", "in-match"}:
            try:
                from . import gpu_flow

                gf = gpu_flow.analyze_payload(payload, phase=phase)
                result["gpu_flow"] = gf
                if not gf.get("skipped"):
                    gpu_strict, gpu_throttle = gpu_flow.shield_peer_hints(gf)
                    shield_peers = list(dict.fromkeys([*shield_peers, *gpu_strict]))
                    if gpu_strict:
                        result["actions"].append(f"gpu_flow_strict:{len(gpu_strict)}")
                    if gpu_throttle:
                        result["actions"].append(f"gpu_flow_throttle:{len(gpu_throttle)}")
            except Exception as exc:
                result["gpu_flow"] = {"ok": False, "error": str(exc)}
        mit_cfg = policies.gaming().get("mitigation") or {}
        if peer_rows and mit_cfg.get("peer_rate_limits_enabled", True):
            try:
                from . import peer_rate_limits

                pr = peer_rate_limits.apply_to_shield(peer_rows, phase=phase, sync_nft=False)
                result["peer_rate_limits"] = pr
                merged = pr.get("merged_peers") or []
                shield_peers = list(dict.fromkeys([*shield_peers, *merged]))
                if merged:
                    result["actions"].append(f"peer_rate:{len(merged)}")
            except Exception as exc:
                result["peer_rate_limits"] = {"ok": False, "error": str(exc)}
        shield = _sync_shield(level, shield_peers, cfg)
        result["shield"] = shield
        result["actions"].append(f"shield:{level}")
        if session_events:
            session_events.append(
                "shield.sync",
                session_hex=session_hex or None,
                phase=phase,
                detail=f"level={level}",
                meta={"peer_count": len(peer_ips)},
            )

    if phase == "in-match" and cfg.get("auto_route_pref_in_match", True):
        from . import gaming as gaming_mod

        route = gaming_mod.apply_route_pref(session_hex=session_hex or None, phase=phase)
        result["route_pref"] = route
        if route.get("ok"):
            result["actions"].append("route_pref:apply")

    if allowlist_learn and phase == "in-match":
        learn = allowlist_learn.auto_learn_in_match(session_hex=session_hex or None, phase=phase)
        result["allowlist_learn"] = learn
        if learn.get("apply", {}).get("added"):
            result["actions"].append(f"allowlist:+{len(learn['apply']['added'])}")

    if asvi and phase in {"matchmaking", "in-match"}:
        scan = asvi.scan_session(session_hex=session_hex or None, limit=200)
        result["asvi"] = {
            "void_count": scan.get("void_count"),
            "max_asvi": scan.get("max_asvi"),
            "smst_summary": scan.get("smst_summary"),
        }
        act_voids = [v for v in (scan.get("voids") or []) if v.get("smst") == "act"]
        if act_voids:
            result["actions"].append(f"asvi_voids:{len(act_voids)}")

    try:
        from . import qce

        if qce._cfg().get("enabled", True):  # noqa: SLF001
            qce_measure = qce.measure_session(session_hex=session_hex or None, limit=200)
            result["qce"] = {
                "entanglement_entropy": qce_measure.get("entanglement_entropy"),
                "consciousness_score": qce_measure.get("consciousness_score"),
                "peak_entropy_band": qce_measure.get("peak_entropy_band"),
                "iit_phi": qce_measure.get("iit_phi"),
            }
            if qce_measure.get("peak_entropy_band") and int(qce_measure.get("unknown_count") or 0) >= 3:
                result["actions"].append("qce:investigate_peak")
    except Exception:
        pass

    if probe_sink:
        ingested = probe_sink.ingest_listener_log()
        result["probe_sink_ingest"] = ingested
        if ingested.get("ingested"):
            result["actions"].append(f"probe_sink:{ingested.get('ingested')}")
        result["probe_sink_counters"] = probe_sink.poll_counters()
        if session_hex:
            result["probe_correlation"] = probe_sink.correlate_session(session_hex)
        try:
            from . import adaptive_honeypot

            recent = probe_sink.recent_events(limit=24)
            ah = adaptive_honeypot.ingest_probe_hits(recent, session_hex=session_hex or "")
            result["adaptive_honeypot"] = ah
            if ah.get("active_ports"):
                result["actions"].append(f"honeypot_ports:{len(ah['active_ports'])}")
        except Exception as exc:
            result["adaptive_honeypot"] = {"ok": False, "error": str(exc)}

    peer_rows = _extract_peer_rows(payload)
    if peer_rows and phase in {"matchmaking", "in-match"}:
        try:
            from . import gaming_probe_ids

            gp = gaming_probe_ids.enforce_from_peers(peer_rows, phase=phase)
            result["gaming_probe_ids"] = gp
            if gp.get("blocked"):
                result["actions"].append(f"gaming_probe_ids:{gp['blocked']}")
        except Exception as exc:
            result["gaming_probe_ids"] = {"ok": False, "error": str(exc)}

    if phase == "in-match":
        metrics = {}
        pkt = payload.get("packets") or payload.get("packet_analysis") or {}
        if isinstance(pkt, dict):
            metrics = pkt.get("metrics") or {}
        jitter = metrics.get("wan_jitter") or metrics.get("server_jitter")
        mit_cfg = policies.gaming().get("mitigation") or {}
        if mit_cfg.get("download_desync_enabled", True) and jitter:
            try:
                if float(jitter) >= float(mit_cfg.get("download_desync_jitter_min") or 0.35):
                    from . import qos

                    dl = qos.download_boost_apply(session_hex=session_hex or None, phase=phase)
                    result["download_desync"] = dl
                    if dl.get("ok"):
                        result["actions"].append("download_boost:desync")
            except (TypeError, ValueError):
                pass

    if session_hex and peer_rows:
        try:
            from . import probe_intel

            result["probe_intel"] = probe_intel.ingest_session_peers(session_hex, peer_rows)
            if result["probe_intel"].get("ingested"):
                result["actions"].append(f"probe_intel:{result['probe_intel']['ingested']}")
        except Exception as exc:
            result["probe_intel"] = {"ok": False, "error": str(exc)}

    try:
        from . import nat as nat_mod

        result["wan_nat"] = nat_mod.ensure_wan_nat()
    except Exception as exc:
        result["wan_nat"] = {"ok": False, "error": str(exc)}

    try:
        from . import ai_ops

        if payload.get("ai_actions"):
            ai_act = ai_ops.execute_ai_actions(payload)
            result["ai_actions"] = ai_act
            if ai_act.get("execution", {}).get("executed"):
                result["actions"].append(f"ai_actions:{len(ai_act['execution']['executed'])}")

        if payload.get("session_outcome") or payload.get("bad_lobby") is not None:
            result["outcome_learning"] = ai_ops.record_outcome_from_payload(payload)

        ai_tick = ai_ops.tick(sentinel_payload=payload, source="mitigate", force=False)
        result["ai_ops"] = {
            "verdict": (ai_tick.get("plan") or {}).get("verdict"),
            "summary": (ai_tick.get("plan") or {}).get("summary"),
            "executed": len((ai_tick.get("execution") or {}).get("executed") or []),
            "mode": ai_tick.get("mode"),
            "skipped": ai_tick.get("skipped"),
            "playability": ai_tick.get("playability"),
        }
        if ai_tick.get("execution", {}).get("executed"):
            result["actions"].append(f"ai_ops:{len(ai_tick['execution']['executed'])}")
    except Exception as exc:
        result["ai_ops"] = {"ok": False, "error": str(exc)}

    return result
