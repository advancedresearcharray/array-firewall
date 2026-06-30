from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from . import policies

RUNNER = Path("/opt/array-firewall/scripts/run-gaming.sh")
CONF = Path("/opt/array-firewall/gaming-tools/gaming.conf")


def run_script(name: str, args: list[str] | None = None) -> dict[str, Any]:
    if not RUNNER.is_file():
        return {"ok": False, "error": "gaming runner missing"}
    cmd = [str(RUNNER), name, *(args or [])]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    out = proc.stdout.strip()
    try:
        parsed = json.loads(out)
        return {"ok": proc.returncode == 0, "data": parsed, "stderr": proc.stderr.strip()}
    except json.JSONDecodeError:
        return {
            "ok": proc.returncode == 0,
            "stdout": out,
            "stderr": proc.stderr.strip(),
        }


def run_script_api(name: str, args: list[str] | None = None) -> dict[str, Any]:
    """Firewalla-compatible /api/v1/run response for Warzone sentinel."""
    if not RUNNER.is_file():
        return {"ok": False, "error": "gaming runner missing", "stderr": "gaming runner missing"}
    cmd = [str(RUNNER), name, *(args or [])]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    out = proc.stdout.strip()
    err = proc.stderr.strip()
    if proc.returncode != 0:
        return {"ok": False, "stdout": out, "stderr": err, "error": err or f"exit {proc.returncode}"}
    return {"ok": True, "stdout": out, "stderr": err}


def _ensure_wan_nat_after_shield(result: dict[str, Any]) -> dict[str, Any]:
    if not result.get("ok"):
        return result
    try:
        from . import nat as nat_mod

        result["wan_nat"] = nat_mod.ensure_wan_nat()
    except Exception as exc:
        result["wan_nat"] = {"ok": False, "error": str(exc)}
    return result


def apply_in_match_mode(
    *,
    enabled: bool = True,
    peer_ips: list[str] | None = None,
    session_hex: str | None = None,
    phase: str | None = None,
) -> dict[str, Any]:
    """In-match shield — Warzone + Xbox Live allowlist only; drop all other inbound to Xbox."""
    if not enabled:
        return apply_packet_shield("relax", session_hex=session_hex, phase=phase)
    level = policies.effective_shield_level("in-match")
    args = ["shield", level]
    if peer_ips:
        args.extend(peer_ips)
    result = run_script_api("packet-shield-nft.sh", args)
    result = _ensure_wan_nat_after_shield(result)
    result["in_match_mode"] = enabled
    if result.get("ok"):
        result["packet_shield"] = _shield_status()
        _log_shield_event("in-match", session_hex=session_hex, phase=phase or "in-match", peer_ips=peer_ips)
    return result


def apply_upload_boost() -> dict[str, Any]:
    from . import qos as qos_mod

    return qos_mod.upload_boost_apply()


def relax_upload_boost() -> dict[str, Any]:
    from . import qos as qos_mod

    return qos_mod.upload_boost_relax()


def upload_boost_status() -> dict[str, Any]:
    from . import qos as qos_mod

    return qos_mod.upload_boost_status()


def apply_console_mode(
    *,
    enabled: bool = True,
    peer_ips: list[str] | None = None,
    session_hex: str | None = None,
    phase: str | None = None,
) -> dict[str, Any]:
    """Enable console shield — allowlisted backends only; drop all non-allowlist game-port inbound."""
    if not enabled:
        return apply_packet_shield("relax", session_hex=session_hex, phase=phase)
    args = ["shield", "console"]
    if peer_ips:
        args.extend(peer_ips)
    result = run_script_api("packet-shield-nft.sh", args)
    result = _ensure_wan_nat_after_shield(result)
    result["console_mode"] = enabled
    if result.get("ok"):
        result["packet_shield"] = _shield_status()
        _log_shield_event("console", session_hex=session_hex, phase=phase, peer_ips=peer_ips)
    return result


def _log_shield_event(
    level: str,
    *,
    session_hex: str | None = None,
    phase: str | None = None,
    peer_ips: list[str] | None = None,
) -> None:
    from . import session_events

    session_events.append(
        "shield.apply",
        session_hex=session_hex,
        phase=phase,
        detail=f"level={level}",
        meta={"level": level, "peer_count": len(peer_ips or [])},
    )


def apply_packet_shield(
    level: str = "normal",
    *,
    session_hex: str | None = None,
    phase: str | None = None,
    peer_ips: list[str] | None = None,
) -> dict[str, Any]:
    """Enable or relax nft packet shield for configured Xbox IP."""
    level = (level or "normal").lower()
    if level in ("off", "relax", "none"):
        result = run_script_api("packet-shield-nft.sh", ["relax"])
        result = _ensure_wan_nat_after_shield(result)
        if result.get("ok"):
            from . import session_events

            session_events.append("shield.relax", session_hex=session_hex, phase=phase, detail="shield relaxed")
    elif level in ("strict", "whitelist", "peer-strict", "matchmaking", "console", "in-match"):
        level = policies.effective_shield_level(level)
        args = ["shield", level, *(peer_ips or [])]
        result = run_script_api("packet-shield-nft.sh", args)
        result = _ensure_wan_nat_after_shield(result)
        if result.get("ok"):
            _log_shield_event(level, session_hex=session_hex, phase=phase, peer_ips=peer_ips)
    else:
        result = run_script_api("packet-shield-nft.sh", ["shield", "normal"])
        result = _ensure_wan_nat_after_shield(result)
        if result.get("ok"):
            _log_shield_event("normal", session_hex=session_hex, phase=phase, peer_ips=peer_ips)
    result["level"] = level
    if result.get("ok"):
        result["packet_shield"] = _shield_status()
    return result


def route_pref_status() -> dict[str, Any]:
    state_path = Path("/var/lib/array-firewall/gaming-route.state")
    state = {}
    if state_path.is_file():
        for line in state_path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                state[k.strip()] = v.strip()
    result = run_script_api("gaming-route-pref.sh", ["status"])
    stdout = str(result.get("stdout") or "")
    active = "route=pref" in stdout or state.get("route", "").startswith("pref")
    return {
        "ok": True,
        "active": active,
        "state": state,
        "script": result,
    }


def apply_route_pref(*, gateway: str | None = None, session_hex: str | None = None, phase: str | None = None) -> dict[str, Any]:
    from . import session_events

    args = ["apply"]
    if gateway:
        args.append(gateway)
    result = run_script_api("gaming-route-pref.sh", args)
    result["status"] = route_pref_status()
    if result.get("ok"):
        session_events.append(
            "route.pref",
            session_hex=session_hex,
            phase=phase,
            detail=f"gw={gateway or 'auto'}",
        )
    return result


def clear_route_pref(*, session_hex: str | None = None, phase: str | None = None) -> dict[str, Any]:
    from . import session_events

    result = run_script_api("gaming-route-pref.sh", ["clear"])
    result["status"] = route_pref_status()
    if result.get("ok"):
        session_events.append("route.clear", session_hex=session_hex, phase=phase, detail="route preference cleared")
    return result


def session_timeline(session_hex: str, *, limit: int = 150) -> dict[str, Any]:
    from . import session_timeline as timeline_mod

    return timeline_mod.build(session_hex, limit=limit)


def causal_timeline(session_hex: str, *, limit: int = 150) -> dict[str, Any]:
    from . import causal_timeline as causal_mod

    return causal_mod.build(session_hex, limit=limit)


def peer_rate_limits_status() -> dict[str, Any]:
    from . import peer_rate_limits

    return peer_rate_limits.status()


def probe_intel_status() -> dict[str, Any]:
    from . import probe_intel

    return probe_intel.status()


def match_cockpit() -> dict[str, Any]:
    """Unified match view — Sentinel + ai_ops + playability (stay in lobby)."""
    out: dict[str, Any] = {"ok": True, "posture": "stay_and_mitigate"}
    try:
        from . import sentinel

        dash = sentinel.dashboard_data() or {}
        out["sentinel"] = {
            "phase": dash.get("phase"),
            "session_hex": dash.get("session_hex"),
            "cheater_label": (dash.get("cheater_lobby") or {}).get("label"),
            "network_guard": dash.get("network_guard"),
            "peer_tracker": dash.get("peer_tracker"),
            "game_state": dash.get("game_state"),
        }
        out["session_hex"] = dash.get("session_hex") or (dash.get("peer_tracker") or {}).get("session_hex")
    except Exception as exc:
        out["sentinel"] = {"ok": False, "error": str(exc)}
    try:
        from . import ai_ops

        st = ai_ops.status()
        out["ai_ops"] = {
            "mode": st.get("mode"),
            "playability": st.get("playability"),
            "pre_burst_forecast": st.get("pre_burst_forecast"),
            "game_fusion": st.get("game_fusion"),
            "mesh_reputation": st.get("mesh_reputation"),
        }
    except Exception as exc:
        out["ai_ops"] = {"ok": False, "error": str(exc)}
    try:
        from . import peer_rate_limits, mesh_reputation, adaptive_honeypot

        out["peer_rate_limits"] = peer_rate_limits.status().get("analysis")
        out["mesh_reputation"] = mesh_reputation.status()
        out["adaptive_honeypot"] = adaptive_honeypot.status().get("state")
    except Exception:
        pass
    return out


def allowlist_learn_status() -> dict[str, Any]:
    from . import allowlist_learn

    return allowlist_learn.status()


def allowlist_learn_analyze(*, session_hex: str | None = None) -> dict[str, Any]:
    from . import allowlist_learn

    return allowlist_learn.analyze(session_hex=session_hex)


def allowlist_learn_apply(*, reload_shield: bool = False) -> dict[str, Any]:
    from . import allowlist_learn

    return allowlist_learn.apply_learned(reload_shield=reload_shield)


def _shield_status() -> dict[str, Any]:
    state = Path("/var/lib/array-firewall/packet-shield.state")
    if not state.is_file():
        return {"active": False, "mode": "inactive"}
    shield = {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in state.read_text(encoding="utf-8").splitlines()
        if "=" in line
    }
    shield["active"] = shield.get("mode") == "shield"
    return shield


_DEFAULT_MITIGATION: dict[str, Any] = {
    "auto_block_peers": True,
    "auto_ids_block": True,
    "auto_shield_sync": True,
    "matchmaking_allowlist": True,
    "console_mode": True,
    "peer_ttl_sec": 86400,
    "ids_block_ttl_sec": 3600,
    "per_source_udp_rate": 500,
    "conn_cap_per_peer": 40,
    "min_mitigate_interval_sec": 15,
    "repeat_offender_hits": 3,
    "repeat_offender_ttl_sec": 604800,
    "honeypot_enabled": True,
    "sink_port": 39217,
    "auto_block_on_probe": True,
    "probe_block_ttl_sec": 86400,
    "tcp_rst_non_game": True,
    "auto_route_pref_in_match": True,
    "peer_rate_limits_enabled": True,
}

_DEFAULT_UPLOAD_ASSIST: dict[str, Any] = {
    "enabled": True,
    "ceil_factor": 0.98,
    "other_ceil_factor": 0.55,
    "xbox_rate_factor": 0.85,
    "pressure_warn_pct": 80,
    "in_match_desync_buffer": True,
    "auto_boost_in_lobby": True,
    "buffer": {
        "gaming_xbox_rtt": "8ms",
        "gaming_ifb_rtt": "8ms",
        "desync_xbox_rtt": "5ms",
        "desync_ifb_rtt": "5ms",
        "kick_xbox_rtt": "3ms",
        "kick_ifb_rtt": "3ms",
        "xbox_memlimit": "4mb",
        "ifb_memlimit": "8mb",
    },
}


def ensure_mitigation_policy(*, idle_shield: str = "console") -> dict[str, Any]:
    """Ensure Xbox kick/desync mitigation policy keys exist (Open NAT + DMZ safe)."""
    from . import policies

    data = policies.load()
    gaming = data.setdefault("gaming", {})
    mit = gaming.setdefault("mitigation", {})
    for key, val in _DEFAULT_MITIGATION.items():
        mit.setdefault(key, val)
    upload = gaming.setdefault("upload_assist", {})
    download = gaming.setdefault("download_assist", {})
    for key, val in _DEFAULT_UPLOAD_ASSIST.items():
        if key == "buffer":
            buf = upload.setdefault("buffer", {})
            for bk, bv in val.items():
                buf.setdefault(bk, bv)
        else:
            upload.setdefault(key, val)
    gaming["packet_shield_idle_level"] = idle_shield
    gaming.setdefault("packet_shield_in_match_only", True)
    grp = (data.get("device_groups") or {}).get("gaming") or {}
    cfg = grp.setdefault("config", {})
    if str(cfg.get("packet_shield", "off")).lower() in {"off", "normal", ""}:
        cfg["packet_shield"] = idle_shield
    policies.save(data)
    return {"mitigation": mit, "upload_assist": upload, "download_assist": download, "idle_shield": idle_shield}


def apply_xbox_secure_stack(
    *,
    shield_level: str = "console",
    buffer_profile: str = "desync",
    apply_upload_boost: bool = True,
    apply_download_boost: bool = True,
) -> dict[str, Any]:
    """
    Open NAT (DMZ + UPnP) with anticheat: console/in-match shield, honeypot, peer blocks, desync buffer.
    Safe with xbox_wan_dmz — p2p_block stays off; tiny-packet + allowlist kick protection remains.
    """
    from . import nat, peer_blocklist, policies, qos

    policy = ensure_mitigation_policy(idle_shield=shield_level)
    nat.ensure_wan_nat()
    nat_status = nat.status()
    if not (nat_status.get("dmz") or {}).get("enabled"):
        return {"ok": False, "error": "xbox DMZ not enabled — run enable_xbox_wan_dmz first", "nat": nat_status}

    shield = peer_blocklist.sync_shield(level=shield_level)
    if not shield.get("ok"):
        return {"ok": False, "error": "packet shield failed", "shield": shield, "nat": nat_status}
    nat.ensure_wan_nat()
    nat_status = nat.status()

    buffer = qos.buffer_tune_apply(buffer_profile)
    upload = None
    download = None
    upload_cfg = (policies.gaming().get("upload_assist") or {})
    if apply_upload_boost and upload_cfg.get("enabled", True):
        upload = qos.upload_boost_apply()
    download_cfg = (policies.gaming().get("download_assist") or {})
    if apply_download_boost and download_cfg.get("enabled", True):
        download = qos.download_boost_apply()

    probe = {"running": False}
    try:
        from . import probe_sink

        probe = probe_sink.status()
    except Exception:
        pass

    return {
        "ok": True,
        "shield_level": shield_level,
        "buffer_profile": buffer_profile,
        "policy": policy,
        "nat": {
            "dmz": nat_status.get("dmz"),
            "upnp": nat_status.get("upnp"),
            "nat_open": nat_status.get("nat_open"),
        },
        "shield": shield,
        "packet_shield": _shield_status(),
        "buffer": buffer,
        "upload_boost": upload,
        "download_boost": download,
        "probe_sink": probe,
        "peer_blocklist": peer_blocklist.status(),
    }


def snapshot(xbox_ip: str | None = None) -> dict[str, Any]:
    ip = xbox_ip
    if not ip and CONF.is_file():
        for line in CONF.read_text(encoding="utf-8").splitlines():
            if line.startswith("XBOX_IP="):
                ip = line.split("=", 1)[1].strip()
    result = run_script("gaming-snapshot.sh", [ip] if ip else [])
    data = result.get("data")
    if result.get("ok") and isinstance(data, dict):
        pc = data.get("packetCapture") or data.get("packet_capture") or {}
        records = pc.get("records") or []
        if records:
            from . import perf as perf_mod

            result["gpu_analysis"] = perf_mod.analyze_packets_gpu(records)
    return result
