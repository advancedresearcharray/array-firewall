"""Post-cutover hardening bundle — provider ranges, zones, IDS, allowlist learn."""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

from . import devices, ids, nft, policies, subnet_blocklist

HARDENING_STATE = Path("/var/lib/array-firewall/hardening.state")


def _cfg() -> dict[str, Any]:
    return dict(policies.load().get("hardening") or {})


def status() -> dict[str, Any]:
    cfg = _cfg()
    data = policies.load()
    subnet = dict((data.get("gaming") or {}).get("mitigation") or {}).get("subnet_block") or {}
    zone_allow = dict((data.get("zones") or {}).get("allow") or {})
    ids_cfg = data.get("ids") or {}
    learn = dict((data.get("gaming") or {}).get("allowlist_learn") or {})
    last = {}
    if HARDENING_STATE.is_file():
        try:
            last = dict(
                line.split("=", 1)
                for line in HARDENING_STATE.read_text(encoding="utf-8").splitlines()
                if "=" in line
            )
        except OSError:
            last = {}
    return {
        "ok": True,
        "enabled": cfg.get("enabled", True),
        "applied": last.get("applied") == "1",
        "last_apply": last.get("updated"),
        "targets": {
            "enforce_provider_ranges": bool(subnet.get("enforce_provider_ranges")),
            "restricted_lateral": bool(zone_allow.get("restricted_lateral")),
            "ids_mode": str(ids_cfg.get("mode") or "log_only"),
            "allowlist_learn_auto": bool(learn.get("auto_apply_in_match")),
            "default_posture": (data.get("network") or {}).get("default_posture"),
        },
        "config": cfg,
    }


def apply(*, stage: str = "full", force: bool = False) -> dict[str, Any]:
    """Apply post-cutover hardening toggles and reload firewall subsystems."""
    cfg = _cfg()
    if not cfg.get("enabled", True) and not force:
        return {"ok": True, "skipped": True, "reason": "disabled"}

    if not policies.cutover_enabled() and policies.role() not in {"gateway", "xbox_router"}:
        return {
            "ok": False,
            "error": "cutover not live — run gateway cutover first or use force=true",
            "role": policies.role(),
        }

    data = policies.load()
    steps: list[dict[str, Any]] = []

    if stage in {"full", "subnet"}:
        mit = data.setdefault("gaming", {}).setdefault("mitigation", {})
        sb = mit.setdefault("subnet_block", {})
        if cfg.get("enforce_provider_ranges", True):
            sb["enforce_provider_ranges"] = True
            sb.setdefault("enabled", True)
        steps.append({"step": "subnet_policy", "enforce_provider_ranges": sb.get("enforce_provider_ranges")})

    if stage in {"full", "zones"}:
        zone = data.setdefault("zones", {})
        zone.setdefault("enabled", True)
        allow = zone.setdefault("allow", {})
        if cfg.get("restricted_lateral", True):
            allow["restricted_lateral"] = True
        net = data.setdefault("network", {})
        if cfg.get("default_posture_deny", True):
            net["default_posture"] = "deny_new_devices"
        steps.append({"step": "zones_policy", "restricted_lateral": allow.get("restricted_lateral")})

    if stage in {"full", "ids"}:
        ids_cfg = data.setdefault("ids", {})
        ids_cfg.setdefault("enabled", True)
        if cfg.get("ids_mode"):
            ids_cfg["mode"] = str(cfg.get("ids_mode"))
        elif cfg.get("ids_enforce", True):
            ids_cfg["mode"] = "enforce"
        steps.append({"step": "ids_policy", "mode": ids_cfg.get("mode")})

    if stage in {"full", "allowlist"}:
        learn = data.setdefault("gaming", {}).setdefault("allowlist_learn", {})
        if cfg.get("allowlist_learn_auto", False):
            learn["auto_apply_in_match"] = True
        steps.append({"step": "allowlist_learn", "auto_apply_in_match": learn.get("auto_apply_in_match")})

    policies.save(data)
    steps.append({"step": "policies_saved", "ok": True})

    reload_steps: list[dict[str, Any]] = []
    try:
        if stage in {"full", "subnet"}:
            prov = subnet_blocklist.enforce_provider_catalog()
            reload_steps.append({"step": "provider_catalog", **prov})
    except Exception as exc:
        reload_steps.append({"step": "provider_catalog", "ok": False, "error": str(exc)})

    try:
        if stage in {"full", "zones"}:
            reload_steps.append({"step": "zones_policy", "ok": True, "restricted_lateral": True})
    except Exception as exc:
        reload_steps.append({"step": "zones_policy", "ok": False, "error": str(exc)})

    try:
        if stage in {"full", "ids"}:
            scan = ids.analyze(force=True)
            reload_steps.append({"step": "ids_scan", "ok": scan.get("ok", True)})
    except Exception as exc:
        reload_steps.append({"step": "ids_scan", "ok": False, "error": str(exc)})

    try:
        nft_result = nft.apply_ruleset()
        reload_steps.append({"step": "nft_apply", "ok": nft_result.get("ok", False)})
    except Exception as exc:
        reload_steps.append({"step": "nft_apply", "ok": False, "error": str(exc)})

    try:
        subprocess.run(
            ["/opt/array-firewall/scripts/setup-dnsmasq.sh"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        reload_steps.append({"step": "dnsmasq", "ok": True})
    except OSError as exc:
        reload_steps.append({"step": "dnsmasq", "ok": False, "error": str(exc)})

    HARDENING_STATE.parent.mkdir(parents=True, exist_ok=True)
    HARDENING_STATE.write_text(
        f"applied=1\nupdated={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\nstage={stage}\n",
        encoding="utf-8",
    )

    return {
        "ok": True,
        "stage": stage,
        "posture": "stay_and_mitigate",
        "admin_mac": devices.admin_mac(),
        "policy_steps": steps,
        "reload_steps": reload_steps,
        "status": status(),
    }
