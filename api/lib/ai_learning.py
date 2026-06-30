"""Outcome-trained fusion weights from lobby feedback (stay-in-lobby — tune mitigation, not exit)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import policies

LEARNING_FILE = Path("/var/lib/array-firewall/ai-learning.json")
OUTCOMES_FILE = Path("/var/lib/array-firewall/ai-outcomes.jsonl")
MAX_OUTCOMES = 2000

DEFAULT_WEIGHTS = {
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
}


def _now() -> float:
    return time.time()


def _load() -> dict[str, Any]:
    if not LEARNING_FILE.is_file():
        return {"weights": dict(DEFAULT_WEIGHTS), "outcome_count": 0, "adjustments": {}}
    try:
        return json.loads(LEARNING_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"weights": dict(DEFAULT_WEIGHTS), "outcome_count": 0, "adjustments": {}}


def _save(data: dict[str, Any]) -> None:
    LEARNING_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = LEARNING_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(LEARNING_FILE)


def fuse_weights() -> dict[str, float]:
    cfg = policies.load().get("ai_ops") or {}
    base = dict(DEFAULT_WEIGHTS)
    base.update(cfg.get("fuse_weights") or {})
    learned = _load().get("weights") or {}
    for k, v in learned.items():
        if k in base:
            try:
                base[k] = float(v)
            except (TypeError, ValueError):
                pass
    return base


def record_outcome(
    *,
    session_hex: str | None,
    verdict: str,
    bad_lobby: bool | None = None,
    cheater_label: str | None = None,
    signals: list[str] | None = None,
    autopilot_actions: list[str] | None = None,
    peer_ips: list[str] | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Record session outcome for weight tuning. verdict: clean|bad|kicked|mitigated."""
    row = {
        "ts": _now(),
        "session_hex": session_hex,
        "verdict": verdict,
        "bad_lobby": bad_lobby,
        "cheater_label": cheater_label,
        "signals": signals or [],
        "autopilot_actions": autopilot_actions or [],
        "peer_ips": peer_ips or [],
        "note": note,
    }
    OUTCOMES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTCOMES_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, separators=(",", ":")) + "\n")
    _trim_outcomes()
    return _adjust_weights(row)


def _trim_outcomes() -> None:
    if not OUTCOMES_FILE.is_file():
        return
    try:
        lines = OUTCOMES_FILE.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_OUTCOMES:
            OUTCOMES_FILE.write_text("\n".join(lines[-MAX_OUTCOMES:]) + "\n")
    except OSError:
        pass


def _adjust_weights(outcome: dict[str, Any]) -> dict[str, Any]:
    data = _load()
    weights = dict(data.get("weights") or DEFAULT_WEIGHTS)
    adj = dict(data.get("adjustments") or {})
    lr = float((policies.load().get("ai_ops") or {}).get("learning_rate") or 0.04)
    bad = outcome.get("bad_lobby") is True or str(outcome.get("verdict") or "") in {"bad", "kicked"}
    clean = outcome.get("bad_lobby") is False or str(outcome.get("verdict") or "") == "clean"
    delta_dir = 1.0 if bad else (-0.5 if clean else 0.0)
    if delta_dir == 0.0:
        return {"ok": True, "adjusted": False}

    signal_map = {
        "vps_probe": "vps_probe",
        "identical": "identical_burst",
        "asvi": "asvi_act",
        "qce": "qce_peak",
        "ids_ai": "ids_ai_high",
        "gpu_flood": "gpu_flood",
        "reputation": "reputation_bad",
        "pre_burst": "pre_burst",
        "sentinel": "sentinel_likely",
    }
    touched: list[str] = []
    for sig in outcome.get("signals") or []:
        sig_l = str(sig).lower()
        for prefix, key in signal_map.items():
            if prefix in sig_l and key in weights:
                weights[key] = round(
                    max(0.05, min(0.95, float(weights[key]) + lr * delta_dir)),
                    4,
                )
                adj[key] = int(adj.get(key) or 0) + (1 if bad else -1)
                touched.append(key)
                break

    if bad and any("block" in str(a) for a in (outcome.get("autopilot_actions") or [])):
        weights["vps_probe"] = round(min(0.95, float(weights.get("vps_probe", 0.4)) + lr * 0.5), 4)
        touched.append("vps_probe")

    data["weights"] = weights
    data["adjustments"] = adj
    data["outcome_count"] = int(data.get("outcome_count") or 0) + 1
    data["last_outcome"] = outcome
    _save(data)
    return {"ok": True, "adjusted": True, "touched": touched, "weights": weights}


def status() -> dict[str, Any]:
    data = _load()
    return {
        "ok": True,
        "weights": fuse_weights(),
        "outcome_count": data.get("outcome_count", 0),
        "adjustments": data.get("adjustments") or {},
        "last_outcome": data.get("last_outcome"),
    }
