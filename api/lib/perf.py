"""Gateway performance: kernel tuning, QoS helpers, optional GPU packet analysis."""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CONF = Path("/etc/array-firewall/array-firewall.conf")
PERF_TUNE = Path("/opt/array-firewall/scripts/perf-tune.sh")
BUFFER_STATE = Path("/var/lib/array-firewall/buffer-tune.state")
DSCP_STATE = Path("/var/lib/array-firewall/dscp-gaming.state")
PERF_STATE = Path("/var/lib/array-firewall/perf-tune.state")
GPU_DEFAULT = "http://192.168.167.221:8795"


def _read_conf() -> dict[str, str]:
    out: dict[str, str] = {}
    if not CONF.is_file():
        return out
    for line in CONF.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        out[key.strip()] = val.strip().strip('"')
    return out


def gpu_url() -> str:
    conf = _read_conf()
    return (
        conf.get("GPU_PERF_URL")
        or os.environ.get("GPU_PERF_URL")
        or os.environ.get("ARRAY_FW_GPU_PERF_URL")
        or GPU_DEFAULT
    ).rstrip("/")


def gpu_enabled() -> bool:
    conf = _read_conf()
    val = conf.get("GPU_PERF_ENABLED", os.environ.get("GPU_PERF_ENABLED", "1"))
    return str(val).lower() not in {"0", "false", "off", "no"}


def _run(script: Path, *args: str, timeout: int = 60) -> dict[str, Any]:
    if not script.is_file():
        return {"ok": False, "error": f"missing {script}"}
    proc = subprocess.run(
        [str(script), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    return {
        "ok": proc.returncode == 0,
        "stdout": out,
        "stderr": err,
        "exit": proc.returncode,
    }


def apply_tune() -> dict[str, Any]:
    result = _run(PERF_TUNE, "apply")
    return {"ok": result["ok"], "tune": result}


def tune_status() -> dict[str, Any]:
    proc = subprocess.run(
        [str(PERF_TUNE), "json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    kernel: dict[str, Any] = {}
    if proc.stdout.strip():
        try:
            kernel = json.loads(proc.stdout)
        except json.JSONDecodeError:
            kernel = {"raw": proc.stdout.strip()}
    buffer = BUFFER_STATE.read_text(encoding="utf-8").strip() if BUFFER_STATE.is_file() else ""
    dscp = DSCP_STATE.read_text(encoding="utf-8").strip() if DSCP_STATE.is_file() else ""
    last = PERF_STATE.read_text(encoding="utf-8").strip() if PERF_STATE.is_file() else ""
    return {
        "ok": True,
        "kernel": kernel,
        "last_tune": last or None,
        "buffer_profile": buffer or "normal",
        "dscp": dscp or "inactive",
        "gpu": gpu_status(),
    }


def gpu_probe() -> dict[str, Any]:
    url = f"{gpu_url()}/health"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            data["reachable"] = True
            data["url"] = gpu_url()
            return data
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reachable": False, "url": gpu_url(), "error": str(exc)}


def gpu_status() -> dict[str, Any]:
    if not gpu_enabled():
        return {"enabled": False, "url": gpu_url()}
    probe = gpu_probe()
    probe["enabled"] = True
    return probe


def analyze_packets_gpu(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Offload batch packet fingerprint analysis to fleet GPU host (.221)."""
    if not records:
        return {"ok": True, "skipped": True, "reason": "no records"}
    if not gpu_enabled():
        return analyze_packets_cpu(records)

    from . import folding as folding_mod

    body_obj = {"packets": records[:512]}
    body_text = json.dumps(body_obj, separators=(",", ":"))
    wire = folding_mod.wire_compress(body_text.encode("utf-8"))
    body = json.dumps({"wire": wire, "packets": records[:512]}).encode("utf-8")
    url = f"{gpu_url()}/v1/analyze"
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            data["backend"] = "gpu"
            data["url"] = gpu_url()
            data["wire_compression"] = {
                "ratio": wire.get("ratio"),
                "orig_size": wire.get("orig_size"),
                "compressed_size": wire.get("compressed_size"),
            }
            return data
    except Exception as exc:  # noqa: BLE001
        local = analyze_packets_cpu(records)
        local["gpu_fallback"] = str(exc)
        return local


def analyze_packets_cpu(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Local CPU fallback when GPU host is unreachable."""
    sizes = [int(r.get("len") or r.get("size") or 0) for r in records]
    dirs = [str(r.get("dir") or r.get("direction") or "") for r in records]
    if not sizes:
        return {"ok": True, "backend": "cpu", "count": 0}
    tiny = sum(1 for s in sizes if 0 < s <= 79)
    inbound = sum(1 for d in dirs if d.startswith("in"))
    outbound = len(sizes) - inbound
    avg = sum(sizes) / len(sizes)
    flood_score = min(100.0, (tiny / max(len(sizes), 1)) * 120 + (inbound / max(outbound, 1)) * 15)
    return {
        "ok": True,
        "backend": "cpu",
        "count": len(sizes),
        "tiny_packets": tiny,
        "inbound": inbound,
        "outbound": outbound,
        "avg_size": round(avg, 1),
        "flood_score": round(flood_score, 2),
        "anomaly": flood_score >= 35,
    }


def apply_all() -> dict[str, Any]:
    from . import qos as qos_mod
    from . import stability as stability_mod

    tune = apply_tune()
    steps: dict[str, Any] = {}

    if _perf_cfg().get("autorate_before_apply") and not stability_mod.contract_rates():
        steps["autorate"] = stability_mod.autorate(apply_qos=False)

    stability_mod.ensure_group_defaults()
    try:
        steps["xbox"] = stability_mod.ensure_xbox_in_gaming_group()
    except Exception as exc:  # noqa: BLE001
        steps["xbox"] = {"error": str(exc)}
    try:
        steps["mesh"] = stability_mod.auto_assign_mesh_devices()
    except Exception as exc:  # noqa: BLE001
        steps["mesh"] = {"error": str(exc)}

    qos_result: dict[str, Any] = {"ok": False}
    try:
        qos_result = qos_mod.apply()
    except Exception as exc:  # noqa: BLE001
        qos_result = {"ok": False, "error": str(exc)}
    moca = _run(Path("/opt/array-firewall/gaming-tools/gaming-moca-tune.sh"), "apply")
    route = _run(Path("/opt/array-firewall/gaming-tools/gaming-route-pref.sh"), "apply")
    return {
        "ok": tune.get("ok") and qos_result.get("ok", False),
        "tune": tune,
        "qos": qos_result,
        "dscp": moca,
        "route": route,
        "gpu": gpu_status(),
        "steps": steps,
    }


def _perf_cfg() -> dict[str, Any]:
    from . import policies

    return policies.load().get("perf") or {}
