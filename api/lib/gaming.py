from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

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


def apply_packet_shield(level: str = "normal") -> dict[str, Any]:
    """Enable nft packet shield for configured Xbox IP."""
    level = (level or "normal").lower()
    if level in ("off", "relax", "none"):
        return run_script_api("packet-shield-nft.sh", ["relax"])
    if level in ("strict", "whitelist"):
        return run_script_api("packet-shield-nft.sh", ["shield", level])
    return run_script_api("packet-shield-nft.sh", ["shield", "normal"])


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
