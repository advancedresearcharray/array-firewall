"""Proxy and config bridge to co-hosted Warzone Lobby Sentinel."""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CONF = Path("/etc/array-firewall/array-firewall.conf")
DEFAULT_PORT = 8098
DEFAULT_BASE = f"http://127.0.0.1:{DEFAULT_PORT}"


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


def base_url() -> str:
    conf = _read_conf()
    port = int(conf.get("SENTINEL_PORT") or os.environ.get("WZ_INGEST_PORT") or DEFAULT_PORT)
    return f"http://127.0.0.1:{port}"


def xbox_ip() -> str:
    conf = _read_conf()
    return conf.get("XBOX_IP") or "192.168.167.65"


def sync_all(restart: bool = False) -> dict[str, Any]:
    """Sync sentinel token/env from array-firewall and optionally restart service."""
    sync_token()
    sync_env_file()
    restarted = False
    if restart:
        proc = subprocess.run(
            ["systemctl", "restart", "warzone-lobby-sentinel"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        restarted = proc.returncode == 0
    conf = _read_conf()
    api_port = conf.get("API_PORT", "8090")
    return {
        "ok": True,
        "xbox_ip": xbox_ip(),
        "apiUrl": f"http://127.0.0.1:{api_port}",
        "sentinelUrl": base_url(),
        "restarted": restarted,
    }


def sync_token(api_token_file: Path | None = None) -> None:
    """Write array-firewall API token for sentinel /api/v1/run auth."""
    src = api_token_file or Path("/etc/array-firewall/api.token")
    dst = Path("/etc/warzone-sentinel/array-firewall.token")
    if not src.is_file():
        return
    token = src.read_text(encoding="utf-8").strip()
    if not token:
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(f"{token}\n", encoding="utf-8")
    dst.chmod(0o600)
    # Legacy path for older sentinel builds
    legacy = Path("/etc/warzone-sentinel/firewalla.token")
    legacy.write_text(f"FIREWALLA_API_TOKEN={token}\n", encoding="utf-8")
    legacy.chmod(0o600)


def sync_env_file(env_path: Path | None = None) -> None:
    """Point sentinel at local array-firewall API and shared Xbox IP."""
    env = env_path or Path("/etc/default/warzone-lobby-sentinel")
    if not env.is_file():
        return
    conf = _read_conf()
    xip = conf.get("XBOX_IP", "192.168.167.65")
    api_port = conf.get("API_PORT", "8090")
    lines = env.read_text(encoding="utf-8").splitlines()
    updates = {
        "WZ_ARRAY_FW_API_URL": f"http://127.0.0.1:{api_port}",
        "WZ_XBOX_IP": xip,
        "WZ_ARRAY_FW_API_TOKEN_FILE": "/etc/warzone-sentinel/array-firewall.token",
    }
    seen = set()
    new_lines: list[str] = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            new_lines.append(line)
    for key, val in updates.items():
        if key not in seen:
            new_lines.append(f"{key}={val}")
    env.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def _fetch(path: str, timeout: float = 4.0) -> dict[str, Any]:
    url = f"{base_url().rstrip('/')}{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {"ok": True}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {"error": raw or exc.reason}
        data.setdefault("ok", False)
        data["httpStatus"] = exc.code
        return data
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "url": url}


def health() -> dict[str, Any]:
    data = _fetch("/health")
    data["sentinelUrl"] = base_url()
    data["integrated"] = bool(data.get("ok"))
    return data


def status() -> dict[str, Any]:
    data = _fetch("/v1/status")
    data["sentinelUrl"] = base_url()
    return data


def dashboard_data() -> dict[str, Any]:
    return _fetch("/v1/dashboard/data", timeout=6.0)


def summary() -> dict[str, Any]:
    """Compact view for array-firewall dashboard card."""
    h = health()
    d = dashboard_data() if h.get("ok") else {}
    session = (h.get("learning") or {}).get("active_session") or {}
    ng = h.get("network_guard") or {}
    verdict = d.get("verdict") or session.get("worst_verdict") or "—"
    phase = "—"
    phases = session.get("phases") or []
    if phases:
        phase = phases[-1].get("phase", "—")
    conns = session.get("peak_conns")
    if conns is None:
        conns = d.get("connections")
    return {
        "ok": h.get("ok", False),
        "error": h.get("error"),
        "mode": h.get("mode"),
        "polls": h.get("polls"),
        "source": h.get("source"),
        "verdict": verdict,
        "phase": phase,
        "connections": conns,
        "network_guard": {
            "mitigation": ng.get("mitigation"),
            "engage": ng.get("engage"),
            "packet_shield_active": (ng.get("packet_shield") or {}).get("active"),
        },
        "xbox_ip": xbox_ip(),
        "sentinelUrl": base_url(),
        "dashboardPath": "/v1/dashboard",
    }
