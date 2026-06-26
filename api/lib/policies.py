from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

POLICIES_PATH = Path(os.environ.get("ARRAY_FW_POLICIES", "/var/lib/array-firewall/policies.json"))


def load() -> dict[str, Any]:
    if POLICIES_PATH.is_file():
        return json.loads(POLICIES_PATH.read_text(encoding="utf-8"))
    return {}


def save(data: dict[str, Any]) -> None:
    POLICIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = POLICIES_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(POLICIES_PATH)


def network() -> dict[str, Any]:
    return load().get("network", {})


def role() -> str:
    n = network()
    if n.get("role"):
        return str(n["role"])
    return os.environ.get("ARRAY_FW_ROLE", "lab")


def cutover_enabled() -> bool:
    n = network()
    if "cutover" in n:
        return bool(n.get("cutover"))
    conf = Path("/etc/array-firewall/array-firewall.conf")
    if conf.is_file():
        for line in conf.read_text(encoding="utf-8").splitlines():
            if line.startswith("CUTOVER="):
                return line.split("=", 1)[1].strip() in {"1", "true", "yes"}
    return False


def gaming() -> dict[str, Any]:
    return load().get("gaming", {})


def nat_config() -> dict[str, Any]:
    data = load()
    return {
        "port_forwards": data.get("port_forwards") or [],
        "dmz": data.get("dmz") or {},
        "upnp": data.get("upnp") or {},
    }
