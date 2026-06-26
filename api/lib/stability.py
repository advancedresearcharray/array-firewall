"""Internet stability: CAKE autorate, gaming policy, shaping health."""
from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import devices, groups, policies, qos

AUTORATE_STATE = Path("/var/lib/array-firewall/qos-autorate.json")
SHAPING_STATE = Path("/var/lib/array-firewall/shaping.state.json")
PING_TARGET = "1.1.1.1"
_UA = "array-firewall/1.0 (bandwidth-probe)"


def _fetch_bytes(url: str, *, timeout: float = 45.0, method: str = "GET", data: bytes | None = None) -> tuple[bytes, float]:
    headers = {"User-Agent": _UA, "Accept": "*/*"}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        blob = resp.read()
    return blob, max(time.perf_counter() - t0, 0.001)


def _perf_cfg() -> dict[str, Any]:
    return policies.load().get("perf") or {}


def _qos_cfg() -> dict[str, Any]:
    return policies.load().get("qos") or {}


def contract_rates(*, factor: float | None = None) -> dict[str, Any] | None:
    """Return shaped WAN rates from configured ISP contract (ignores speed tests)."""
    cfg = _qos_cfg()
    contract_up = cfg.get("contract_up") or cfg.get("isp_up")
    contract_down = cfg.get("contract_down") or cfg.get("isp_down")
    if not contract_up and not contract_down:
        return None
    perf = _perf_cfg()
    factor = factor if factor is not None else float(perf.get("autorate_factor") or 0.95)
    factor = max(0.5, min(factor, 1.0))
    up_mbit = parse_mbit(str(contract_up or contract_down))
    if cfg.get("sync") or cfg.get("symmetric"):
        down_mbit = up_mbit
    else:
        down_mbit = parse_mbit(str(contract_down or contract_up))
    shaped_up = up_mbit * factor
    shaped_down = down_mbit * factor
    return {
        "source": "contract",
        "sync": bool(cfg.get("sync") or cfg.get("symmetric")),
        "factor": factor,
        "contract_up": mbit_str(up_mbit),
        "contract_down": mbit_str(down_mbit),
        "wan_up": mbit_str(shaped_up),
        "wan_down": mbit_str(shaped_down),
        "upload_mbps_shaped": round(shaped_up, 2),
        "download_mbps_shaped": round(shaped_down, 2),
    }


def apply_contract_bandwidth(*, factor: float | None = None, apply_qos: bool = True) -> dict[str, Any]:
    rates = contract_rates(factor=factor)
    if not rates:
        return {"ok": False, "error": "contract_up/contract_down not configured"}
    result = apply_bandwidth(rates["wan_up"], rates["wan_down"], apply_qos=apply_qos)
    record = {**rates, "ok": True, "applied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    AUTORATE_STATE.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "measurement": record, "apply": result}


def mbit_str(mbps: float) -> str:
    mbps = max(1.0, mbps)
    if mbps >= 100:
        return f"{int(round(mbps))}mbit"
    return f"{int(round(mbps))}mbit"


def parse_mbit(val: str) -> float:
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(mbit|mbps|m)?$", str(val or "").strip().lower())
    if not m:
        return 1000.0
    return float(m.group(1))


def derive_class_rates(wan_up_mbit: float, wan_down_mbit: float) -> tuple[dict[str, dict[str, Any]], str]:
    up = max(wan_up_mbit, 5.0)
    xbox = min(up * 0.92, up)
    classes = {
        "high": {"rate": mbit_str(xbox), "ceil": mbit_str(up * 0.98), "prio": 1},
        "medium": {"rate": mbit_str(up * 0.35), "ceil": mbit_str(up * 0.88), "prio": 5},
        "low": {"rate": mbit_str(up * 0.08), "ceil": mbit_str(up * 0.22), "prio": 10},
    }
    return classes, mbit_str(xbox)


def measure_bandwidth(
    *,
    download_bytes: int = 20_000_000,
    upload_bytes: int = 5_000_000,
    timeout: float = 45.0,
) -> dict[str, Any]:
    """Measure WAN throughput via public speed endpoints."""
    result: dict[str, Any] = {"ok": False, "method": "cloudflare"}
    down_mbps = 0.0
    down_sources = [
        f"https://speed.cloudflare.com/__down?bytes={download_bytes}",
        "http://speedtest.tele2.net/10MB.zip",
        "http://proof.ovh.net/files/10Mb.dat",
    ]
    for down_url in down_sources:
        try:
            blob, elapsed = _fetch_bytes(down_url, timeout=timeout)
            down_mbps = (len(blob) * 8) / elapsed / 1_000_000
            result["download_mbps_raw"] = round(down_mbps, 2)
            result["download_bytes"] = len(blob)
            result["download_sec"] = round(elapsed, 2)
            result["download_url"] = down_url
            break
        except Exception as exc:  # noqa: BLE001
            result.setdefault("download_errors", []).append(f"{down_url}: {exc}")
    else:
        result["download_error"] = "; ".join(result.get("download_errors", []))
        return result

    upload_sources = [
        ("https://speed.cloudflare.com/__up", upload_bytes),
        ("https://httpbin.org/post", min(upload_bytes, 1_000_000)),
    ]
    for up_url, up_size in upload_sources:
        try:
            payload = b"x" * up_size
            _, elapsed = _fetch_bytes(
                up_url,
                timeout=timeout,
                method="POST",
                data=payload,
            )
            up_mbps = (len(payload) * 8) / elapsed / 1_000_000
            result["upload_mbps_raw"] = round(up_mbps, 2)
            result["upload_bytes"] = len(payload)
            result["upload_sec"] = round(elapsed, 2)
            result["upload_url"] = up_url
            break
        except Exception as exc:  # noqa: BLE001
            result.setdefault("upload_errors", []).append(f"{up_url}: {exc}")
    else:
        result["upload_mbps_raw"] = round(down_mbps * 0.12, 2)
        result["upload_estimated"] = True
        result["upload_error"] = "; ".join(result.get("upload_errors", []))

    result["ok"] = True
    result["measured_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return result


def apply_bandwidth(
    wan_up: str,
    wan_down: str,
    *,
    reshape_classes: bool = True,
    apply_qos: bool = True,
) -> dict[str, Any]:
    data = policies.load()
    q = data.setdefault("qos", {})
    q["wan_up"] = wan_up
    q["wan_down"] = wan_down
    if reshape_classes:
        classes, xbox_rate = derive_class_rates(parse_mbit(wan_up), parse_mbit(wan_down))
        q["xbox_rate"] = xbox_rate
        q["classes"] = classes
    policies.save(data)
    out: dict[str, Any] = {"ok": True, "wan_up": wan_up, "wan_down": wan_down, "qos": q}
    if apply_qos:
        out["applied"] = qos.apply()
    return out


def autorate(*, factor: float | None = None, apply_qos: bool = True) -> dict[str, Any]:
    cfg = _perf_cfg()
    factor = factor if factor is not None else float(cfg.get("autorate_factor") or 0.95)
    factor = max(0.5, min(factor, 1.0))

    contract = contract_rates(factor=factor)
    if contract:
        result = apply_bandwidth(contract["wan_up"], contract["wan_down"], apply_qos=apply_qos)
        record = {
            **contract,
            "ok": True,
            "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        AUTORATE_STATE.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return {"ok": True, "measurement": record, "apply": result, "used_contract": True}

    measured = measure_bandwidth()
    if not measured.get("ok"):
        return {"ok": False, "error": "measurement failed", "measurement": measured}

    qos_cfg = _qos_cfg()
    up = measured["upload_mbps_raw"] * factor
    down = measured["download_mbps_raw"] * factor
    if qos_cfg.get("sync") or qos_cfg.get("symmetric"):
        down = up
    wan_up = mbit_str(up)
    wan_down = mbit_str(down)

    result = apply_bandwidth(wan_up, wan_down, apply_qos=apply_qos)
    record = {
        **measured,
        "factor": factor,
        "wan_up": wan_up,
        "wan_down": wan_down,
        "upload_mbps_shaped": round(up, 2),
        "download_mbps_shaped": round(down, 2),
        "source": "measurement",
    }
    AUTORATE_STATE.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "measurement": record, "apply": result}


def last_autorate() -> dict[str, Any] | None:
    if not AUTORATE_STATE.is_file():
        return None
    try:
        return json.loads(AUTORATE_STATE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def ping_latency(host: str = PING_TARGET, count: int = 5) -> dict[str, Any]:
    try:
        out = subprocess.check_output(
            ["ping", "-c", str(count), "-W", "2", host],
            text=True,
            timeout=15,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "host": host, "error": str(exc)}
    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", out)
    loss_m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    return {
        "ok": True,
        "host": host,
        "avg_ms": float(m.group(1)) if m else None,
        "loss_pct": float(loss_m.group(1)) if loss_m else 0.0,
    }


def shaping_stats(*, record: bool = True) -> dict[str, Any]:
    cfg = qos.config()
    wan = cfg.get("wan_if", "eth1")
    stats: dict[str, Any] = {"wan_if": wan, "interfaces": {}}
    prev: dict[str, Any] = {}
    if SHAPING_STATE.is_file():
        try:
            prev = json.loads(SHAPING_STATE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            prev = {}
    prev_ts = float(prev.get("ts") or 0)
    now = time.time()
    dt = max(now - prev_ts, 0.001) if prev_ts else 0.0
    prev_if = prev.get("interfaces") or {}

    for label, dev in (("upload", wan), ("download", "ifb0")):
        try:
            raw = subprocess.check_output(["tc", "-s", "qdisc", "show", "dev", dev], text=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            stats["interfaces"][label] = {"ok": False}
            continue
        dropped = sum(int(x) for x in re.findall(r"dropped (\d+)", raw))
        overlimits = sum(int(x) for x in re.findall(r"overlimits (\d+)", raw))
        requeues = sum(int(x) for x in re.findall(r"requeues (\d+)", raw))
        backlog = re.search(r"backlog (\d+)b", raw)
        backlog_bytes = int(backlog.group(1)) if backlog else 0
        prev_row = prev_if.get(label) or {}
        prev_over = int(prev_row.get("overlimits") or 0)
        prev_drop = int(prev_row.get("dropped") or 0)
        over_delta = max(0, overlimits - prev_over) if prev_ts else 0
        drop_delta = max(0, dropped - prev_drop) if prev_ts else 0
        over_per_sec = over_delta / dt if prev_ts else 0.0
        stats["interfaces"][label] = {
            "ok": True,
            "dropped": dropped,
            "dropped_delta": drop_delta,
            "overlimits": overlimits,
            "overlimits_delta": over_delta,
            "overlimits_per_sec": round(over_per_sec, 1) if prev_ts else None,
            "requeues": requeues,
            "backlog_bytes": backlog_bytes,
            "healthy": dropped == 0 and backlog_bytes == 0,
        }

    stats["ok"] = all(v.get("ok") for v in stats["interfaces"].values())
    stats["active"] = bool(stats["ok"])
    congested = False
    for label in ("upload", "download"):
        iface = stats["interfaces"].get(label) or {}
        if not iface.get("ok"):
            continue
        if int(iface.get("backlog_bytes") or 0) > 65536:
            congested = True
        if int(iface.get("dropped_delta") or 0) > 0:
            congested = True
        ops = iface.get("overlimits_per_sec")
        if ops is not None and float(ops) > 800:
            congested = True
    stats["congested"] = congested
    stats["saturated"] = congested

    if record and stats["ok"]:
        SHAPING_STATE.write_text(
            json.dumps(
                {
                    "ts": now,
                    "interfaces": {
                        label: {
                            "overlimits": (stats["interfaces"].get(label) or {}).get("overlimits", 0),
                            "dropped": (stats["interfaces"].get(label) or {}).get("dropped", 0),
                        }
                        for label in ("upload", "download")
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return stats


def ensure_group_defaults() -> list[str]:
    """Normalize group configs for stability (infra/mesh low, gaming high)."""
    data = policies.load()
    grps = data.setdefault("device_groups", {})
    changes: list[str] = []

    templates = {
        "gaming": {
            "name": "Gaming",
            "description": "Xbox and gaming clients — highest priority",
            "config": {
                "internet": "allowed",
                "qos_profile": "high",
                "dns_filter": "off",
                "packet_shield": "normal",
                "dhcp_allocate": True,
            },
        },
        "google-mesh": {
            "name": "Google Mesh",
            "description": "Nest/Google Wifi — deprioritized bulk traffic",
            "config": {
                "internet": "allowed",
                "qos_profile": "low",
                "dns_filter": "off",
                "packet_shield": "off",
                "dhcp_allocate": False,
            },
        },
        "infrastructure": {
            "config": {"qos_profile": "low", "internet": "allowed", "packet_shield": "off"},
        },
    }
    for gid, tmpl in templates.items():
        grp = grps.setdefault(gid, {"name": gid, "members": [], "config": {}})
        for key in ("name", "description"):
            if key in tmpl and not grp.get(key):
                grp[key] = tmpl[key]
                changes.append(f"{gid}.{key}")
        cfg = grp.setdefault("config", {})
        for k, v in tmpl.get("config", {}).items():
            if cfg.get(k) != v:
                cfg[k] = v
                changes.append(f"{gid}.config.{k}")
    if changes:
        policies.save(data)
    return changes


def ensure_xbox_in_gaming_group(*, apply: bool = True) -> dict[str, Any]:
    g = policies.gaming()
    mac = (g.get("xbox_mac") or "").strip().lower()
    if not mac:
        return {"ok": False, "error": "XBOX_MAC not configured"}
    ensure_group_defaults()
    members = groups.get_group("gaming").get("members") or []
    if mac in [m.lower() for m in members]:
        return {"ok": True, "already_member": True, "mac": mac}
    result = groups.add_member("gaming", mac, apply=apply)
    return {"ok": True, "added": True, "mac": mac, "result": result}


def auto_assign_mesh_devices(*, apply: bool = True) -> dict[str, Any]:
    ensure_group_defaults()
    assigned: list[str] = []
    for dev in devices.list_devices():
        mac = dev.get("mac", "")
        if not mac or not groups.is_google_mesh(mac, dev.get("hostname", ""), dev.get("label", "")):
            continue
        if "google-mesh" in (dev.get("groups") or []):
            continue
        groups.add_member("google-mesh", mac, apply=apply)
        assigned.append(mac)
    return {"ok": True, "assigned": assigned, "count": len(assigned)}


def bootstrap_on_boot() -> dict[str, Any]:
    """Run on gateway boot: policy defaults, optional autorate, full perf stack."""
    from . import perf as perf_mod

    results: dict[str, Any] = {"ok": True, "steps": []}
    cfg = _perf_cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "skipped": True}

    for fn, name in (
        (ensure_group_defaults, "group_defaults"),
        (lambda: ensure_xbox_in_gaming_group(apply=False), "xbox_gaming_group"),
        (lambda: auto_assign_mesh_devices(apply=False), "mesh_assign"),
    ):
        try:
            results["steps"].append({name: fn()})
        except Exception as exc:  # noqa: BLE001
            results["steps"].append({name: {"ok": False, "error": str(exc)}})

    if cfg.get("autorate_on_boot"):
        try:
            results["steps"].append({"autorate": autorate(apply_qos=False)})
        except Exception as exc:  # noqa: BLE001
            results["steps"].append({"autorate": {"ok": False, "error": str(exc)}})

    try:
        results["steps"].append({"perf": perf_mod.apply_all()})
    except Exception as exc:  # noqa: BLE001
        results["steps"].append({"perf": {"ok": False, "error": str(exc)}})
        results["ok"] = False

    try:
        groups.apply_group_config("gaming")
        groups.apply_group_config("google-mesh")
        results["steps"].append({"groups_applied": True})
    except Exception as exc:  # noqa: BLE001
        results["steps"].append({"groups_applied": {"ok": False, "error": str(exc)}})

    return results


def apply_stability_stack(*, autorate_first: bool = False) -> dict[str, Any]:
    from . import perf as perf_mod

    steps: list[dict[str, Any]] = []
    if autorate_first:
        steps.append({"autorate": autorate()})
    steps.append({"group_defaults": ensure_group_defaults()})
    steps.append({"xbox": ensure_xbox_in_gaming_group()})
    steps.append({"mesh": auto_assign_mesh_devices()})
    steps.append({"perf": perf_mod.apply_all()})
    try:
        groups.apply_group_config("gaming")
        groups.apply_all_groups()
        steps.append({"groups": "applied"})
    except Exception as exc:  # noqa: BLE001
        steps.append({"groups": {"error": str(exc)}})
    return {
        "ok": True,
        "steps": steps,
        "latency": ping_latency(),
        "shaping": shaping_stats(),
        "autorate": last_autorate(),
    }


def status() -> dict[str, Any]:
    q = qos.status()
    lat = ping_latency()
    shape = shaping_stats()
    auto = last_autorate()
    cfg = _qos_cfg()
    contract = contract_rates()
    recommendations: list[str] = []
    if not contract and not auto:
        recommendations.append("Run bandwidth autorate so CAKE matches your ISP speed")
    qos_cfg = q.get("config") or {}
    shaped_up = str(qos_cfg.get("wan_up") or "")
    shaped_down = str(qos_cfg.get("wan_down") or "")
    if shape.get("congested"):
        if contract and shaped_up == str(contract.get("wan_up", "")) and shaped_down == str(
            contract.get("wan_down", "")
        ):
            recommendations.append(
                f"Queue pressure detected — shaped rates already match contract ({shaped_up}↑ / {shaped_down}↓)"
            )
        else:
            recommendations.append(
                "Queue pressure detected — run autorate or set wan_up/wan_down to ~95% of your ISP sync speed"
            )
    elif shape.get("active") and contract:
        recommendations.append(
            f"CAKE shaping active at {shaped_up}↑ / {shaped_down}↓ ({int((contract.get('factor') or 0.95) * 100)}% of 1G contract)"
        )
    if lat.get("avg_ms") and lat["avg_ms"] > 40:
        recommendations.append(f"WAN latency elevated ({lat['avg_ms']}ms) — check modem or ISP path")
    if not contract:
        up = parse_mbit(cfg.get("wan_up", "1000mbit"))
        if up >= 900 and not auto:
            recommendations.append("wan_up still near 1000mbit — set contract speeds or run autorate")

    return {
        "ok": True,
        "qos": q,
        "latency": lat,
        "shaping": shape,
        "autorate": auto,
        "contract": contract,
        "recommendations": recommendations,
    }
