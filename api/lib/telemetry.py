"""Gateway traffic telemetry — WAN ingress/egress, queue health, per-device counters."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from . import devices, policies, qos, stability

STATE = Path("/var/lib/array-firewall/telemetry-state.json")
HISTORY = Path("/var/lib/array-firewall/telemetry-history.json")
HISTORY_MAX_SAMPLES = 120
HISTORY_BUCKETS = 24
NFT_PATH = Path("/var/lib/array-firewall/telemetry.nft")
NFT_HASH = Path("/var/lib/array-firewall/telemetry.nft.hash")
_PING_CACHE: dict[str, Any] = {"ts": 0.0, "data": {}}
_CONN_CACHE: dict[str, Any] = {"ts": 0.0, "data": {}}
_LAST_HISTORY_APPEND = 0.0
LIVE_POLL_INTERVAL_SEC = 0.5
HISTORY_LIVE_INTERVAL_SEC = 10.0
_DEVICES_META_CACHE: dict[str, Any] = {"ts": 0.0, "devices": []}


def _fmt_bps(bps: float) -> str:
    bps = max(0.0, float(bps))
    for unit, div in (("Gbps", 1e9), ("Mbps", 1e6), ("Kbps", 1e3)):
        if bps >= div:
            return f"{bps / div:.1f} {unit}"
    return f"{int(bps)} bps"


def _fmt_bytes(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def _mbit_value(rate: str) -> float:
    m = re.match(r"([\d.]+)\s*(mbit|mbps|gbit|gbps)?", str(rate or "").strip().lower())
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = m.group(2) or "mbit"
    if unit.startswith("g"):
        return val * 1000.0
    return val


def _iface_counters(ifname: str) -> dict[str, Any]:
    base = Path(f"/sys/class/net/{ifname}/statistics")
    if not base.is_dir():
        return {"ok": False, "ifname": ifname}
    out: dict[str, Any] = {"ok": True, "ifname": ifname}
    for key in (
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_errors",
        "tx_errors",
        "rx_dropped",
        "tx_dropped",
    ):
        try:
            out[key] = int((base / key).read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            out[key] = 0
    return out


def _load_state() -> dict[str, Any]:
    if not STATE.is_file():
        return {}
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, TypeError):
        return {}


def _save_state(data: dict[str, Any]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _load_history() -> dict[str, Any]:
    if not HISTORY.is_file():
        return {"samples": [], "max_samples": HISTORY_MAX_SAMPLES}
    try:
        data = json.loads(HISTORY.read_text(encoding="utf-8"))
        data.setdefault("samples", [])
        data.setdefault("max_samples", HISTORY_MAX_SAMPLES)
        return data
    except (json.JSONDecodeError, TypeError):
        return {"samples": [], "max_samples": HISTORY_MAX_SAMPLES}


def _save_history(data: dict[str, Any]) -> None:
    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    HISTORY.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def append_history(
    *,
    ingress_bps: float,
    egress_bps: float,
    latency_ms: float | None,
    devices: list[dict[str, Any]],
) -> None:
    """Ring buffer of rate samples for histograms (one entry per telemetry poll)."""
    data = _load_history()
    limit = int(data.get("max_samples") or HISTORY_MAX_SAMPLES)
    dev_map: dict[str, Any] = {}
    for dev in devices:
        ip = str(dev.get("ip") or "")
        if not ip:
            continue
        tr = dev.get("traffic") or {}
        dev_map[ip] = {
            "label": dev.get("display_name") or dev.get("label") or dev.get("hostname") or ip,
            "bps_up": float(tr.get("bps_up") or 0),
            "bps_down": float(tr.get("bps_down") or 0),
        }
    sample = {
        "ts": time.time(),
        "ingress_bps": round(float(ingress_bps), 1),
        "egress_bps": round(float(egress_bps), 1),
        "latency_ms": round(float(latency_ms), 2) if latency_ms is not None else None,
        "devices": dev_map,
    }
    samples = list(data.get("samples") or [])
    samples.append(sample)
    data["samples"] = samples[-limit:]
    data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _save_history(data)


def _histogram(values: list[float], *, buckets: int = HISTORY_BUCKETS) -> dict[str, Any]:
    vals = [max(0.0, float(v)) for v in values]
    if not vals:
        return {
            "buckets": [],
            "peak_bps": 0.0,
            "low_bps": 0.0,
            "current_bps": 0.0,
            "avg_bps": 0.0,
            "peak_human": "0 bps",
            "low_human": "0 bps",
            "current_human": "0 bps",
            "avg_human": "0 bps",
        }
    peak = max(vals)
    low = min(vals)
    current = vals[-1]
    avg = sum(vals) / len(vals)
    ceiling = max(peak, 100_000.0)
    width = ceiling / max(buckets, 1)
    counts = [0] * buckets
    for v in vals:
        idx = min(buckets - 1, int(v / width) if width else 0)
        counts[idx] += 1
    max_count = max(counts) or 1
    bucket_list = []
    for i, count in enumerate(counts):
        lo = i * width
        hi = (i + 1) * width if i < buckets - 1 else ceiling
        bucket_list.append(
            {
                "from_bps": round(lo, 1),
                "to_bps": round(hi, 1),
                "from_human": _fmt_bps(lo),
                "to_human": _fmt_bps(hi),
                "count": count,
                "pct": round((count / len(vals)) * 100, 1),
                "height_pct": round((count / max_count) * 100, 1),
            }
        )
    return {
        "buckets": bucket_list,
        "peak_bps": round(peak, 1),
        "low_bps": round(low, 1),
        "current_bps": round(current, 1),
        "avg_bps": round(avg, 1),
        "peak_human": _fmt_bps(peak),
        "low_human": _fmt_bps(low),
        "current_human": _fmt_bps(current),
        "avg_human": _fmt_bps(avg),
        "samples": len(vals),
    }


def history_report(*, device_ip: str | None = None) -> dict[str, Any]:
    data = _load_history()
    samples = list(data.get("samples") or [])
    if not samples:
        empty = _histogram([])
        return {
            "ok": True,
            "sample_count": 0,
            "window_minutes": 0,
            "ingress": empty,
            "egress": empty,
            "updated_at": data.get("updated_at"),
        }

    if device_ip:
        ingress_vals: list[float] = []
        egress_vals: list[float] = []
        for s in samples:
            dev = (s.get("devices") or {}).get(device_ip) or {}
            ingress_vals.append(float(dev.get("bps_down") or 0))
            egress_vals.append(float(dev.get("bps_up") or 0))
        label = device_ip
        for s in reversed(samples):
            dev = (s.get("devices") or {}).get(device_ip) or {}
            if dev.get("label"):
                label = str(dev["label"])
                break
        span = max(0.0, float(samples[-1].get("ts") or 0) - float(samples[0].get("ts") or 0))
        return {
            "ok": True,
            "device_ip": device_ip,
            "device_label": label,
            "sample_count": len(samples),
            "window_minutes": round(span / 60.0, 1),
            "ingress": _histogram(ingress_vals),
            "egress": _histogram(egress_vals),
            "updated_at": data.get("updated_at"),
        }

    ingress_vals = [float(s.get("ingress_bps") or 0) for s in samples]
    egress_vals = [float(s.get("egress_bps") or 0) for s in samples]
    span = max(0.0, float(samples[-1].get("ts") or 0) - float(samples[0].get("ts") or 0))
    return {
        "ok": True,
        "sample_count": len(samples),
        "window_minutes": round(span / 60.0, 1),
        "ingress": _histogram(ingress_vals),
        "egress": _histogram(egress_vals),
        "latency_ms": {
            "current": samples[-1].get("latency_ms"),
            "peak": max((s.get("latency_ms") or 0) for s in samples),
            "low": min((s.get("latency_ms") or 0) for s in samples if s.get("latency_ms") is not None) or None,
        },
        "updated_at": data.get("updated_at"),
    }


def _rate_pair(current: int, previous: int, dt: float) -> dict[str, Any]:
    delta = max(0, int(current) - int(previous))
    bps = (delta * 8) / max(dt, 0.001)
    return {"bytes_delta": delta, "bps": round(bps, 1), "human": _fmt_bps(bps)}


def _parse_htb_root_rate(dev: str) -> str | None:
    try:
        raw = subprocess.check_output(["tc", "class", "show", "dev", dev], text=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"class htb 1:1\b[^\n]* rate (\S+)", raw, re.I)
    return m.group(1) if m else None


def _leaf_qdisc_line(raw: str) -> str:
    for line in raw.splitlines():
        low = line.lower()
        if "qdisc cake" in low or "qdisc fq_codel" in low:
            return line.strip()
    return raw.split("\n")[0].strip() if raw else ""


def _parse_queue_telemetry(
    raw: str,
    *,
    dev: str,
    shaped_rate: str | None,
    prev: dict[str, Any],
    dt: float,
) -> dict[str, Any]:
    root_rate = _parse_htb_root_rate(dev)
    display_rate = shaped_rate or root_rate

    leaf_line = _leaf_qdisc_line(raw)
    leaf_kind = "htb"
    if "cake" in leaf_line.lower():
        leaf_kind = "cake"
    elif "fq_codel" in leaf_line.lower():
        leaf_kind = "fq_codel"

    def _num(pattern: str, text: str, cast=float):
        m = re.search(pattern, text, re.I)
        return cast(m.group(1)) if m else None

    dropped_total = sum(int(x) for x in re.findall(r"dropped (\d+)", raw))
    overlimits_total = sum(int(x) for x in re.findall(r"overlimits (\d+)", raw))
    requeues = sum(int(x) for x in re.findall(r"requeues (\d+)", raw))
    backlogs = [int(x) for x in re.findall(r"backlog (\d+)b", raw)]
    backlog = max(backlogs) if backlogs else 0

    prev_over = int(prev.get("overlimits") or 0)
    prev_drop = int(prev.get("dropped") or 0)
    has_queue_prev = bool(prev and "overlimits" in prev and dt > 0)
    over_delta = max(0, overlimits_total - prev_over) if has_queue_prev else None
    drop_delta = max(0, dropped_total - prev_drop) if has_queue_prev else 0
    over_per_sec = (over_delta / max(dt, 0.001)) if has_queue_prev and over_delta is not None else None

    grade = _buffer_grade_interval(
        backlog,
        over_per_sec or 0.0,
        drop_delta,
        has_prev=has_queue_prev,
    )

    return {
        "kind": leaf_kind,
        "summary": leaf_line or raw.split("\n")[0].strip(),
        "shaped_rate": display_rate,
        "root_htb_rate": root_rate,
        "bandwidth": display_rate,
        "target_ms": _num(r"target ([\d.]+)ms", leaf_line or raw),
        "interval_ms": _num(r"interval ([\d.]+)ms", leaf_line or raw),
        "limit_packets": _num(r"limit (\d+)p", leaf_line or raw, int),
        "memory_limit": _num(r"memory_limit ([\d.]+\w+)", leaf_line or raw, str),
        "dropped": dropped_total,
        "dropped_delta": drop_delta,
        "overlimits": overlimits_total,
        "overlimits_delta": over_delta,
        "overlimits_per_sec": round(over_per_sec, 1) if over_per_sec is not None else None,
        "requeues": requeues,
        "backlog_bytes": backlog,
        "healthy": grade in ("excellent", "good") and backlog == 0,
        "saturated": grade == "poor" or backlog > 65536,
        "buffer_grade": grade,
    }


def _buffer_grade_interval(
    backlog: int,
    over_per_sec: float,
    drop_delta: int,
    *,
    has_prev: bool,
) -> str:
    if not has_prev:
        return "unknown"
    if drop_delta > 10 or backlog > 262144 or over_per_sec > 800:
        return "poor"
    if drop_delta > 0 or backlog > 65536 or over_per_sec > 250:
        return "fair"
    if backlog > 16384 or over_per_sec > 80:
        return "good"
    return "excellent"


def queue_stats(*, prev: dict[str, Any] | None = None, dt: float = 0.0, live: bool = False) -> dict[str, Any]:
    cfg = qos.config()
    wan = str(cfg.get("wan_if") or "eth1")
    prev = prev or {}
    prev_queues = prev.get("queues") or {}
    out: dict[str, Any] = {"ok": True, "wan_if": wan, "queues": {}}
    for label, dev, shaped in (
        ("egress_upload", wan, str(cfg.get("wan_up") or "")),
        ("ingress_download", "ifb0", str(cfg.get("wan_down") or "")),
    ):
        try:
            raw = subprocess.check_output(["tc", "-s", "qdisc", "show", "dev", dev], text=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            out["queues"][label] = {"ok": False, "dev": dev}
            continue
        out["queues"][label] = {
            "ok": True,
            "dev": dev,
            **_parse_queue_telemetry(
                raw,
                dev=dev,
                shaped_rate=shaped or None,
                prev=prev_queues.get(label) or {},
                dt=dt,
            ),
        }
    if live:
        out["shaping"] = {}
    else:
        shaping = stability.shaping_stats()
        out["shaping"] = shaping.get("interfaces") or {}
    out["latency"] = _cached_ping()
    out["sample_interval_sec"] = round(dt, 2) if prev.get("ts") and dt else None
    return out


def _is_ipv4_lan(ip: str) -> bool:
    if not ip or ":" in ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts) and _is_lan_ip(ip)
    except ValueError:
        return False


def _device_ips() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for dev in devices.list_devices():
        ip = str(dev.get("ip") or "").strip()
        mac = str(dev.get("mac") or "").strip()
        if not ip or ip in seen or not _is_ipv4_lan(ip):
            continue
        seen.add(ip)
        rows.append({"ip": ip, "mac": mac})
    cfg = qos.config()
    xbox_ip = str(cfg.get("xbox_ip") or "")
    if xbox_ip and xbox_ip not in seen:
        rows.append({"ip": xbox_ip, "mac": str(policies.gaming().get("xbox_mac") or "")})
    return rows


def _lan_prefixes() -> tuple[str, ...]:
    cfg = qos.config()
    lan = str(cfg.get("lan_if") or "eth0")
    cidr = str(policies.network().get("lan_cidr") or policies.load().get("network", {}).get("lan_cidr") or "192.168.167.0/24")
    if cidr.startswith("192.168."):
        parts = cidr.split("/")[0].rsplit(".", 1)[0]
        return (f"{parts}.",)
    if cidr.startswith("10."):
        return ("10.",)
    return ("192.168.", "10.")


def _is_lan_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _lan_prefixes())


def _telemetry_table_present() -> bool:
    for spec in (
        ("inet", "telemetry"),
        ("netdev", "telemetry_dev"),
    ):
        family, tname = spec
        proc = subprocess.run(
            ["nft", "list", "table", family, tname],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return False
        if family == "netdev" and "lan_ingress" not in (proc.stdout or ""):
            return False
        if family == "inet" and "ifb_download" not in (proc.stdout or ""):
            return False
    return True


def _render_nft_telemetry() -> str:
    cfg = qos.config()
    lan = str(cfg.get("lan_if") or "eth0")
    wan = str(cfg.get("wan_if") or "eth1")
    counter_decls: list[str] = []
    for row in _device_ips():
        ip = row["ip"]
        safe = ip.replace(".", "_")
        counter_decls.append(f"  counter tel_{safe}_up {{}}")
        counter_decls.append(f"  counter tel_{safe}_down {{}}")
    decls = "\n".join(counter_decls) if counter_decls else "  # no devices"
    rules_lan_in = "\n".join(
        f'    ip saddr {row["ip"]} counter name tel_{row["ip"].replace(".", "_")}_up'
        for row in _device_ips()
    ) or "    # no device IPs"
    rules_fwd_down = "\n".join(
        f'    iifname "{wan}" oifname "{lan}" ip daddr {row["ip"]} counter name tel_{row["ip"].replace(".", "_")}_down'
        for row in _device_ips()
    ) or "    # no device IPs"
    rules_lan_out = "\n".join(
        f'    ip daddr {row["ip"]} counter name tel_{row["ip"].replace(".", "_")}_down'
        for row in _device_ips()
    ) or "    # no device IPs"
    rules_ifb_down = "\n".join(
        f'    iifname "ifb0" ct original ip saddr {row["ip"]} counter name tel_{row["ip"].replace(".", "_")}_down'
        for row in _device_ips()
    ) or "    # no device IPs"
    return f"""table netdev telemetry_dev {{
{decls}
  chain lan_ingress {{
    type filter hook ingress device "{lan}" priority -30; policy accept;
{rules_lan_in}
  }}
  chain lan_egress {{
    type filter hook egress device "{lan}" priority -30; policy accept;
{rules_lan_out}
  }}
}}

table inet telemetry {{
{decls}
  chain ifb_download {{
    type filter hook prerouting priority -30; policy accept;
{rules_ifb_down}
  }}
  chain wan_to_lan {{
    type filter hook forward priority filter - 30; policy accept;
{rules_fwd_down}
  }}
}}
"""


def ensure_device_counters(*, force: bool = False) -> dict[str, Any]:
    text = _render_nft_telemetry()
    digest = hashlib.sha256(text.encode()).hexdigest()[:16]
    prev = NFT_HASH.read_text(encoding="utf-8").strip() if NFT_HASH.is_file() else ""
    if digest == prev and _telemetry_table_present() and not force:
        return {"ok": True, "updated": False, "devices": len(_device_ips()), "table": "present"}
    NFT_PATH.write_text(text, encoding="utf-8")
    subprocess.run(["nft", "delete", "table", "inet", "telemetry"], capture_output=True, timeout=5)
    subprocess.run(["nft", "delete", "table", "netdev", "telemetry_dev"], capture_output=True, timeout=5)
    proc = subprocess.run(["nft", "-f", str(NFT_PATH)], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "nft failed").strip()
        return {"ok": False, "error": err, "devices": len(_device_ips())}
    NFT_HASH.write_text(digest + "\n", encoding="utf-8")
    return {"ok": True, "updated": True, "devices": len(_device_ips()), "table": "loaded"}


def _read_nft_counters() -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for table in ("netdev", "inet"):
        tname = "telemetry" if table == "inet" else "telemetry_dev"
        try:
            raw = subprocess.check_output(
                ["nft", "-j", "list", "counters", "table", table, tname],
                text=True,
                timeout=5,
            )
            data = json.loads(raw)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            continue
        for item in data.get("nftables", []):
            counter = item.get("counter")
            if not counter:
                continue
            name = str(counter.get("name") or "")
            m = re.match(r"tel_(\d+_\d+_\d+_\d+)_(up|down)", name)
            if not m:
                continue
            ip = m.group(1).replace("_", ".")
            direction = m.group(2)
            row = out.setdefault(ip, {"up_bytes": 0, "down_bytes": 0, "up_packets": 0, "down_packets": 0})
            key_b = "up_bytes" if direction == "up" else "down_bytes"
            key_p = "up_packets" if direction == "up" else "down_packets"
            row[key_b] = max(row[key_b], int(counter.get("bytes") or 0))
            row[key_p] = max(row[key_p], int(counter.get("packets") or 0))
    return out


def _cached_ping() -> dict[str, Any]:
    now = time.time()
    if now - float(_PING_CACHE.get("ts") or 0) < 12:
        cached = _PING_CACHE.get("data")
        if cached:
            return cached
    data = stability.ping_latency()
    _PING_CACHE["ts"] = now
    _PING_CACHE["data"] = data
    return data


def _qos_mode() -> str:
    mode_file = Path("/var/lib/array-firewall/qos-mode.state")
    if mode_file.is_file():
        for line in mode_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("mode="):
                return line.split("=", 1)[1].strip().split()[0]
    return "unknown"


def _conntrack_connection_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    try:
        raw = subprocess.check_output(
            ["conntrack", "-L"],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return counts
    for line in raw.splitlines():
        for m in re.finditer(r"\b(?:src|dst)=([\d.]+)", line):
            ip = m.group(1)
            if _is_lan_ip(ip):
                counts[ip] = counts.get(ip, 0) + 1
    return counts


def _conntrack_traffic() -> dict[str, dict[str, int]]:
    """Active flow byte totals keyed by LAN device IP."""
    out: dict[str, dict[str, int]] = {}
    try:
        raw = subprocess.check_output(
            ["conntrack", "-L", "-o", "extended"],
            text=True,
            timeout=12,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return out

    def _acc(ip: str, up: int, down: int) -> None:
        if not _is_lan_ip(ip):
            return
        row = out.setdefault(ip, {"up_bytes": 0, "down_bytes": 0, "up_packets": 0, "down_packets": 0})
        row["up_bytes"] += up
        row["down_bytes"] += down

    for line in raw.splitlines():
        src_m = re.search(r"\bsrc=([\d.]+)", line)
        dst_m = re.search(r"\bdst=([\d.]+)", line)
        bytes_m = re.search(r"\bbytes=(\d+)", line)
        reply_m = re.search(r"\breply_bytes=(\d+)", line)
        if not src_m or not bytes_m:
            continue
        src = src_m.group(1)
        dst = dst_m.group(1) if dst_m else ""
        orig = int(bytes_m.group(1))
        reply = int(reply_m.group(1)) if reply_m else 0
        if _is_lan_ip(src):
            _acc(src, orig, reply)
        if dst and _is_lan_ip(dst):
            _acc(dst, reply, orig)
    return out


def _device_traffic_counters() -> tuple[dict[str, dict[str, int]], str, dict[str, Any]]:
    ensure = ensure_device_counters()
    nft = _read_nft_counters() if ensure.get("ok") else {}
    nft_total = sum(v.get("up_bytes", 0) + v.get("down_bytes", 0) for v in nft.values())
    if nft_total > 0:
        return nft, "nft", ensure
    ct = _conntrack_traffic()
    if ct:
        return ct, "conntrack", ensure
    if ensure.get("ok"):
        return nft, "nft", ensure
    return {}, "none", ensure


def _conntrack_counts() -> dict[str, int]:
    return _conntrack_connection_counts()


def _cached_connection_counts() -> dict[str, int]:
    now = time.time()
    if now - float(_CONN_CACHE.get("ts") or 0) < 10:
        cached = _CONN_CACHE.get("data")
        if cached is not None:
            return cached
    data = _conntrack_connection_counts()
    _CONN_CACHE["ts"] = now
    _CONN_CACHE["data"] = data
    return data


def _device_traffic_counters_fast() -> tuple[dict[str, dict[str, int]], str, dict[str, Any]]:
    if _telemetry_table_present():
        nft = _read_nft_counters()
        return nft, "nft", {"ok": True}
    return _device_traffic_counters()


def _cached_device_list() -> list[dict[str, Any]]:
    now = time.time()
    if now - float(_DEVICES_META_CACHE.get("ts") or 0) < 5:
        return list(_DEVICES_META_CACHE.get("devices") or [])
    rows = devices.list_devices()
    _DEVICES_META_CACHE["ts"] = now
    _DEVICES_META_CACHE["devices"] = rows
    return rows


def wan_telemetry(*, live: bool = False, prev: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = qos.config()
    wan = str(cfg.get("wan_if") or "eth1")
    now = time.time()
    counters = _iface_counters(wan)
    prev = prev if prev is not None else _load_state()
    prev_ts = float(prev.get("ts") or 0)
    dt = max(now - prev_ts, 0.001) if prev_ts else 0.0

    ingress = {
        "bytes": counters.get("rx_bytes", 0),
        "packets": counters.get("rx_packets", 0),
        "errors": counters.get("rx_errors", 0),
        "drops": counters.get("rx_dropped", 0),
    }
    egress = {
        "bytes": counters.get("tx_bytes", 0),
        "packets": counters.get("tx_packets", 0),
        "errors": counters.get("tx_errors", 0),
        "drops": counters.get("tx_dropped", 0),
    }

    prev_wan = (prev.get("wan") or {}) if prev else {}
    if prev_ts and prev_wan:
        ingress.update(_rate_pair(ingress["bytes"], prev_wan.get("rx_bytes", 0), dt))
        egress.update(_rate_pair(egress["bytes"], prev_wan.get("tx_bytes", 0), dt))
    else:
        ingress.update({"bytes_delta": 0, "bps": 0.0, "human": "—"})
        egress.update({"bytes_delta": 0, "bps": 0.0, "human": "—"})

    down_mbit = _mbit_value(str(cfg.get("wan_down") or ""))
    up_mbit = _mbit_value(str(cfg.get("wan_up") or ""))
    ingress["utilization_pct"] = round((ingress.get("bps", 0) / (down_mbit * 1e6)) * 100, 1) if down_mbit else None
    egress["utilization_pct"] = round((egress.get("bps", 0) / (up_mbit * 1e6)) * 100, 1) if up_mbit else None
    ingress["bytes_human"] = _fmt_bytes(ingress["bytes"])
    egress["bytes_human"] = _fmt_bytes(egress["bytes"])

    latency = {} if live else _cached_ping()
    if live and _PING_CACHE.get("data"):
        latency = _PING_CACHE["data"]
    shaping: dict[str, Any] = {}
    if not live:
        shaping = stability.shaping_stats().get("interfaces") or {}

    return {
        "ok": counters.get("ok", False),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "wan_if": wan,
        "ingress": ingress,
        "egress": egress,
        "shaping": shaping,
        "latency": latency,
        "qos": {
            "wan_up": cfg.get("wan_up"),
            "wan_down": cfg.get("wan_down"),
            "mode": _qos_mode(),
        },
        "sample_interval_sec": round(dt, 2) if prev_ts else None,
    }


def devices_telemetry(
    *,
    counters: dict[str, dict[str, int]] | None = None,
    backend: str | None = None,
    ensure: dict[str, Any] | None = None,
    live: bool = False,
    prev: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if counters is None or backend is None or ensure is None:
        counters, backend, ensure = _device_traffic_counters_fast() if live else _device_traffic_counters()
    now = time.time()
    prev = prev if prev is not None else _load_state()
    prev_ts = float(prev.get("ts") or 0)
    dt = max(now - prev_ts, 0.001) if prev_ts else 0.0
    prev_dev = prev.get("devices") or {}

    nft = counters
    conn: dict[str, int] = {}
    if not live and backend == "nft":
        conn = _conntrack_connection_counts()
    cfg = qos.config()
    xbox_ip = str(cfg.get("xbox_ip") or "")
    rows: list[dict[str, Any]] = []
    dev_list = _cached_device_list() if live else devices.list_devices()

    for dev in dev_list:
        ip = str(dev.get("ip") or "").strip()
        mac = str(dev.get("mac") or "").strip()
        tier = qos.classify_device(dev, xbox_ip) if ip or mac else "medium"
        ctr = nft.get(ip) or {}
        up_b = int(ctr.get("up_bytes") or 0)
        down_b = int(ctr.get("down_bytes") or 0)
        prev_row = prev_dev.get(ip) or {}
        if prev_ts and ip:
            up_rate = _rate_pair(up_b, prev_row.get("up_bytes", 0), dt)
            down_rate = _rate_pair(down_b, prev_row.get("down_bytes", 0), dt)
        else:
            up_rate = {"bps": 0.0, "human": "—", "bytes_delta": 0}
            down_rate = {"bps": 0.0, "human": "—", "bytes_delta": 0}
        rows.append(
            {
                "mac": mac,
                "ip": ip or None,
                "label": dev.get("display_name") or dev.get("label") or dev.get("hostname") or mac or dev.get("ip") or "device",
                "hostname": dev.get("hostname"),
                "groups": dev.get("groups") or [],
                "qos_tier": tier,
                "internet": dev.get("internet"),
                "last_seen": dev.get("last_seen"),
                "traffic": {
                    "bytes_up": up_b,
                    "bytes_down": down_b,
                    "bytes_up_human": _fmt_bytes(up_b),
                    "bytes_down_human": _fmt_bytes(down_b),
                    "bps_up": up_rate.get("bps", 0),
                    "bps_down": down_rate.get("bps", 0),
                    "bps_up_human": up_rate.get("human", "—"),
                    "bps_down_human": down_rate.get("human", "—"),
                    "connections": conn.get(ip, 0),
                },
            }
        )

    rows.sort(key=lambda r: (r["traffic"]["bps_up"] + r["traffic"]["bps_down"]), reverse=True)

    return {
        "ok": True,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "devices": rows,
        "sample_interval_sec": round(dt, 2) if prev_ts else None,
        "counter_backend": backend,
        "counters": ensure,
    }


def record_sample(*, queues: dict[str, Any] | None = None, dev_counters: dict[str, dict[str, int]] | None = None) -> None:
    """Persist counters for next rate delta."""
    cfg = qos.config()
    wan = str(cfg.get("wan_if") or "eth1")
    counters = _iface_counters(wan)
    if dev_counters is None:
        dev_counters, _, _ = _device_traffic_counters()
    queue_state: dict[str, Any] = {}
    if queues:
        for label in ("egress_upload", "ingress_download"):
            q = (queues.get("queues") or {}).get(label) or {}
            queue_state[label] = {
                "overlimits": int(q.get("overlimits") or 0),
                "dropped": int(q.get("dropped") or 0),
                "backlog_bytes": int(q.get("backlog_bytes") or 0),
            }
    state = {
        "ts": time.time(),
        "wan": {
            "rx_bytes": counters.get("rx_bytes", 0),
            "tx_bytes": counters.get("tx_bytes", 0),
        },
        "devices": {
            ip: {"up_bytes": v.get("up_bytes", 0), "down_bytes": v.get("down_bytes", 0)}
            for ip, v in dev_counters.items()
        },
        "queues": queue_state,
    }
    _save_state(state)


def summary(*, device_ip: str | None = None) -> dict[str, Any]:
    prev = _load_state()
    now = time.time()
    prev_ts = float(prev.get("ts") or 0)
    dt = max(now - prev_ts, 0.001) if prev_ts else 0.0
    dev_counters, backend, ensure = _device_traffic_counters()
    wan = wan_telemetry(prev=prev)
    devs = devices_telemetry(counters=dev_counters, backend=backend, ensure=ensure, prev=prev)
    queues = queue_stats(prev=prev, dt=dt)
    record_sample(queues=queues, dev_counters=dev_counters)
    if prev_ts and wan.get("sample_interval_sec"):
        lat = (wan.get("latency") or {}).get("avg_ms")
        append_history(
            ingress_bps=float((wan.get("ingress") or {}).get("bps") or 0),
            egress_bps=float((wan.get("egress") or {}).get("bps") or 0),
            latency_ms=float(lat) if lat is not None else None,
            devices=list(devs.get("devices") or []),
        )
    top = devs.get("devices") or []
    hist = history_report()
    device_hist = history_report(device_ip=device_ip) if device_ip else None
    return {
        "ok": True,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "wan": wan,
        "devices": devs,
        "queues": queues,
        "history": hist,
        "device_history": device_hist,
        "top_devices": top[:5],
    }


def live(
    *,
    device_ip: str | None = None,
    include_history: bool = False,
    include_queues: bool = True,
    include_device_history: bool = True,
) -> dict[str, Any]:
    """Fast telemetry sample for dashboard streaming (~500ms cadence)."""
    global _LAST_HISTORY_APPEND
    prev = _load_state()
    now = time.time()
    prev_ts = float(prev.get("ts") or 0)
    dt = max(now - prev_ts, 0.001) if prev_ts else 0.0
    dev_counters, backend, ensure = _device_traffic_counters_fast()
    if not ensure.get("ok") and not dev_counters:
        dev_counters, backend, ensure = _device_traffic_counters()
    wan = wan_telemetry(live=True, prev=prev)
    devs = devices_telemetry(
        counters=dev_counters,
        backend=backend,
        ensure=ensure,
        live=True,
        prev=prev,
    )
    queues = queue_stats(prev=prev, dt=dt, live=True) if include_queues else {"ok": True, "queues": {}}
    record_sample(queues=queues if include_queues else None, dev_counters=dev_counters)
    if prev_ts and wan.get("sample_interval_sec") and (now - _LAST_HISTORY_APPEND) >= HISTORY_LIVE_INTERVAL_SEC:
        lat = (wan.get("latency") or {}).get("avg_ms")
        append_history(
            ingress_bps=float((wan.get("ingress") or {}).get("bps") or 0),
            egress_bps=float((wan.get("egress") or {}).get("bps") or 0),
            latency_ms=float(lat) if lat is not None else None,
            devices=list(devs.get("devices") or []),
        )
        _LAST_HISTORY_APPEND = now
    payload: dict[str, Any] = {
        "ok": True,
        "live": True,
        "stream": True,
        "poll_interval_ms": int(LIVE_POLL_INTERVAL_SEC * 1000),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sample_interval_sec": round(dt, 3) if prev_ts else None,
        "wan": wan,
        "devices": devs,
        "queues": queues,
        "top_devices": (devs.get("devices") or [])[:5],
    }
    if device_ip and include_device_history:
        payload["device_history"] = history_report(device_ip=device_ip)
    if include_history:
        payload["history"] = history_report()
    return payload
