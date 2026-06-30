from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from . import devices, policies

CONF = Path("/etc/array-firewall/array-firewall.conf")
APPLY_SCRIPT = Path("/opt/array-firewall/scripts/apply-qos.sh")
STATE = Path("/var/lib/array-firewall/qos.state")

PROXMOX_OUI = "bc:24:11"
PROXMOX_HOSTS = {"192.168.167.39", "192.168.167.221"}
PROXMOX_NAME_RE = re.compile(
    r"(proxmox|array-|pct|qemu|vm\d|ct\d|lxc|hypervisor|thirtynince)",
    re.I,
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ipv4(ip: str) -> bool:
    if not ip or ":" in ip:
        return False
    if not _IPV4_RE.match(ip):
        return False
    try:
        return all(0 <= int(p) <= 255 for p in ip.split("."))
    except ValueError:
        return False

# Priority order: 1 xbox → 2 wireless → 3 laptop → 4 phone → 5 other
PRIORITY_ORDER = ("xbox", "wireless", "laptop", "phone", "other")
PRIORITY_LABELS = {
    "xbox": "1 · Xbox / gaming",
    "wireless": "2 · Wireless infrastructure",
    "laptop": "3 · Laptops",
    "phone": "4 · Phones",
    "other": "5 · Everything else",
}

PHONE_OUIS = (
    "28:37:37",  # Apple
    "3c:22:fb",
    "40:d1:60",
    "48:3b:38",
    "5c:1d:d9",
    "64:b0:a6",
    "7c:01:91",
    "a4:5e:60",
    "ac:bc:32",
    "bc:92:6b",
    "d0:03:4b",
    "f0:99:bf",
    "00:1a:11",  # Google Pixel
    "94:eb:2c",
    "f4:f5:e8",
    "48:5a:b6",  # Samsung
    "50:32:37",
    "8c:f5:a3",
    "c0:bd:d1",
    "e4:12:1d",
)

WIRELESS_OUIS = (
    "18:b4:30",
    "64:16:66",
    "54:60:09",
    "f4:f5:d8",
    "94:eb:2c",
    "74:ac:b9",  # Ubiquiti
    "78:8a:20",
    "fc:ec:da",
    "b4:fb:e4",  # Eero
    "18:e8:29",
)

WIRELESS_NAME_RE = re.compile(
    r"(nest|google.?wifi|mesh|wifi.?point|eero|ubiquiti|unifi|u6-|u7-|access.?point|\bap[-\d]|router|orbi|deco|amplifi|routeros)",
    re.I,
)
LAPTOP_NAME_RE = re.compile(
    r"(laptop|macbook|thinkpad|xps|surface|precision|zenbook|vivobook|chromebook|notebook|\bpc\b)",
    re.I,
)
PHONE_NAME_RE = re.compile(
    r"(iphone|ipad|android|pixel|galaxy|phone|mobile|oneplus|samsung-sm)",
    re.I,
)
XBOX_NAME_RE = re.compile(r"(xbox|squatx|gaming)", re.I)

DEFAULT_QOS: dict[str, Any] = {
    "enabled": True,
    "profile": "throughput",
    "wan_if": "eth1",
    "lan_if": "eth0",
    "wan_up": "1000mbit",
    "wan_down": "1000mbit",
    "xbox_ip": "192.168.167.65",
    "xbox_rate": "500mbit",
    "marks": {
        "xbox": 0x10,
        "wireless": 0x14,
        "laptop": 0x20,
        "phone": 0x28,
        "other": 0x30,
        "high": 0x10,
        "medium": 0x20,
        "low": 0x30,
    },
    "classes": {
        "xbox": {"rate": "400mbit", "ceil": "931mbit", "prio": 1},
        "wireless": {"rate": "200mbit", "ceil": "836mbit", "prio": 2},
        "laptop": {"rate": "150mbit", "ceil": "700mbit", "prio": 3},
        "phone": {"rate": "100mbit", "ceil": "500mbit", "prio": 4},
        "other": {"rate": "50mbit", "ceil": "200mbit", "prio": 5},
        "high": {"rate": "400mbit", "ceil": "931mbit", "prio": 1},
        "medium": {"rate": "150mbit", "ceil": "700mbit", "prio": 3},
        "low": {"rate": "50mbit", "ceil": "200mbit", "prio": 5},
    },
}


def parse_mbit(val: str) -> float:
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(mbit|mbps|m)?$", str(val or "").strip().lower())
    if not m:
        return 1000.0
    return float(m.group(1))


def config() -> dict[str, Any]:
    data = policies.load()
    cfg = dict(DEFAULT_QOS)
    qos_pol = dict(data.get("qos") or {})
    cfg.update(qos_pol)
    marks = dict(DEFAULT_QOS["marks"])
    marks.update(qos_pol.get("marks") or {})
    cfg["marks"] = marks
    classes = dict(DEFAULT_QOS["classes"])
    for tier in PRIORITY_ORDER:
        if tier in (qos_pol.get("classes") or {}):
            classes[tier] = {**classes.get(tier, {}), **qos_pol["classes"][tier]}
    # Map legacy high/medium/low policy tiers onto xbox/laptop/other defaults.
    legacy = qos_pol.get("classes") or {}
    if legacy.get("high") and "xbox" not in (qos_pol.get("classes") or {}):
        classes["xbox"] = {**classes.get("xbox", {}), **legacy["high"]}
        classes["wireless"] = {**classes.get("wireless", {}), **legacy.get("medium", legacy["high"])}
    if legacy.get("medium"):
        classes["laptop"] = {**classes.get("laptop", {}), **legacy["medium"]}
        classes["phone"] = {**classes.get("phone", {}), **{**legacy["medium"], "rate": legacy["medium"].get("rate", "150mbit")}}
    if legacy.get("low"):
        classes["other"] = {**classes.get("other", {}), **legacy["low"]}
    if qos_pol.get("xbox_rate"):
        classes["xbox"] = {**classes.get("xbox", {}), "rate": str(qos_pol["xbox_rate"])}
    if qos_pol.get("xbox_ceil"):
        classes["xbox"] = {**classes.get("xbox", {}), "ceil": str(qos_pol["xbox_ceil"])}
    # Avoid HTB rate<ceil throttling on the gaming tier during multi-flow speed tests.
    xbox_ceil = str(classes.get("xbox", {}).get("ceil") or "")
    xbox_rate = str(classes.get("xbox", {}).get("rate") or "")
    if xbox_ceil and (not xbox_rate or parse_mbit(xbox_rate) < parse_mbit(xbox_ceil) * 0.95):
        classes["xbox"] = {**classes.get("xbox", {}), "rate": xbox_ceil}
    cfg["classes"] = classes
    g = policies.gaming()
    if g.get("xbox_ip"):
        cfg["xbox_ip"] = g["xbox_ip"]
    net = policies.network()
    if net.get("wan_if"):
        cfg["wan_if"] = net["wan_if"]
    if net.get("lan_if"):
        cfg["lan_if"] = net["lan_if"]
    if policies.role() == "xbox_router":
        # Default sidecar: direct WAN (Firewalla parity). Set qos.profile=gaming for HTB/CAKE + boosts.
        if not qos_pol.get("profile"):
            cfg["profile"] = "throughput"
    return cfg


def is_proxmox_host(mac: str, ip: str = "", hostname: str = "", label: str = "") -> bool:
    mac = mac.lower()
    text = f"{hostname} {label}".lower()
    if mac.startswith(PROXMOX_OUI):
        return True
    if ip in PROXMOX_HOSTS:
        return True
    return bool(PROXMOX_NAME_RE.search(text))


def is_wireless_infra(mac: str, hostname: str = "", label: str = "", groups: list[str] | None = None) -> bool:
    mac = mac.lower()
    text = f"{hostname} {label}"
    grp = groups or []
    if "wireless" in grp or "google-mesh" in grp or "wireless-infra" in grp:
        return True
    if any(mac.startswith(o) for o in WIRELESS_OUIS):
        return True
    return bool(WIRELESS_NAME_RE.search(text))


def is_phone(mac: str, hostname: str = "", label: str = "", groups: list[str] | None = None) -> bool:
    mac = mac.lower()
    text = f"{hostname} {label}"
    grp = groups or []
    if "phones" in grp or "mobile" in grp:
        return True
    if any(mac.startswith(o) for o in PHONE_OUIS):
        return True
    return bool(PHONE_NAME_RE.search(text))


def is_laptop(mac: str, hostname: str = "", label: str = "", groups: list[str] | None = None) -> bool:
    from . import devices as devmod

    text = f"{hostname} {label}"
    grp = groups or []
    admin = devmod.admin_mac()
    if admin and mac.lower() == admin.lower():
        return True
    if "laptops" in grp:
        return True
    return bool(LAPTOP_NAME_RE.search(text))


def is_xbox(dev: dict[str, Any], xbox_ip: str) -> bool:
    ip = str(dev.get("ip") or "")
    mac = str(dev.get("mac") or "")
    groups = dev.get("groups") or []
    policy = dev.get("policy") or {}
    text = f"{dev.get('hostname', '')} {dev.get('label', '')}"
    if ip == xbox_ip or mac.lower() == str(policies.gaming().get("xbox_mac", "")).lower():
        return True
    if policy.get("qos_profile") in ("gaming", "high") and "gaming" in groups:
        return True
    if "gaming" in groups:
        return True
    if policy.get("qos_profile") in ("gaming", "high") and XBOX_NAME_RE.search(text):
        return True
    return bool(XBOX_NAME_RE.search(text) and policy.get("qos_profile") in ("gaming", "high", "balanced"))


def classify_device(dev: dict[str, Any], xbox_ip: str) -> str:
    """Return traffic priority tier: xbox | wireless | laptop | phone | other."""
    ip = str(dev.get("ip") or "")
    mac = str(dev.get("mac") or "")
    groups = dev.get("groups") or []
    policy = dev.get("policy") or {}
    hostname = str(dev.get("hostname") or "")
    label = str(dev.get("label") or "")

    explicit = policy.get("priority_tier") or policy.get("traffic_priority")
    if explicit in PRIORITY_ORDER:
        return str(explicit)

    if is_xbox(dev, xbox_ip):
        return "xbox"
    if is_wireless_infra(mac, hostname, label, groups):
        return "wireless"
    if is_laptop(mac, hostname, label, groups):
        return "laptop"
    if is_phone(mac, hostname, label, groups):
        return "phone"
    if policy.get("qos_profile") == "low" or "infrastructure" in groups:
        return "other"
    if is_proxmox_host(mac, ip, hostname, label):
        return "other"
    return "other" if policy.get("qos_profile") == "low" else "phone" if policy.get("qos_profile") == "balanced" else "other"


def _legacy_tier(priority: str) -> str:
    if priority == "xbox":
        return "high"
    if priority == "wireless":
        return "high"
    if priority == "laptop":
        return "medium"
    if priority == "phone":
        return "medium"
    return "low"


def classification_map() -> dict[str, list[dict[str, str]]]:
    cfg = config()
    xbox_ip = cfg["xbox_ip"]
    buckets: dict[str, list[dict[str, str]]] = {t: [] for t in PRIORITY_ORDER}
    for dev in devices.list_devices():
        tier = classify_device(dev, xbox_ip)
        buckets[tier].append(
            {
                "mac": dev.get("mac", ""),
                "ip": dev.get("ip", ""),
                "label": dev.get("label") or dev.get("hostname") or dev.get("mac", ""),
                "priority": tier,
                "priority_label": PRIORITY_LABELS.get(tier, tier),
                "legacy_tier": _legacy_tier(tier),
            }
        )
    return buckets


def priority_summary() -> dict[str, Any]:
    buckets = classification_map()
    cfg = config()
    return {
        "order": list(PRIORITY_ORDER),
        "labels": PRIORITY_LABELS,
        "counts": {k: len(v) for k, v in buckets.items()},
        "devices": buckets,
        "marks": {k: hex(cfg["marks"].get(k, 0)) for k in PRIORITY_ORDER if k in cfg["marks"]},
        "ai_managed": True,
    }


def render_nft_mangle() -> str:
    cfg = config()
    if not cfg.get("enabled", True):
        return ""
    marks = cfg["marks"]
    xbox_ip = cfg["xbox_ip"]
    lan_if = cfg["lan_if"]
    wan_if = cfg["wan_if"]
    buckets = classification_map()

    def ips_for(*tiers: str) -> set[str]:
        out: set[str] = set()
        for t in tiers:
            for d in buckets.get(t, []):
                ip = d.get("ip")
                if ip and _is_ipv4(str(ip)):
                    out.add(str(ip))
        return out

    xbox_ips = ips_for("xbox")
    if xbox_ip and _is_ipv4(str(xbox_ip)):
        xbox_ips.add(str(xbox_ip))
    wireless_ips = ips_for("wireless")
    laptop_ips = ips_for("laptop")
    phone_ips = ips_for("phone")
    other_ips = ips_for("other")
    if _is_ipv4("192.168.167.39"):
        other_ips.add("192.168.167.39")

    def mark_rules(ips: set[str], mark_key: str) -> str:
        mk = marks.get(mark_key, marks.get("other", 0x30))
        lines = []
        for ip in sorted(ips):
            if not ip:
                continue
            lines.append(f'    ip saddr {ip} meta mark set {mk} ct mark set {mk}')
        return "\n".join(lines)

    preroute_high: list[str] = []
    for ip in sorted(xbox_ips | wireless_ips):
        for mk in (marks.get("xbox", 0x10), marks.get("wireless", 0x14)):
            pass
        preroute_high.append(
            f'    iifname "{wan_if}" ct original ip saddr {ip} meta mark set {marks["xbox"] if ip in xbox_ips else marks["wireless"]} ct mark set {marks["xbox"] if ip in xbox_ips else marks["wireless"]}'
        )
        preroute_high.append(
            f'    iifname "ifb0" ct original ip saddr {ip} meta mark set {marks["xbox"] if ip in xbox_ips else marks["wireless"]} ct mark set {marks["xbox"] if ip in xbox_ips else marks["wireless"]}'
        )
    preroute_high_rules = "\n".join(preroute_high)

    forward_rules: list[str] = []
    tier_ips = [
        (xbox_ips, marks.get("xbox", 0x10)),
        (wireless_ips, marks.get("wireless", 0x14)),
        (laptop_ips, marks.get("laptop", 0x20)),
        (phone_ips, marks.get("phone", 0x28)),
        (other_ips, marks.get("other", 0x30)),
    ]
    for ips, mk in tier_ips:
        for ip in sorted(ips):
            forward_rules.append(
                f'    iifname "{lan_if}" oifname "{wan_if}" ip saddr {ip} meta mark set {mk} ct mark set {mk}'
            )
            forward_rules.append(
                f'    iifname "{wan_if}" oifname "{lan_if}" ip daddr {ip} meta mark set {mk} ct mark set {mk}'
            )

    return f"""table inet qos {{
  chain prerouting {{
    type filter hook prerouting priority mangle; policy accept;
    iifname "{wan_if}" ct mark {marks.get("xbox", 0x10)} meta mark set ct mark
    iifname "{wan_if}" ct mark {marks.get("wireless", 0x14)} meta mark set ct mark
    iifname "{wan_if}" ct mark {marks.get("other", 0x30)} meta mark set ct mark
    iifname "ifb0" ct mark {marks.get("xbox", 0x10)} meta mark set ct mark
    iifname "ifb0" ct mark {marks.get("wireless", 0x14)} meta mark set ct mark
    iifname "ifb0" ct mark {marks.get("other", 0x30)} meta mark set ct mark
{preroute_high_rules}
  }}
  chain forward {{
    type filter hook forward priority mangle; policy accept;
    iifname "{lan_if}" oifname "{wan_if}" meta mark set {marks.get("phone", 0x28)}
    iifname "{wan_if}" oifname "{lan_if}" meta mark set {marks.get("phone", 0x28)}
    iifname "{lan_if}" oifname "{wan_if}" ether saddr {PROXMOX_OUI}:00:00:00/24 meta mark set {marks.get("other", 0x30)} ct mark set {marks.get("other", 0x30)}
{mark_rules(laptop_ips, "laptop")}
{mark_rules(phone_ips, "phone")}
{mark_rules(other_ips, "other")}
{chr(10).join(forward_rules)}
  }}
}}
"""


def apply() -> dict[str, Any]:
    cfg = config()
    if not cfg.get("enabled", True):
        subprocess.run(["/opt/array-firewall/scripts/apply-qos.sh", "clear"], check=False, timeout=30)
        return {"ok": True, "enabled": False}

    profile = str(cfg.get("profile") or "throughput").lower()
    throughput = profile in ("throughput", "direct", "firewalla", "off", "passthrough")

    if throughput:
        subprocess.run(["nft", "delete", "table", "inet", "qos"], capture_output=True, timeout=5)
        proc = subprocess.run(
            [str(APPLY_SCRIPT), "throughput"],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "WAN_IF": str(cfg["wan_if"])},
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "apply-qos throughput failed")
        STATE.write_text(
            json.dumps({"ok": True, "profile": "throughput", "config": cfg}, indent=2) + "\n",
            encoding="utf-8",
        )
        return status()

    mangle = render_nft_mangle()
    mangle_path = Path("/var/lib/array-firewall/qos-mangle.nft")
    mangle_path.write_text(mangle, encoding="utf-8")
    subprocess.run(["nft", "delete", "table", "inet", "qos"], capture_output=True, timeout=5)
    subprocess.run(["nft", "-f", str(mangle_path)], check=True, timeout=15)

    buckets = classification_map()
    marks = cfg["marks"]
    xbox_ips = sorted({d["ip"] for d in buckets["xbox"] if d.get("ip") and _is_ipv4(d["ip"])} | ({str(cfg["xbox_ip"])} if _is_ipv4(str(cfg["xbox_ip"])) else set()))
    wireless_ips = sorted({d["ip"] for d in buckets["wireless"] if d.get("ip") and _is_ipv4(d["ip"])})
    laptop_ips = sorted({d["ip"] for d in buckets["laptop"] if d.get("ip") and _is_ipv4(d["ip"])})
    phone_ips = sorted({d["ip"] for d in buckets["phone"] if d.get("ip") and _is_ipv4(d["ip"])})

    if not APPLY_SCRIPT.is_file():
        raise FileNotFoundError(str(APPLY_SCRIPT))

    classes = cfg["classes"]
    proc = subprocess.run(
        [str(APPLY_SCRIPT), "apply"],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **os.environ,
            "WAN_IF": str(cfg["wan_if"]),
            "WAN_UP": str(cfg["wan_up"]),
            "WAN_DOWN": str(cfg["wan_down"]),
            "XBOX_IP": str(cfg["xbox_ip"]),
            "HIGH_IPS": ",".join(xbox_ips),
            "WIRELESS_IPS": ",".join(wireless_ips),
            "LAPTOP_IPS": ",".join(laptop_ips),
            "PHONE_IPS": ",".join(phone_ips),
            "XBOX_RATE": str(classes["xbox"]["rate"]),
            "WIRELESS_RATE": str(classes["wireless"]["rate"]),
            "LAPTOP_RATE": str(classes["laptop"]["rate"]),
            "PHONE_RATE": str(classes["phone"]["rate"]),
            "OTHER_RATE": str(classes["other"]["rate"]),
            "XBOX_CEIL": str(classes["xbox"]["ceil"]),
            "WIRELESS_CEIL": str(classes["wireless"]["ceil"]),
            "LAPTOP_CEIL": str(classes["laptop"]["ceil"]),
            "PHONE_CEIL": str(classes["phone"]["ceil"]),
            "OTHER_CEIL": str(classes["other"]["ceil"]),
            "MARK_XBOX": hex(marks["xbox"]),
            "MARK_WIRELESS": hex(marks["wireless"]),
            "MARK_LAPTOP": hex(marks["laptop"]),
            "MARK_PHONE": hex(marks["phone"]),
            "MARK_OTHER": hex(marks["other"]),
            "MARK_HIGH": hex(marks.get("xbox", 0x10)),
            "MARK_MEDIUM": hex(marks.get("laptop", 0x20)),
            "MARK_LOW": hex(marks.get("other", 0x30)),
            "QOS_MODE": str(cfg.get("mode") or "auto"),
        },
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "apply-qos failed")

    try:
        from . import telemetry

        telemetry.ensure_device_counters(force=True)
    except ImportError:
        pass

    STATE.write_text(
        json.dumps({"ok": True, "classification": buckets, "priority": priority_summary(), "config": cfg}, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        from . import nat as nat_mod

        nat_mod.ensure_wan_nat()
    except Exception:
        pass
    return status()


def status() -> dict[str, Any]:
    cfg = config()
    buckets = classification_map()
    tc_up = _tc_summary(cfg["wan_if"])
    tc_down = _tc_summary("ifb0")
    mode = "unknown"
    mode_file = Path("/var/lib/array-firewall/qos-mode.state")
    if mode_file.is_file():
        for line in mode_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("mode="):
                mode = line.split("=", 1)[1].strip().split()[0]
    legacy = {"high": len(buckets["xbox"]) + len(buckets["wireless"]), "medium": len(buckets["laptop"]) + len(buckets["phone"]), "low": len(buckets["other"])}
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "profile": str(cfg.get("profile") or "throughput"),
        "mode": mode,
        "config": cfg,
        "priority_order": list(PRIORITY_ORDER),
        "priority_labels": PRIORITY_LABELS,
        "classification": {k: len(v) for k, v in buckets.items()},
        "legacy_classification": legacy,
        "devices": buckets,
        "priority": priority_summary(),
        "tc": {"upload": tc_up, "download": tc_down},
    }


def update_bandwidth(wan_up: str, wan_down: str, *, apply_now: bool = True) -> dict[str, Any]:
    from . import stability

    return stability.apply_bandwidth(wan_up, wan_down, apply_qos=apply_now)


def autorate_bandwidth(**kwargs: Any) -> dict[str, Any]:
    from . import stability

    return stability.autorate(**kwargs)


UPLOAD_BOOST_STATE = Path("/var/lib/array-firewall/upload-boost.state")
UPLOAD_BOOST_BASELINE = Path("/var/lib/array-firewall/upload-boost.baseline.json")
DOWNLOAD_BOOST_STATE = Path("/var/lib/array-firewall/download-boost.state")
DOWNLOAD_BOOST_BASELINE = Path("/var/lib/array-firewall/download-boost.baseline.json")
BUFFER_TUNE_STATE = Path("/var/lib/array-firewall/buffer-tune.state")

VALID_BUFFER_PROFILES = frozenset({"gaming", "normal", "light", "desync", "kick"})


def upload_boost_config() -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "enabled": True,
        "ceil_factor": 0.98,
        "other_ceil_factor": 0.55,
        "xbox_rate_factor": 0.85,
        "pressure_warn_pct": 80,
    }
    ua = dict(policies.gaming().get("upload_assist") or {})
    defaults.update(ua)
    return defaults


def _parse_kv_state(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def upload_boost_status() -> dict[str, Any]:
    from . import gaming as gaming_mod

    cfg = upload_boost_config()
    state = _parse_kv_state(UPLOAD_BOOST_STATE)
    baseline = None
    if UPLOAD_BOOST_BASELINE.is_file():
        try:
            baseline = json.loads(UPLOAD_BOOST_BASELINE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            baseline = None
    tc_xbox = ""
    try:
        wan = str(config().get("wan_if") or "eth1")
        raw = subprocess.check_output(["tc", "class", "show", "dev", wan], text=True, timeout=5)
        for line in raw.splitlines():
            if "class htb 1:10" in line:
                tc_xbox = line.strip()
                break
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        tc_xbox = "unavailable"
    active = state.get("active") == "1"
    return {
        "ok": True,
        "active": active,
        "config": cfg,
        "state": state,
        "baseline": baseline,
        "tc_xbox_class": tc_xbox,
        "script": gaming_mod.run_script_api("gaming-upload-boost.sh", ["status"]),
    }


def upload_boost_apply(*, session_hex: str | None = None, phase: str | None = None) -> dict[str, Any]:
    from . import gaming as gaming_mod, session_events

    if not upload_boost_config().get("enabled", True):
        return {"ok": False, "error": "upload_assist disabled in policy"}
    result = gaming_mod.run_script_api("gaming-upload-boost.sh", ["apply"])
    result["status"] = upload_boost_status()
    if result.get("ok"):
        session_events.append(
            "upload.boost",
            session_hex=session_hex,
            phase=phase,
            detail="upload assist applied",
        )
    return result


def upload_boost_relax(*, session_hex: str | None = None, phase: str | None = None) -> dict[str, Any]:
    from . import gaming as gaming_mod, session_events

    result = gaming_mod.run_script_api("gaming-upload-boost.sh", ["relax"])
    result["status"] = upload_boost_status()
    if result.get("ok"):
        session_events.append(
            "upload.relax",
            session_hex=session_hex,
            phase=phase,
            detail="upload assist relaxed",
        )
    return result


def download_boost_config() -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "enabled": True,
        "ceil_factor": 0.98,
        "ifb_rtt": "3ms",
        "ifb_memlimit": "32mb",
    }
    da = dict(policies.gaming().get("download_assist") or {})
    defaults.update(da)
    return defaults


def download_boost_status() -> dict[str, Any]:
    from . import gaming as gaming_mod

    cfg = download_boost_config()
    state = _parse_kv_state(DOWNLOAD_BOOST_STATE)
    baseline = None
    if DOWNLOAD_BOOST_BASELINE.is_file():
        try:
            baseline = json.loads(DOWNLOAD_BOOST_BASELINE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            baseline = None
    tc_ifb = ""
    try:
        raw = subprocess.check_output(["tc", "qdisc", "show", "dev", "ifb0"], text=True, timeout=5)
        for line in raw.splitlines():
            if "qdisc cake" in line and "root" in line:
                tc_ifb = line.strip()
                break
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        tc_ifb = "unavailable"
    return {
        "ok": True,
        "active": state.get("active") == "1",
        "config": cfg,
        "state": state,
        "baseline": baseline,
        "tc_ifb_cake": tc_ifb,
        "script": gaming_mod.run_script_api("gaming-download-boost.sh", ["status"]),
    }


def download_boost_apply(*, session_hex: str | None = None, phase: str | None = None) -> dict[str, Any]:
    from . import gaming as gaming_mod, session_events

    if not download_boost_config().get("enabled", True):
        return {"ok": False, "error": "download_assist disabled in policy"}
    result = gaming_mod.run_script_api("gaming-download-boost.sh", ["apply"])
    result["status"] = download_boost_status()
    if result.get("ok"):
        session_events.append(
            "download.boost",
            session_hex=session_hex,
            phase=phase,
            detail="download assist applied",
        )
    return result


def download_boost_relax(*, session_hex: str | None = None, phase: str | None = None) -> dict[str, Any]:
    from . import gaming as gaming_mod, session_events

    result = gaming_mod.run_script_api("gaming-download-boost.sh", ["relax"])
    result["status"] = download_boost_status()
    if result.get("ok"):
        session_events.append(
            "download.relax",
            session_hex=session_hex,
            phase=phase,
            detail="download assist relaxed",
        )
    return result


def buffer_tune_status() -> dict[str, Any]:
    from . import gaming as gaming_mod

    state = _parse_kv_state(BUFFER_TUNE_STATE)
    result = gaming_mod.run_script_api("gaming-buffer-tune.sh", ["status"])
    profile = "gaming"
    if BUFFER_TUNE_STATE.is_file():
        first = BUFFER_TUNE_STATE.read_text(encoding="utf-8").splitlines()[0].strip()
        if first.startswith("profile="):
            profile = first.split()[0].split("=", 1)[1].strip()
        elif first.startswith("mode="):
            profile = first.split("=", 1)[1].strip()
        elif state.get("profile"):
            profile = str(state["profile"]).split()[0]
    active = profile not in ("", "gaming", "normal", "off")
    return {
        "ok": True,
        "active": active,
        "profile": profile,
        "state": state,
        "script": result,
    }


def buffer_tune_apply(
    profile: str = "gaming",
    *,
    session_hex: str | None = None,
    phase: str | None = None,
    sample: dict[str, float] | None = None,
    auto_rqd: bool = False,
) -> dict[str, Any]:
    from . import gaming as gaming_mod, session_events

    if auto_rqd and profile in ("auto", "rqd"):
        from . import rqd

        rqd_pick = rqd.select_buffer_profile(sample or {})
        profile = str(rqd_pick.get("profile") or "gaming")
    profile = (profile or "gaming").lower()
    if profile in ("off", "relax", "idle"):
        result = gaming_mod.run_script_api("gaming-buffer-tune.sh", ["off"])
        event_kind = "buffer.off"
    elif profile not in VALID_BUFFER_PROFILES:
        return {"ok": False, "error": f"profile must be one of: {sorted(VALID_BUFFER_PROFILES)}"}
    else:
        result = gaming_mod.run_script_api("gaming-buffer-tune.sh", ["apply", profile])
        event_kind = f"buffer.{profile}"
    result["status"] = buffer_tune_status()
    if result.get("ok"):
        session_events.append(
            event_kind,
            session_hex=session_hex,
            phase=phase,
            detail=f"buffer profile {profile}",
            meta={"profile": profile, "auto_rqd": auto_rqd},
        )
    return result


def rqd_buffer_recommendation(sample: dict[str, float] | None = None) -> dict[str, Any]:
    """RQD buffer profile pick from live telemetry (Zenodo 20942201)."""
    from . import folding, rqd

    if sample is None:
        sample = {}
        try:
            from . import stability

            shaping = stability.shaping_stats()
            q_up = (shaping.get("queues") or shaping.get("interfaces") or {}).get("egress_upload") or {}
            sample["upload_util_pct"] = float(q_up.get("utilization_pct") or 0)
            sample["queue_pressure"] = float(q_up.get("backlog_bytes") or 0)
        except Exception:
            pass
        sample.update(folding.system_sample())
    return rqd.select_buffer_profile(sample)


def _tc_summary(dev: str) -> str:
    try:
        out = subprocess.check_output(["tc", "-s", "qdisc", "show", "dev", dev], text=True, timeout=5)
        return out.strip().split("\n")[0] if out.strip() else "none"
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return "unavailable"
