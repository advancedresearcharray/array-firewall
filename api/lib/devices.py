from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

STORE = Path(os.environ.get("ARRAY_FW_DEVICES_FILE", "/var/lib/array-firewall/devices.json"))
CONF = Path("/etc/array-firewall/array-firewall.conf")
LEASES = Path("/var/lib/misc/dnsmasq.leases")
CLIENT_IF = os.environ.get("ARRAY_FW_CLIENT_IF", "eth1")
LAB_CIDR = os.environ.get("ARRAY_FW_LAB_CIDR", "10.99.0.0/24")

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_AUTO_LABELS = frozenset({"", "unknown", "unknown device", "device", "unnamed device"})
_NEIGH_RANK = {"REACHABLE": 0, "STALE": 1, "DELAY": 2, "PROBE": 3}


def norm_mac(mac: str) -> str:
    parts = mac.lower().replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid mac: {mac}")
    return ":".join(f"{int(p, 16):02x}" for p in parts)


def _is_ipv4(ip: str) -> bool:
    ip = str(ip or "").strip()
    if not IPV4_RE.match(ip):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in ip.split("."))
    except ValueError:
        return False


def _is_mac_like(value: str | None) -> bool:
    return bool(MAC_RE.match(str(value or "").strip()))


def _clean_hostname(name: str | None) -> str:
    host = str(name or "").strip().rstrip(".")
    if not host or host == "*" or _is_mac_like(host):
        return ""
    return host.split(".")[0]


def _forward_confirms(ip: str, hostname: str) -> bool:
    if not _is_ipv4(ip) or not hostname:
        return False
    try:
        socket.setdefaulttimeout(1.0)
        for info in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
            if info[4][0] == ip:
                return True
    except OSError:
        return False
    return False


def _resolve_ptr(ip: str) -> str:
    if not _is_ipv4(ip):
        return ""
    try:
        socket.setdefaulttimeout(1.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return _clean_hostname(host)
    except OSError:
        return ""


def _load_reservations_by_mac() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    try:
        from . import dhcp as dhcp_mod

        for res in dhcp_mod.config().get("reservations") or []:
            mac = norm_mac(str(res.get("mac") or ""))
            out[mac] = {
                "ip": str(res.get("ip") or "").strip(),
                "hostname": _clean_hostname(res.get("hostname")),
                "source": "reservation",
            }
    except Exception:
        pass
    return out


def _build_identity_maps() -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    leases_by_mac: dict[str, dict[str, str]] = {}
    for row in _parse_leases():
        mac = row["mac"]
        leases_by_mac[mac] = {
            "ip": row["ip"] if _is_ipv4(row["ip"]) else "",
            "hostname": _clean_hostname(row.get("hostname")),
            "source": "lease",
        }

    reservations_by_mac = _load_reservations_by_mac()
    probed_by_mac = _load_probed_by_mac()

    arp_by_mac: dict[str, dict[str, str | int]] = {}
    for row in _parse_neigh():
        ip = str(row.get("ip") or "").strip()
        if not _is_ipv4(ip):
            continue
        mac = row["mac"]
        rank = _NEIGH_RANK.get(str(row.get("state") or ""), 9)
        prev = arp_by_mac.get(mac)
        if prev is None or rank < int(prev["rank"]):
            arp_by_mac[mac] = {"ip": ip, "rank": rank, "source": "arp"}

    return leases_by_mac, reservations_by_mac, probed_by_mac, arp_by_mac


def _load_probed_by_mac() -> dict[str, dict[str, str]]:
    try:
        from . import hostname_probe

        return hostname_probe.load_probed_by_mac()
    except Exception:
        return {}


def _resolve_identity(
    mac: str,
    entry: dict[str, Any],
    leases_by_mac: dict[str, dict[str, str]],
    reservations_by_mac: dict[str, dict[str, str]],
    probed_by_mac: dict[str, dict[str, str]],
    arp_by_mac: dict[str, dict[str, str | int]],
) -> dict[str, str]:
    lease = leases_by_mac.get(mac, {})
    reservation = reservations_by_mac.get(mac, {})
    probed = probed_by_mac.get(mac, {})
    arp = arp_by_mac.get(mac, {})

    ip = ""
    ip_source = ""
    if reservation.get("ip"):
        ip, ip_source = str(reservation["ip"]), "reservation"
    elif lease.get("ip"):
        ip, ip_source = str(lease["ip"]), "lease"
    elif probed.get("ip") and _is_ipv4(str(probed.get("ip"))):
        ip, ip_source = str(probed["ip"]), "probe"
    elif arp.get("ip"):
        ip, ip_source = str(arp["ip"]), "arp"
    elif _is_ipv4(str(entry.get("ip") or "")):
        ip, ip_source = str(entry["ip"]), "stored"

    hostname = ""
    hostname_source = ""
    if reservation.get("hostname"):
        hostname, hostname_source = str(reservation["hostname"]), "reservation"
    elif lease.get("hostname"):
        hostname, hostname_source = str(lease["hostname"]), "lease"
    elif probed.get("hostname") and (not probed.get("ip") or not ip or str(probed.get("ip")) == ip):
        hostname, hostname_source = str(probed["hostname"]), "probe"
    elif ip:
        ptr = _resolve_ptr(ip)
        if ptr and (_forward_confirms(ip, ptr) or (not lease.get("hostname") and not reservation.get("hostname"))):
            hostname, hostname_source = ptr, "ptr"

    old_ip = str(entry.get("ip") or "").strip()
    old_host = _clean_hostname(entry.get("hostname"))
    if ip and old_ip and ip != old_ip and not entry.get("label_manual"):
        old_host = ""

    if not hostname and old_host and old_ip == ip:
        if hostname_source in {"lease", "reservation", "probe"} or _forward_confirms(ip, old_host):
            hostname, hostname_source = old_host, str(entry.get("hostname_source") or "stored")

    if hostname and ip and hostname_source == "ptr" and not _forward_confirms(ip, hostname):
        hostname, hostname_source = "", ""

    return {
        "ip": ip,
        "ip_source": ip_source,
        "hostname": hostname,
        "hostname_source": hostname_source,
    }


def _is_auto_label(label: str | None) -> bool:
    text = str(label or "").strip().lower()
    if text in _AUTO_LABELS:
        return True
    return _is_ipv4(text)


def display_name(entry: dict[str, Any]) -> str:
    """Preferred UI label: validated hostname, manual label, then IPv4 — never MAC."""
    host = _clean_hostname(entry.get("hostname"))
    if host:
        return host
    label = str(entry.get("label") or "").strip()
    if label and not _is_auto_label(label) and not _is_mac_like(label):
        return label
    ip = str(entry.get("ip") or "").strip()
    if _is_ipv4(ip):
        return f"device-{ip.split('.')[-1]}"
    return "Unnamed device"


def _sync_auto_label(entry: dict[str, Any]) -> None:
    if entry.get("label_manual"):
        return
    label = display_name(entry)
    entry["label"] = label
    if _is_mac_like(entry.get("hostname")):
        entry["hostname"] = ""


def _set_posture(entry: dict[str, Any]) -> None:
    if entry.get("allowed"):
        entry["posture"] = "approved"
        entry["approved"] = True
    else:
        entry["posture"] = "quarantine"
        entry["approved"] = False


def _read_conf() -> dict[str, str]:
    out: dict[str, str] = {}
    if not CONF.is_file():
        return out
    for line in CONF.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"')
    return out


def admin_mac() -> str:
    conf = _read_conf()
    mac = conf.get("ADMIN_LAPTOP_MAC", "").strip()
    if mac:
        return norm_mac(mac)
    data = load_store()
    return norm_mac(data.get("admin_laptop_mac", "")) if data.get("admin_laptop_mac") else ""


def load_store() -> dict[str, Any]:
    if STORE.is_file():
        return json.loads(STORE.read_text(encoding="utf-8"))
    return {"version": 1, "admin_laptop_mac": "", "devices": {}}


def save_store(data: dict[str, Any]) -> None:
    STORE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(STORE)


def _parse_leases() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if not LEASES.is_file():
        return rows
    for line in LEASES.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            rows.append(
                {
                    "expires": parts[0],
                    "mac": norm_mac(parts[1]),
                    "ip": parts[2],
                    "hostname": parts[3] if parts[3] != "*" else "",
                }
            )
    return rows


def _client_if() -> str:
    """LAN-facing interface for neighbor discovery (eth0 in gateway mode)."""
    if os.environ.get("ARRAY_FW_CLIENT_IF"):
        return os.environ["ARRAY_FW_CLIENT_IF"]
    conf = _read_conf()
    if conf.get("CUTOVER") in {"1", "true", "yes"} or conf.get("ROLE") == "gateway":
        return conf.get("LAN_IF", "eth0")
    return conf.get("LAN_IF", conf.get("LAB_IF", "eth1"))


def _parse_neigh() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    client_if = _client_if()
    try:
        out = subprocess.check_output(["ip", "neigh", "show", "dev", client_if], text=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return rows
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[1] != "lladdr":
            continue
        ip, mac, state = parts[0], parts[2], parts[-1]
        if state in {"FAILED", "INCOMPLETE"}:
            continue
        if not MAC_RE.match(mac):
            continue
        rows.append({"ip": ip, "mac": norm_mac(mac), "hostname": "", "state": state})
    return rows


def _all_known_macs(
    leases_by_mac: dict[str, dict[str, str]],
    reservations_by_mac: dict[str, dict[str, str]],
    arp_by_mac: dict[str, dict[str, str | int]],
    devices: dict[str, Any],
) -> list[str]:
    macs: set[str] = set(devices.keys())
    macs.update(leases_by_mac.keys())
    macs.update(reservations_by_mac.keys())
    macs.update(arp_by_mac.keys())
    return sorted(macs)


def _resolve_ip_collisions(
    devices: dict[str, Any],
    leases_by_mac: dict[str, dict[str, str]],
    reservations_by_mac: dict[str, dict[str, str]],
    arp_by_mac: dict[str, dict[str, str | int]],
) -> None:
    by_ip: dict[str, list[str]] = {}
    for mac, entry in devices.items():
        ip = str(entry.get("ip") or "").strip()
        if _is_ipv4(ip):
            by_ip.setdefault(ip, []).append(mac)

    def _score(mac: str) -> tuple[int, int, str]:
        entry = devices.get(mac, {})
        rank = 100 if mac in leases_by_mac else 0
        rank += 50 if mac in reservations_by_mac else 0
        if mac in arp_by_mac:
            rank += 20 - int(arp_by_mac[mac].get("rank", 9))
        return (rank, int(bool(entry.get("allowed"))), mac)

    for _ip, macs in by_ip.items():
        if len(macs) < 2:
            continue
        ranked = sorted(macs, key=_score, reverse=True)
        for mac in ranked[1:]:
            entry = devices.get(mac, {})
            if mac in leases_by_mac or mac in reservations_by_mac:
                continue
            if mac not in arp_by_mac:
                entry["ip"] = ""
                entry["hostname"] = ""
                entry["ip_source"] = "stale"
                entry["hostname_source"] = ""
                if not entry.get("label_manual"):
                    _sync_auto_label(entry)


PROBE_INTERVAL_SEC = int(os.environ.get("ARRAY_FW_PROBE_INTERVAL", "300"))


def _maybe_refresh_probed_hostnames() -> None:
    probed_file = Path(os.environ.get("ARRAY_FW_PROBED_HOSTNAMES", "/var/lib/array-firewall/probed-hostnames.json"))
    if probed_file.is_file():
        age = time.time() - probed_file.stat().st_mtime
        if age < PROBE_INTERVAL_SEC:
            return
    try:
        subprocess.Popen(
            [
                "python3",
                "-c",
                "import sys; sys.path.insert(0,'/opt/array-firewall/api'); "
                "from lib import hostname_probe, devices; "
                "hostname_probe.refresh(); hostname_probe.apply_to_dhcp_reservations(); devices.discover()",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        pass


def discover() -> dict[str, Any]:
    _maybe_refresh_probed_hostnames()
    data = load_store()
    devices: dict[str, Any] = data.setdefault("devices", {})
    admin = admin_mac()
    if admin and not data.get("admin_laptop_mac"):
        data["admin_laptop_mac"] = admin

    leases_by_mac, reservations_by_mac, probed_by_mac, arp_by_mac = _build_identity_maps()
    mesh_macs: list[str] = []

    for mac in _all_known_macs(leases_by_mac, reservations_by_mac, arp_by_mac, devices):
        entry = devices.get(mac, {})
        identity = _resolve_identity(mac, entry, leases_by_mac, reservations_by_mac, probed_by_mac, arp_by_mac)
        entry.update(
            {
                "mac": mac,
                "ip": identity.get("ip") or "",
                "hostname": identity.get("hostname") or "",
                "ip_source": identity.get("ip_source") or "",
                "hostname_source": identity.get("hostname_source") or "",
                "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )
        if identity.get("ip") and identity.get("hostname") and identity.get("hostname_source") in {"lease", "reservation", "probe"}:
            entry["identity_valid"] = True
        elif identity.get("ip") and identity.get("hostname"):
            entry["identity_valid"] = _forward_confirms(str(identity["ip"]), str(identity["hostname"]))
        else:
            entry["identity_valid"] = bool(identity.get("ip"))

        if "first_seen" not in entry:
            entry["first_seen"] = entry["last_seen"]

        if mac == admin:
            entry["allowed"] = True
            entry["approved"] = True
            entry["posture"] = "approved"
            entry["label"] = entry.get("label") or "Admin laptop"
            entry["label_manual"] = bool(entry.get("label_manual"))
        elif "allowed" not in entry:
            entry["allowed"] = False
            entry["approved"] = False
            entry["posture"] = "quarantine"
        else:
            _set_posture(entry)

        # Google Mesh appliances — DHCP from Google router, not array-firewall
        try:
            from . import groups as device_groups

            if device_groups.is_google_mesh(mac, entry.get("hostname", ""), entry.get("label", "")):
                grps = entry.setdefault("groups", [])
                if "google-mesh" not in grps:
                    grps.append("google-mesh")
                dhcp_cfg = entry.setdefault("dhcp", {"allocate": True, "reserve": False, "ip": ""})
                if dhcp_cfg.get("allocate", True):
                    mesh_macs.append(mac)
                dhcp_cfg["allocate"] = False
                dhcp_cfg["reserve"] = False
                dhcp_cfg["source"] = "google-router"
        except Exception:
            pass

        if mac != admin and not entry.get("label_manual"):
            _sync_auto_label(entry)

        try:
            from . import groups as device_groups

            if device_groups.is_google_mesh(mac, entry.get("hostname", ""), entry.get("label", "")):
                if not entry.get("label_manual"):
                    host = _clean_hostname(entry.get("hostname"))
                    label = str(entry.get("label") or "").strip()
                    if host:
                        entry["label"] = host
                    elif label and not _is_auto_label(label) and not _is_mac_like(label):
                        entry["label"] = label
                    else:
                        entry["label"] = "Google Nest"
        except Exception:
            pass

        # Drop stale ARP-only records that are no longer on the network.
        if (
            entry.get("ip")
            and identity.get("ip_source") in {"arp", "stored"}
            and mac not in arp_by_mac
            and mac not in leases_by_mac
            and mac not in probed_by_mac
            and mac not in reservations_by_mac
        ):
            entry["ip"] = ""
            entry["hostname"] = ""
            entry["ip_source"] = "offline"
            if not entry.get("label_manual"):
                _sync_auto_label(entry)

        devices[mac] = entry

    _resolve_ip_collisions(devices, leases_by_mac, reservations_by_mac, arp_by_mac)

    save_store(data)
    if mesh_macs:
        from . import dhcp as dhcp_mod

        try:
            dhcp_mod.apply()
        except Exception:
            pass
    return data


def _dhcp_entry(dev: dict[str, Any]) -> dict[str, Any]:
    dhcp = dev.get("dhcp") or {}
    allocate = dhcp.get("allocate", True)
    reserve = bool(dhcp.get("reserve", False)) and allocate
    ip = str(dhcp.get("ip") or dev.get("ip") or "").strip()
    if allocate and reserve and not ip:
        reserve = False
    if not allocate:
        try:
            from . import groups as device_groups

            mac = str(dev.get("mac") or "").lower()
            grps = [str(g).lower() for g in (dev.get("groups") or [])]
            if "google-mesh" in grps or device_groups.is_google_mesh(
                mac, dev.get("hostname", ""), dev.get("label", "")
            ):
                status = "google-router"
            else:
                status = "external"
        except Exception:
            status = "external"
    else:
        status = "reserved" if reserve else "dynamic"
    return {
        "allocate": allocate,
        "reserve": reserve,
        "ip": ip,
        "status": status,
    }


def set_dhcp(
    mac: str,
    *,
    allocate: bool | None = None,
    reserve: bool | None = None,
    ip: str | None = None,
) -> dict[str, Any]:
    mac = norm_mac(mac)
    data = discover()
    devices_map = data.setdefault("devices", {})
    entry = devices_map.setdefault(
        mac,
        {
            "mac": mac,
            "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "posture": "quarantine",
            "approved": False,
        },
    )
    _sync_auto_label(entry)
    dhcp = entry.setdefault("dhcp", {"allocate": True, "reserve": False, "ip": ""})

    if allocate is not None:
        dhcp["allocate"] = bool(allocate)
        if not dhcp["allocate"]:
            dhcp["reserve"] = False

    if reserve is not None and dhcp.get("allocate", True):
        dhcp["reserve"] = bool(reserve)

    if ip is not None:
        dhcp["ip"] = ip.strip()
    elif not dhcp.get("ip") and entry.get("ip"):
        dhcp["ip"] = entry["ip"]

    if dhcp.get("reserve") and not dhcp.get("ip"):
        dhcp["reserve"] = False

    entry["dhcp"] = dhcp
    entry["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    devices_map[mac] = entry
    save_store(data)

    from . import dhcp as dhcp_mod

    dhcp_mod.sync_device(mac, entry)
    return {**entry, "dhcp": _dhcp_entry(entry)}


def dhcp_overrides() -> dict[str, dict[str, Any]]:
    """Per-MAC DHCP policy for dnsmasq rendering."""
    data = load_store()
    out: dict[str, dict[str, Any]] = {}
    for mac, dev in data.get("devices", {}).items():
        d = _dhcp_entry(dev)
        out[norm_mac(mac)] = {
            **d,
            "hostname": dev.get("hostname") or dev.get("label") or "",
        }
    return out


def list_devices() -> list[dict[str, Any]]:
    data = discover()
    admin = admin_mac()
    out = []
    for mac, dev in sorted(data.get("devices", {}).items()):
        item = dict(dev)
        item["is_admin"] = mac == admin
        _set_posture(item)
        item["internet"] = "allowed" if dev.get("allowed") else "quarantine"
        item["display_name"] = display_name(item)
        if not item.get("label_manual"):
            item["label"] = item["display_name"]
        try:
            from . import groups as device_groups

            item["groups"] = device_groups.groups_for_mac(mac)
        except Exception:
            item["groups"] = dev.get("groups", [])
        item.update(_dhcp_entry(dev))
        out.append(item)
    return out


def set_allowed(mac: str, allowed: bool, label: str | None = None) -> dict[str, Any]:
    mac = norm_mac(mac)
    data = discover()
    devices = data.setdefault("devices", {})
    entry = devices.setdefault(
        mac,
        {
            "mac": mac,
            "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "posture": "quarantine" if not allowed else "approved",
            "approved": allowed,
        },
    )
    entry["allowed"] = allowed
    entry["approved"] = allowed
    entry["posture"] = "approved" if allowed else "quarantine"
    if label:
        entry["label"] = label
        entry["label_manual"] = True
    elif not entry.get("label_manual"):
        _sync_auto_label(entry)
    entry["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    devices[mac] = entry
    save_store(data)
    return entry


def allowed_macs() -> list[str]:
    data = discover()
    macs = [m for m, d in data.get("devices", {}).items() if d.get("allowed")]
    admin = admin_mac()
    if admin and admin not in macs:
        macs.append(admin)
    return sorted(set(macs))


def quarantine_macs() -> list[str]:
    data = load_store()
    return sorted(
        m for m, d in data.get("devices", {}).items() if not d.get("allowed") and m != admin_mac()
    )
