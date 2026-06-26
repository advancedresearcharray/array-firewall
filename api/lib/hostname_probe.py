"""Probe LAN devices for authoritative hostnames via Proxmox inventory and mDNS."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from . import devices

PROBED_FILE = Path(os.environ.get("ARRAY_FW_PROBED_HOSTNAMES", "/var/lib/array-firewall/probed-hostnames.json"))
PROXMOX_NODES = [
    ip.strip()
    for ip in os.environ.get("ARRAY_FW_PROXMOX_NODES", "192.168.167.9,192.168.167.39,192.168.167.53").split(",")
    if ip.strip()
]
MDNS_NODE = os.environ.get("ARRAY_FW_MDNS_NODE", "192.168.167.9")

HYPERVISORS: dict[str, dict[str, str]] = {
    "192.168.167.9": {"hostname": "node9", "mac": "c8:7f:54:03:51:43"},
    "192.168.167.39": {"hostname": "thirtynince", "mac": "50:eb:f6:cd:86:ec"},
    "192.168.167.53": {"hostname": "opencase", "mac": "d4:3d:7e:be:e9:7a"},
}

_INVENTORY_PY = r"""
import glob, json, re, subprocess, socket

def clean(name):
    name = (name or "").strip().rstrip(".")
    if not name or name == "*":
        return ""
    return name.split(".")[0]

rows = []
for path in sorted(glob.glob("/etc/pve/lxc/*.conf")):
    text = open(path, encoding="utf-8").read()
    mac = re.search(r"hwaddr=([0-9A-F:]+)", text, re.I)
    ipm = re.search(r"ip=192\.168\.167\.(\d+)", text)
    hn = re.search(r"^hostname:\s*(\S+)", text, re.M)
    vmid = path.split("/")[-1].split(".")[0]
    if not mac:
        continue
    ip = f"192.168.167.{ipm.group(1)}" if ipm else ""
    hostname = clean(hn.group(1) if hn else "")
    if vmid.isdigit():
        try:
            live = subprocess.check_output(["pct", "exec", vmid, "--", "hostname", "-s"], text=True, timeout=8).strip()
            hostname = clean(live) or hostname
        except Exception:
            pass
    if hostname:
        rows.append({"mac": mac.group(1).lower(), "ip": ip, "hostname": hostname, "source": "proxmox-lxc"})

for path in sorted(glob.glob("/etc/pve/qemu-server/*.conf")):
    text = open(path, encoding="utf-8").read()
    mac = re.search(r"hwaddr=([0-9A-F:]+)", text, re.I)
    ipm = re.search(r"ip=192\.168\.167\.(\d+)", text)
    name = re.search(r"^name:\s*(\S+)", text, re.M)
    if not mac:
        continue
    ip = f"192.168.167.{ipm.group(1)}" if ipm else ""
    hostname = clean(name.group(1) if name else "")
    if hostname:
        rows.append({"mac": mac.group(1).lower(), "ip": ip, "hostname": hostname, "source": "proxmox-vm"})

print(json.dumps(rows))
"""


def _clean_hostname(name: str | None) -> str:
    host = str(name or "").strip().rstrip(".")
    if not host or host == "*" or devices._is_mac_like(host):
        return ""
    return host.split(".")[0]


def _ssh(node: str, remote_cmd: str, *, timeout: int = 12) -> str:
    proc = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={min(timeout, 8)}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"root@{node}",
            remote_cmd,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"ssh failed to {node}")
    return proc.stdout


def _run_remote_python(node: str, script: str, *, timeout: int = 30) -> str:
    encoded = base64.b64encode(script.encode()).decode()
    return _ssh(node, f"python3 -c \"import base64; exec(base64.b64decode('{encoded}').decode())\"", timeout=timeout)


def _probe_proxmox() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for node in PROXMOX_NODES:
        try:
            raw = _run_remote_python(node, _INVENTORY_PY)
            rows = json.loads(raw)
        except Exception:
            continue
        for row in rows:
            mac = str(row.get("mac") or "").lower()
            hostname = _clean_hostname(row.get("hostname"))
            if not mac or not hostname:
                continue
            out[mac] = {
                "mac": mac,
                "ip": str(row.get("ip") or "").strip(),
                "hostname": hostname,
                "source": str(row.get("source") or "proxmox"),
                "node": node,
            }
        hv = HYPERVISORS.get(node, {})
        mac = str(hv.get("mac") or "").lower()
        hostname = _clean_hostname(hv.get("hostname"))
        if mac and hostname:
            out[mac] = {"mac": mac, "ip": node, "hostname": hostname, "source": "proxmox-host", "node": node}
    return out


def _ips_needing_names() -> list[str]:
    ips: set[str] = set()
    data = devices.load_store()
    for dev in data.get("devices", {}).values():
        ip = str(dev.get("ip") or "").strip()
        if not devices._is_ipv4(ip):
            continue
        host = _clean_hostname(dev.get("hostname"))
        label = str(dev.get("label") or "").strip()
        if not host or label == ip:
            ips.add(ip)
    return sorted(ips)


def _probe_mdns(ips: list[str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for ip in ips:
        try:
            raw = _ssh(MDNS_NODE, f"avahi-resolve -a {ip} 2>/dev/null | awk '{{print $2}}'", timeout=15)
            hostname = _clean_hostname(raw.strip())
            if hostname:
                out[ip] = {"ip": ip, "hostname": hostname, "source": "mdns"}
        except Exception:
            continue
    return out


def _probe_direct_ssh(ips: list[str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for ip in ips:
        if not devices._is_ipv4(ip):
            continue
        for user in ("root", "ubuntu", "ck", "admin"):
            try:
                proc = subprocess.run(
                    [
                        "ssh",
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "ConnectTimeout=3",
                        "-o",
                        "StrictHostKeyChecking=accept-new",
                        f"{user}@{ip}",
                        "hostname -s",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=6,
                )
                if proc.returncode == 0:
                    host = _clean_hostname(proc.stdout)
                    if host:
                        out[ip] = {
                            "ip": ip,
                            "hostname": host,
                            "source": "ssh",
                            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        }
                        break
            except (subprocess.TimeoutExpired, OSError):
                continue
    return out


def refresh(*, force: bool = False) -> dict[str, Any]:
    probed = _probe_proxmox()
    need_ips = _ips_needing_names()
    # Also probe any online device still missing a probed hostname.
    data = devices.load_store()
    for mac, dev in data.get("devices", {}).items():
        mac = devices.norm_mac(mac)
        if mac in probed and probed[mac].get("hostname"):
            continue
        ip = str(dev.get("ip") or "").strip()
        if devices._is_ipv4(ip):
            need_ips.append(ip)
    need_ips = sorted(set(need_ips))
    mdns = _probe_mdns(need_ips)
    ssh_by_ip = _probe_direct_ssh(need_ips)

    for mac, dev in data.get("devices", {}).items():
        mac = devices.norm_mac(mac)
        if mac in probed:
            continue
        ip = str(dev.get("ip") or "").strip()
        if ip in mdns:
            probed[mac] = {"mac": mac, "ip": ip, **mdns[ip]}

    for mac, row in probed.items():
        ip = str(row.get("ip") or "").strip()
        if ip in mdns and not row.get("hostname"):
            row["hostname"] = mdns[ip]["hostname"]
            row["source"] = "mdns"

    for ip, row in ssh_by_ip.items():
        for mac, dev in data.get("devices", {}).items():
            if str(dev.get("ip") or "") == ip and devices.norm_mac(mac) not in probed:
                probed[devices.norm_mac(mac)] = {
                    "mac": devices.norm_mac(mac),
                    "ip": ip,
                    "hostname": row["hostname"],
                    "source": "ssh",
                }
        if ip not in mdns:
            mdns[ip] = row

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for row in probed.values():
        row["updated"] = now

    payload = {"version": 1, "updated": now, "by_mac": probed, "by_ip": mdns}
    PROBED_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PROBED_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(PROBED_FILE)
    return payload


def load_probed_by_mac() -> dict[str, dict[str, str]]:
    if not PROBED_FILE.is_file():
        return {}
    try:
        data = json.loads(PROBED_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    out: dict[str, dict[str, str]] = {}
    for mac, row in (data.get("by_mac") or {}).items():
        mac = str(mac).lower()
        hostname = _clean_hostname(row.get("hostname"))
        if not hostname:
            continue
        out[mac] = {
            "mac": mac,
            "ip": str(row.get("ip") or "").strip(),
            "hostname": hostname,
            "source": str(row.get("source") or "probe"),
        }
    return out


def apply_to_dhcp_reservations() -> dict[str, Any]:
    from . import dhcp as dhcp_mod

    applied: list[str] = []
    for mac, row in load_probed_by_mac().items():
        ip = str(row.get("ip") or "").strip()
        hostname = _clean_hostname(row.get("hostname"))
        if not ip or not hostname or not devices._is_ipv4(ip):
            continue
        dhcp_mod.add_reservation(mac, ip, hostname)
        applied.append(mac)
    return {"ok": True, "applied": len(applied), "macs": applied}
