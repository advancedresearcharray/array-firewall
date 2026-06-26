#!/usr/bin/env bash
# Discover path MTU toward game/WAN targets (DF ping binary search).
set -euo pipefail

TOOLS_DIR="/home/pi/gaming-tools"
CONF="${TOOLS_DIR}/gaming.conf"
INPUT="${1:-}"

if [[ -f "$CONF" ]]; then
  # shellcheck disable=SC1090
  source "$CONF"
fi

exec python3 - "${INPUT}" "${XBOX_IP:-}" "${WAN_PROBE_HOST:-one.one.one.one}" <<'PY'
import ipaddress
import json
import socket
import subprocess
import sys

input_path, xbox_ip, wan_default = sys.argv[1:4]


def load_targets():
    if input_path:
        with open(input_path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("targets") or []
    return [
        {"label": "WAN probe", "hostname": wan_default},
        {"label": "Cloudflare DNS", "hostname": "1.1.1.1", "ip": "1.1.1.1"},
        {"label": "Azure East US", "hostname": "mpsqosprod.eastus.cloudapp.azure.com"},
        {"label": "Warzone PlayFab", "hostname": "playfab.com"},
    ]


def resolve_host(item):
    if item.get("ip"):
        return [item["ip"]]
    host = item.get("hostname") or item.get("label")
    if not host:
        return []
    ips = []
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        return []
    v4 = [i for i in ips if ":" not in i]
    v6 = [i for i in ips if ":" in i]
    return (v4[:1] or []) + (v6[:1] or [])


def ping_df(ip, payload_size, timeout=2):
    try:
        version = ipaddress.ip_address(ip.split("%")[0]).version
    except ValueError:
        return False, None
    if version == 6:
        cmd = ["ping", "-6", "-c", "1", "-W", str(timeout), "-M", "do", "-s", str(payload_size), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), "-M", "do", "-s", str(payload_size), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2, check=False)
    except Exception:
        return False, None
    if proc.returncode == 0:
        return True, None
    err = (proc.stderr + proc.stdout).lower()
    if "frag" in err or "message too long" in err or "mtu" in err:
        return False, "fragmentation"
    return False, "timeout"


def discover_mtu(ip, low=1200, high=1500):
    if not ping_df(ip, 8)[0]:
        return None, "unreachable", False
    if not ping_df(ip, 512)[0]:
        try:
            proc = subprocess.run(
                ["ping", "-c", "1", "-W", "2", ip],
                capture_output=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0:
                return 1500, "icmp-size-filtered", False
        except Exception:
            pass
        return None, "icmp-filtered", False
    lo, hi = low, high
    best = 8
    while lo <= hi:
        mid = (lo + hi) // 2
        ok, _ = ping_df(ip, mid)
        if ok:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    try:
        version = ipaddress.ip_address(ip.split("%")[0]).version
    except ValueError:
        version = 4
    header = 48 if version == 6 else 28
    path_mtu = best + header
    if path_mtu < 576:
        return None, "icmp-unreliable", False
    return path_mtu, None, path_mtu < 1500


def probe_target(item):
    results = []
    for ip in resolve_host(item):
        path_mtu, err, risk = discover_mtu(ip)
        try:
            version = ipaddress.ip_address(ip.split("%")[0]).version
        except ValueError:
            version = 4
        results.append(
            {
                "label": item.get("label") or item.get("hostname") or ip,
                "hostname": item.get("hostname"),
                "ip": ip,
                "stack": "ipv6" if version == 6 else "ipv4",
                "pathMtu": path_mtu,
                "status": "ok" if path_mtu else "unknown",
                "error": err,
                "fragmentationRisk": bool(risk),
            }
        )
    return results


targets = load_targets()
rows = []
for item in targets[:12]:
    rows.extend(probe_target(item))

if xbox_ip:
    path_mtu, err, risk = discover_mtu(xbox_ip, low=1400, high=1500)
    rows.insert(
        0,
        {
            "label": "Xbox (LAN)",
            "hostname": None,
            "ip": xbox_ip,
            "stack": "ipv4",
            "pathMtu": path_mtu,
            "status": "ok" if path_mtu else "unknown",
            "error": err,
            "fragmentationRisk": bool(risk),
        },
    )

risk = [r for r in rows if r.get("fragmentationRisk")]
payload = {
    "targets": rows,
    "summary": {
        "probed": len(rows),
        "fragmentationRiskCount": len(risk),
        "lowestMtu": min((r["pathMtu"] for r in rows if r.get("pathMtu")), default=None),
    },
    "recommendation": (
        "Path MTU looks healthy (≥1500) on all probes"
        if not risk
        else f"{len(risk)} path(s) below 1500 bytes — hidden fragmentation may add latency"
    ),
}
print(json.dumps(payload, separators=(",", ":")))
PY
