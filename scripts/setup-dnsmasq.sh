#!/usr/bin/env bash
# Render dnsmasq config from policies.json (dhcp section).
set -euo pipefail

CONF="/etc/array-firewall/array-firewall.conf"
OUT="/etc/dnsmasq.d/array-firewall.conf"
POLICIES="/var/lib/array-firewall/policies.json"

# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

python3 - "$OUT" "$POLICIES" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
policies_path = Path(sys.argv[2])
devices_path = Path("/var/lib/array-firewall/devices.json")

GOOGLE_MESH_OUIS = (
    "18:b4:30",
    "20:6d:31",
    "64:16:66",
    "54:60:09",
    "f4:f5:d8",
    "94:eb:2c",
)


def is_google_mesh_mac(mac: str) -> bool:
    mac = mac.lower()
    return any(mac.startswith(o) for o in GOOGLE_MESH_OUIS)

defaults = {
    "enabled": True,
    "interface": "eth1",
    "range_start": "198.51.100.50",
    "range_end": "198.51.100.200",
    "netmask": "255.255.255.0",
    "lease_time": "12h",
    "gateway": "198.51.100.1",
    "dns": "198.51.100.1",
    "domain": "array-firewall.local",
    "upstream_dns": ["192.0.2.1"],
    "authoritative": True,
    "reservations": [],
}

data = json.loads(policies_path.read_text()) if policies_path.is_file() else {}
net = data.get("network", {})
dhcp = dict(defaults)
dhcp.update(data.get("dhcp") or {})

role = net.get("role", "lab")
cutover = bool(net.get("cutover"))
lan_if = dhcp.get("interface") or net.get("lan_if", "eth1")
mgmt_if = "eth0"
wan_if = net.get("wan_if", "eth1")
gaming = data.get("gaming") or {}

if role == "xbox_router":
    xbox_ip = (gaming.get("xbox_ip") or "").strip()
    xbox_mac = (gaming.get("xbox_mac") or "").strip().lower()
    xbox_gw = net.get("gateway_ip") or "203.0.113.1"
    if xbox_ip and xbox_mac:
        xbox_dns = "1.1.1.1"
        xbox_lines = [
            "# array-firewall dnsmasq — xbox_router (Xbox-only, same wire)",
            f"# mac={xbox_mac} ip={xbox_ip} gw={xbox_gw}",
            f"interface={lan_if}",
            "bind-interfaces",
            f"except-interface={wan_if}",
            f"listen-address={xbox_gw}",
            f"dhcp-range={xbox_ip},{xbox_ip},255.255.255.0,{dhcp.get('lease_time', '12h')}",
            f"dhcp-host={xbox_mac},{xbox_ip},squatx,infinite",
            f"dhcp-option=3,{xbox_gw}",
            f"dhcp-option=6,{xbox_dns}",
            f"domain={dhcp.get('domain', 'array.local')}",
            "log-dhcp",
            "dhcp-authoritative",
        ]
        for upstream in dhcp.get("upstream_dns") or []:
            xbox_lines.append(f"server={upstream}")
        out_path.write_text("\n".join(xbox_lines) + "\n")
        print(f"[setup-dnsmasq] xbox_router DHCP {xbox_ip} on {lan_if} gw={xbox_gw}")
        sys.exit(0)

if role == "gateway" and cutover:
    gw = net.get("gateway_ip", dhcp.get("gateway", "192.0.2.1"))
    cidr = net.get("lan_cidr", "192.0.2.0/24")
    mask = cidr.split("/")[-1] if "/" in cidr else "24"
    parts = gw.split(".")
    if not dhcp.get("range_start"):
        dhcp["range_start"] = f"{parts[0]}.{parts[1]}.{parts[2]}.50"
    if not dhcp.get("range_end"):
        dhcp["range_end"] = f"{parts[0]}.{parts[1]}.{parts[2]}.200"
    dhcp["gateway"] = gw
    dhcp["dns"] = dhcp.get("dns") or gw
    dhcp["netmask"] = dhcp.get("netmask") or ("255.255.255.0" if mask == "24" else f"255.255.255.{256-2**(32-int(mask))}")

lines = [
    "# array-firewall dnsmasq — managed via dashboard/API",
    f"# role={role} cutover={cutover}",
]

if not dhcp.get("enabled", True):
    lines.append("# DHCP disabled via dashboard")
    out_path.write_text("\n".join(lines) + "\n")
    sys.exit(0)

lines += [
    f"interface={lan_if}",
    "bind-interfaces",
    f"except-interface={wan_if if role == 'gateway' and cutover else mgmt_if}",
    f"listen-address={dhcp['gateway']}",
    f"# Trusted LAN DHCP only — wireless mesh uses Google router at 192.0.2.2 (.3-.50)",
    f"dhcp-range={dhcp['range_start']},{dhcp['range_end']},{dhcp['netmask']},{dhcp['lease_time']}",
    f"dhcp-option=3,{dhcp['gateway']}",
    f"dhcp-option=6,{dhcp['dns']}",
    f"domain={dhcp['domain']}",
    "log-dhcp",
]

if dhcp.get("authoritative", True):
    lines.append("dhcp-authoritative")

for upstream in dhcp.get("upstream_dns") or []:
    lines.append(f"server={upstream}")

device_dhcp: dict[str, dict] = {}
if devices_path.is_file():
    try:
        dev_data = json.loads(devices_path.read_text())
        for mac, dev in (dev_data.get("devices") or {}).items():
            mac = mac.lower()
            d = dev.get("dhcp") or {}
            allocate = d.get("allocate", True)
            reserve = bool(d.get("reserve", False)) and allocate
            ip = (d.get("ip") or dev.get("ip") or "").strip()
            device_dhcp[mac] = {
                "allocate": allocate,
                "reserve": reserve,
                "ip": ip,
                "hostname": dev.get("hostname") or dev.get("label") or "",
            }
    except (json.JSONDecodeError, OSError):
        pass

handled_macs: set[str] = set()

# Google mesh / wireless-infra — never lease from array-firewall (.1)
if devices_path.is_file():
    try:
        dev_data = json.loads(devices_path.read_text())
        for mac, dev in (dev_data.get("devices") or {}).items():
            mac = mac.lower()
            if mac in handled_macs:
                continue
            grps = [g.lower() for g in (dev.get("groups") or [])]
            d = dev.get("dhcp") or {}
            if (
                not d.get("allocate", True)
                or "google-mesh" in grps
                or "wireless-infra" in grps
                or is_google_mesh_mac(mac)
            ):
                lines.append(f"dhcp-host={mac},ignore")
                handled_macs.add(mac)
    except (json.JSONDecodeError, OSError):
        pass

for mac, d in sorted(device_dhcp.items()):
    if mac in handled_macs:
        continue
    if not d.get("allocate", True):
        lines.append(f"dhcp-host={mac},ignore")
        handled_macs.add(mac)
    elif d.get("reserve") and d.get("ip"):
        host = d.get("hostname") or ""
        if host:
            lines.append(f"dhcp-host={mac},{d['ip']},{host},infinite")
        else:
            lines.append(f"dhcp-host={mac},{d['ip']},infinite")
        handled_macs.add(mac)

for res in dhcp.get("reservations") or []:
    mac = res.get("mac", "").lower()
    ip = res.get("ip", "")
    host = res.get("hostname", "")
    if mac in handled_macs or not mac or not ip:
        continue
    if host:
        lines.append(f"dhcp-host={mac},{ip},{host},infinite")
    else:
        lines.append(f"dhcp-host={mac},{ip},infinite")

out_path.write_text("\n".join(lines) + "\n")
print(f"[setup-dnsmasq] wrote {out_path} enabled={dhcp.get('enabled')} if={lan_if}")
PY

if python3 - <<'PY' 2>/dev/null
import json
from pathlib import Path
p = Path("$POLICIES")
data = json.loads(p.read_text()) if p.is_file() else {}
net = data.get("network") or {}
gaming = data.get("gaming") or {}
dhcp = data.get("dhcp") or {}
if net.get("role") == "xbox_router" and gaming.get("xbox_mac") and gaming.get("xbox_ip"):
    raise SystemExit(0)
raise SystemExit(0 if dhcp.get("enabled", True) else 1)
PY
then
  exec 9>/run/array-firewall-setup-dnsmasq.lock
  flock -n 9 || exit 0
  if systemctl is-active --quiet dnsmasq 2>/dev/null; then
    systemctl reload dnsmasq 2>/dev/null || systemctl restart dnsmasq 2>/dev/null || true
  else
    systemctl reset-failed dnsmasq 2>/dev/null || true
    systemctl start dnsmasq 2>/dev/null || true
  fi
else
  if grep -qE '^dhcp-(range|host)=' "$OUT" 2>/dev/null; then
    :
  else
    systemctl stop dnsmasq 2>/dev/null || true
  fi
fi
