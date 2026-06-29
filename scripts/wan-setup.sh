#!/usr/bin/env bash
# Bring up WAN: modem on eth1, upstream via Firewalla on eth0, or dual-iface xbox_router.
set -euo pipefail

CONF="/etc/array-firewall/array-firewall.conf"
POLICIES="/var/lib/array-firewall/policies.json"
STATE="/var/lib/array-firewall/wan.state"
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

MODEM_IF="${MODEM_IF:-eth1}"
UPLINK_IF="${UPLINK_IF:-eth0}"
XBOX_IF="${LAN_IF:-eth1}"
MODEM_GW="${MODEM_GW:-192.168.1.254}"
MODEM_IP="${MODEM_IP:-192.168.1.67}"
UPSTREAM_GW="${UPSTREAM_GW:-192.168.167.1}"
MGMT_IP="${MGMT_IP:-192.168.167.3}"
XBOX_GW_IP="${LAN_GATEWAY_IP:-192.168.5.1}"

read -r POLICY_UPSTREAM POLICY_MODE POLICY_ROLE POLICY_LAN POLICY_UPLINK POLICY_GW POLICY_MGMT <<<"$(python3 - <<'PY'
import json
from pathlib import Path
p = Path("/var/lib/array-firewall/policies.json")
if not p.is_file():
    print("192.168.167.1 upstream xbox_router eth1 eth0 192.168.5.1 192.168.167.3")
    raise SystemExit
n = json.loads(p.read_text()).get("network", {})
print(
    n.get("upstream_gateway", "192.168.167.1"),
    n.get("wan_mode", "auto"),
    n.get("role", ""),
    n.get("lan_if", "eth1"),
    n.get("uplink_if", n.get("wan_if", "eth0")),
    n.get("gateway_ip", "192.168.5.1"),
    n.get("mgmt_ip", "192.168.167.3"),
)
PY
)"
UPSTREAM_GW="${POLICY_UPSTREAM:-$UPSTREAM_GW}"
XBOX_IF="${POLICY_LAN:-$XBOX_IF}"
UPLINK_IF="${POLICY_UPLINK:-$UPLINK_IF}"
XBOX_GW_IP="${POLICY_GW:-$XBOX_GW_IP}"
MGMT_IP="${POLICY_MGMT:-$MGMT_IP}"

stop_dhcp() {
  local ifc="$1"
  local pid
  pid="$(pgrep -f "dhclient.*${ifc}" || true)"
  [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
}

write_dhclient_conf() {
  local ifc="$1"
  local mac cfg
  mac="$(cat "/sys/class/net/${ifc}/address" | tr ':' ':')"
  cfg="/etc/dhcp/dhclient-${ifc}.conf"
  cat >"$cfg" <<EOF
reject 192.168.167.0/24;
reject 192.168.28.0/24;
reject 192.168.5.0/24;
send dhcp-client-identifier 1:${mac};
EOF
}

try_modem_static() {
  ip link set "$MODEM_IF" up
  ip addr flush dev "$MODEM_IF"
  ip addr add "${MODEM_IP}/24" dev "$MODEM_IF"
  ip route replace default via "$MODEM_GW" dev "$MODEM_IF"
  ping -c1 -W2 "$MODEM_GW" >/dev/null 2>&1
}

try_modem_dhcp() {
  write_dhclient_conf "$MODEM_IF"
  ip addr flush dev "$MODEM_IF"
  ip link set "$MODEM_IF" up
  rm -f "/run/dhclient.${MODEM_IF}.pid"
  timeout 15 dhclient -1 -cf "/etc/dhcp/dhclient-${MODEM_IF}.conf" \
    -pf "/run/dhclient.${MODEM_IF}.pid" "$MODEM_IF" 2>/dev/null || return 1
  local gw
  gw="$(ip route show default dev "$MODEM_IF" 2>/dev/null | awk 'NR==1{print $3}')"
  [[ -n "$gw" ]] && ping -c1 -W2 "$gw" >/dev/null 2>&1
}

set_policies_upstream() {
  python3 - "$UPLINK_IF" "$XBOX_IF" "$UPSTREAM_GW" "$POLICIES" <<'PY'
import json
import sys
from pathlib import Path

uplink, xbox_if, upstream, path = sys.argv[1:5]
p = Path(path)
data = json.loads(p.read_text()) if p.is_file() else {"version": 1}
net = data.setdefault("network", {})
net["wan_mode"] = "upstream"
net["upstream_gateway"] = upstream
net["uplink_if"] = uplink
net["wan_if"] = uplink
net["lan_if"] = xbox_if
p.write_text(json.dumps(data, indent=2) + "\n")
PY
}

use_xbox_router_eth0_xbox_eth1_wan() {
  # eth0: house mgmt + 192.168.5.1 Xbox gateway; eth1: DHCP WAN (e.g. 192.168.39.x)
  stop_dhcp "$MGMT_IF"
  ip link set "$MGMT_IF" up
  ip addr flush dev "$MGMT_IF"
  ip addr add "${MGMT_IP}/24" dev "$MGMT_IF"
  ip addr add "${XBOX_GW_IP}/24" dev "$MGMT_IF"

  if try_modem_dhcp; then
    WAN_GW="$(ip route show default dev "$MODEM_IF" 2>/dev/null | awk 'NR==1{print $3}')"
    [[ -z "$WAN_GW" ]] && WAN_GW="$(python3 - <<PY
import json
from pathlib import Path
p = Path("$POLICIES")
if p.is_file():
    print(json.loads(p.read_text()).get("network", {}).get("upstream_gateway", ""))
PY
)"
    ip route replace default via "${WAN_GW}" dev "$MODEM_IF"
    python3 - "$MODEM_IF" "$MGMT_IF" "${WAN_GW}" "$POLICIES" <<'PY'
import json, sys
from pathlib import Path
wan, xbox_if, upstream, path = sys.argv[1:5]
p = Path(path)
data = json.loads(p.read_text()) if p.is_file() else {"version": 1}
net = data.setdefault("network", {})
net["wan_mode"] = "upstream"
net["upstream_gateway"] = upstream
net["uplink_if"] = wan
net["wan_if"] = wan
net["lan_if"] = xbox_if
p.write_text(json.dumps(data, indent=2) + "\n")
PY
    echo "mode=xbox_router wan=${MODEM_IF}:${WAN_GW} xbox=${MGMT_IF}:${XBOX_GW_IP} mgmt=${MGMT_IP}" >"$STATE"
    echo "[wan-setup] xbox_router: ${MGMT_IF}=${MGMT_IP}+${XBOX_GW_IP}/24 Xbox, ${MODEM_IF} DHCP WAN via ${WAN_GW}"
  else
    echo "[wan-setup] eth1 DHCP failed; mgmt+xbox addresses applied on ${MGMT_IF}" >&2
    return 1
  fi
}

use_xbox_router_dual() {
  stop_dhcp "$MODEM_IF"
  stop_dhcp "$UPLINK_IF"
  stop_dhcp "$XBOX_IF"
  ip addr flush dev "$MODEM_IF" 2>/dev/null || true
  ip link set "$MODEM_IF" down 2>/dev/null || true

  ip link set "$UPLINK_IF" up
  ip addr flush dev "$UPLINK_IF"
  ip addr add "${MGMT_IP}/24" dev "$UPLINK_IF"
  ip route replace default via "$UPSTREAM_GW" dev "$UPLINK_IF"

  ip link set "$XBOX_IF" up
  ip addr flush dev "$XBOX_IF"
  ip addr add "${XBOX_GW_IP}/24" dev "$XBOX_IF"

  set_policies_upstream
  echo "mode=xbox_router uplink=${UPLINK_IF}:${MGMT_IP} xbox=${XBOX_IF}:${XBOX_GW_IP} gw=${UPSTREAM_GW}" >"$STATE"
  echo "[wan-setup] xbox_router dual: ${XBOX_IF}=${XBOX_GW_IP}/24 (Xbox) ${UPLINK_IF}=${MGMT_IP}/24 -> ${UPSTREAM_GW}"
}

use_upstream_single() {
  local ifc="${UPLINK_IF}"
  stop_dhcp "$MODEM_IF"
  ip addr flush dev "$MODEM_IF" 2>/dev/null || true
  ip link set "$MODEM_IF" down 2>/dev/null || true
  ip link set "$ifc" up
  ip route replace default via "$UPSTREAM_GW" dev "$ifc"
  set_policies_upstream
  echo "mode=upstream gw=${UPSTREAM_GW} if=${ifc}" >"$STATE"
  echo "[wan-setup] upstream via ${UPSTREAM_GW} on ${ifc}"
}

use_direct() {
  python3 - "$MODEM_IF" "$POLICIES" <<'PY'
import json, sys
from pathlib import Path
wan, path = sys.argv[1:3]
p = Path(path)
data = json.loads(p.read_text()) if p.is_file() else {"version": 1}
net = data.setdefault("network", {})
net["wan_mode"] = "direct"
net["wan_if"] = wan
net["uplink_if"] = wan
net.pop("upstream_gateway", None)
p.write_text(json.dumps(data, indent=2) + "\n")
PY
  echo "mode=direct gw=${MODEM_GW} if=${MODEM_IF}" >"$STATE"
  echo "[wan-setup] direct modem on ${MODEM_IF} via ${MODEM_GW}"
}

if [[ "$POLICY_ROLE" == "xbox_router" && "$POLICY_LAN" == "eth0" && "$POLICY_UPLINK" == "eth1" ]]; then
  MGMT_IF=eth0
  XBOX_IF=eth0
  MODEM_IF=eth1
  use_xbox_router_eth0_xbox_eth1_wan
elif [[ "$POLICY_ROLE" == "xbox_router" && "$XBOX_IF" != "$UPLINK_IF" ]]; then
  use_xbox_router_dual
elif [[ "$POLICY_ROLE" == "xbox_router" ]] || [[ "$POLICY_MODE" == "upstream" ]]; then
  use_upstream_single
elif try_modem_static 2>/dev/null || try_modem_dhcp; then
  use_direct
elif ping -c1 -W2 "$UPSTREAM_GW" >/dev/null 2>&1; then
  use_upstream_single
else
  echo "[wan-setup] failed: no modem on ${MODEM_IF} and upstream ${UPSTREAM_GW} unreachable" >&2
  exit 1
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1 || true
sysctl -w "net.ipv4.conf.${UPLINK_IF}.rp_filter=2" >/dev/null 2>&1 || true
sysctl -w "net.ipv4.conf.${XBOX_IF}.rp_filter=2" >/dev/null 2>&1 || true

if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
  echo "[wan-setup] internet OK"
else
  echo "[wan-setup] default route up; internet probe failed (may be nft/dns)"
fi

echo "=== ${UPLINK_IF} (upstream) ==="
ip -br addr show "$UPLINK_IF" 2>/dev/null || true
echo "=== ${XBOX_IF} (xbox) ==="
ip -br addr show "$XBOX_IF" 2>/dev/null || true
ip route show default || true
