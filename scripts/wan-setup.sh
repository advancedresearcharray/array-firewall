#!/usr/bin/env bash
# Bring up WAN interface (DHCP from ISP on nic1).
set -euo pipefail

CONF="/etc/array-firewall/array-firewall.conf"
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

WAN_IF="${WAN_IF:-eth1}"

ip link set "$WAN_IF" up 2>/dev/null || true

if ! pgrep -f "dhclient.*${WAN_IF}" >/dev/null 2>&1; then
  dhclient -v "$WAN_IF" 2>/dev/null || dhcpcd "$WAN_IF" 2>/dev/null || true
fi

echo "=== ${WAN_IF} ==="
ip -br addr show "$WAN_IF"
ip route show default || true
