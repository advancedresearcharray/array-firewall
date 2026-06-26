#!/usr/bin/env bash
# Shared Xbox device identity helpers — all gaming-tools scripts must scope
# firewall/QoS/DNS changes to these sources only (never LAN-wide).
set -euo pipefail

require_xbox_ip() {
  if [[ -z "${XBOX_IP:-}" ]]; then
    echo "[xbox-scope] ERROR: XBOX_IP is not set in gaming.conf — refusing to apply network policy" >&2
    exit 1
  fi
  if [[ "$XBOX_IP" == *"/"* ]]; then
    echo "[xbox-scope] ERROR: XBOX_IP must be a single host address, not a subnet ($XBOX_IP)" >&2
    exit 1
  fi
}

discover_xbox_ipv6() {
  [[ -n "${XBOX_MAC:-}" ]] || return 0
  local mac="${XBOX_MAC,,}"
  ip -6 neigh show dev "${LAN_IF:-br2}" 2>/dev/null | while read -r line; do
    [[ "${line,,}" == *"$mac"* ]] || continue
    echo "$line" | awk '{print $1}'
  done | grep -v '^fe80:' || true
}

xbox_sources() {
  require_xbox_ip
  { echo "${XBOX_IP}"; discover_xbox_ipv6; } | sort -u | grep -v '^$' || true
}

# Inbound whitelist for flood guard — Xbox Live + Call of Duty: Warzone (Xbox One / Series)
# Ref: Activision platform ports + standard Xbox Live requirements
# UDP: 88, 500, 3074-3075, 3544, 4500, 53, 9002 (remote play)
# TCP: 3074, 80, 53 (+ 443 HTTPS / store backends)
XBOX_UDP_PORTS=(88 500 3074 3075 3544 4500 53 9002)
XBOX_TCP_PORTS=(3074 80 53 443 2869)
