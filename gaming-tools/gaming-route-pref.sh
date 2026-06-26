#!/usr/bin/env bash
# Prefer low-latency WAN path for Xbox (policy routing + optional ISP gateway).
set -euo pipefail

CONF="/etc/array-firewall/array-firewall.conf"
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

XBOX_IP="${XBOX_IP:-192.168.167.65}"
WAN="${WAN_IF:-eth1}"
TABLE="${ROUTE_TABLE_GAMING:-100}"
STATE="/var/lib/array-firewall/gaming-route.state"

log() { printf '[gaming-route] %s\n' "$*"; }

apply_route() {
  local gw="${1:-}"
  ip rule del from "$XBOX_IP" table "$TABLE" 2>/dev/null || true
  ip route flush table "$TABLE" 2>/dev/null || true
  if [[ -z "$gw" ]]; then
    gw="$(ip route show default dev "$WAN" 2>/dev/null | awk '{print $3; exit}')"
  fi
  [[ -n "$gw" ]] || { echo "no gateway for $WAN"; return 1; }
  ip route add default via "$gw" dev "$WAN" table "$TABLE"
  ip rule add from "$XBOX_IP" table "$TABLE" priority 100
  echo "route=pref gw=$gw table=$TABLE xbox=$XBOX_IP" >"$STATE"
  log "Xbox $XBOX_IP -> table $TABLE via $gw"
  echo "gaming-route=applied gw=$gw xbox=$XBOX_IP"
}

clear_route() {
  ip rule del from "$XBOX_IP" table "$TABLE" 2>/dev/null || true
  ip route flush table "$TABLE" 2>/dev/null || true
  echo "route=cleared" >"$STATE"
  echo "gaming-route=cleared"
}

case "${1:-status}" in
  apply) apply_route "${2:-}" ;;
  prefer) apply_route "${2:-}" ;;
  clear|off) clear_route ;;
  status)
    [[ -f "$STATE" ]] && cat "$STATE" || echo "gaming-route=inactive"
    ip rule show | grep -F "$XBOX_IP" || true
    ;;
  *)
    echo "Usage: $0 {apply [gw]|prefer [gw]|clear|status}"; exit 2
    ;;
esac
