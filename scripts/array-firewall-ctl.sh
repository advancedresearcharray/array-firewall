#!/usr/bin/env bash
# array-firewall control — status, apply rules, packet shield.
set -euo pipefail

ROOT="/opt/array-firewall"
CONF="/etc/array-firewall/array-firewall.conf"
SHIELD="${ROOT}/scripts/packet-shield-nft.sh"
APPLY="${ROOT}/scripts/apply-firewall.sh"
API_PORT="${ARRAY_FW_API_PORT:-8090}"

# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

log() { printf '[array-firewall] %s\n' "$*"; }

cmd_status() {
  echo "=== array-firewall ==="
  echo "host: $(hostname -f)"
  ip -br addr show "${MGMT_IF:-eth0}" "${LAB_IF:-eth1}" 2>/dev/null || ip -br addr
  echo ""
  echo "=== policy ==="
  echo "default_deny=forward,input"
  echo "nat=masquerade (${LAB_IF:-eth1} -> ${UPLINK_IF:-eth0})"
  echo "mac_allowlist=$(python3 -c 'import sys; sys.path.insert(0,"/opt/array-firewall/api"); from lib import devices; print(len(devices.allowed_macs()))' 2>/dev/null || echo '?') allowed"
  echo ""
  echo "=== config ==="
  grep -E '^(XBOX_IP|ADMIN_LAPTOP_MAC|FIREWALLA_API_URL|API_PORT|SENTINEL_PORT|UPLINK_IF)=' "$CONF" 2>/dev/null || true
  echo ""
  echo "=== packet shield ==="
  "$SHIELD" status
  echo ""
  echo "=== api ==="
  curl -sf -m 3 "http://127.0.0.1:${API_PORT}/api/health" && echo || echo "api=not running on :${API_PORT}"
  echo ""
  echo "=== sentinel ==="
  curl -sf -m 3 "http://127.0.0.1:${SENTINEL_PORT:-8098}/health" | head -c 200 && echo || echo "sentinel=not running"
}

case "${1:-status}" in
  status) cmd_status ;;
  reload|apply) "$APPLY" ;;
  shield) shift; "$SHIELD" shield "$@" ;;
  strict) "$SHIELD" strict ;;
  relax) "$SHIELD" relax ;;
  *) echo "Usage: $0 {status|apply|shield [normal|strict]|relax}"; exit 2 ;;
esac
