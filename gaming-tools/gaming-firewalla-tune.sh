#!/usr/bin/env bash
# CPU/softirq tuning during high-risk matchmaking (no GPU on gateway CT).
set -euo pipefail

CONF="/etc/array-firewall/array-firewall.conf"
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

WAN="${WAN_IF:-eth1}"
STATE="/var/lib/array-firewall/cpu-tune.state"

apply_tune() {
  # Reduce latency variance under flood: favor network over background IO
  sysctl -w vm.swappiness=10 >/dev/null 2>&1 || true
  sysctl -w net.core.busy_poll=50 >/dev/null 2>&1 || true
  sysctl -w net.core.busy_read=50 >/dev/null 2>&1 || true
  if [[ -d "/sys/class/net/$WAN/queues" ]]; then
    for q in /sys/class/net/"$WAN"/queues/rx-*; do
      echo 4096 >"${q}/rps_flow_cnt" 2>/dev/null || true
    done
  fi
  echo "tuned=true wan=$WAN ip=${1:-}" >"$STATE"
  echo "firewalla-tune=applied backend=array-firewall ip=${1:-}"
}

restore_tune() {
  sysctl -w vm.swappiness=60 >/dev/null 2>&1 || true
  sysctl -w net.core.busy_poll=0 >/dev/null 2>&1 || true
  sysctl -w net.core.busy_read=0 >/dev/null 2>&1 || true
  echo "tuned=false" >"$STATE"
  echo "firewalla-tune=restored"
}

case "${1:-status}" in
  apply) apply_tune "${2:-}" ;;
  restore|off) restore_tune ;;
  status)
    if [[ -f "$STATE" ]]; then cat "$STATE"; else echo "backend=array-firewall tuned=false"; fi
    ;;
  *)
    echo "Usage: $0 {apply [ip]|restore|status}"; exit 2
    ;;
esac
