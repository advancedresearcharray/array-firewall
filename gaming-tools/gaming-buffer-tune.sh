#!/usr/bin/env bash
# fq_codel + sysctl buffer profiles for Xbox (matchmaking desync/kick mitigation).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONF="/etc/array-firewall/array-firewall.conf"
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

WAN="${WAN_IF:-eth1}"
IFB="${IFB_DEV:-ifb0}"
XBOX_IP="${XBOX_IP:-192.168.167.65}"
STATE="/var/lib/array-firewall/buffer-tune.state"

log() { printf '[buffer-tune] %s\n' "$*"; }

fq_params() {
  local target="$1" interval="$2" limit="$3" mem="$4"
  for dev in "$WAN" "$IFB"; do
    tc qdisc change dev "$dev" parent 1:10 handle 10: fq_codel \
      limit "$limit" flows 1024 quantum 1514 target "${target}ms" interval "${interval}ms" memory_limit "$mem" 2>/dev/null || true
  done
}

apply_profile() {
  local profile="${1:-normal}"
  case "$profile" in
    normal)
      fq_params 5 100 10240 32Mb
      sysctl -w net.core.netdev_max_backlog=250000 >/dev/null 2>&1 || true
      ;;
    light)
      fq_params 8 100 16384 48Mb
      sysctl -w net.core.netdev_max_backlog=300000 >/dev/null 2>&1 || true
      ;;
    desync)
      fq_params 3 80 8192 24Mb
      sysctl -w net.core.netdev_max_backlog=400000 >/dev/null 2>&1 || true
      sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1 || true
      ;;
    kick)
      fq_params 2 50 6144 16Mb
      sysctl -w net.core.netdev_max_backlog=500000 >/dev/null 2>&1 || true
      ;;
    *)
      echo "unknown profile=$profile"; return 2
      ;;
  esac
  echo "profile=$profile ip=${2:-$XBOX_IP} target=fq_codel backend=array-firewall" >"$STATE"
  log "applied profile=$profile xbox=${2:-$XBOX_IP}"
}

case "${1:-status}" in
  apply) apply_profile "${2:-normal}" "${3:-}" ;;
  off)
    apply_profile normal "$XBOX_IP"
    echo "buffers restored profile=normal" >"$STATE"
    echo "buffers restored (normal fq_codel)"
    ;;
  status)
    if [[ -f "$STATE" ]]; then cat "$STATE"; else echo "mode=stable backend=array-firewall"; fi
    tc qdisc show dev "$WAN" 2>/dev/null | grep -E '1:10|fq_codel' | head -3 || true
    ;;
  *)
    echo "Usage: $0 {apply <normal|light|desync|kick> [ip]|off|status}"; exit 2
    ;;
esac
