#!/usr/bin/env bash
# Gateway performance tuning — kernel, conntrack, NIC offload (datapath stays on CPU/nft).
set -euo pipefail

CONF="/etc/array-firewall/array-firewall.conf"
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

WAN_IF="${WAN_IF:-eth1}"
LAN_IF="${LAN_IF:-eth0}"
STATE="/var/lib/array-firewall/perf-tune.state"

log() { printf '[perf-tune] %s\n' "$*"; }

apply_sysctl() {
  modprobe tcp_bbr 2>/dev/null || true
  local f="/etc/sysctl.d/99-array-firewall-perf.conf"
  cat >"$f" <<EOF
# array-firewall gateway performance
net.core.netdev_max_backlog=250000
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=1048576
net.core.wmem_default=1048576
net.core.somaxconn=4096
net.ipv4.tcp_rmem=4096 1048576 16777216
net.ipv4.tcp_wmem=4096 1048576 16777216
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.netfilter.nf_conntrack_max=262144
net.netfilter.nf_conntrack_tcp_timeout_established=7200
EOF
  if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    echo "net.ipv4.tcp_congestion_control=bbr" >>"$f"
    echo "net.core.default_qdisc=fq" >>"$f"
  fi
  sysctl -p "$f" >/dev/null 2>&1 || true
  log "sysctl applied ($(grep -c '=' "$f") keys)"
  local rmem
  rmem="$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)"
  if [[ "${rmem:-0}" -lt 1048576 ]]; then
    log "WARN: net.core.rmem_max=${rmem} — run /opt/array-firewall/scripts/tune-host-gw.sh on Proxmox host and reboot CT"
  fi
}

tune_nic() {
  local ifc="$1"
  [[ -d "/sys/class/net/$ifc" ]] || return 0
  ip link set "$ifc" up 2>/dev/null || true
  # Match veth bridge MTU (9000 inside CT vs 1500 on wire causes silent perf loss).
  if [[ "$ifc" == "${WAN_IF:-eth1}" ]]; then
    ip link set "$ifc" mtu 1500 2>/dev/null || true
  fi
  if command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$ifc" gro on gso on tso on rx on tx on sg on 2>/dev/null || true
    ethtool -G "$ifc" rx 4096 tx 4096 2>/dev/null || \
      ethtool -G "$ifc" rx 1024 tx 1024 2>/dev/null || true
    log "ethtool tuned $ifc"
  fi
}

status_json() {
  local cc bbr_avail
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  bbr_avail=0
  grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null && bbr_avail=1
  printf '{"congestion_control":"%s","bbr_available":%s,"wan_if":"%s","lan_if":"%s"}' \
    "$cc" "$bbr_avail" "$WAN_IF" "$LAN_IF"
}

case "${1:-apply}" in
  apply)
    modprobe tcp_bbr 2>/dev/null || true
    modprobe sch_cake 2>/dev/null || true
    apply_sysctl
    tune_nic "$WAN_IF"
    tune_nic "$LAN_IF"
    mkdir -p "$(dirname "$STATE")"
    date -Iseconds >"$STATE"
    log "done wan=$WAN_IF lan=$LAN_IF cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo ?)"
    ;;
  status)
    echo "wan=$WAN_IF cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo ?)"
    ethtool -k "$WAN_IF" 2>/dev/null | grep -E '^(rx-checksumming|tcp-segmentation-offload|generic-segmentation-offload)' || true
    ;;
  json)
    status_json
    ;;
  *)
    echo "Usage: $0 {apply|status|json}" >&2
    exit 2
    ;;
esac
