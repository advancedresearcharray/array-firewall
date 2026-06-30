#!/usr/bin/env bash
# DSCP EF (Expedited Forwarding) on Xbox game ports — MoCA/QoS path priority.
set -euo pipefail

CONF="/etc/array-firewall/array-firewall.conf"
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

LAN="${LAN_IF:-eth0}"
WAN="${WAN_IF:-eth1}"
XBOX_IP="${XBOX_IP:-192.0.2.65}"
NFT="/var/lib/array-firewall/dscp-gaming.nft"
STATE="/var/lib/array-firewall/dscp-gaming.state"

UDP_PORTS="${XBOX_UDP_PORTS:-88 500 3074 3075 3544 4500 53 9002}"
TCP_PORTS="${XBOX_TCP_PORTS:-3074 80 53 443 2869}"

log() { printf '[moca-tune] %s\n' "$*"; }

render_nft() {
  local udp_set tcp_set
  udp_set=$(echo "$UDP_PORTS" | tr ' ' ',')
  tcp_set=$(echo "$TCP_PORTS" | tr ' ' ',')
  cat >"$NFT" <<EOF
table inet dscp_gaming {
  chain forward {
    type filter hook forward priority mangle - 5; policy accept;
    iifname "$LAN" oifname "$WAN" ip saddr $XBOX_IP udp dport { $udp_set } ip dscp set ef
    iifname "$LAN" oifname "$WAN" ip saddr $XBOX_IP tcp dport { $tcp_set } ip dscp set ef
    iifname "$WAN" oifname "$LAN" ip daddr $XBOX_IP udp sport { $udp_set } ip dscp set ef
    iifname "$WAN" oifname "$LAN" ip daddr $XBOX_IP tcp sport { $tcp_set } ip dscp set ef
  }
}
EOF
}

apply_dscp() {
  nft delete table inet dscp_gaming 2>/dev/null || true
  render_nft
  nft -f "$NFT"
  echo "active=true dscp=ef xbox=$XBOX_IP" >"$STATE"
  log "DSCP EF applied for Xbox game ports"
  echo "moca-qos=ef backend=array-firewall xbox=$XBOX_IP"
}

relax_dscp() {
  nft delete table inet dscp_gaming 2>/dev/null || true
  echo "active=false" >"$STATE"
  log "DSCP relaxed"
  echo "moca-qos=relaxed"
}

case "${1:-status}" in
  apply) apply_dscp ;;
  relax|off) relax_dscp ;;
  status)
    if [[ -f "$STATE" ]]; then cat "$STATE"; else echo "backend=array-firewall moca=false"; fi
    nft list table inet dscp_gaming 2>/dev/null | head -8 || true
    ;;
  *)
    echo "Usage: $0 {apply|relax|status}"; exit 2
    ;;
esac
