#!/usr/bin/env bash
# nftables packet shield — drops inbound tiny floods to Xbox game ports.
set -euo pipefail

CONF="${ARRAY_FW_CONF:-/etc/array-firewall/array-firewall.conf}"
STATE="/var/lib/array-firewall/packet-shield.state"
TABLE="inet gaming"

# shellcheck disable=SC1090
source "$CONF"

log() { printf '[packet-shield-nft] %s\n' "$*"; }

need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Run as root"; exit 1; }; }

require_xbox() {
  if [[ -z "${XBOX_IP:-}" ]]; then
    echo "XBOX_IP not set in $CONF" >&2
    exit 1
  fi
}

udp_ports_csv() {
  local IFS=,
  echo "${XBOX_UDP_PORTS[*]}"
}

tcp_ports_csv() {
  local IFS=,
  echo "${XBOX_TCP_PORTS[*]}"
}

cmd_status() {
  [[ -f "$STATE" ]] && cat "$STATE" || echo "mode=inactive"
  nft list table "$TABLE" 2>/dev/null | head -40 || echo "table inactive"
}

cmd_relax() {
  need_root
  nft delete table "$TABLE" 2>/dev/null || true
  rm -f "$STATE" "/var/lib/array-firewall/suspicious-peers.txt"
  log "RELAX — gaming nft table removed"
}

write_peer_list() {
  local peers_file="/var/lib/array-firewall/suspicious-peers.txt"
  mkdir -p "$(dirname "$peers_file")"
  if [[ $# -gt 0 ]]; then
    printf '%s\n' "$@" >"$peers_file"
  else
    rm -f "$peers_file"
  fi
}

cmd_shield() {
  need_root
  require_xbox
  local level="${1:-normal}"
  shift || true
  cmd_relax
  write_peer_list "$@"

  local tiny_rate=30
  local tiny_burst=60
  local whitelist=0
  local peer_strict=0
  local peers_file="/var/lib/array-firewall/suspicious-peers.txt"
  case "$level" in
    strict|whitelist)
      whitelist=1
      tiny_rate=12
      tiny_burst=24
      ;;
    peer-strict)
      peer_strict=1
      tiny_rate=20
      tiny_burst=40
      ;;
    normal|*) ;;
  esac

  nft add table "$TABLE"
  nft add chain "$TABLE" xbox_shield '{ type filter hook forward priority filter; policy accept; }'
  nft add chain "$TABLE" xbox_in '{ }'

  nft add rule "$TABLE" xbox_shield ip daddr "$XBOX_IP" jump xbox_in
  nft add rule "$TABLE" xbox_shield ip6 daddr "$XBOX_IP" jump xbox_in 2>/dev/null || true

  nft add rule "$TABLE" xbox_in ct state established,related accept

  if [[ "$peer_strict" == "1" && -f "$peers_file" ]]; then
    nft add set "$TABLE" suspicious_peers '{ type ipv4_addr; flags dynamic; size 64; }'
    while IFS= read -r peer_ip || [[ -n "$peer_ip" ]]; do
      peer_ip="${peer_ip%%#*}"
      peer_ip="${peer_ip// /}"
      [[ -n "$peer_ip" ]] || continue
      nft add element "$TABLE" suspicious_peers "{ $peer_ip }" 2>/dev/null || true
    done < "$peers_file"
    # Hard drop tiny probes from flagged game-peer hosts (VPS kick tools)
    nft add rule "$TABLE" xbox_in ip saddr @suspicious_peers ip protocol udp \
      udp length 0-"$TINY_MAX" counter drop comment '"peer tiny probe"'
    nft add rule "$TABLE" xbox_in ip saddr @suspicious_peers ip protocol udp \
      limit rate 15/second burst 30 packets accept
    nft add rule "$TABLE" xbox_in ip saddr @suspicious_peers ip protocol udp \
      counter drop comment '"peer flood cap"'
    nft add rule "$TABLE" xbox_in ip saddr @suspicious_peers ip protocol tcp tcp flags syn \
      meta length 0-$((TINY_MAX + 60)) counter drop comment '"peer tcp probe"'
  fi

  local udp_set tcp_set
  udp_set="{ $(udp_ports_csv) }"
  tcp_set="{ $(tcp_ports_csv) }"

  # Rate-limited tiny UDP on game ports, then hard drop remainder ≤ TINY_MAX
  nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" \
    udp length 0-"$TINY_MAX" limit rate "${tiny_rate}/second" burst "${tiny_burst} packets" accept
  nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" \
    udp length 0-"$TINY_MAX" drop

  # Tiny TCP SYN on game/aux ports (meta length — tcp length expr unavailable in nft 1.0.6)
  local tcp_meta_max=$((TINY_MAX + 60))
  nft add rule "$TABLE" xbox_in ip protocol tcp tcp dport "$tcp_set" tcp flags syn \
    meta length 0-"$tcp_meta_max" limit rate "${tiny_rate}/second" burst "${tiny_burst} packets" accept
  nft add rule "$TABLE" xbox_in ip protocol tcp tcp dport "$tcp_set" tcp flags syn \
    meta length 0-"$tcp_meta_max" drop

  # Normal game traffic
  nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" accept
  nft add rule "$TABLE" xbox_in ip protocol tcp tcp dport "$tcp_set" ct state new,established,related accept

  if [[ "$whitelist" == "1" ]]; then
    # Strict/whitelist: drop anything not accepted above (non-game ports, ICMP, etc.)
    nft add rule "$TABLE" xbox_in counter drop comment '"non-game inbound"'
  else
    # Residual tiny UDP/TCP caps — rate-limit floods but allow other traffic
    nft add rule "$TABLE" xbox_in ip protocol udp udp length 0-"$TINY_MAX" drop
    nft add rule "$TABLE" xbox_in ip protocol udp limit rate 600/second burst 1200 packets accept
    nft add rule "$TABLE" xbox_in ip protocol udp drop
    nft add rule "$TABLE" xbox_in ip protocol tcp tcp flags syn limit rate 80/second burst 160 packets accept
    nft add rule "$TABLE" xbox_in ip protocol tcp tcp flags syn drop
    nft add rule "$TABLE" xbox_in accept
  fi

  {
    echo "mode=shield"
    echo "level=${level}"
    echo "whitelist_non_game=${whitelist}"
    echo "peer_strict=${peer_strict}"
    if [[ "$peer_strict" == "1" && -f "$peers_file" ]]; then
      echo "suspicious_peers=$(grep -cve '^[[:space:]]*$' "$peers_file" 2>/dev/null || echo 0)"
    fi
    echo "backend=nftables"
    echo "tiny_max_bytes=${TINY_MAX}"
    echo "tiny_rate_per_src=${tiny_rate}/sec"
    echo "xbox_ip=${XBOX_IP}"
    echo "updated=$(date -Is)"
  } >"$STATE"

  if [[ "$whitelist" == "1" ]]; then
    log "SHIELD (${level}) — nft forward shield active for ${XBOX_IP}; non-game inbound dropped"
  elif [[ "$peer_strict" == "1" ]]; then
    log "SHIELD (${level}) — nft forward shield active for ${XBOX_IP}; aggressive peer probe drop"
  else
    log "SHIELD (${level}) — nft forward shield active for ${XBOX_IP}"
  fi
}

case "${1:-status}" in
  status) cmd_status ;;
  shield) shift; cmd_shield "${1:-normal}" ;;
  strict) cmd_shield strict ;;
  peer-strict) cmd_shield peer-strict ;;
  relax|off) cmd_relax ;;
  *) echo "Usage: $0 {status|shield [normal|strict|whitelist|peer-strict]|strict|peer-strict|relax}"; exit 2 ;;
esac
