#!/usr/bin/env bash
# nftables packet shield — drops inbound tiny floods to Xbox game ports.
set -euo pipefail

CONF="${ARRAY_FW_CONF:-/etc/array-firewall/array-firewall.conf}"
STATE="/var/lib/array-firewall/packet-shield.state"
TABLE="inet gaming"
PERSISTENT_PEERS="/var/lib/array-firewall/persistent-peers.txt"
MM_ALLOWLIST="/opt/array-firewall/config/matchmaking-allowlist.json"
IN_MATCH_ALLOWLIST="/opt/array-firewall/config/in-match-allowlist.json"
PER_SRC_UDP_RATE="${PER_SRC_UDP_RATE:-500}"
CONN_CAP_PER_PEER="${CONN_CAP_PER_PEER:-40}"
PROBE_SINK_PORT="${PROBE_SINK_PORT:-39217}"
HONEYPOT_TCP="{ 23, 21, 445, 135, 139, 3389, 5900, 8080, 8443, 31337, 4444, 5555, 6667 }"

# shellcheck disable=SC1090
source "$CONF"

log() { printf '[packet-shield-nft] %s\n' "$*"; }

ensure_wan_nat_py() {
  command -v python3 >/dev/null 2>&1 || return 0
  python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/array-firewall/api")
from lib import nat
nat.ensure_wan_nat()
PY
}

need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Run as root"; exit 1; }; }

require_xbox() {
  if [[ -z "${XBOX_IP:-}" ]]; then
    echo "XBOX_IP not set in $CONF" >&2
    exit 1
  fi
}

sentinel_tiny_only() {
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/array-firewall/api")
from lib import policies
raise SystemExit(0 if policies.sentinel_tiny_only() else 1)
PY
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
  nft list table "$TABLE" 2>/dev/null | head -80 || echo "table inactive"
  nft list chain ip nat probe_blackhole 2>/dev/null | head -20 || true
}

relax_honeypot_nat() {
  nft flush chain ip nat probe_blackhole 2>/dev/null || true
}

setup_honeypot_nat() {
  ensure_wan_nat_py
  local gw="${LAN_GATEWAY_IP:-192.168.167.1}"
  local wan_if="${WAN_IF:-eth1}"
  local sink="127.0.0.1:${PROBE_SINK_PORT}"
  nft list table ip nat >/dev/null 2>&1 || nft add table ip nat
  if ! nft list chain ip nat probe_blackhole >/dev/null 2>&1; then
    nft add chain ip nat probe_blackhole '{ type nat hook prerouting priority dstnat - 5; policy accept; }'
  fi
  nft flush chain ip nat probe_blackhole
  # Internet scans hit WAN IP (eth1) before DMZ DNAT — sink obvious probe ports here.
  nft add rule ip nat probe_blackhole iifname "$wan_if" tcp dport "$HONEYPOT_TCP" \
    dnat to "$sink" comment '"wan-honeypot-tcp-sink"'
  nft add rule ip nat probe_blackhole ip daddr "$XBOX_IP" tcp dport "$HONEYPOT_TCP" \
    dnat to "${gw}:${PROBE_SINK_PORT}" comment '"honeypot-tcp-sink"'
  systemctl enable array-firewall-probe-sink 2>/dev/null || true
  systemctl start array-firewall-probe-sink 2>/dev/null || true
}

cmd_relax() {
  need_root
  nft delete table "$TABLE" 2>/dev/null || true
  relax_honeypot_nat
  rm -f "$STATE" "/var/lib/array-firewall/suspicious-peers.txt"
  log "RELAX — gaming nft table removed (persistent peer list retained)"
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

merge_peer_ips() {
  local -a merged=()
  local -A seen=()
  local ip
  for ip in "$@"; do
    ip="${ip%%#*}"
    ip="${ip// /}"
    [[ -n "$ip" ]] || continue
    [[ -n "${seen[$ip]+x}" ]] && continue
    seen[$ip]=1
    merged+=("$ip")
  done
  if [[ -f "$PERSISTENT_PEERS" ]]; then
    while IFS= read -r ip || [[ -n "$ip" ]]; do
      ip="${ip%%#*}"
      ip="${ip// /}"
      [[ -n "$ip" ]] || continue
      [[ -n "${seen[$ip]+x}" ]] && continue
      seen[$ip]=1
      merged+=("$ip")
    done <"$PERSISTENT_PEERS"
  fi
  printf '%s\n' "${merged[@]}"
}

load_allowlist_cidrs() {
  local file="${1:-$MM_ALLOWLIST}"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  python3 - "$file" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
for c in data.get("cidrs") or []:
    print(c.strip())
PY
}

load_mm_cidrs() {
  load_allowlist_cidrs "$MM_ALLOWLIST"
}

add_non_game_syn_rst() {
  # Remaining TCP SYN (non-game ports) — send RST instead of silent drop (port scan feedback).
  nft add rule "$TABLE" xbox_in ip protocol tcp tcp flags syn \
    counter name probe_tcp_rst reject with tcp reset comment '"non-game syn rst"'
}

add_wan_scan_policy() {
  # DMZ exposes WAN IP — block internet port scans; only Xbox Live / game ports reach console.
  local wan_if="${WAN_IF:-eth1}"
  local udp_set="$1"
  local tcp_set="$2"

  nft add counter "$TABLE" wan_scan_drop
  nft add rule "$TABLE" xbox_in iifname "$wan_if" ip protocol udp udp dport "$udp_set" accept \
    comment '"wan game udp"'
  nft add rule "$TABLE" xbox_in iifname "$wan_if" ip protocol tcp tcp dport "$tcp_set" \
    ct state new,established,related accept comment '"wan game tcp"'
  nft add rule "$TABLE" xbox_in iifname "$wan_if" ip protocol udp udp dport "$HONEYPOT_TCP" \
    counter name probe_udp_sink drop comment '"wan honeypot udp"'
  nft add rule "$TABLE" xbox_in iifname "$wan_if" ip protocol tcp tcp dport "$HONEYPOT_TCP" \
    counter name wan_scan_drop drop comment '"wan honeypot tcp"'
  nft add rule "$TABLE" xbox_in iifname "$wan_if" ip protocol tcp tcp flags syn \
    counter name probe_tcp_rst reject with tcp reset comment '"wan scan syn rst"'
  nft add rule "$TABLE" xbox_in iifname "$wan_if" counter name wan_scan_drop drop \
    comment '"wan unsolicited drop"'
  log "WAN scan filter — only Xbox game ports reach console from ${wan_if}"
}

setup_wan_scanner_block() {
  nft add set "$TABLE" wan_scanners '{ type ipv4_addr; flags timeout; size 4096; }'
  nft add counter "$TABLE" wan_scanner_block
  local elems=""
  if command -v python3 >/dev/null 2>&1; then
    elems="$(python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/array-firewall/api")
from lib import wan_scan_block
print(wan_scan_block.render_nft_elements())
PY
)"
  fi
  if [[ -n "$elems" ]]; then
    nft add element "$TABLE" wan_scanners "{ $elems }" 2>/dev/null || true
  fi
}

setup_blocked_subnets() {
  nft add set "$TABLE" blocked_subnets '{ type ipv4_addr; flags interval, timeout; size 65536; }'
  nft add counter "$TABLE" subnet_block
  local elems=""
  if command -v python3 >/dev/null 2>&1; then
    elems="$(python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/array-firewall/api")
from lib import subnet_blocklist
print(subnet_blocklist.render_nft_elements())
PY
)"
  fi
  if [[ -n "$elems" ]]; then
    nft add element "$TABLE" blocked_subnets "{ $elems }" 2>/dev/null || true
  fi
}

cmd_shield() {
  need_root
  require_xbox
  ensure_wan_nat_py
  local level="${1:-normal}"
  shift || true

    if sentinel_tiny_only; then
    level="normal"
    set --
    if [[ -f "$STATE" ]] && grep -q '^mode=shield$' "$STATE" && grep -q '^level=normal$' "$STATE"; then
      if nft list set "$TABLE" wan_scanners >/dev/null 2>&1 \
        && nft list set "$TABLE" blocked_subnets >/dev/null 2>&1; then
        log "SHIELD (normal/tiny-only) already active — skip rebuild"
        return 0
      fi
      log "SHIELD active but wan_scanners/blocked_subnets missing — rebuilding"
    fi
  fi

  local -a session_peers=("$@")
  mapfile -t all_peers < <(merge_peer_ips "${session_peers[@]}")
  if ((${#all_peers[@]} > 0)); then
    write_peer_list "${all_peers[@]}"
  else
    write_peer_list
  fi

  cmd_relax

  local tiny_rate=30
  local tiny_burst=60
  local whitelist=0
  local peer_strict=0
  local matchmaking=0
  local console_mode=0
  local in_match_mode=0
  local allowlist_file="$MM_ALLOWLIST"
  local peers_file="/var/lib/array-firewall/suspicious-peers.txt"
  case "$level" in
    in-match)
      in_match_mode=1
      console_mode=1
      matchmaking=1
      whitelist=1
      allowlist_file="$IN_MATCH_ALLOWLIST"
      tiny_rate=12
      tiny_burst=24
      ;;
    console)
      console_mode=1
      matchmaking=1
      whitelist=1
      tiny_rate=12
      tiny_burst=24
      ;;
    matchmaking)
      matchmaking=1
      console_mode=1
      whitelist=1
      tiny_rate=20
      tiny_burst=40
      ;;
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

  setup_honeypot_nat

  local wan_if="${WAN_IF:-eth1}"
  local xbox_dmz=0
  if command -v python3 >/dev/null 2>&1; then
    xbox_dmz="$(python3 - <<PY
import json
from pathlib import Path
p = Path("/var/lib/array-firewall/policies.json")
c = Path("/etc/array-firewall/array-firewall.conf")
xbox = ""
if c.is_file():
    for line in c.read_text().splitlines():
        if line.startswith("XBOX_IP="):
            xbox = line.split("=", 1)[1].strip()
if p.is_file():
    d = json.loads(p.read_text())
    dmz = d.get("dmz") or {}
    if dmz.get("enabled") and (dmz.get("host_ip") or "") == xbox:
        print("1")
        raise SystemExit
print("0")
PY
)"
  fi

  nft add table "$TABLE"
  nft add chain "$TABLE" xbox_shield '{ type filter hook forward priority filter; policy accept; }'
  nft add chain "$TABLE" xbox_in '{ }'

  nft add counter "$TABLE" probe_tcp_rst
  nft add counter "$TABLE" probe_udp_sink

  nft add rule "$TABLE" xbox_shield ip daddr "$XBOX_IP" jump xbox_in
  nft add rule "$TABLE" xbox_shield ip6 daddr "$XBOX_IP" jump xbox_in 2>/dev/null || true

  nft add rule "$TABLE" xbox_in ct state established,related accept
  setup_wan_scanner_block
  setup_blocked_subnets
  nft add rule "$TABLE" xbox_in ip saddr @wan_scanners counter name wan_scanner_block drop \
    comment '"wan-scanner-block"'
  nft add rule "$TABLE" xbox_in ip saddr @blocked_subnets counter name subnet_block drop \
    comment '"auto-blocked-subnet"'
  # Full WAN DMZ DNAT marks every inbound scan as dnat — do not blanket-accept those.
  if [[ "$xbox_dmz" != "1" ]]; then
    nft add rule "$TABLE" xbox_in ct status dnat accept comment '"wan port-forward"'
  fi

  local lan_cidr="${LAN_CIDR:-}"
  if [[ -z "$lan_cidr" && -n "${XBOX_IP:-}" ]]; then
    lan_cidr="${XBOX_IP%.*}.0/24"
  fi
  if [[ -n "$lan_cidr" ]]; then
    nft add rule "$TABLE" xbox_in ip saddr "$lan_cidr" accept comment '"lan-local"'
  fi

  local udp_set tcp_set
  udp_set="{ $(udp_ports_csv) }"
  tcp_set="{ $(tcp_ports_csv) }"
  local tcp_meta_max=$((TINY_MAX + 60))

  # Tiny probes on game ports — drop before any wide accept (including WAN DMZ).
  nft add counter "$TABLE" global_tiny_drop
  nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" \
    udp length 0-"$TINY_MAX" counter name global_tiny_drop drop \
    comment '"global tiny udp game port"'
  nft add rule "$TABLE" xbox_in ip protocol tcp tcp dport "$tcp_set" tcp flags syn \
    meta length 0-"$tcp_meta_max" counter name global_tiny_drop drop \
    comment '"global tiny tcp game port"'

  if [[ "$xbox_dmz" == "1" ]]; then
    add_wan_scan_policy "$udp_set" "$tcp_set"
  fi

  if [[ "$matchmaking" == "1" || "$console_mode" == "1" ]]; then
    mapfile -t mm_cidrs < <(load_allowlist_cidrs "$allowlist_file")
    if ((${#mm_cidrs[@]} > 0)); then
      local mm_csv
      mm_csv=$(IFS=,; echo "${mm_cidrs[*]}")
      nft add set "$TABLE" mm_allow '{ type ipv4_addr; flags interval; }'
      nft add element "$TABLE" mm_allow "{ $mm_csv }" 2>/dev/null || true
      local service_udp="{ 53, 88, 500, 3544, 4500, 9002 }"
      local service_tcp="{ 53, 80, 443, 2869 }"
      # Xbox Live / Azure — service ports only (never P2P game ports).
      nft add rule "$TABLE" xbox_in ip saddr @mm_allow ip protocol tcp tcp dport "$service_tcp" accept \
        comment '"allowlist service tcp"'
      nft add rule "$TABLE" xbox_in ip saddr @mm_allow ip protocol udp udp dport "$service_udp" accept \
        comment '"allowlist service udp"'

      # Outbound: explicit allow for dedicated-server / allowlisted backends (default accept).
      nft add chain "$TABLE" xbox_out '{ }'
      nft add rule "$TABLE" xbox_shield ip saddr "$XBOX_IP" jump xbox_out
      nft add rule "$TABLE" xbox_out ip daddr @mm_allow ip protocol udp udp dport "$udp_set" accept \
        comment '"allowlist game udp out"'
      nft add rule "$TABLE" xbox_out ip daddr @mm_allow ip protocol tcp tcp dport "$tcp_set" accept \
        comment '"allowlist game tcp out"'
      nft add rule "$TABLE" xbox_out accept comment '"xbox outbound default accept"'
    fi
  fi

  # Block all inbound P2P to Xbox — unless Open NAT mode (Xbox Live needs 3074 inbound).
  local xbox_nat_open=0
  if [[ "${XBOX_NAT_OPEN:-0}" == "1" ]]; then
    xbox_nat_open=1
  elif command -v python3 >/dev/null 2>&1; then
    xbox_nat_open="$(python3 - <<'PY'
import json
from pathlib import Path
p = Path("/var/lib/array-firewall/policies.json")
if p.is_file():
    g = json.loads(p.read_text()).get("gaming") or {}
    print("1" if g.get("nat_open") else "0")
else:
    print("0")
PY
)"
  fi
  if [[ "$xbox_nat_open" != "1" && "$xbox_dmz" != "1" ]]; then
    nft add counter "$TABLE" p2p_block
    nft add rule "$TABLE" xbox_in ip protocol udp udp dport { 3074, 3075 } \
      counter name p2p_block drop comment '"block all p2p udp"'
    nft add rule "$TABLE" xbox_in ip protocol tcp tcp dport 3074 tcp flags syn \
      counter name p2p_block drop comment '"block all p2p tcp syn"'
    nft add rule "$TABLE" xbox_in ip protocol udp udp dport 1024-65535 udp dport != { 53, 88, 500, 3544, 4500, 9002 } \
      counter name p2p_block drop comment '"block high-port p2p udp"'
  else
    log "NAT open — inbound Xbox Live ports allowed (3074/88/500/3544/4500)"
  fi

  if [[ "$peer_strict" == "1" || ${#all_peers[@]} -gt 0 ]] && [[ "$xbox_dmz" != "1" ]]; then
    nft add set "$TABLE" suspicious_peers '{ type ipv4_addr; flags dynamic; size 256; }'
    for peer_ip in "${all_peers[@]}"; do
      [[ -n "$peer_ip" ]] || continue
      nft add element "$TABLE" suspicious_peers "{ $peer_ip }" 2>/dev/null || true
    done
    nft add rule "$TABLE" xbox_in ip saddr @suspicious_peers ip protocol udp \
      udp length 0-"$TINY_MAX" counter drop comment '"peer tiny probe"'
    nft add rule "$TABLE" xbox_in ip saddr @suspicious_peers ip protocol udp \
      limit rate 15/second burst 30 packets accept
    nft add rule "$TABLE" xbox_in ip saddr @suspicious_peers ip protocol udp \
      counter drop comment '"peer flood cap"'
    nft add rule "$TABLE" xbox_in ip saddr @suspicious_peers ip protocol tcp tcp flags syn \
      meta length 0-$((TINY_MAX + 60)) counter reject with tcp reset comment '"peer tcp probe rst"'
    nft add rule "$TABLE" xbox_in ip saddr @suspicious_peers counter drop comment '"persistent peer block"'
  fi

  if [[ "$console_mode" == "1" ]]; then
    nft add counter "$TABLE" console_non_game_drop
    if [[ "$xbox_dmz" != "1" ]]; then
      nft add counter "$TABLE" console_p2p_drop
      # Non-allowlist P2P-shaped game-port traffic — not real lobby players; drop all sizes.
      nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" \
        counter name console_p2p_drop drop comment '"console non-allowlist game udp"'
      nft add rule "$TABLE" xbox_in ip protocol tcp tcp dport "$tcp_set" \
        counter name console_p2p_drop drop comment '"console non-allowlist game tcp"'
    fi
  else
    nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" \
      udp length 0-"$TINY_MAX" limit rate "${tiny_rate}/second" burst "${tiny_burst} packets" accept
    nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" \
      udp length 0-"$TINY_MAX" counter drop comment '"tiny udp game"'
    nft add rule "$TABLE" xbox_in ip protocol tcp tcp dport "$tcp_set" tcp flags syn \
      meta length 0-"$tcp_meta_max" limit rate "${tiny_rate}/second" burst "${tiny_burst} packets" accept
    nft add rule "$TABLE" xbox_in ip protocol tcp tcp dport "$tcp_set" tcp flags syn \
      meta length 0-"$tcp_meta_max" counter drop comment '"tiny tcp game"'

    nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" \
      meter xbox_udp_per_src "{ ip saddr limit rate over ${PER_SRC_UDP_RATE}/second burst 200 packets }" accept \
      comment '"per-src game udp rate"'
    nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" \
      counter drop comment '"per-src game udp flood"'

    nft add rule "$TABLE" xbox_in ct state new ip protocol udp \
      meter xbox_conn_cap "{ ip saddr ct count over ${CONN_CAP_PER_PEER} }" drop \
      comment '"conn cap per peer"'

    nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$udp_set" accept
    nft add rule "$TABLE" xbox_in ip protocol tcp tcp dport "$tcp_set" ct state new,established,related accept
  fi

  # Obvious probe UDP ports (not game) — log and drop
  nft add rule "$TABLE" xbox_in ip protocol udp udp dport "$HONEYPOT_TCP" \
    counter name probe_udp_sink drop comment '"honeypot udp sink"'

  if [[ "$whitelist" == "1" ]]; then
    add_non_game_syn_rst
    if [[ "$console_mode" == "1" ]]; then
      nft add rule "$TABLE" xbox_in counter name console_non_game_drop drop comment '"console non-game inbound"'
    else
      nft add rule "$TABLE" xbox_in counter drop comment '"non-game inbound"'
    fi
  else
    nft add rule "$TABLE" xbox_in ip protocol udp udp length 0-"$TINY_MAX" drop
    nft add rule "$TABLE" xbox_in ip protocol udp limit rate 600/second burst 1200 packets accept
    nft add rule "$TABLE" xbox_in ip protocol udp drop
    add_non_game_syn_rst
    nft add rule "$TABLE" xbox_in accept
  fi

  {
    echo "mode=shield"
    echo "level=${level}"
    echo "whitelist_non_game=${whitelist}"
    echo "console_mode=${console_mode}"
    echo "in_match_mode=${in_match_mode}"
    echo "allowlist=${allowlist_file}"
    echo "peer_strict=${peer_strict}"
    echo "matchmaking_allowlist=${matchmaking}"
    echo "honeypot_sink_port=${PROBE_SINK_PORT}"
    echo "tcp_rst_non_game=1"
    echo "persistent_peers=$(grep -cve '^[[:space:]]*$' "$PERSISTENT_PEERS" 2>/dev/null || echo 0)"
    if [[ -f "$peers_file" ]]; then
      echo "suspicious_peers=$(grep -cve '^[[:space:]]*$' "$peers_file" 2>/dev/null || echo 0)"
    fi
    echo "p2p_block=$([[ "$xbox_nat_open" == "1" || "$xbox_dmz" == "1" ]] && echo off || echo all_inbound)"
    echo "xbox_wan_dmz=$([[ "$xbox_dmz" == "1" ]] && echo 1 || echo 0)"
    echo "xbox_out_allowlist=1"
    echo "backend=nftables"
    echo "tiny_max_bytes=${TINY_MAX}"
    echo "tiny_rate_per_src=${tiny_rate}/sec"
    echo "per_src_udp_rate=${PER_SRC_UDP_RATE}/sec"
    echo "conn_cap_per_peer=${CONN_CAP_PER_PEER}"
    echo "xbox_ip=${XBOX_IP}"
    echo "tiny_packet_only=$(sentinel_tiny_only && echo 1 || echo 0)"
    echo "updated=$(date -Is)"
  } >"$STATE"

  if ! sentinel_tiny_only; then
    if command -v conntrack >/dev/null 2>&1; then
      conntrack -D -d "$XBOX_IP" 2>/dev/null || true
      conntrack -D -s "$XBOX_IP" 2>/dev/null || true
    fi
  fi

  log "SHIELD (${level}) active for ${XBOX_IP} — RST on non-game SYN, honeypot :${PROBE_SINK_PORT}"
}

case "${1:-status}" in
  status) cmd_status ;;
  shield) shift; cmd_shield "$@" ;;
  console) cmd_shield console ;;
  in-match) cmd_shield in-match ;;
  strict) cmd_shield strict ;;
  peer-strict) cmd_shield peer-strict ;;
  matchmaking) cmd_shield matchmaking ;;
  relax|off) cmd_relax ;;
  *) echo "Usage: $0 {status|shield [normal|strict|whitelist|peer-strict|matchmaking|console [peer-ip...]]|console|strict|peer-strict|matchmaking|relax}"; exit 2 ;;
esac
