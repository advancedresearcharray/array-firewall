#!/usr/bin/env bash
# apply-qos.sh — five-tier AI traffic priority + CAKE download pipe.
set -euo pipefail

ACTION="${1:-apply}"
WAN="${WAN_IF:-eth1}"
IFB="${IFB_DEV:-ifb0}"
QOS_MODE="${QOS_MODE:-auto}"

MARK_XBOX="${MARK_XBOX:-0x10}"
MARK_WIRELESS="${MARK_WIRELESS:-0x14}"
MARK_LAPTOP="${MARK_LAPTOP:-0x20}"
MARK_PHONE="${MARK_PHONE:-0x28}"
MARK_OTHER="${MARK_OTHER:-0x30}"
MARK_HIGH="${MARK_HIGH:-$MARK_XBOX}"
MARK_MED="${MARK_MEDIUM:-$MARK_LAPTOP}"
MARK_LOW="${MARK_LOW:-$MARK_OTHER}"

WAN_UP="${WAN_UP:-1000mbit}"
WAN_DOWN="${WAN_DOWN:-1000mbit}"
XBOX_IP="${XBOX_IP:-192.168.167.65}"
HIGH_IPS="${HIGH_IPS:-$XBOX_IP}"
WIRELESS_IPS="${WIRELESS_IPS:-}"
LAPTOP_IPS="${LAPTOP_IPS:-}"
PHONE_IPS="${PHONE_IPS:-}"

XBOX_RATE="${XBOX_RATE:-400mbit}"
WIRELESS_RATE="${WIRELESS_RATE:-200mbit}"
LAPTOP_RATE="${LAPTOP_RATE:-150mbit}"
PHONE_RATE="${PHONE_RATE:-100mbit}"
OTHER_RATE="${OTHER_RATE:-50mbit}"
XBOX_CEIL="${XBOX_CEIL:-931mbit}"
WIRELESS_CEIL="${WIRELESS_CEIL:-836mbit}"
LAPTOP_CEIL="${LAPTOP_CEIL:-700mbit}"
PHONE_CEIL="${PHONE_CEIL:-500mbit}"
OTHER_CEIL="${OTHER_CEIL:-200mbit}"

STATE="/var/lib/array-firewall/qos-mode.state"

log() { printf '[apply-qos] %s\n' "$*"; }

has_cake() {
  modprobe sch_cake 2>/dev/null || true
  tc qdisc add dev lo root cake 2>/dev/null || return 1
  tc qdisc del dev lo root 2>/dev/null || true
  return 0
}

resolve_mode() {
  local m="${QOS_MODE:-auto}"
  if [[ "$m" == "auto" ]]; then
    if has_cake; then echo cake; else echo htb; fi
    return
  fi
  if [[ "$m" == "cake" ]] && has_cake; then echo cake; return; fi
  echo htb
}

leaf_qdisc() {
  local dev="$1" parent="$2" handle="$3" bandwidth="$4" tier="$5"
  local mode="$6"
  if [[ "$mode" == "cake" ]]; then
    local diffserv=""
    local rtt="25ms"
    local isolate="dual-dsthost"
    [[ "$tier" == "xbox" || "$tier" == "wireless" ]] && diffserv="diffserv4"
    [[ "$tier" == "xbox" ]] && rtt="5ms"
    [[ "$tier" == "wireless" ]] && rtt="20ms"
    # Xbox speed tests fan out to many server IPs; per-dst isolation caps each at ~rate/N.
    [[ "$tier" == "xbox" ]] && isolate="flowblind"
    local memlimit=""
    [[ "$tier" == "xbox" ]] && memlimit="memlimit 16mb"
    tc qdisc add dev "$dev" parent "$parent" handle "$handle" cake bandwidth "$bandwidth" $diffserv besteffort $isolate nat wash rtt "$rtt" split-gso $memlimit 2>/dev/null || \
      tc qdisc add dev "$dev" parent "$parent" handle "$handle" fq_codel limit 8192 flows 1024 quantum 1514 target 3ms interval 80ms memory_limit 24Mb
    return
  fi
  case "$tier" in
    xbox|wireless) tc qdisc add dev "$dev" parent "$parent" handle "$handle" fq_codel limit 8192 flows 1024 quantum 1514 target 3ms interval 80ms memory_limit 24Mb ;;
    laptop|phone) tc qdisc add dev "$dev" parent "$parent" handle "$handle" fq_codel limit 10240 flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ;;
    other) tc qdisc add dev "$dev" parent "$parent" handle "$handle" fq_codel limit 10240 flows 1024 quantum 1514 target 8ms interval 100ms memory_limit 32Mb ;;
  esac
}

clear_qos() {
  tc qdisc del dev "$WAN" root 2>/dev/null || true
  tc qdisc del dev "$WAN" ingress 2>/dev/null || true
  tc qdisc del dev "$IFB" root 2>/dev/null || true
  ip link set "$IFB" down 2>/dev/null || true
  nft delete table inet qos 2>/dev/null || true
  log "cleared"
}

setup_ifb() {
  modprobe ifb numifbs=1 2>/dev/null || modprobe ifb 2>/dev/null || true
  ip link add "$IFB" type ifb 2>/dev/null || true
  ip link set "$IFB" up txqueuelen 1000
}

add_ip_filters() {
  local dev="$1" flowid="$2" ips_csv="$3" prio="$4"
  [[ -n "$ips_csv" ]] || return 0
  IFS=',' read -ra _IPS <<< "$ips_csv"
  for ip in "${_IPS[@]}"; do
    [[ -n "$ip" ]] || continue
    tc filter add dev "$dev" protocol ip parent 1:0 prio "$prio" flower src_ip "$ip" flowid "$flowid" 2>/dev/null || \
      tc filter add dev "$dev" protocol ip parent 1:0 prio "$prio" u32 match ip src "$ip" flowid "$flowid" 2>/dev/null || true
    prio=$((prio + 1))
  done
}

apply_htb_filters() {
  local dev="$1" dir_label="$2"
  local prio=1

  if [[ "$dir_label" == "download" ]]; then
    return 0
  fi

  local marks=("$MARK_XBOX" "$MARK_WIRELESS" "$MARK_LAPTOP" "$MARK_PHONE" "$MARK_OTHER")
  local flowids=("1:10" "1:20" "1:30" "1:40" "1:50")
  local i
  # IP-based filters first (prio 1-9) — classify Xbox even before conntrack mark is set.
  add_ip_filters "$dev" "1:10" "$HIGH_IPS" 1; prio=10
  add_ip_filters "$dev" "1:20" "$WIRELESS_IPS" "$prio"; prio=$((prio + 10))
  add_ip_filters "$dev" "1:30" "$LAPTOP_IPS" "$prio"; prio=$((prio + 10))
  add_ip_filters "$dev" "1:40" "$PHONE_IPS" "$prio"; prio=$((prio + 10))
  prio=20
  for i in "${!marks[@]}"; do
    tc filter add dev "$dev" parent 1:0 prio "$prio" protocol ip flower ct_mark "${marks[$i]}" flowid "${flowids[$i]}" 2>/dev/null || true
    prio=$((prio + 1))
  done

  tc filter add dev "$dev" protocol ip parent 1:0 prio 90 handle "$MARK_XBOX" fw flowid 1:10 2>/dev/null || true
  tc filter add dev "$dev" protocol ip parent 1:0 prio 91 handle "$MARK_WIRELESS" fw flowid 1:20 2>/dev/null || true
  tc filter add dev "$dev" protocol ip parent 1:0 prio 92 handle "$MARK_LAPTOP" fw flowid 1:30 2>/dev/null || true
  tc filter add dev "$dev" protocol ip parent 1:0 prio 93 handle "$MARK_PHONE" fw flowid 1:40 2>/dev/null || true
  tc filter add dev "$dev" protocol ip parent 1:0 prio 94 handle "$MARK_OTHER" fw flowid 1:50 2>/dev/null || true
}

apply_throughput() {
  clear_qos
  # Firewalla parity (Smart Queue OFF): no IFB mirred redirect, no HTB tiers.
  # noqueue on WAN — fq_codel adds ~5–15% overhead at 1G; use noqueue for line rate.
  tc qdisc add dev "$WAN" root noqueue 2>/dev/null || \
    tc qdisc add dev "$WAN" root fq_codel limit 10240 flows 1024 quantum 1514 ecn 2>/dev/null || \
    tc qdisc add dev "$WAN" root pfifo_fast 2>/dev/null || true
  echo "profile=throughput mode=direct" >"$STATE"
  log "throughput profile: direct WAN path (no IFB/HTB), noqueue on $WAN"
}

apply_htb() {
  local dev="$1" total="$2" dir_label="$3" mode="$4"

  tc qdisc del dev "$dev" root 2>/dev/null || true

  if [[ "$dir_label" == "download" ]]; then
    # flowblind + nonat: avoid triple-isolate/dual-dsthost splitting download across
    # many CDN IPs during multi-connection speed tests (~950/N Mbps per host).
    tc qdisc add dev "$dev" root handle 1: cake bandwidth "$total" diffserv4 besteffort flowblind nonat nowash rtt 5ms memlimit 64mb split-gso 2>/dev/null || \
      tc qdisc add dev "$dev" root handle 1: fq_codel limit 10240 flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb
    return 0
  fi

  tc qdisc add dev "$dev" root handle 1: htb default 50
  tc class add dev "$dev" parent 1: classid 1:1 htb rate "$total" ceil "$total"
  tc class add dev "$dev" parent 1:1 classid 1:10 htb rate "$XBOX_RATE" ceil "$XBOX_CEIL" prio 1
  tc class add dev "$dev" parent 1:1 classid 1:20 htb rate "$WIRELESS_RATE" ceil "$WIRELESS_CEIL" prio 2
  tc class add dev "$dev" parent 1:1 classid 1:30 htb rate "$LAPTOP_RATE" ceil "$LAPTOP_CEIL" prio 3
  tc class add dev "$dev" parent 1:1 classid 1:40 htb rate "$PHONE_RATE" ceil "$PHONE_CEIL" prio 4
  tc class add dev "$dev" parent 1:1 classid 1:50 htb rate "$OTHER_RATE" ceil "$OTHER_CEIL" prio 5

  apply_htb_filters "$dev" "$dir_label"

  leaf_qdisc "$dev" 1:10 10: "$XBOX_CEIL" xbox "$mode"
  leaf_qdisc "$dev" 1:20 20: "$WIRELESS_CEIL" wireless "$mode"
  leaf_qdisc "$dev" 1:30 30: "$LAPTOP_CEIL" laptop "$mode"
  leaf_qdisc "$dev" 1:40 40: "$PHONE_CEIL" phone "$mode"
  leaf_qdisc "$dev" 1:50 50: "$OTHER_CEIL" other "$mode"
}

case "$ACTION" in
  clear) clear_qos; exit 0 ;;
  throughput) apply_throughput; exit 0 ;;
  apply)
    MODE="$(resolve_mode)"
    echo "mode=$MODE" >"$STATE"
    log "WAN=$WAN up=$WAN_UP down=$WAN_DOWN mode=$MODE tiers=xbox,wireless,laptop,phone,other"
    setup_ifb
    apply_htb "$WAN" "$WAN_UP" upload "$MODE"
    tc qdisc del dev "$WAN" ingress 2>/dev/null || true
    tc qdisc add dev "$WAN" handle ffff: ingress
    tc filter add dev "$WAN" parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev "$IFB"
    ip link del dev ifb1 2>/dev/null || true
    apply_htb "$IFB" "$WAN_DOWN" download "$MODE"
    log "applied 5-tier upload shaping + download CAKE"
    ;;
  status)
    cat "$STATE" 2>/dev/null || echo "mode=unknown"
    tc -s qdisc show dev "$WAN" || true
    tc -s qdisc show dev "$IFB" || true
    ;;
  *)
    echo "Usage: $0 {apply|throughput|clear|status}" >&2
    exit 1
    ;;
esac
