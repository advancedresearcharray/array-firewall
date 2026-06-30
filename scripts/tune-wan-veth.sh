#!/usr/bin/env bash
# Host-side WAN veth tuning for array-firewall CT line-rate (run on Proxmox host).
set -euo pipefail

CTID="${1:-${ARRAY_FW_CTID:?Set ARRAY_FW_CTID or pass CTID as arg}}"
WAN_BRIDGE="${WAN_BRIDGE:-vmbr1}"
HOST_NIC="${HOST_NIC:-nic2}"

veth=""
peer=""
while IFS= read -r line; do
  if [[ "$line" =~ ^net([0-9]+): ]] && [[ "$line" == *"bridge=${WAN_BRIDGE}"* ]]; then
    n="${BASH_REMATCH[1]}"
    veth="$(echo "$line" | sed -n 's/.*name=\([^,]*\).*/\1/p')"
    peer="veth${CTID}i${n}"
    break
  fi
done < <(pct config "$CTID" 2>/dev/null | grep '^net')

if [[ -d "/sys/class/net/${HOST_NIC}" ]]; then
  ethtool -G "$HOST_NIC" rx 4096 tx 4096 2>/dev/null || true
  echo "[tune-wan-veth] ring buffers $HOST_NIC"
fi

  if [[ -n "${peer:-}" && -d "/sys/class/net/$peer" ]]; then
    ip link set "$peer" mtu 1500 2>/dev/null || true
    ip link set "$peer" txqueuelen 10000 2>/dev/null || true
    echo "[tune-wan-veth] mtu 1500 txqueuelen 10000 on $peer"
  fi

if [[ -n "${veth:-}" ]]; then
  echo "[tune-wan-veth] CT $CTID WAN if=$veth bridge=$WAN_BRIDGE peer=$peer"
else
  echo "[tune-wan-veth] CT $CTID — could not detect WAN veth on $WAN_BRIDGE" >&2
fi
