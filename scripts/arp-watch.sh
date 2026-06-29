#!/usr/bin/env bash
# Watch ARP/neighbor events for the Xbox MAC on the LAN-facing interface.
set -euo pipefail

CONF="/etc/array-firewall/array-firewall.conf"
POLICIES="/var/lib/array-firewall/policies.json"
LOG="/var/lib/array-firewall/arp-watch.jsonl"
STATE="/var/lib/array-firewall/arp-watch.state"

# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

read -r WATCH_MAC LAN_IF GW_IP <<<"$(python3 - <<'PY'
import json
from pathlib import Path

conf = {}
for line in Path("/etc/array-firewall/array-firewall.conf").read_text().splitlines():
    if "=" in line and not line.strip().startswith("#"):
        k, v = line.split("=", 1)
        conf[k.strip()] = v.strip()

pol = {}
p = Path("/var/lib/array-firewall/policies.json")
if p.is_file():
    pol = json.loads(p.read_text())

gaming = pol.get("gaming") or {}
net = pol.get("network") or {}
mac = (gaming.get("xbox_mac") or conf.get("XBOX_MAC") or "28:ea:0b:75:3b:75").lower()
lan = net.get("lan_if") or conf.get("LAN_IF") or conf.get("MGMT_IF") or "eth0"
gw = net.get("gateway_ip") or conf.get("LAN_GATEWAY_IP") or "192.168.5.1"
print(mac, lan, gw)
PY
)"

WATCH_MAC="${WATCH_MAC,,}"
LAN_IF="${LAN_IF:-eth0}"
GW_IP="${GW_IP:-192.168.5.1}"

mkdir -p "$(dirname "$LOG")"

log_event() {
  local kind="$1"
  local detail="$2"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  python3 - "$ts" "$kind" "$WATCH_MAC" "$LAN_IF" "$GW_IP" "$detail" "$LOG" "$STATE" <<'PY'
import json, sys
from pathlib import Path

ts, kind, mac, lan_if, gw_ip, detail, log_path, state_path = sys.argv[1:9]
row = {
    "ts": ts,
    "kind": kind,
    "mac": mac,
    "if": lan_if,
    "gateway_ip": gw_ip,
    "detail": detail,
}
Path(log_path).open("a", encoding="utf-8").write(json.dumps(row) + "\n")
Path(state_path).write_text(json.dumps({"updated": ts, "last": row}, indent=2) + "\n", encoding="utf-8")
print(json.dumps(row))
PY
}

snapshot_neigh() {
  ip neigh show dev "$LAN_IF" 2>/dev/null | grep -i "$WATCH_MAC" || true
}

echo "[arp-watch] mac=${WATCH_MAC} if=${LAN_IF} gw=${GW_IP}" >&2
log_event "start" "arp-watch online"

prev="$(snapshot_neigh)"
if [[ -n "$prev" ]]; then
  log_event "neigh" "$prev"
fi

# Background tcpdump for ARP involving Xbox or gateway validation traffic.
if command -v tcpdump >/dev/null 2>&1; then
  tcpdump -i "$LAN_IF" -n -l -q -e \
    "ether host ${WATCH_MAC} or (arp and (host ${GW_IP} or host 192.168.5.11))" 2>/dev/null |
    while read -r line; do
      log_event "tcpdump" "$line"
    done &
  TCPDUMP_PID=$!
  trap 'kill "$TCPDUMP_PID" 2>/dev/null || true' EXIT
fi

ip monitor neigh dev "$LAN_IF" 2>/dev/null |
while read -r line; do
  lower="${line,,}"
  [[ "$lower" == *"${WATCH_MAC}"* ]] || continue
  log_event "neigh" "$line"
done
