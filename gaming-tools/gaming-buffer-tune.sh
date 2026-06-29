#!/usr/bin/env bash
# CAKE rtt/memlimit + sysctl buffer profiles for Xbox — never re-enable host isolation
# (dual-dsthost/triple-isolate caps multi-connection speed tests at ~950/N Mbps).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONF="/etc/array-firewall/array-firewall.conf"
POLICIES="${ARRAY_FW_POLICIES:-/var/lib/array-firewall/policies.json}"
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

WAN="${WAN_IF:-eth1}"
IFB="${IFB_DEV:-ifb0}"
XBOX_IP="${XBOX_IP:-192.168.167.65}"
XBOX_CEIL="${XBOX_CEIL:-931mbit}"
WAN_DOWN="${WAN_DOWN:-1000mbit}"
STATE="/var/lib/array-firewall/buffer-tune.state"

log() { printf '[buffer-tune] %s\n' "$*"; }

read_policy() {
  python3 - "$POLICIES" <<'PY'
import json, sys
from pathlib import Path
defaults = {
    "gaming_xbox_rtt": "8ms",
    "gaming_ifb_rtt": "8ms",
    "light_xbox_rtt": "10ms",
    "light_ifb_rtt": "10ms",
    "desync_xbox_rtt": "5ms",
    "desync_ifb_rtt": "5ms",
    "kick_xbox_rtt": "3ms",
    "kick_ifb_rtt": "3ms",
    "xbox_memlimit": "16mb",
    "ifb_memlimit": "64mb",
    "wan_down": "1000mbit",
    "xbox_ceil": "980mbit",
}
path = Path(sys.argv[1])
if path.is_file():
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        qos = data.get("qos") or {}
        defaults["wan_down"] = str(qos.get("wan_down") or defaults["wan_down"])
        hi = (qos.get("classes") or {}).get("high") or {}
        defaults["xbox_ceil"] = str(hi.get("ceil") or qos.get("xbox_ceil") or defaults["xbox_ceil"])
        ua = (data.get("gaming") or {}).get("upload_assist") or {}
        buf = ua.get("buffer") or {}
        defaults.update(buf)
    except json.JSONDecodeError:
        pass
for k, v in defaults.items():
    print(f"{k}={v}")
PY
}

restore_qos() {
  python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/array-firewall/api")
from lib import qos
qos.apply()
print("qos restored")
PY
}

cake_ifb() {
  local bandwidth="$1" rtt="$2" memlimit_val="$3"
  tc qdisc change dev "$IFB" root cake \
    bandwidth "$bandwidth" diffserv4 besteffort flowblind nonat nowash rtt "$rtt" split-gso memlimit "$memlimit_val" 2>/dev/null || \
  tc qdisc replace dev "$IFB" root cake \
    bandwidth "$bandwidth" diffserv4 besteffort flowblind nonat nowash rtt "$rtt" split-gso memlimit "$memlimit_val" 2>/dev/null || true
}

cake_xbox_leaf() {
  local bandwidth="$1" rtt="$2" memlimit_val="$3"
  tc qdisc change dev "$WAN" parent 1:10 handle 10: cake \
    bandwidth "$bandwidth" diffserv4 besteffort flowblind nat wash rtt "$rtt" split-gso memlimit "$memlimit_val" 2>/dev/null || \
  tc qdisc replace dev "$WAN" parent 1:10 handle 10: cake \
    bandwidth "$bandwidth" diffserv4 besteffort flowblind nat wash rtt "$rtt" split-gso memlimit "$memlimit_val" 2>/dev/null || true
}

apply_profile() {
  local profile="${1:-gaming}"
  if python3 - "$POLICIES" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
prof = "throughput"
if p.is_file():
    try:
        prof = str((json.loads(p.read_text()).get("qos") or {}).get("profile") or prof).lower()
    except json.JSONDecodeError:
        pass
sys.exit(0 if prof in ("throughput", "direct", "firewalla", "off", "passthrough") else 1)
PY
  then
    local backlog=262144 tcp_idle=""
    case "$profile" in
      desync) backlog=131072; tcp_idle=1 ;;
      kick) backlog=65536; tcp_idle=1 ;;
    esac
    sysctl -w "net.core.netdev_max_backlog=$backlog" >/dev/null 2>&1 || true
    if [[ "$tcp_idle" == "1" ]]; then
      sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1 || true
    fi
    log "throughput profile active — buffer sysctl only (no CAKE/IFB changes)"
    echo "profile=$profile mode=throughput-sysctl-only ip=${2:-$XBOX_IP} backlog=$backlog" >"$STATE"
    return 0
  fi

  local -A cfg=()
  while IFS='=' read -r k v; do
    [[ -n "$k" ]] && cfg["$k"]="$v"
  done < <(read_policy)

  local xbox_rtt ifb_rtt backlog tcp_idle="" xbox_mem ifb_mem
  case "$profile" in
    gaming|normal)
      xbox_rtt="${cfg[gaming_xbox_rtt]:-8ms}"
      ifb_rtt="${cfg[gaming_ifb_rtt]:-8ms}"
      backlog=262144
      ;;
    light)
      xbox_rtt="${cfg[light_xbox_rtt]:-10ms}"
      ifb_rtt="${cfg[light_ifb_rtt]:-10ms}"
      backlog=262144
      ;;
    desync)
      xbox_rtt="${cfg[desync_xbox_rtt]:-5ms}"
      ifb_rtt="${cfg[desync_ifb_rtt]:-5ms}"
      backlog=131072
      tcp_idle=1
      ;;
    kick)
      xbox_rtt="${cfg[kick_xbox_rtt]:-3ms}"
      ifb_rtt="${cfg[kick_ifb_rtt]:-3ms}"
      backlog=65536
      tcp_idle=1
      ;;
    *)
      echo "unknown profile=$profile"; return 2
      ;;
  esac
  xbox_mem="${cfg[xbox_memlimit]:-16mb}"
  ifb_mem="${cfg[ifb_memlimit]:-64mb}"
  local wan_down="${cfg[wan_down]:-$WAN_DOWN}"
  local xbox_ceil="${cfg[xbox_ceil]:-$XBOX_CEIL}"

  cake_xbox_leaf "$xbox_ceil" "$xbox_rtt" "$xbox_mem"
  cake_ifb "$wan_down" "$ifb_rtt" "$ifb_mem"

  sysctl -w "net.core.netdev_max_backlog=$backlog" >/dev/null 2>&1 || true
  if [[ "$tcp_idle" == "1" ]]; then
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1 || true
  fi

  echo "profile=$profile ip=${2:-$XBOX_IP} xbox_rtt=$xbox_rtt ifb_rtt=$ifb_rtt backlog=$backlog target=cake backend=array-firewall isolation=flowblind" >"$STATE"
  log "applied profile=$profile xbox_rtt=$xbox_rtt ifb_rtt=$ifb_rtt backlog=$backlog xbox=${2:-$XBOX_IP} wan=$WAN ifb=$IFB"
}

case "${1:-status}" in
  apply) apply_profile "${2:-gaming}" "${3:-}" ;;
  off)
    restore_qos
    echo "buffers restored profile=off qos=applied isolation=flowblind" >"$STATE"
    echo "buffers restored (full QoS re-applied, flowblind throughput)"
    ;;
  status)
    if [[ -f "$STATE" ]]; then cat "$STATE"; else echo "mode=gaming backend=array-firewall"; fi
    tc qdisc show dev "$WAN" 2>/dev/null | grep -E '1:10|cake' | head -3 || true
    tc qdisc show dev "$IFB" 2>/dev/null | grep cake | head -2 || true
    ;;
  *)
    echo "Usage: $0 {apply <gaming|normal|light|desync|kick> [ip]|off|status}"; exit 2
    ;;
esac
