#!/usr/bin/env bash
# Raise ifb0 CAKE bandwidth + buffers during Xbox download-heavy sessions.
set -euo pipefail

CONF="${ARRAY_FW_CONF:-/etc/array-firewall/array-firewall.conf}"
STATE="/var/lib/array-firewall/download-boost.state"
BASELINE="/var/lib/array-firewall/download-boost.baseline.json"
AUTORATE="/var/lib/array-firewall/qos-autorate.json"
POLICIES="${ARRAY_FW_POLICIES:-/var/lib/array-firewall/policies.json}"

# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

IFB="${IFB_DEV:-ifb0}"
WAN_DOWN="${WAN_DOWN:-1000mbit}"

log() { printf '[download-boost] %s\n' "$*"; }

need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Run as root"; exit 1; }; }

read_policy() {
  python3 - "$POLICIES" <<'PY'
import json, sys
from pathlib import Path
defaults = {
    "enabled": True,
    "ceil_factor": 0.98,
    "ifb_rtt": "3ms",
    "ifb_memlimit": "32mb",
}
path = Path(sys.argv[1])
if path.is_file():
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        defaults.update((data.get("gaming") or {}).get("download_assist") or {})
    except json.JSONDecodeError:
        pass
for k, v in defaults.items():
    print(f"{k}={v}")
PY
}

shaped_download_mbit() {
  if [[ -f "$AUTORATE" ]]; then
    python3 - "$AUTORATE" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
try:
    d = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    sys.exit(1)
for key in ("download_mbps_shaped", "download_mbps_raw"):
    v = d.get(key)
    if v:
        print(int(float(v)))
        raise SystemExit
wan = str(d.get("wan_down") or "")
if wan.endswith("mbit"):
    print(int(float(wan.replace("mbit", ""))))
    raise SystemExit
sys.exit(1)
PY
    return 0
  fi
  echo "${WAN_DOWN/mbit/}" | awk '{print int($1+0.5)}'
}

parse_ifb_cake() {
  python3 - "$IFB" <<'PY'
import re, subprocess, sys, json
ifb = sys.argv[1]
try:
    out = subprocess.check_output(["tc", "qdisc", "show", "dev", ifb], text=True, timeout=5)
except Exception:
    print(json.dumps({}))
    raise SystemExit
line = ""
for raw in out.splitlines():
    if "qdisc cake" in raw and "root" in raw:
        line = raw
        break
if not line:
    print(json.dumps({}))
    raise SystemExit
def grab(pattern, default=""):
    m = re.search(pattern, line, re.I)
    return m.group(1) if m else default
data = {
    "bandwidth": grab(r"bandwidth (\S+)", ""),
    "rtt": grab(r"\brtt (\S+)", "5ms"),
    "memlimit": grab(r"memlimit (\S+)", "64Mb"),
}
print(json.dumps(data))
PY
}

save_baseline() {
  [[ -f "$BASELINE" ]] && return 0
  local parsed
  parsed="$(parse_ifb_cake)"
  python3 - "$parsed" "$BASELINE" <<'PY'
import json, sys
from pathlib import Path
raw = sys.argv[1].strip()
path = sys.argv[2]
try:
    data = json.loads(raw) if raw else {}
except json.JSONDecodeError:
    data = {}
if not data.get("bandwidth"):
    data = {"bandwidth": "1000Mbit", "rtt": "5ms", "memlimit": "64Mb"}
Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY
}

cake_ifb() {
  local bandwidth="$1" rtt="$2" memlimit_val="$3"
  tc qdisc change dev "$IFB" root cake \
    bandwidth "$bandwidth" diffserv4 besteffort flowblind nonat nowash rtt "$rtt" split-gso memlimit "$memlimit_val" 2>/dev/null || \
  tc qdisc replace dev "$IFB" root cake \
    bandwidth "$bandwidth" diffserv4 besteffort flowblind nonat nowash rtt "$rtt" split-gso memlimit "$memlimit_val" 2>/dev/null || true
}

cmd_apply() {
  need_root
  local enabled=1 ceil_factor=0.98 ifb_rtt=3ms ifb_mem=32mb
  while IFS='=' read -r k v; do
    case "$k" in
      enabled) [[ "$v" == "True" || "$v" == "true" || "$v" == "1" ]] || enabled=0 ;;
      ceil_factor) ceil_factor="$v" ;;
      ifb_rtt) ifb_rtt="$v" ;;
      ifb_memlimit) ifb_mem="$v" ;;
    esac
  done < <(read_policy)

  if [[ "$enabled" != "1" ]]; then
    log "disabled in policy — skipping"
    echo "active=0 reason=policy_disabled"
    return 0
  fi

  if ! tc qdisc show dev "$IFB" 2>/dev/null | grep -q 'qdisc cake.*root'; then
    log "ifb0 CAKE missing — run apply-qos first"
    echo "active=0 reason=no_ifb_cake"
    return 1
  fi

  save_baseline
  local shaped bw_m
  shaped="$(shaped_download_mbit)"
  [[ -n "$shaped" && "$shaped" -gt 0 ]] || shaped="$(echo "${WAN_DOWN/mbit/}" | awk '{print int($1+0.5)}')"
  bw_m="$(python3 - "$shaped" "$ceil_factor" <<'PY'
import sys
shaped = float(sys.argv[1])
factor = float(sys.argv[2])
print(max(50, int(shaped * factor)))
PY
)"

  cake_ifb "${bw_m}mbit" "$ifb_rtt" "$ifb_mem"

  {
    echo "active=1"
    echo "shaped_mbps=${shaped}"
    echo "ifb_bandwidth=${bw_m}mbit"
    echo "ifb_rtt=${ifb_rtt}"
    echo "ifb_memlimit=${ifb_mem}"
    echo "ifb=${IFB}"
    echo "updated=$(date -Is)"
  } >"$STATE"

  log "APPLY ifb0 ${bw_m}mbit rtt=${ifb_rtt} mem=${ifb_mem} shaped=${shaped}Mbps"
  echo "active=1 ifb_bandwidth=${bw_m}mbit shaped_mbps=${shaped}"
}

cmd_relax() {
  need_root
  if [[ ! -f "$BASELINE" ]]; then
    rm -f "$STATE"
    log "RELAX — no baseline saved"
    echo "active=0 reason=no_baseline"
    return 0
  fi
  local bandwidth rtt memlimit
  bandwidth="$(python3 - "$BASELINE" <<'PY'
import json, sys
print(json.loads(open(sys.argv[1]).read()).get("bandwidth", "1000Mbit"))
PY
)"
  rtt="$(python3 - "$BASELINE" <<'PY'
import json, sys
print(json.loads(open(sys.argv[1]).read()).get("rtt", "5ms"))
PY
)"
  memlimit="$(python3 - "$BASELINE" <<'PY'
import json, sys
print(json.loads(open(sys.argv[1]).read()).get("memlimit", "64Mb"))
PY
)"
  cake_ifb "$bandwidth" "$rtt" "$memlimit"
  rm -f "$STATE"
  log "RELAX — baseline ifb0 CAKE restored ($bandwidth rtt=$rtt mem=$memlimit)"
  echo "active=0 restored=1"
}

cmd_status() {
  if [[ -f "$STATE" ]]; then
    cat "$STATE"
  else
    echo "active=0"
  fi
  tc qdisc show dev "$IFB" 2>/dev/null | grep cake | head -2 || true
}

case "${1:-status}" in
  apply) cmd_apply ;;
  relax|off) cmd_relax ;;
  status) cmd_status ;;
  *)
    echo "Usage: $0 {apply|relax|status}"
    exit 2
    ;;
esac
