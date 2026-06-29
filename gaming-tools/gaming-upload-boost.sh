#!/usr/bin/env bash
# Raise Xbox HTB ceil during lobby/match — ~98% of shaped upload; trim other tiers.
set -euo pipefail

CONF="${ARRAY_FW_CONF:-/etc/array-firewall/array-firewall.conf}"
STATE="/var/lib/array-firewall/upload-boost.state"
BASELINE="/var/lib/array-firewall/upload-boost.baseline.json"
AUTORATE="/var/lib/array-firewall/qos-autorate.json"
POLICIES="${ARRAY_FW_POLICIES:-/var/lib/array-firewall/policies.json}"

# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

WAN="${WAN_IF:-eth1}"
XBOX_RATE="${XBOX_RATE:-400mbit}"
XBOX_CEIL="${XBOX_CEIL:-931mbit}"
WIRELESS_RATE="${WIRELESS_RATE:-200mbit}"
WIRELESS_CEIL="${WIRELESS_CEIL:-836mbit}"
LAPTOP_RATE="${LAPTOP_RATE:-150mbit}"
LAPTOP_CEIL="${LAPTOP_CEIL:-700mbit}"
PHONE_RATE="${PHONE_RATE:-100mbit}"
PHONE_CEIL="${PHONE_CEIL:-500mbit}"
OTHER_RATE="${OTHER_RATE:-50mbit}"
OTHER_CEIL="${OTHER_CEIL:-200mbit}"
WAN_UP="${WAN_UP:-1000mbit}"

log() { printf '[upload-boost] %s\n' "$*"; }

need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Run as root"; exit 1; }; }

read_policy() {
  python3 - "$POLICIES" <<'PY'
import json, sys
from pathlib import Path
defaults = {
    "enabled": True,
    "ceil_factor": 0.98,
    "other_ceil_factor": 0.55,
    "xbox_rate_factor": 0.85,
    "pressure_warn_pct": 80,
}
path = Path(sys.argv[1])
if path.is_file():
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        defaults.update((data.get("gaming") or {}).get("upload_assist") or {})
    except json.JSONDecodeError:
        pass
for k, v in defaults.items():
    print(f"{k}={v}")
PY
}

mbit_num() {
  local raw="${1/mbit/}"
  raw="${raw/Mbit/}"
  raw="${raw/gbit/000}"
  raw="${raw/Gbit/000}"
  echo "$raw" | awk '{print int($1+0.5)}'
}

shaped_upload_mbit() {
  if [[ -f "$AUTORATE" ]]; then
    python3 - "$AUTORATE" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
try:
    d = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    sys.exit(1)
for key in ("upload_mbps_shaped", "upload_mbps_raw"):
    v = d.get(key)
    if v:
        print(int(float(v)))
        raise SystemExit
wan = str(d.get("wan_up") or "")
if wan.endswith("mbit"):
    print(int(float(wan.replace("mbit", ""))))
    raise SystemExit
sys.exit(1)
PY
    return 0
  fi
  mbit_num "$WAN_UP"
}

save_baseline() {
  [[ -f "$BASELINE" ]] && return 0
  python3 - <<PY
import json
from pathlib import Path
data = {
    "xbox_rate": "${XBOX_RATE}",
    "xbox_ceil": "${XBOX_CEIL}",
    "wireless_rate": "${WIRELESS_RATE}",
    "wireless_ceil": "${WIRELESS_CEIL}",
    "laptop_rate": "${LAPTOP_RATE}",
    "laptop_ceil": "${LAPTOP_CEIL}",
    "phone_rate": "${PHONE_RATE}",
    "phone_ceil": "${PHONE_CEIL}",
    "other_rate": "${OTHER_RATE}",
    "other_ceil": "${OTHER_CEIL}",
}
Path("${BASELINE}").write_text(json.dumps(data, indent=2) + "\\n", encoding="utf-8")
PY
}

load_baseline_var() {
  local key="$1"
  python3 - "$BASELINE" "$key" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
key = sys.argv[2]
data = json.loads(p.read_text(encoding="utf-8"))
print(data.get(key, ""))
PY
}

class_change() {
  local classid="$1" rate="$2" ceil="$3"
  tc class change dev "$WAN" parent 1:1 classid "$classid" htb rate "$rate" ceil "$ceil" 2>/dev/null || \
    tc class replace dev "$WAN" parent 1:1 classid "$classid" htb rate "$rate" ceil "$ceil" 2>/dev/null || true
}

cmd_apply() {
  need_root
  local enabled=1 ceil_factor=0.98 other_factor=0.55 rate_factor=0.85
  while IFS='=' read -r k v; do
    case "$k" in
      enabled) [[ "$v" == "True" || "$v" == "true" || "$v" == "1" ]] || enabled=0 ;;
      ceil_factor) ceil_factor="$v" ;;
      other_ceil_factor) other_factor="$v" ;;
      xbox_rate_factor) rate_factor="$v" ;;
    esac
  done < <(read_policy)

  if [[ "$enabled" != "1" ]]; then
    log "disabled in policy — skipping"
    echo "active=0 reason=policy_disabled"
    return 0
  fi

  if ! tc class show dev "$WAN" 2>/dev/null | grep -q 'class htb 1:10'; then
    log "HTB class 1:10 missing — run apply-qos first"
    echo "active=0 reason=no_htb"
    return 1
  fi

  save_baseline
  local shaped
  shaped="$(shaped_upload_mbit)"
  [[ -n "$shaped" && "$shaped" -gt 0 ]] || shaped="$(mbit_num "$WAN_UP")"

  local xbox_ceil_m xbox_rate_m other_ceil_m
  xbox_ceil_m="$(python3 - "$shaped" "$ceil_factor" <<'PY'
import sys
shaped = float(sys.argv[1])
factor = float(sys.argv[2])
print(max(50, int(shaped * factor)))
PY
)"
  xbox_rate_m="$(python3 - "$xbox_ceil_m" "$(mbit_num "$XBOX_RATE")" "$rate_factor" <<'PY'
import sys
ceil_m = int(sys.argv[1])
base = int(sys.argv[2])
factor = float(sys.argv[3])
print(max(base, int(ceil_m * factor)))
PY
)"
  other_ceil_m="$(python3 - "$shaped" "$other_factor" <<'PY'
import sys
shaped = float(sys.argv[1])
factor = float(sys.argv[2])
print(max(20, int(shaped * factor)))
PY
)"

  class_change "1:10" "${xbox_rate_m}mbit" "${xbox_ceil_m}mbit"
  class_change "1:20" "${WIRELESS_RATE}" "${other_ceil_m}mbit"
  class_change "1:30" "${LAPTOP_RATE}" "${other_ceil_m}mbit"
  class_change "1:40" "${PHONE_RATE}" "${other_ceil_m}mbit"
  class_change "1:50" "${OTHER_RATE}" "${other_ceil_m}mbit"

  {
    echo "active=1"
    echo "shaped_mbps=${shaped}"
    echo "xbox_rate=${xbox_rate_m}mbit"
    echo "xbox_ceil=${xbox_ceil_m}mbit"
    echo "other_ceil=${other_ceil_m}mbit"
    echo "wan=${WAN}"
    echo "updated=$(date -Is)"
  } >"$STATE"

  log "APPLY xbox ${xbox_rate_m}/${xbox_ceil_m}mbit other_ceil=${other_ceil_m}mbit shaped=${shaped}Mbps"
  echo "active=1 xbox_ceil=${xbox_ceil_m}mbit shaped_mbps=${shaped}"
}

cmd_relax() {
  need_root
  if [[ ! -f "$BASELINE" ]]; then
    rm -f "$STATE"
    log "RELAX — no baseline saved"
    echo "active=0 reason=no_baseline"
    return 0
  fi
  class_change "1:10" "$(load_baseline_var xbox_rate)" "$(load_baseline_var xbox_ceil)"
  class_change "1:20" "$(load_baseline_var wireless_rate)" "$(load_baseline_var wireless_ceil)"
  class_change "1:30" "$(load_baseline_var laptop_rate)" "$(load_baseline_var laptop_ceil)"
  class_change "1:40" "$(load_baseline_var phone_rate)" "$(load_baseline_var phone_ceil)"
  class_change "1:50" "$(load_baseline_var other_rate)" "$(load_baseline_var other_ceil)"
  rm -f "$STATE"
  log "RELAX — baseline HTB classes restored"
  echo "active=0 restored=1"
}

cmd_status() {
  if [[ -f "$STATE" ]]; then
    cat "$STATE"
  else
    echo "active=0"
  fi
  tc class show dev "$WAN" 2>/dev/null | grep -E 'class htb 1:(10|20|30|40|50)' || true
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
