#!/usr/bin/env bash
# Run allowlisted gaming script locally on array-firewall.
set -euo pipefail

TOOLS="/opt/array-firewall/gaming-tools"
CONF="${TOOLS}/gaming.conf"
[[ -f "$CONF" ]] && source "$CONF"

ALLOWED=(
  gaming-snapshot.sh
  gaming-link-status.sh
  gaming-mtu-probe.sh
  packet-shield-nft.sh
  gaming-packet-shield.sh
  gaming-flood-guard.sh
  gaming-buffer-tune.sh
  gaming-firewalla-tune.sh
  gaming-moca-tune.sh
  gaming-route-pref.sh
  gaming-upload-boost.sh
  gaming-download-boost.sh
)

script="${1:-}"
shift || true
[[ -n "$script" ]] || { echo "Usage: $0 <script> [args...]"; exit 2; }

ok=0
for s in "${ALLOWED[@]}"; do
  [[ "$script" == "$s" ]] && ok=1 && break
done
[[ "$ok" == 1 ]] || { echo "script not allowed: $script"; exit 2; }

path="${TOOLS}/${script}"
[[ -x "$path" ]] || chmod +x "$path"
exec "$path" "$@"
