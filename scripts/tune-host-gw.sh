#!/usr/bin/env bash
# Host-side tuning required for 900+ Mbps gateway download through CT940.
# Run on Proxmox host (not inside the container).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SYSCTL_FILE="/etc/sysctl.d/99-array-firewall-gw.conf"
CTID="${1:-940}"

cat >"$SYSCTL_FILE" <<'EOF'
# Line-rate gateway TCP buffers for array-firewall CT940.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 250000
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
EOF

sysctl -p "$SYSCTL_FILE"
echo "[tune-host-gw] applied $SYSCTL_FILE (rmem_max=$(sysctl -n net.core.rmem_max))"

if [[ -x "$ROOT/scripts/tune-wan-veth.sh" ]]; then
  "$ROOT/scripts/tune-wan-veth.sh" "$CTID"
fi

echo "[tune-host-gw] restart CT $CTID if it was running before sysctl change"
