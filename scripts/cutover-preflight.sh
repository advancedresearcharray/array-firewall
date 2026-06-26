#!/usr/bin/env bash
# Pre-cutover checks — no network changes.
set -euo pipefail

CTID="${ARRAY_FW_CTID:-940}"
FW_IP="${ARRAY_FW_IP:-192.168.167.241}"
TOKEN_FILE="${ARRAY_FW_TOKEN:-}"

echo "=== array-firewall cutover preflight ==="
echo ""

fail=0
check() {
  local name="$1"
  local ok="$2"
  local detail="$3"
  if [[ "$ok" == "1" ]]; then
    echo "[OK]   $name — $detail"
  else
    echo "[FAIL] $name — $detail"
    fail=$((fail + 1))
  fi
}

# SSH to firewall
if ssh -o BatchMode=yes -o ConnectTimeout=5 "root@${FW_IP}" 'true' 2>/dev/null; then
  check "ssh_firewall" 1 "root@${FW_IP}"
else
  check "ssh_firewall" 0 "cannot SSH to root@${FW_IP}"
fi

# API preflight via python on box
if ssh -o BatchMode=yes "root@${FW_IP}" 'python3 -c "
import sys
sys.path.insert(0, \"/opt/array-firewall/api\")
from lib.cutover import preflight
import json
p = preflight()
print(json.dumps(p))
"' 2>/dev/null | python3 -c "
import json,sys
p=json.load(sys.stdin)
for c in p.get('checks',[]):
    s='OK' if c['ok'] else ('FAIL' if c.get('required') else 'WARN')
    print(f\"[{s}] {c['name']}: {c['detail']}\")
if not p.get('ok'):
    sys.exit(1)
" 2>/dev/null; then
  check "api_preflight" 1 "all required checks passed"
else
  check "api_preflight" 0 "see details above"
  fail=$((fail + 1))
fi

# Proxmox access
if ssh -o BatchMode=yes -o ConnectTimeout=5 root@192.168.167.39 "pct status ${CTID}" &>/dev/null; then
  check "proxmox_ct" 1 "CT${CTID} on .39"
else
  check "proxmox_ct" 0 "cannot reach Proxmox .39 or CT${CTID}"
fi

# Firewalla still up (informational)
if curl -s -m 3 http://192.168.167.1/ &>/dev/null || ping -c1 -W2 192.168.167.1 &>/dev/null; then
  echo "[INFO] Firewalla/current .1 is reachable — must be disabled before cutover"
else
  echo "[INFO] 192.168.167.1 not responding (may already be offline)"
fi

echo ""
if [[ "$fail" -gt 0 ]]; then
  echo "Preflight FAILED ($fail required check(s)). Fix before cutover."
  echo "See: /root/deploy/array-firewall/docs/CUTOVER.md"
  exit 1
fi

echo "Preflight PASSED. Ready for cutover when wiring is complete."
echo ""
echo "Next:"
echo "  1. Wire ISP → nic1, LAN switch → nic0 (see CUTOVER.md)"
echo "  2. Disable Firewalla as gateway"
echo "  3. FORCE_CUTOVER=1 ./scripts/cutover-gateway.sh"
exit 0
