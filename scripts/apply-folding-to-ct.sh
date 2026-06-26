#!/usr/bin/env bash
# Wire Zenodo folding into array-firewall CT940 (or any CTID).
# Usage: ARRAY_FW_CTID=940 FOLD_RELAY_URL=http://192.168.167.39:19557 ./scripts/apply-folding-to-ct.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTID="${ARRAY_FW_CTID:-940}"
PROX="${PROXMOX_NODE:-192.168.167.39}"
RELAY="${FOLD_RELAY_URL:-}"

echo "[folding] Pushing folding.py + config to CT${CTID} via ${PROX}..."
for f in api/lib/folding.py api/server.py api/lib/perf.py api/static/dashboard.html config/array-firewall.conf docs/ZENODO-FOLDING.md scripts/verify-array-firewall-folding.sh; do
  scp -o BatchMode=yes "$ROOT/$f" "root@${PROX}:/tmp/$(basename "$f")"
  ssh -o BatchMode=yes "root@${PROX}" "pct push ${CTID} /tmp/$(basename "$f") /opt/array-firewall/$f && rm -f /tmp/$(basename "$f")"
done

ssh -o BatchMode=yes "root@${PROX}" "pct exec ${CTID} -- bash -s" <<REMOTE
set -euo pipefail
chmod +x /opt/array-firewall/scripts/verify-array-firewall-folding.sh
if grep -q '^FOLDING_ENABLED=' /etc/array-firewall/array-firewall.conf 2>/dev/null; then
  sed -i 's|^FOLDING_ENABLED=.*|FOLDING_ENABLED=1|' /etc/array-firewall/array-firewall.conf
else
  echo 'FOLDING_ENABLED=1' >> /etc/array-firewall/array-firewall.conf
fi
if [[ -n "${RELAY}" ]]; then
  if grep -q '^FOLD_RELAY_URL=' /etc/array-firewall/array-firewall.conf; then
    sed -i "s|^FOLD_RELAY_URL=.*|FOLD_RELAY_URL=${RELAY}|" /etc/array-firewall/array-firewall.conf
  else
    echo "FOLD_RELAY_URL=${RELAY}" >> /etc/array-firewall/array-firewall.conf
  fi
fi
systemctl restart array-firewall-api.service
REMOTE

echo "[folding] Verify inside CT:"
ssh -o BatchMode=yes "root@${PROX}" "pct exec ${CTID} -- /opt/array-firewall/scripts/verify-array-firewall-folding.sh" || true
echo "[folding] Done. Dashboard → Gaming & Performance → Dimensional folding"
