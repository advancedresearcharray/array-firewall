#!/usr/bin/env bash
# Rollback gateway cutover → lab/sidecar mode on array-firewall CT.
set -euo pipefail

: "${ARRAY_FW_CTID:?Set ARRAY_FW_CTID}"
: "${PROXMOX_NODE:?Set PROXMOX_NODE}"
CTID="${ARRAY_FW_CTID}"
PROXMOX="${PROXMOX_NODE}"
RESTORE_IP="${ARRAY_FW_IP:-192.0.2.241}"
LAB_CIDR="${ARRAY_FW_LAB_IP:-198.51.100.1/24}"

log() { printf '[rollback] %s\n' "$*"; }

echo "=== array-firewall cutover ROLLBACK ==="
echo "Restores lab mode: eth0=${RESTORE_IP}, eth1=${LAB_CIDR}"
echo ""
if [[ "${FORCE_ROLLBACK:-}" != "1" ]]; then
  read -r -p "Rollback to lab mode? [y/N] " ans
  [[ "${ans,,}" == "y" ]] || { echo "Aborted."; exit 1; }
fi

# Try SSH via gateway IP or old IP
TARGET=""
for ip in 192.0.2.1 "${RESTORE_IP}"; do
  if ssh -o BatchMode=yes -o ConnectTimeout=3 "root@${ip}" 'true' 2>/dev/null; then
    TARGET="$ip"
    break
  fi
done

log "Updating Proxmox network..."
ssh -o BatchMode=yes "root@${PROXMOX}" bash -s -- "$CTID" "$RESTORE_IP" "$LAB_CIDR" <<'PVE'
set -euo pipefail
CTID="$1"
RESTORE_IP="$2"
LAB_CIDR="$3"
pct set "$CTID" -net0 "name=eth0,bridge=vmbr0,gw=192.0.2.1,ip=${RESTORE_IP}/24,type=veth"
pct set "$CTID" -net1 "name=eth1,bridge=vmbr1,ip=${LAB_CIDR},type=veth"
pct reboot "$CTID"
PVE

sleep 12

ssh -o BatchMode=yes "root@${PROXMOX}" "pct exec ${CTID} -- bash -s" <<'INNER'
set -euo pipefail
sed -i 's/^ROLE=.*/ROLE=lab/' /etc/array-firewall/array-firewall.conf
sed -i 's/^CUTOVER=.*/CUTOVER=0/' /etc/array-firewall/array-firewall.conf
sed -i 's|^LAN_IF=.*|LAN_IF=eth1|' /etc/array-firewall/array-firewall.conf
sed -i 's|^WAN_IF=.*|WAN_IF=eth1|' /etc/array-firewall/array-firewall.conf
sed -i 's|^UPLINK_IF=.*|UPLINK_IF=eth0|' /etc/array-firewall/array-firewall.conf
sed -i 's|^LAN_CIDR=.*|LAN_CIDR=198.51.100.0/24|' /etc/array-firewall/array-firewall.conf

python3 - <<'PY'
import json
from pathlib import Path
p = Path("/var/lib/array-firewall/policies.json")
data = json.loads(p.read_text()) if p.is_file() else {"version": 1}
data.setdefault("network", {}).update({
    "role": "lab",
    "cutover": False,
    "lan_if": "eth1",
    "wan_if": "eth1",
    "uplink_if": "eth0",
    "lan_cidr": "198.51.100.0/24",
})
dhcp = data.setdefault("dhcp", {})
dhcp.update({
    "enabled": True,
    "interface": "eth1",
    "range_start": "198.51.100.50",
    "range_end": "198.51.100.200",
    "gateway": "198.51.100.1",
    "dns": "198.51.100.1",
    "upstream_dns": ["192.0.2.1"],
})
p.write_text(json.dumps(data, indent=2) + "\n")
PY

BACKUP="/var/lib/array-firewall/cutover-backup.json"
if [[ -f "$BACKUP" ]]; then
  python3 - <<'PY'
import json
from pathlib import Path
b = json.loads(Path("/var/lib/array-firewall/cutover-backup.json").read_text())
# restore devices if present
if b.get("devices"):
    Path("/var/lib/array-firewall/devices.json").write_text(json.dumps(b["devices"], indent=2)+"\n")
print("restored devices from backup")
PY
fi

/opt/array-firewall/scripts/setup-dnsmasq.sh
apply-array-firewall

if [[ -f /etc/default/warzone-lobby-sentinel ]]; then
  sed -i 's|^WZ_FIREWALLA_API_URL=.*|WZ_FIREWALLA_API_URL=http://192.0.2.1:9378|' /etc/default/warzone-lobby-sentinel 2>/dev/null || true
  systemctl restart warzone-lobby-sentinel 2>/dev/null || true
fi

echo "Rollback complete — lab mode"
hostname -I
INNER

log ""
log "Rollback done. array-firewall CT @ ${RESTORE_IP}"
log "Re-enable Firewalla as 192.0.2.1 if needed."
log "Dashboard: http://${RESTORE_IP}:8090/"
