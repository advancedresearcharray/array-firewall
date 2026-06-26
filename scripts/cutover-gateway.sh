#!/usr/bin/env bash
# Gateway cutover — array-firewall becomes 192.168.167.1 network exit.
set -euo pipefail

CTID="${ARRAY_FW_CTID:-940}"
PROXMOX="${PROXMOX_NODE:-192.168.167.39}"
LAN_GW="${LAN_GATEWAY_IP:-192.168.167.1}"
OLD_IP="${ARRAY_FW_IP:-192.168.167.241}"
LAB_IP="${ARRAY_FW_LAB_IP:-10.99.0.1/24}"

log() { printf '[cutover] %s\n' "$*"; }

echo "=== array-firewall gateway cutover ==="
echo "Target LAN gateway: ${LAN_GW}"
echo "Proxmox: ${PROXMOX} CT${CTID}"
echo ""
echo "Physical wiring (two separate networks — do not cross-connect):"
echo "  nic2 → ISP/modem     (CT940 eth1 / WAN — e.g. 192.168.1.x from modem)"
echo "  nic0 → house switch  (CT940 eth0 / LAN — 192.168.167.0/24)"
echo "  Firewalla must NOT remain gateway at ${LAN_GW}"
echo ""

if [[ "${FORCE_CUTOVER:-}" != "1" ]]; then
  read -r -p "Physical wiring done and Firewalla disabled? [y/N] " ans
  [[ "${ans,,}" == "y" ]] || { echo "Aborted."; exit 1; }
fi

log "Running preflight on ${OLD_IP}..."
ssh -o BatchMode=yes "root@${OLD_IP}" '/opt/array-firewall/scripts/cutover-preflight.sh' 2>/dev/null || \
  ssh -o BatchMode=yes "root@${OLD_IP}" 'python3 -c "
import sys; sys.path.insert(0,\"/opt/array-firewall/api\")
from lib.cutover import preflight
p=preflight()
import json; print(json.dumps(p,indent=2))
sys.exit(0 if p[\"ok\"] else 1)
"' || { echo "Preflight failed — fix issues first"; exit 1; }

log "Backing up state on CT${CTID}..."
ssh -o BatchMode=yes "root@${OLD_IP}" 'python3 -c "
import sys; sys.path.insert(0,\"/opt/array-firewall/api\")
from lib.cutover import backup_state
import json; print(json.dumps(backup_state()))
"'

log "Updating Proxmox network (eth0=${LAN_GW}/24, eth1=DHCP WAN)..."
ssh -o BatchMode=yes "root@${PROXMOX}" bash -s -- "$CTID" "$LAN_GW" <<'PVE'
set -euo pipefail
CTID="$1"
LAN_GW="$2"
pct set "$CTID" -net0 "name=eth0,bridge=vmbr0,ip=${LAN_GW}/24,type=veth"
pct set "$CTID" -net1 "name=eth1,bridge=vmbr1,ip=dhcp,type=veth"
pct reboot "$CTID"
PVE

log "Waiting for container boot..."
sleep 12

# Use pct exec — SSH to new IP may not work immediately
ssh -o BatchMode=yes "root@${PROXMOX}" "pct exec ${CTID} -- bash -s" -- "$LAN_GW" <<'INNER'
set -euo pipefail
LAN_GW="$1"

# Config
sed -i 's/^ROLE=.*/ROLE=gateway/' /etc/array-firewall/array-firewall.conf
grep -q '^CUTOVER=' /etc/array-firewall/array-firewall.conf || echo 'CUTOVER=1' >> /etc/array-firewall/array-firewall.conf
sed -i 's/^CUTOVER=.*/CUTOVER=1/' /etc/array-firewall/array-firewall.conf
sed -i 's|^LAN_IF=.*|LAN_IF=eth0|' /etc/array-firewall/array-firewall.conf
sed -i 's|^WAN_IF=.*|WAN_IF=eth1|' /etc/array-firewall/array-firewall.conf
sed -i 's|^UPLINK_IF=.*|UPLINK_IF=eth1|' /etc/array-firewall/array-firewall.conf
sed -i 's|^LAN_CIDR=.*|LAN_CIDR=192.168.167.0/24|' /etc/array-firewall/array-firewall.conf
sed -i "s|^LAN_GATEWAY_IP=.*|LAN_GATEWAY_IP=${LAN_GW}|" /etc/array-firewall/array-firewall.conf

python3 - <<'PY'
import json
from pathlib import Path

p = Path("/var/lib/array-firewall/policies.json")
data = json.loads(p.read_text()) if p.is_file() else {"version": 1}
data.setdefault("network", {}).update({
    "role": "gateway",
    "cutover": True,
    "lan_if": "eth0",
    "wan_if": "eth1",
    "uplink_if": "eth1",
    "lan_cidr": "192.168.167.0/24",
    "gateway_ip": "192.168.167.1",
})
dhcp = data.setdefault("dhcp", {})
dhcp.update({
    "enabled": True,
    "interface": "eth0",
    "range_start": "192.168.167.50",
    "range_end": "192.168.167.200",
    "netmask": "255.255.255.0",
    "lease_time": "12h",
    "gateway": "192.168.167.1",
    "dns": "192.168.167.1",
    "domain": "array.local",
    "upstream_dns": ["1.1.1.1", "8.8.8.8"],
    "authoritative": True,
})
# Xbox reservation
res = dhcp.setdefault("reservations", [])
xbox = {"mac": "28:ea:0b:75:3b:75", "ip": "192.168.167.65", "hostname": "xbox"}
if not any(r.get("mac") == xbox["mac"] for r in res):
    res.append(xbox)
p.write_text(json.dumps(data, indent=2) + "\n")
PY

# Allow Xbox MAC for internet
python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/array-firewall/api")
from lib import devices
devices.set_allowed("28:ea:0b:75:3b:75", True, "Xbox SQUATX")
PY

/opt/array-firewall/scripts/wan-setup.sh || true
/opt/array-firewall/scripts/setup-dnsmasq.sh
apply-array-firewall

if [[ -f /etc/default/warzone-lobby-sentinel ]]; then
  /opt/array-firewall/scripts/sync-sentinel-config.sh 2>/dev/null || true
fi

echo ""
echo "=== cutover complete inside container ==="
hostname -I
ip route show default || true
systemctl is-active dnsmasq array-firewall-api warzone-lobby-sentinel 2>/dev/null || true
INNER

log ""
log "=== CUTOVER COMPLETE ==="
log "LAN gateway:  http://${LAN_GW}"
log "Dashboard:    http://${LAN_GW}:8090/"
log "Sentinel:     http://${LAN_GW}:8098/"
log "API token:    ssh root@${PROXMOX} \"pct exec ${CTID} -- cat /etc/array-firewall/api.token\""
log ""
log "Verify: renew DHCP on laptop, ping ${LAN_GW}, allow devices in dashboard."
log "Rollback: ./scripts/cutover-rollback.sh"
