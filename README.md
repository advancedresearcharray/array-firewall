# array-firewall on Proxmox

Custom **network exit** firewall — Firewalla-class protection (default deny, NAT, device approval, unsolicited blocked) with **full customization** via dashboard + API.

**Target:** replace the legacy gateway as the house exit. **Now:** lab mode on a secondary NIC for safe testing.

See **[docs/CUTOVER.md](docs/CUTOVER.md)** for the full gateway cutover procedure (preflight → wiring → cutover → verify → rollback).

```bash
./scripts/cutover-preflight.sh          # checks only
FORCE_CUTOVER=1 ./scripts/cutover-gateway.sh   # go live
./scripts/cutover-rollback.sh         # undo
```

## Deployment reference

Set these in your environment (or a local secrets file — **never commit site-specific values**):

| Variable | Purpose |
|----------|---------|
| `PROXMOX_NODE` | Proxmox host (management reachability) |
| `ARRAY_FW_CTID` | LXC ID for `array-firewall` |
| `ARRAY_FW_IP` | Container management IP on LAN (`eth0`) |
| `ARRAY_FW_LAB_CIDR` | Lab / bench client subnet on `eth1` (e.g. `198.51.100.1/24`) |

| Item | Example (RFC 5737 documentation space) |
|------|----------------------------------------|
| Proxmox | `${PROXMOX_NODE}` |
| Container | CT `${ARRAY_FW_CTID}` |
| Management | `${ARRAY_FW_IP}` (`eth0`) |
| Lab / clients | `${ARRAY_FW_LAB_CIDR}` (`eth1` → lab bridge) |
| Dashboard | `http://${ARRAY_FW_IP}:8090/` |
| Sentinel | `http://${ARRAY_FW_IP}:8098/` |

## Security model

- **Forward + input:** drop by default; only established/related + explicit allows
- **Internet (lab → uplink):** only MACs in allowlist (admin laptop pre-approved)
- **NAT:** masquerade lab CIDR → uplink
- **Unsolicited inbound:** denied on lab/WAN interface
- **New devices:** discovered via DHCP/ARP, **denied** until allowed in dashboard

## Deploy

```bash
# Set your laptop MAC (recommended)
echo 'ADMIN_LAPTOP_MAC=aa:bb:cc:dd:ee:ff' > /root/.secrets/array-firewall.env

export PROXMOX_NODE=pve-primary.example
export ARRAY_FW_CTID=100
export ARRAY_FW_IP=192.0.2.10

cd /path/to/array-firewall
./deploy.sh
```

Token after deploy: `ssh root@${ARRAY_FW_IP} cat /etc/array-firewall/api.token`

## API (Bearer token)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Service health (no auth) |
| GET | `/api/v1/devices` | List devices + allow status |
| POST | `/api/v1/devices/{mac}/allow` | Grant internet |
| POST | `/api/v1/devices/{mac}/deny` | Revoke internet |
| POST | `/api/v1/firewall/discover` | Rescan DHCP/ARP + reload rules |
| POST | `/api/v1/firewall/reload` | Re-apply nft rules |
| GET | `/api/v1/firewall/status` | NAT, shield, allowlist summary |
| POST | `/api/v1/shield/enable` | `{ "level": "normal" }` |
| POST | `/api/v1/shield/relax` | Disable packet shield |

## Testing

1. Plug a device into the **lab NIC** — gets a DHCP address on the lab subnet, no internet until allowed
2. Open dashboard — allow device with one click
3. Admin laptop MAC (from secrets) has internet from first boot

## Files

```
/opt/array-firewall/api/          # Python API + dashboard
/var/lib/array-firewall/devices.json
/var/lib/array-firewall/ruleset.nft
/etc/array-firewall/api.token
/etc/dnsmasq.d/array-firewall.conf
```
