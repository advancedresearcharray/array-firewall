# array-firewall on Proxmox thirtynince (.39)

Custom **network exit** firewall — Firewalla-class protection (default deny, NAT, device approval, unsolicited blocked) with **full customization** via dashboard + API.

**Target:** replace Firewalla as the house gateway. **Now:** lab mode on nic1 for safe testing.

See **[docs/CUTOVER.md](docs/CUTOVER.md)** for the full gateway cutover procedure (preflight → wiring → cutover → verify → rollback).

```bash
./scripts/cutover-preflight.sh          # checks only
FORCE_CUTOVER=1 ./scripts/cutover-gateway.sh   # go live
./scripts/cutover-rollback.sh         # undo
```

## Host

| Item | Value |
|------|--------|
| Proxmox | **192.168.167.39** (thirtynince) |
| CTID | **940** |
| Management | **192.168.167.241** (eth0) |
| Lab / clients | **10.99.0.1/24** (eth1 → vmbr1 → nic1) |
| Dashboard | **http://192.168.167.241:8090/** |
| Sentinel | **http://192.168.167.241:8098/** |

## Security model

- **Forward + input:** drop by default; only established/related + explicit allows
- **Internet (lab → uplink):** only MACs in allowlist (admin laptop pre-approved)
- **NAT:** masquerade `10.99.0.0/24` → uplink (`eth0` / main LAN until WAN on nic1)
- **Unsolicited inbound:** denied on lab/WAN interface
- **New devices:** discovered via DHCP/ARP, **denied** until allowed in dashboard

## Deploy

```bash
# Set your laptop MAC (recommended)
echo 'ADMIN_LAPTOP_MAC=aa:bb:cc:dd:ee:ff' > /root/.secrets/array-firewall.env

cd /root/deploy/array-firewall
./deploy.sh
```

Token after deploy: `ssh root@192.168.167.241 cat /etc/array-firewall/api.token`

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

1. Plug a device into **nic1** — gets `10.99.0.x` via DHCP, no internet until allowed
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
