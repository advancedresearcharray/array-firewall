# Gateway cutover procedure

Replace the **legacy gateway** as the network exit with **array-firewall** (LXC on Proxmox).

Configure via environment (see `README.md`):

| Variable | Purpose |
|----------|---------|
| `PROXMOX_NODE` | Proxmox host |
| `ARRAY_FW_CTID` | Firewall container ID |
| `ARRAY_FW_IP` | Pre-cutover management IP on LAN (`eth0`) |

| Item | Example (RFC 5737) |
|------|---------------------|
| Proxmox | `${PROXMOX_NODE}` |
| Container | CT `${ARRAY_FW_CTID}` `array-firewall` |
| LAN gateway (after) | **`192.0.2.1`** |
| Dashboard (after) | `http://192.0.2.1:8090/` |
| Management (before) | `http://${ARRAY_FW_IP}:8090/` |

---

## Topology

### Before (lab / sidecar)

```
ISP → legacy gateway (192.0.2.1) → LAN 192.0.2.0/24
                                      └── array-firewall @ sidecar IP (lab on secondary NIC)
```

### After cutover

```
ISP/modem → WAN NIC (eth1, DHCP from modem)
              array-firewall NAT
house LAN → LAN NIC (eth0, 192.0.2.0/24) → switch
              gateway 192.0.2.1 · DHCP · MAC allowlist
```

**Proxmox wiring:** dedicate one physical NIC to WAN (modem) and one to LAN (house switch). Do not bridge WAN and LAN on the same segment.

---

## Prerequisites

- [ ] Lab testing complete on **secondary NIC** (lab subnet DHCP, allow/deny works)
- [ ] **Admin laptop MAC** in allowlist (`ADMIN_LAPTOP_MAC` or dashboard)
- [ ] API token saved (`http://${ARRAY_FW_IP}:8090/` → Connect)
- [ ] Console / gaming device MAC/IP noted in dashboard reservations
- [ ] Maintenance window (~15–30 min, brief outage)
- [ ] Console access to **Proxmox** (if SSH to gateway fails mid-cutover)

---

## Phase 0 — Preflight (no outage)

From any LAN host with the deploy bundle:

```bash
export PROXMOX_NODE=pve-primary.example
export ARRAY_FW_CTID=100
export ARRAY_FW_IP=192.0.2.10

cd /path/to/array-firewall
./scripts/cutover-preflight.sh

# Or via API
TOKEN=$(ssh root@${ARRAY_FW_IP} cat /etc/array-firewall/api.token)
curl -H "Authorization: Bearer $TOKEN" http://${ARRAY_FW_IP}:8090/api/v1/cutover/preflight
```

**All required checks must pass** before continuing.

Record from the old gateway (before shutdown):

- DHCP reservations (console, static devices)
- Port forwards (if any)
- Any custom DNS entries

---

## Phase 1 — Physical wiring

Power off or disconnect WAN on the **legacy gateway** so it is **not** `192.0.2.1` when array-firewall comes up.

| Cable | Connect to |
|-------|------------|
| **ISP / modem** | WAN bridge → container **eth1** |
| **House LAN switch** | LAN bridge → container **eth0** |

Bridges must be **separate** — the firewall is the only path between LAN and WAN.

Do **not** leave the old gateway routing/NAT active on the same LAN segment as array-firewall.

---

## Phase 2 — Run cutover script

From deploy host (SSH to `root@${PROXMOX_NODE}`):

```bash
export PROXMOX_NODE=pve-primary.example
export ARRAY_FW_CTID=100
export ARRAY_FW_IP=192.0.2.10

cd /path/to/array-firewall
./scripts/cutover-gateway.sh
# or: FORCE_CUTOVER=1 ./scripts/cutover-gateway.sh
```

The script will:

1. Backup config to `/var/lib/array-firewall/cutover-backup.json`
2. Set **eth0 = 192.0.2.1/24** (LAN gateway)
3. Set **eth1 = DHCP** (WAN from ISP)
4. Reboot container
5. Apply gateway nft rules (default deny, NAT, MAC allowlist)
6. Start **house DHCP** on eth0
7. DHCP client on WAN (eth1)
8. Restart sentinel

---

## Phase 3 — Verify (first 10 minutes)

```bash
ping -c2 192.0.2.1
ip route | grep default   # → default via 192.0.2.1
```

Dashboard: **http://192.0.2.1:8090/** — mode gateway LIVE, DHCP running.

```bash
TOKEN=$(ssh root@192.0.2.1 cat /etc/array-firewall/api.token)
curl -H "Authorization: Bearer $TOKEN" http://192.0.2.1:8090/api/v1/cutover/status
curl -H "Authorization: Bearer $TOKEN" http://192.0.2.1:8090/api/v1/dhcp
```

WAN check:

```bash
ssh root@192.0.2.1 'ip route show default; curl -s -m 5 https://one.one.one.one/cdn-cgi/trace | head -3'
```

Gaming: DHCP reservation + device allow + sentinel at `:8098/`.

---

## Rollback

```bash
./scripts/cutover-rollback.sh
```

Restores sidecar/lab networking (`ROLE=lab`, pre-cutover IPs). Re-enable the legacy gateway and original cabling.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| No LAN after cutover | eth0 not on switch / wrong IP | Proxmox console, check `ip a` |
| No WAN | eth1 not on ISP / no DHCP | `wan-setup.sh`, check modem |
| Laptop no internet | MAC not allowed | Dashboard → Allow |
| Double gateway | Old device still `.1` | Disable legacy routing |

Emergency console:

```bash
ssh root@${PROXMOX_NODE}
pct enter ${ARRAY_FW_CTID}
array-firewall-ctl status
```
