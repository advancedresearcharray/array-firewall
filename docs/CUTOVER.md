# Gateway cutover procedure

Replace **Firewalla** as the network exit with **array-firewall** (CT940 on Proxmox thirtynince `.39`).

| Item | Value |
|------|--------|
| Firewall host | `192.168.167.39` (Proxmox) |
| Container | CT940 `array-firewall` |
| LAN gateway (after) | **`192.168.167.1`** |
| Dashboard | http://192.168.167.1:8090/ (after cutover) |
| Management (before) | http://192.168.167.241:8090/ |

---

## Topology

### Before (today)

```
ISP → Firewalla (192.168.167.1) → LAN 192.168.167.0/24
                                      └── CT940 @ .241 (sidecar/lab on nic1)
```

### After cutover

```
ISP/modem → nic2 (eth1/WAN, 192.168.1.x from modem)     } two separate
              array-firewall CT940 NAT                     } L2/L3 networks
house LAN → nic0 (eth0/LAN, 192.168.167.0/24) → switch   }
              gateway 192.168.167.1 · DHCP · MAC allowlist
```

**thirtynince (.39) port map:** `nic0` = Realtek 2.5G (house LAN), `nic2` = Intel 1Gb (modem WAN). Do not plug modem into `nic0` or LAN into `nic2`.

---

## Prerequisites

- [ ] Lab testing complete on **nic1** (devices get `10.99.0.x`, allow/deny works)
- [ ] **Admin laptop MAC** in allowlist (`ADMIN_LAPTOP_MAC` or dashboard)
- [ ] API token saved (http://192.168.167.241:8090/ → Connect)
- [ ] Xbox MAC/IP noted: `28:ea:0b:75:3b:75` / `192.168.167.65`
- [ ] Maintenance window (~15–30 min, brief outage)
- [ ] Console access to **Proxmox `.39`** (if SSH to `.1` fails mid-cutover)

---

## Phase 0 — Preflight (no outage)

From any LAN host with the deploy bundle:

```bash
cd /root/deploy/array-firewall

# Automated checks
./scripts/cutover-preflight.sh

# Or via API
TOKEN=$(ssh root@192.168.167.241 cat /etc/array-firewall/api.token)
curl -H "Authorization: Bearer $TOKEN" http://192.168.167.241:8090/api/v1/cutover/preflight
```

**All required checks must pass** before continuing.

Record from Firewalla (before shutdown):

- DHCP reservations (Xbox, static devices)
- Port forwards (if any)
- Any custom DNS entries

---

## Phase 1 — Physical wiring

Power off or disconnect WAN on **Firewalla** so it is **not** `192.168.167.1` when array-firewall comes up.

| Cable | Connect to |
|-------|------------|
| **ISP / modem** | **nic2** (Intel 1Gb) on `.39` → **vmbr1** → CT940 **eth1** (WAN only) |
| **House LAN switch** (all clients) | **nic0** (Realtek 2.5G) → **vmbr0** → CT940 **eth0** (LAN only) |

`vmbr0` and `vmbr1` are **separate bridges** — no shared ports. The firewall is the only path between LAN and WAN.

Do **not** leave Firewalla routing/NAT active on the same LAN segment as array-firewall at `.1`.

Optional: leave Firewalla powered on a **monitor port** only (no gateway/DHCP) for later comparison.

---

## Phase 2 — Run cutover script

From deploy host (has SSH to `root@192.168.167.39`):

```bash
cd /root/deploy/array-firewall

# Interactive (prompts for wiring confirmation)
./scripts/cutover-gateway.sh

# Non-interactive (only after wiring is done)
FORCE_CUTOVER=1 ./scripts/cutover-gateway.sh
```

The script will:

1. Backup config to `/var/lib/array-firewall/cutover-backup.json`
2. Set CT940 **eth0 = 192.168.167.1/24** (LAN gateway)
3. Set CT940 **eth1 = DHCP** (WAN from ISP)
4. Reboot container
5. Apply gateway nft rules (default deny, NAT, MAC allowlist)
6. Start **house DHCP** on eth0 (`192.168.167.50–200`)
7. DHCP client on WAN (eth1)
8. Restart sentinel (still uses Firewalla API if reachable, else local)

---

## Phase 3 — Verify (first 10 minutes)

### 3.1 From your laptop (on LAN)

```bash
# Should be .1 after cutover
ping -c2 192.168.167.1

# Renew DHCP (Linux)
sudo dhclient -r && sudo dhclient

# Check gateway
ip route | grep default
# → default via 192.168.167.1
```

### 3.2 Dashboard

Open **http://192.168.167.1:8090/** (or `.241` if cutover still pending).

- **Mode** → gateway LIVE
- **DHCP** → running, leases appear as devices connect
- **Devices** → allow your laptop + Xbox (and others as needed)

### 3.3 API smoke test

```bash
TOKEN=$(ssh root@192.168.167.1 cat /etc/array-firewall/api.token)

curl -H "Authorization: Bearer $TOKEN" http://192.168.167.1:8090/api/v1/cutover/status
curl -H "Authorization: Bearer $TOKEN" http://192.168.167.1:8090/api/v1/dhcp
curl -H "Authorization: Bearer $TOKEN" http://192.168.167.1:8090/api/v1/firewall/status
```

### 3.4 WAN / internet

```bash
ssh root@192.168.167.1 '
  ip route show default
  curl -s -m 5 https://one.one.one.one/cdn-cgi/trace | head -3
'
```

### 3.5 Xbox / gaming

1. Dashboard → DHCP → add reservation: `28:ea:0b:75:3b:75` → `192.168.167.65`
2. Dashboard → Devices → **Allow** Xbox MAC
3. Sentinel: http://192.168.167.1:8098/
4. Test Warzone matchmaking; packet shield should stay **in-match only**

---

## Phase 4 — Post-cutover tuning

| Task | How |
|------|-----|
| Allow household devices | Dashboard → Devices → Allow |
| Static IPs | Dashboard → DHCP → reservations |
| Xbox gaming | DHCP reservation + device allow + sentinel |
| Firewalla gaming tools | Still on `.1` path via API until ported local |
| Performance tune | BBR + cake QoS + DSCP EF + GPU analyze @ .221 |

---

## Rollback

If something fails, restore lab/sidecar mode:

```bash
cd /root/deploy/array-firewall
./scripts/cutover-rollback.sh
```

This restores:

- CT940 **eth0 = 192.168.167.241/24**
- CT940 **eth1 = 10.99.0.1/24**
- `ROLE=lab`, `CUTOVER=0`
- Lab DHCP on eth1 (`10.99.0.0/24`)

Then **re-enable Firewalla** as gateway (`192.168.167.1`) and restore original cabling.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| No LAN after cutover | eth0 not on switch / wrong IP | `pct enter 940` on `.39`, check `ip a` |
| No WAN | eth1 not on ISP / no DHCP | `wan-setup.sh`, check modem |
| Laptop no internet | MAC not allowed | Dashboard → Allow (admin MAC pre-approved) |
| Can't reach dashboard | Wrong IP / token | Try `.241` from mgmt, or Proxmox console |
| Double gateway | Firewalla still `.1` | Disable Firewalla routing |
| Xbox NAT issues | Strict NAT / double NAT | Ensure single NAT at array-firewall only |

### Emergency console (Proxmox)

```bash
ssh root@192.168.167.39
pct enter 940
array-firewall-ctl status
apply-array-firewall
systemctl status dnsmasq array-firewall-api
```

---

## Quick reference

```bash
# Preflight
./scripts/cutover-preflight.sh

# Cutover
FORCE_CUTOVER=1 ./scripts/cutover-gateway.sh

# Rollback
./scripts/cutover-rollback.sh

# Status
ssh root@192.168.167.1 array-firewall-ctl status
```

---

## Checklist (printable)

```
[ ] Preflight passed
[ ] Firewalla DHCP/reservations exported
[ ] Admin laptop MAC allowed
[ ] ISP → nic1, LAN switch → nic0
[ ] Firewalla no longer gateway .1
[ ] cutover-gateway.sh completed
[ ] ping 192.168.167.1 OK
[ ] laptop has default via .1
[ ] dashboard :8090 loads
[ ] WAN trace OK
[ ] Xbox reservation + allow
[ ] sentinel :8098 polling
[ ] household devices allowed
```
