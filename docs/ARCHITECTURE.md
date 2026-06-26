# array-firewall — target architecture

**North star:** array-firewall becomes the **network exit** for the entire LAN — same job Firewalla does today (protect, NAT, segment, observe) — with **full customization** via dashboard + API.

Current state: **lab mode** on CT940 (bench on nic1). Target state: **gateway mode** inline between ISP and house LAN.

---

## Topology

### Today (lab / sidecar)

```
192.168.167.0/24 (existing LAN, Firewalla still gateway)
        │
   eth0 192.168.167.241  ← management + API + sentinel
        │
   CT940 array-firewall
        │
   eth1 10.99.0.0/24  ← test clients on nic1 only
```

### Target (gateway — full network exit)

```
        ISP / modem
            │
      nic1 (WAN)  eth1  ── default route, unsolicited inbound DROP
            │
     array-firewall CT940
            │
      nic0 (LAN)  eth0  ── DHCP, DNS, whole-house NAT, device policies
            │
    switch / MoCA / Wi‑Fi AP
            │
   Xbox, laptops, IoT, cameras, …
```

Firewalla can then move to **bridge/monitor**, **retire**, or stay as a **read-only telemetry source** during migration.

---

## Design principles

| Principle | Meaning |
|-----------|---------|
| **Default deny** | Forward and input drop; only established/related + explicit allows |
| **Unsolicited blocked** | No inbound from WAN unless port-forward / related |
| **NAT by default** | Masquerade all LAN → WAN |
| **Device-centric** | Every client identified by MAC/IP; allow/deny + per-device policy |
| **Customize everything** | Policies, QoS, shields, routes via API — not locked to vendor UI |
| **Gaming is first-class** | Warzone sentinel + packet shield + role QoS live on the same box |
| **Sidecar → cutover** | Build and test on nic1 lab; flip `ROLE=gateway` when ready |

---

## Firewalla parity matrix

What Firewalla Gold does today vs array-firewall plan:

| Capability | Firewalla today | array-firewall |
|------------|-----------------|----------------|
| Default-deny firewall | ✅ | ✅ (nftables) |
| NAT / PAT | ✅ | ✅ |
| DHCP for LAN | ✅ | ✅ (dnsmasq) |
| DNS for LAN | ✅ | 🔲 unbound/dnsmasq + blocklists |
| Device inventory | ✅ App | ✅ dashboard (DHCP/ARP) |
| New device approval | App alerts | ✅ MAC allowlist (dashboard) |
| Per-device internet block | ✅ | ✅ allow/deny |
| Gaming QoS / mode | ✅ policies 569/570 | 🔲 nft dscp + cake/fq_codel on WAN |
| Ad/tracker block | ✅ | 🔲 dns + nft sets (custom lists) |
| Port forwarding | ✅ | 🔲 API-managed dstnat rules |
| VPN / WireGuard | ✅ | 🔲 optional module |
| IDS / flow logs | ✅ Zeek | 🔲 conntrack + optional suricata |
| Mobile app | ✅ | 🔲 dashboard + API (already) |
| Route / path control | gaming-tools | 🔲 port from gaming-route-* scripts |
| Xbox packet shield | gaming-packet-shield | ✅ packet-shield-nft |
| Cheater lobby sentinel | CT941 sidecar | ✅ co-hosted :8098 |
| **Full customization** | ❌ limited | ✅ **core goal** |

Legend: ✅ done or partial · 🔲 planned · ❌ not a goal to copy blindly

---

## Policy model (customization layer)

All house rules live in **`/var/lib/array-firewall/policies.json`** (API read/write):

```json
{
  "network": {
    "role": "lab",
    "lan_cidr": "10.99.0.0/24",
    "wan_if": "eth1",
    "default_posture": "deny_new_devices"
  },
  "defaults": {
    "internet": "deny_until_approved",
    "dns_filter": "standard",
    "qos_profile": "balanced"
  },
  "devices": {
    "28:ea:0b:75:3b:75": {
      "label": "Xbox SQUATX",
      "internet": "allow",
      "qos_profile": "gaming",
      "packet_shield": "in_match_only"
    }
  },
  "custom": {
    "port_forwards": [],
    "blocklists": [],
    "scripts": []
  }
}
```

**Customize as needed:** add profiles (`gaming`, `kids`, `iot_quarantine`), hook scripts, blocklists, SQM rates — all without vendor firmware changes.

---

## Migration phases

### Phase 1 — Lab (now)
- CT940 on `.39`, nic1 = test LAN
- MAC allowlist, NAT, dashboard, API, sentinel
- Learn policies without touching house traffic

### Phase 2 — Parallel gateway
- Cable **nic1 → ISP**, **nic0 → house switch** (or upstream of Firewalla)
- `ROLE=gateway`, `LAN_CIDR=192.168.167.0/24` (or new RFC1918)
- Firewalla stays backup path; compare telemetry

### Phase 3 — Full exit
- Default route for house → array-firewall only
- Port gaming-tools from Firewalla (`gaming-*`) to native nft modules on CT940
- Sentinel reads **local** flow data (no `:9378` hop)
- Firewalla off or monitor-only

### Phase 4 — Harden + extend
- SQM/cake on WAN
- DNS filtering + DoH blocking
- VPN, VLANs, IoT segment on `10.99.0.0/24` or separate bridge

---

## Performance (gateway duty)

When this box is the **only exit**, optimize for:

1. **Hardware path** — nic1 2.5G WAN where possible; offload-friendly nft rules
2. **Light control plane** — snapshot/poll on-box, not round-trip to old Firewalla
3. **Gaming path** — packet shield in-match only; cake/fq_codel on WAN; DSCP for Xbox
4. **No double-NAT** — single masquerade point at array-firewall WAN

---

## Services on CT940 (target stack)

```
array-firewall-api.service     :8090  dashboard + REST
warzone-lobby-sentinel.service :8098  gaming intelligence
dnsmasq                        LAN DHCP/DNS
nftables                       filter + nat + mangle (+ gaming table)
apply-firewall.service         boot-time rules from policies.json
```

---

## What we are NOT trying to clone

- Firewalla mobile app UX verbatim
- Cloud account / remote management (unless we add it)
- Opaque Redis/netbot internals — we use **open policies + nft + API**

We **are** matching the **security posture** (protect the LAN, approve devices, NAT, block unsolicited) with **more control** for Warzone and house rules.

---

## Config switch (lab → gateway)

In `/etc/array-firewall/array-firewall.conf`:

```bash
ROLE=lab          # lab | gateway
LAN_IF=eth1
WAN_IF=eth1       # lab: uplink via eth0; gateway: nic1 to ISP
UPLINK_IF=eth0      # lab only
LAN_CIDR=10.99.0.0/24
# Gateway cutover example:
# ROLE=gateway
# LAN_IF=eth0
# WAN_IF=eth1
# UPLINK_IF=eth1
# LAN_CIDR=192.168.167.0/24
```

Reload: `apply-array-firewall` or `POST /api/v1/firewall/reload`.
