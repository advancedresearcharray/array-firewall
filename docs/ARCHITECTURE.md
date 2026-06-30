# array-firewall — target architecture

**North star:** array-firewall becomes the **network exit** for the entire LAN — protect, NAT, segment, observe — with **full customization** via dashboard + API.

Current state: **lab mode** (bench on secondary NIC). Target state: **gateway mode** inline between ISP and house LAN.

---

## Topology

### Today (lab / sidecar)

```
192.0.2.0/24 (existing LAN, legacy gateway still active)
        │
   eth0 ${ARRAY_FW_IP}  ← management + API + sentinel
        │
   array-firewall (CT ${ARRAY_FW_CTID})
        │
   eth1 198.51.100.0/24  ← test clients on lab NIC only
```

### Target (gateway — full network exit)

```
        ISP / modem
            │
      WAN  eth1  ── default route, unsolicited inbound DROP
            │
     array-firewall
            │
      LAN  eth0  ── DHCP, DNS, whole-house NAT, device policies
            │
    switch / MoCA / Wi‑Fi AP
            │
   consoles, laptops, IoT, cameras, …
```

The legacy appliance can move to **bridge/monitor**, **retire**, or stay as a **read-only telemetry source** during migration.

---

## Design principles

| Principle | Meaning |
|-----------|---------|
| **Default deny** | Forward and input drop; only established/related + explicit allows |
| **Unsolicited blocked** | No inbound from WAN unless port-forward / related |
| **NAT by default** | Masquerade all LAN → WAN |
| **Device-centric** | Every client identified by MAC/IP; allow/deny + per-device policy |
| **Observable** | Dashboard, API, sentinel, IDS hooks, session timeline |
| **Gaming-aware** | Packet shield, QoS, peer blocklist, upload/download assist |

---

## Migration phases

1. **Lab** — secondary NIC bench; allow/deny, DHCP, API validation
2. **Sidecar** — same LAN as legacy gateway; sentinel + gaming tools online
3. **Cutover** — physical rewire; array-firewall becomes `192.0.2.1` (or your chosen gateway)
4. **Harden** — zones, IDS, subnet blocklist, provider catalog

---

## Services (target stack)

| Service | Port | Role |
|---------|------|------|
| `array-firewall-api` | 8090 | Dashboard + REST API |
| `warzone-lobby-sentinel` | 8098 | Lobby integrity, gaming automation |
| `dnsmasq` | 53/67 | DHCP + DNS (LAN) |
| nftables | — | Forward filter, NAT, gaming sets |

See [CUTOVER.md](CUTOVER.md) for the gateway switch procedure.
