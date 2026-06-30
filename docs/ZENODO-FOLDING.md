# Zenodo dimensional folding on array-firewall

Optional throughput folding stack for telemetry and gaming sidecars.

## Config

Set in `/etc/array-firewall/array-firewall.conf` or environment:

```
FOLDING_ENABLED=1
FOLD_RELAY_URL=                    # optional: http://fold-relay.example:19557
```

When `FOLD_RELAY_URL` points at a host running `array-fold-relay` + `array-payload-field`, lanes proxy to the Rust stack. Otherwise the container runs the local Python engine.

## Apply to container

```bash
export PROXMOX_NODE=pve-primary.example
export ARRAY_FW_CTID=100
export FOLD_RELAY_URL=http://192.0.2.254:19557   # optional relay

./scripts/apply-folding-to-ct.sh
```

## API

- `GET /api/v1/folding/status`
- `POST /api/v1/folding/enable` / `disable`

Dashboard → **Folding** tab when enabled in policies.
