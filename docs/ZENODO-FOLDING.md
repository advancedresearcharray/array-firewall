# Zenodo dimensional folding on array-firewall (CT940)

Operational mapping of Kilpatrick / Advanced Research Array papers to code in this appliance.

| Zenodo | DOI | Implementation |
|--------|-----|----------------|
| [18728103](https://zenodo.org/records/18728103) | 10.5281/zenodo.18728103 | `api/lib/folding.py` — CPU/memory/network/storage lanes, BLSB on network+storage, gzip stack |
| [18453148](https://zenodo.org/records/18453148) | 10.5281/zenodo.18453148 | `/api/v1/folding/wire/*`, GPU analyze wire compression, `network_throughput_factor` |
| [18102374](https://zenodo.org/records/18102374) | 10.5281/zenodo.18102374 | `fold_vector_8196_to_32()` block projection (Sentinel `fold.rs` uses same family) |
| [18143028](https://zenodo.org/records/18143028) | 10.5281/zenodo.18143028 | `cube_space_coords()` on firewall telemetry + fold probe |
| [18005544](https://zenodo.org/records/18005544) | 10.5281/zenodo.18005544 | Unified metadata in `folding.status()` |
| [17373031](https://zenodo.org/records/17373031) | 10.5281/zenodo.17373031 | `information_flow_bits()` conditional entropy proxy |
| [18079593](https://zenodo.org/records/18079593) | 10.5281/zenodo.18079593 | `memory_pattern_*` hints on each lane |
| [17844752](https://zenodo.org/records/17844752) | 10.5281/zenodo.17844752 | `quadrant_shortcut_digest_hex` + LRU shortcut cache |
| [18079453](https://zenodo.org/records/18079453) | 10.5281/zenodo.18079453 | Pattern RLE stage label in `compression_stack` |

## Configuration (`/etc/array-firewall/array-firewall.conf`)

```ini
FOLDING_ENABLED=1
FOLD_RELAY_URL=                    # optional: http://192.168.167.240:19557
ARRAY_PROCESSOR_FOLD_DIM=32
```

When `FOLD_RELAY_URL` points at a host running `array-fold-relay` + `array-payload-field`, lanes proxy to the Rust stack (`deploy/lxc/README.md`). Otherwise CT940 runs the local Python engine.

## API

```
GET  /api/v1/folding/status
GET  /api/v1/folding/savings
POST /api/v1/folding/stats/reset
POST /api/v1/folding/filter/{cpu|memory|network|storage}   {"payload":"..."}
POST /api/v1/folding/wire/compress                         {"payload_b64":"..."}
POST /api/v1/folding/wire/decompress                       {"payload_b64":"..."}
```

## Verify

```bash
./scripts/verify-array-firewall-folding.sh
```

From Proxmox against CT940:

```bash
pct exec 940 -- /opt/array-firewall/scripts/verify-array-firewall-folding.sh
```

## Host relay (optional)

On a fold host with Rust binaries built (`/root/array-payload-field`):

```bash
sudo cp deploy/systemd/array-payload-field.service /etc/systemd/system/
sudo systemctl enable --now array-payload-field array-fold-relay
```

Then set on CT940:

```ini
FOLD_RELAY_URL=http://192.168.167.39:19557
```

See also `deploy/lxc/ZENODO-STACK.md` for the full fleet map.
