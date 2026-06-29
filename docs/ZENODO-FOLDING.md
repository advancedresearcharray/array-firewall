# Zenodo dimensional folding on array-firewall (CT940)

Operational mapping of Kilpatrick / Advanced Research Array papers to code in this appliance.

| Zenodo | DOI | Implementation |
|--------|-----|----------------|
| [18728103](https://zenodo.org/records/18728103) | 10.5281/zenodo.18728103 | `api/lib/folding.py` — CPU/memory/network/storage lanes, BLSB on network+storage, gzip stack |
| [18453148](https://zenodo.org/records/18453148) | 10.5281/zenodo.18453148 | `api/lib/throughput_fold.py` — fold+BLsb+gzip wire pipeline, effective throughput, preservation ratio |
| [18102374](https://zenodo.org/records/18102374) | 10.5281/zenodo.18102374 | `fold_vector_8196_to_32()` block projection (Sentinel `fold.rs` uses same family) |
| [18143028](https://zenodo.org/records/18143028) | 10.5281/zenodo.18143028 | `cube_space_coords()` on firewall telemetry + fold probe |
| [18081661](https://zenodo.org/records/18081661) | 10.5281/zenodo.18081661 | 4096→16→8→4 fold cascade (reference; video streaming at gateway not operational on TLS OTT) |
| [18005544](https://zenodo.org/records/18005544) | 10.5281/zenodo.18005544 | Unified metadata in `folding.status()` |
| [17373031](https://zenodo.org/records/17373031) | 10.5281/zenodo.17373031 | `api/lib/information_flow.py` — Flow(M,x,t)=H(State_t\|State_{t-1}), IDS SI-4-IFC, barrier theorems |
| [18079593](https://zenodo.org/records/18079593) | 10.5281/zenodo.18079593 | `memory_pattern_*` hints on each lane |
| [17844752](https://zenodo.org/records/17844752) | 10.5281/zenodo.17844752 | `quadrant_shortcut_digest_hex` + LRU shortcut cache |
| [20942201](https://zenodo.org/records/20942201) | 10.5281/zenodo.20942201 | `api/lib/rqd.py` — polynomial search, pattern shortcuts, allowlist/investigate/buffer paths |
| [18770016](https://zenodo.org/records/18770016) | 10.5281/zenodo.18770016 | `api/lib/asvi.py` — shell-margin void index, SMST labels, allowlist gap scan |
| [18079453](https://zenodo.org/records/18079453) | 10.5281/zenodo.18079453 | `api/lib/pattern_encode.py` — pattern RLE + LZ backrefs, structural redundancy analysis, wire stage before BLSB |
| [17372973](https://zenodo.org/records/17372973) | 10.5281/zenodo.17372973 | `api/lib/qce.py` — entanglement entropy + IIT Φ proxy, consciousness scaling law, investigation prioritization |

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
GET  /api/v1/folding/throughput
POST /api/v1/folding/throughput/estimate                   {"payload":"..."}
GET  /api/v1/folding/pattern/status
POST /api/v1/folding/pattern/encode                        {"payload":"..."} or {"analyze_only":true}
GET  /api/v1/qce/status
GET  /api/v1/qce/measure?session_hex=...&limit=300
POST /api/v1/qce/measure                                     {"session_hex":"..."} or {"rows":[...]}
GET  /api/v1/rqd/status
GET  /api/v1/rqd/buffer-profile
POST /api/v1/rqd/buffer-profile                            {"apply":true,"sample":{...}}
POST /api/v1/rqd/search                                     {"items":[...],"key_field":"key","score_field":"score"}
POST /api/v1/qos/buffer                                     {"profile":"auto"} or {"auto_rqd":true}
GET  /api/v1/asvi/status
GET  /api/v1/asvi/scan?session_hex=...&limit=300
POST /api/v1/asvi/scan                                      {"session_hex":"...","limit":300}
GET  /api/v1/asvi/unknown-voids?limit=200
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
