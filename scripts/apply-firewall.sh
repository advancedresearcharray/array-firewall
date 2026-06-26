#!/usr/bin/env bash
# Apply MAC-gated NAT + default-deny rules from device store.
set -euo pipefail
cd /opt/array-firewall/api
export PYTHONPATH=/opt/array-firewall/api
python3 - <<'PY'
from lib import devices, nft, perf, qos, stability
devices.discover()
nft.apply_ruleset()
print("[apply-firewall] rules applied, allowed:", devices.allowed_macs())
try:
    stability.bootstrap_on_boot()
    print("[apply-firewall] stability bootstrap done")
except Exception as exc:
    print("[apply-firewall] stability bootstrap skipped:", exc)
try:
    perf.apply_tune()
    print("[apply-firewall] perf tune applied")
except Exception as exc:
    print("[apply-firewall] perf tune skipped:", exc)
try:
    qos.apply()
    print("[apply-firewall] qos applied")
except Exception as exc:
    print("[apply-firewall] qos skipped:", exc)
PY

STATE="/var/lib/array-firewall/packet-shield.state"
if [[ -f "$STATE" ]] && grep -q '^mode=shield' "$STATE" 2>/dev/null; then
  /opt/array-firewall/scripts/packet-shield-nft.sh shield normal || true
fi
