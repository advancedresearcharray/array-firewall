#!/usr/bin/env bash
# Restore Xbox WAN NAT if SNAT/DMZ chains were stripped (probe_blackhole-only state).
set -euo pipefail
export PYTHONPATH=/opt/array-firewall/api
python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/array-firewall/api")
from lib import nat

result = nat.ensure_wan_nat()
if result.get("restored"):
    print("[wan-nat-watchdog] restored:", result)
elif not result.get("ok"):
    print("[wan-nat-watchdog] failed:", result, file=sys.stderr)
    raise SystemExit(1)
PY
