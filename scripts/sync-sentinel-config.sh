#!/usr/bin/env bash
# Sync co-hosted Warzone sentinel with array-firewall API token and Xbox config.
set -euo pipefail
ROOT="/opt/array-firewall"
export PYTHONPATH="${ROOT}/api${PYTHONPATH:+:$PYTHONPATH}"
python3 - <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, "/opt/array-firewall/api")
from lib import sentinel

sentinel.sync_all(restart=False)
print("[sync-sentinel] token + env synced (127.0.0.1:8090)")
PY
if systemctl is-active warzone-lobby-sentinel >/dev/null 2>&1; then
  systemctl restart warzone-lobby-sentinel
  echo "[sync-sentinel] warzone-lobby-sentinel restarted"
fi
