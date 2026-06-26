#!/usr/bin/env bash
# Sentinel-compatible alias for array-firewall nft packet shield.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec "$ROOT/packet-shield-nft.sh" "$@"
