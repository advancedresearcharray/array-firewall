#!/usr/bin/env bash
# Sentinel network-guard flood modes mapped to nft packet shield.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cmd="${1:-status}"
case "$cmd" in
  defend) exec "$ROOT/packet-shield-nft.sh" shield normal ;;
  harden) exec "$ROOT/packet-shield-nft.sh" shield strict ;;
  relax|off) exec "$ROOT/packet-shield-nft.sh" relax ;;
  status) exec "$ROOT/packet-shield-nft.sh" status ;;
  *) echo "Usage: $0 {defend|harden|relax|status}"; exit 2 ;;
esac
