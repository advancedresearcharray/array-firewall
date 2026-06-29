#!/usr/bin/env bash
# Wrapper for fleet push quota checker (source: array-gh-inbox-fleet/bin/gh-push-quota).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$ROOT/scripts/gh-push-quota.py" "$@"
