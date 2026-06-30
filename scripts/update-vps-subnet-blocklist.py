#!/usr/bin/env python3
"""Refresh VPS/cloud provider CIDR catalog and optional subnet enforcement."""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "/opt/array-firewall/api")

from lib import subnet_blocklist  # noqa: E402


def main() -> int:
    result = subnet_blocklist.refresh_providers()
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
