#!/usr/bin/env python3
"""Run one AI Autopilot fusion cycle (systemd timer entry point)."""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "/opt/array-firewall/api")

from lib import ai_ops  # noqa: E402


def main() -> int:
    result = ai_ops.tick(source="systemd", force=False)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
