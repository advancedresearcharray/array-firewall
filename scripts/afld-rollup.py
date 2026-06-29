#!/usr/bin/env python3
"""Roll AFLD hot buffer into folded segments and prune >24h."""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "/opt/array-firewall/api")

from lib import afld  # noqa: E402


def main() -> int:
    rollup = afld.rollup(force=True)
    prune = afld.prune()
    print(json.dumps({"rollup": rollup, "prune": prune, "status": afld.status()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
