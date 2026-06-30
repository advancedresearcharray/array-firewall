#!/usr/bin/env python3
"""Fleet blocklist export + optional HTTP push/pull (systemd timer entry point)."""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "/opt/array-firewall/api")

from lib import fleet_blocklist, policies  # noqa: E402


def main() -> int:
    cfg = policies.load().get("ai_ops") or {}
    if not cfg.get("fleet_sync_enabled", True):
        print(json.dumps({"ok": True, "skipped": True, "reason": "fleet_sync disabled"}))
        return 0

    result: dict = {"ok": True}
    result["export"] = fleet_blocklist.export_bundle()

    export_url = str(cfg.get("fleet_export_url") or "").strip()
    if export_url:
        result["push"] = fleet_blocklist.push_to_url(export_url)

    pull_url = str(cfg.get("fleet_pull_url") or "").strip()
    if pull_url:
        merge = str(cfg.get("fleet_merge_policy") or "merge")
        result["pull"] = fleet_blocklist.scheduled_pull(pull_url, merge_policy=merge)

    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
