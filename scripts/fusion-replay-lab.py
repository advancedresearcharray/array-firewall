#!/usr/bin/env python3
"""Offline fusion replay lab — A/B threshold tuning without live Xbox traffic."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "api"
sys.path.insert(0, str(ROOT))

from lib import replay_lab  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay session through AI fusion (dry or enforce)")
    ap.add_argument("session_json", type=Path, nargs="?", help="Session bundle or peers JSON")
    ap.add_argument("--hex", help="Session hex id under /var/lib/warzone-sentinel/sessions")
    ap.add_argument("--mode", default="observe", choices=["observe", "assist", "enforce"])
    ap.add_argument("--batch", nargs="*", help="Batch replay session hex ids")
    args = ap.parse_args()
    if args.batch:
        print(json.dumps(replay_lab.batch_replay(args.batch, mode=args.mode), indent=2, default=str))
        return 0
    if args.hex:
        result = replay_lab.replay_session_hex(args.hex, mode=args.mode)
    elif args.session_json:
        result = replay_lab.replay_path(args.session_json, mode=args.mode)
    else:
        print(json.dumps(replay_lab.status(), indent=2))
        return 0
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
