#!/usr/bin/env python3
"""Offline fusion replay lab — A/B threshold tuning without live Xbox traffic."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, "/opt/array-firewall/api")

from lib import ai_ops, policies  # noqa: E402


def load_session(path: Path) -> dict:
    if path.suffix == ".json":
        doc = json.loads(path.read_text(encoding="utf-8"))
        if "detail" in doc:
            return doc["detail"]
        if "peers" in doc:
            return doc
        if "files" in doc:
            for f in doc["files"]:
                data = f.get("data") or {}
                if data.get("peers"):
                    return data
    raise ValueError(f"no peers in {path}")


def replay(path: Path, *, mode: str = "observe") -> dict:
    payload = {"peer_tracker": {"peers": load_session(path).get("peers") or []}}
    data = policies.load()
    ai = dict(data.get("ai_ops") or {})
    ai["mode"] = mode
    data["ai_ops"] = ai
    policies.save(data)
    return ai_ops.tick(sentinel_payload=payload, force=True, source=f"replay:{path.name}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay session through AI fusion (dry or enforce)")
    ap.add_argument("session_json", type=Path, help="Session bundle or peers JSON")
    ap.add_argument("--mode", default="observe", choices=["observe", "assist", "enforce"])
    args = ap.parse_args()
    result = replay(args.session_json, mode=args.mode)
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
