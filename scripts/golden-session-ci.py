#!/usr/bin/env python3
"""Golden-session regression — replay sanitized fixtures through fusion (CI-friendly)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "api"
sys.path.insert(0, str(ROOT))

from lib import replay_lab  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "golden-sessions"


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay golden sessions — assert shield/block expectations")
    ap.add_argument("--fixture-dir", type=Path, default=FIXTURES)
    ap.add_argument("--mode", default="observe", choices=("observe", "assist", "enforce"))
    ap.add_argument("--write-fixtures", action="store_true", help="Scaffold empty fixture dir")
    args = ap.parse_args()

    if args.write_fixtures:
        args.fixture_dir.mkdir(parents=True, exist_ok=True)
        (args.fixture_dir / "clean_lobby.json").write_text(
            json.dumps(
                {
                    "name": "clean_lobby",
                    "session_hex": "golden_clean",
                    "phase": "matchmaking",
                    "expect": {"max_blocks": 0, "shield_optional": True},
                    "payload": {"phase": "matchmaking", "cheater_label": "CLEAN", "peer_tracker": {"peers": []}},
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (args.fixture_dir / "bad_vps_mesh.json").write_text(
            json.dumps(
                {
                    "name": "bad_vps_mesh",
                    "session_hex": "golden_bad",
                    "phase": "in-match",
                    "expect": {"verdict": "hostile"},
                    "payload": {
                        "phase": "in-match",
                        "cheater_label": "LIKELY",
                        "peer_tracker": {
                            "peers": [
                                {"ip": "45.76.1.1", "identical_count": 24, "vps_probe": True},
                                {"ip": "45.76.1.2", "identical_count": 22, "vps_probe": True},
                            ]
                        },
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"Wrote fixtures under {args.fixture_dir}")
        return 0

    if not args.fixture_dir.is_dir():
        print(f"No fixtures at {args.fixture_dir} — run with --write-fixtures", file=sys.stderr)
        return 2

    failures = 0
    for path in sorted(args.fixture_dir.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        payload = doc.get("payload") or doc
        replay = replay_lab.replay_payload(payload, mode=args.mode)
        expect = doc.get("expect") or {}
        executed = replay.get("execution", {}).get("executed") or []
        blocks = [e for e in executed if e.get("type") in {"block", "restrict", "subnet"}]
        shields = [e for e in executed if e.get("type") == "shield"]
        ok = True
        verdict = str(replay.get("verdict") or "")
        if "max_blocks" in expect and len(blocks) > int(expect["max_blocks"]):
            ok = False
        if "min_shield_actions" in expect and len(shields) < int(expect["min_shield_actions"]):
            ok = False
        if "verdict" in expect and verdict.lower() != str(expect["verdict"]).lower():
            ok = False
        status = "PASS" if ok else "FAIL"
        print(f"{status} {path.name} blocks={len(blocks)} shields={len(shields)} verdict={replay.get('verdict')}")
        if not ok:
            failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
