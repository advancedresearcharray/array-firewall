#!/usr/bin/env python3
"""Daily GitHub push quota for advancedresearcharray (5–20/day CST)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

USER = os.environ.get("GH_PUSH_QUOTA_USER", "advancedresearcharray")
MIN_PUSHES = int(os.environ.get("DAILY_PUSH_MIN", "5"))
MAX_PUSHES = int(os.environ.get("DAILY_PUSH_MAX", "20"))
TZ = os.environ.get("DAILY_PUSH_TZ", "America/Chicago")


def fetch_push_timestamps() -> list[str]:
    out = subprocess.check_output(
        [
            "gh",
            "api",
            f"/users/{USER}/events",
            "--paginate",
            "-q",
            '.[] | select(.type=="PushEvent") | .created_at',
        ],
        text=True,
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def count_today(timestamps: list[str]) -> tuple[int, str]:
    tz = ZoneInfo(TZ)
    today = datetime.now(tz).date()
    count = sum(
        1
        for ts in timestamps
        if datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(tz).date() == today
    )
    return count, today.isoformat()


def main() -> int:
    json_out = "--json" in sys.argv
    count, day = count_today(fetch_push_timestamps())
    payload = {
        "user": USER,
        "day": day,
        "timezone": TZ,
        "count": count,
        "min": MIN_PUSHES,
        "max": MAX_PUSHES,
        "below_min": count < MIN_PUSHES,
        "at_or_over_max": count >= MAX_PUSHES,
    }
    if json_out:
        print(json.dumps(payload, indent=2))
    else:
        if count < MIN_PUSHES:
            print(f"pushes {count}/{MIN_PUSHES}-{MAX_PUSHES} on {day} ({TZ}) — need {MIN_PUSHES - count} more")
        elif count >= MAX_PUSHES:
            print(f"pushes {count}/{MIN_PUSHES}-{MAX_PUSHES} on {day} ({TZ}) — at max, stop pushing")
        else:
            print(f"pushes {count}/{MIN_PUSHES}-{MAX_PUSHES} on {day} ({TZ}) — ok ({MAX_PUSHES - count} room left)")
    if count < MIN_PUSHES:
        return 1
    if count >= MAX_PUSHES:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
