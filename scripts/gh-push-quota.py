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
DEFAULT_EXEMPT_REPOS = (
    "advancedresearcharray/array-firewall",
    "advancedresearcharray/warzone-lobby-sentinel",
)
DEFAULT_EXEMPT_TAGS = ("[no-quota]", "[infra-deploy]")


def _load_config() -> dict:
    paths = [
        os.environ.get("GH_INBOX_CONFIG", "").strip(),
        "/opt/array-fleet-ops/gh-inbox-agent/gh-inbox.config.json",
        "/root/data/gh-inbox.config.json",
    ]
    for path in paths:
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
    return {}


def _policy() -> tuple[int, int, str, str, set[str], tuple[str, ...]]:
    cfg = _load_config()
    min_p = int(cfg.get("daily_push_min", MIN_PUSHES))
    max_p = int(cfg.get("daily_push_max", MAX_PUSHES))
    tz = cfg.get("daily_push_limit_timezone") or cfg.get("daily_pr_limit_timezone") or TZ
    user = cfg.get("github_user") or cfg.get("gh_user") or USER
    exempt_repos = set(cfg.get("daily_push_exempt_repos") or DEFAULT_EXEMPT_REPOS)
    exempt_tags = tuple(cfg.get("daily_push_exempt_tags") or DEFAULT_EXEMPT_TAGS)
    return min_p, max_p, tz, user, exempt_repos, exempt_tags


def fetch_push_events(user: str) -> list[dict]:
    out = subprocess.check_output(
        [
            "gh",
            "api",
            f"/users/{user}/events",
            "--paginate",
            "-q",
            '.[] | select(.type=="PushEvent") | {created_at, repo: .repo.name, messages: [.payload.commits[]?.message // ""]}',
        ],
        text=True,
    )
    events: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def _is_exempt(event: dict, exempt_repos: set[str], exempt_tags: tuple[str, ...]) -> bool:
    repo = str(event.get("repo") or "")
    if repo in exempt_repos:
        return True
    for msg in event.get("messages") or []:
        text = str(msg or "")
        if any(tag in text for tag in exempt_tags):
            return True
    return False


def count_today(
    events: list[dict],
    tz_name: str,
    exempt_repos: set[str],
    exempt_tags: tuple[str, ...],
) -> tuple[int, int, int, str]:
    tz = ZoneInfo(tz_name)
    today = datetime.now(tz).date()
    counted = 0
    exempted = 0
    for event in events:
        ts = str(event.get("created_at") or "")
        if not ts:
            continue
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(tz)
        if dt.date() != today:
            continue
        if _is_exempt(event, exempt_repos, exempt_tags):
            exempted += 1
        else:
            counted += 1
    return counted, exempted, counted + exempted, today.isoformat()


def main() -> int:
    json_out = "--json" in sys.argv
    min_p, max_p, tz, user, exempt_repos, exempt_tags = _policy()
    events = fetch_push_events(user)
    count, exempt, raw, day = count_today(events, tz, exempt_repos, exempt_tags)
    payload = {
        "user": user,
        "day": day,
        "timezone": tz,
        "count": count,
        "exempt": exempt,
        "raw": raw,
        "min": min_p,
        "max": max_p,
        "below_min": count < min_p,
        "at_or_over_max": count >= max_p,
        "exempt_repos": sorted(exempt_repos),
        "exempt_tags": list(exempt_tags),
    }
    if json_out:
        print(json.dumps(payload, indent=2))
    else:
        if count < min_p:
            print(
                f"pushes {count}/{min_p}-{max_p} on {day} ({tz}) "
                f"— need {min_p - count} more ({exempt} exempt)"
            )
        elif count >= max_p:
            print(
                f"pushes {count}/{min_p}-{max_p} on {day} ({tz}) "
                f"— at max, stop pushing ({exempt} exempt)"
            )
        else:
            print(
                f"pushes {count}/{min_p}-{max_p} on {day} ({tz}) "
                f"— ok ({max_p - count} room left, {exempt} exempt)"
            )
    if count < min_p:
        return 1
    if count >= max_p:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
