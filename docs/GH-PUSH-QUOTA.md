# GitHub daily push quota

Account `advancedresearcharray` targets **5–20 pushes per calendar day** (America/Chicago).

## Check status

```bash
./scripts/gh-push-quota.sh
./scripts/gh-push-quota.sh --json
python3 scripts/gh-push-quota.py
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Within range (5–19 pushes today) |
| 1 | Below minimum — need more pushes |
| 2 | At or over maximum — stop pushing |

## Fleet integration

Canonical tooling lives in the private `array-gh-inbox-fleet` repo:

- `bin/gh-push-quota` — full checker with config file support
- `gh-inbox quota` / `gh-inbox doctor` — CT933 inbox agent hooks

Config keys: `daily_push_min`, `daily_push_max`, `daily_push_limit_timezone`.

## Why

GitHub activity and agent cycles should spread real commits across the day instead of batching everything into one push or flooding with 30+ pushes.
