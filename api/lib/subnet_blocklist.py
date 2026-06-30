"""Automated subnet blocking — persisted CIDR list + inet gaming nft interval set."""
from __future__ import annotations

import ipaddress
import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from . import peer_blocklist, policies

BLOCKLIST_PATH = Path("/var/lib/array-firewall/blocked_subnets.json")
TABLE = "inet"
CHAIN_TABLE = "gaming"
SET_NAME = "blocked_subnets"
_LOCK = threading.Lock()

DEFAULT_PROVIDERS = {
    "vultr": "https://cloud-ip-ranges.com/download/vultr.txt",
    "linode": "https://cloud-ip-ranges.com/download/linode.txt",
    "digitalocean": "https://cloud-ip-ranges.com/download/digitalocean.txt",
    "hetzner": "https://cloud-ip-ranges.com/download/hetzner.txt",
}


def _cfg() -> dict[str, Any]:
    gaming = policies.gaming()
    mit = dict(gaming.get("mitigation") or {})
    base: dict[str, Any] = {
        "enabled": True,
        "default_ttl_days": 30,
        "prefix_len": 24,
        "auto_block_on_vps_mesh": True,
        "enforce_provider_ranges": False,
        "provider_ttl_days": 365,
        "max_active_subnets": 512,
        "providers": dict(DEFAULT_PROVIDERS),
    }
    base.update(mit.get("subnet_block") or {})
    return base


def _now() -> float:
    return time.time()


def _load() -> dict[str, Any]:
    if not BLOCKLIST_PATH.is_file():
        return {"subnets": {}, "provider_catalog": {}, "last_updated": None}
    try:
        return json.loads(BLOCKLIST_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"subnets": {}, "provider_catalog": {}, "last_updated": None}


def _save(data: dict[str, Any]) -> None:
    BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    data["last_updated"] = _now()
    tmp = BLOCKLIST_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(BLOCKLIST_PATH)


def _valid_cidr(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        return False
    if net.version != 4:
        return False
    if net.is_private or net.is_loopback or net.is_link_local:
        return False
    return True


def _subnet_skipped(cidr: str) -> bool:
    """Skip subnets that overlap Xbox matchmaking allowlist."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return True
    for path in (
        Path("/opt/array-firewall/config/matchmaking-allowlist.json"),
        Path("/opt/array-firewall/config/in-match-allowlist.json"),
    ):
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for raw in data.get("cidrs") or []:
            try:
                allow = ipaddress.ip_network(str(raw).strip(), strict=False)
            except ValueError:
                continue
            if net.overlaps(allow):
                return True
    return False


def ip_to_subnet(ip: str, prefix_len: int | None = None) -> str | None:
    ip = str(ip or "").strip()
    if not ip or peer_blocklist.in_game_allowlist(ip):
        return None
    plen = int(prefix_len if prefix_len is not None else _cfg().get("prefix_len") or 24)
    plen = max(8, min(32, plen))
    try:
        return str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))
    except ValueError:
        return None


def _nft_add_subnet(cidr: str, ttl_sec: int) -> bool:
    ttl_sec = max(300, int(ttl_sec))
    proc = subprocess.run(
        [
            "nft",
            "add",
            "element",
            TABLE,
            CHAIN_TABLE,
            SET_NAME,
            "{",
            f"{cidr} timeout {ttl_sec}s",
            "}",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return proc.returncode == 0


def _nft_remove_subnet(cidr: str) -> bool:
    proc = subprocess.run(
        ["nft", "delete", "element", TABLE, CHAIN_TABLE, SET_NAME, "{", cidr, "}"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return proc.returncode == 0


def _nft_set_exists() -> bool:
    proc = subprocess.run(
        ["nft", "list", "set", TABLE, CHAIN_TABLE, SET_NAME],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return proc.returncode == 0


def _nft_rule_exists() -> bool:
    proc = subprocess.run(
        ["nft", "-a", "list", "chain", TABLE, CHAIN_TABLE, "xbox_in"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if proc.returncode != 0:
        return False
    return "auto-blocked-subnet" in proc.stdout or f"@{SET_NAME}" in proc.stdout


def ensure_nft_infrastructure() -> dict[str, Any]:
    """Create blocked_subnets set + drop rule on live shield without full rebuild."""
    table_proc = subprocess.run(
        ["nft", "list", "table", TABLE, CHAIN_TABLE],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if table_proc.returncode != 0:
        return {"ok": False, "error": "gaming_table_missing"}

    if not _nft_set_exists():
        proc = subprocess.run(
            [
                "nft",
                "add",
                "set",
                TABLE,
                CHAIN_TABLE,
                SET_NAME,
                "{",
                "type",
                "ipv4_addr;",
                "flags",
                "interval,",
                "timeout;",
                "size",
                "65536;",
                "}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return {"ok": False, "error": "set_create_failed", "detail": proc.stderr.strip()}

    counter_proc = subprocess.run(
        ["nft", "add", "counter", TABLE, CHAIN_TABLE, "subnet_block"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if counter_proc.returncode != 0 and "exists" not in (counter_proc.stderr or "").lower():
        return {"ok": False, "error": "counter_create_failed", "detail": counter_proc.stderr.strip()}

    if _nft_rule_exists():
        return {"ok": True, "set": True, "rule": True}

    insert_at: int | None = None
    chain_proc = subprocess.run(
        ["nft", "-a", "list", "chain", TABLE, CHAIN_TABLE, "xbox_in"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if chain_proc.returncode == 0:
        for line in chain_proc.stdout.splitlines():
            if "wan-scanner-block" not in line and "wan_scanner_block" not in line:
                continue
            parts = line.strip().split()
            for i, part in enumerate(parts):
                if part == "handle" and i + 1 < len(parts):
                    try:
                        insert_at = int(parts[i + 1]) + 1
                    except ValueError:
                        insert_at = None
                    break
            break

    args = ["nft", "add", "rule", TABLE, CHAIN_TABLE, "xbox_in"]
    if insert_at is not None:
        args.extend(["position", str(insert_at)])
    args.extend(
        [
            "ip",
            "saddr",
            f"@{SET_NAME}",
            "counter",
            "name",
            "subnet_block",
            "drop",
            "comment",
            '"auto-blocked-subnet"',
        ]
    )
    proc = subprocess.run(args, capture_output=True, text=True, timeout=5)
    if proc.returncode != 0:
        return {"ok": False, "error": "rule_create_failed", "detail": proc.stderr.strip()}
    return {"ok": True, "set": True, "rule": True, "inserted_at": insert_at}


def render_nft_elements() -> str:
    """Active enforced subnets for packet-shield restore."""
    prune()
    data = _load()
    now = _now()
    parts: list[str] = []
    for cidr, meta in (data.get("subnets") or {}).items():
        if not meta.get("enforced", True):
            continue
        remaining = max(60, int(float(meta.get("expires") or 0) - now))
        parts.append(f"{cidr} timeout {remaining}s")
    return ", ".join(parts)


def add_subnet(
    cidr: str,
    *,
    reason: str = "vps-probe-mesh",
    tier: str = "dynamic",
    source: str = "api",
    ttl_days: int | None = None,
    enforced: bool | None = None,
    hits: int = 1,
) -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "skipped": True, "reason": "subnet_block_disabled"}

    cidr = str(cidr or "").strip()
    if not _valid_cidr(cidr):
        return {"ok": False, "error": "invalid_cidr", "cidr": cidr}
    if _subnet_skipped(cidr):
        return {"ok": True, "skipped": True, "reason": "allowlist_overlap", "cidr": cidr}

    ttl_d = int(ttl_days if ttl_days is not None else cfg.get("default_ttl_days") or 30)
    ttl_sec = max(300, ttl_d * 86400)
    if tier == "provider":
        ttl_d = int(cfg.get("provider_ttl_days") or 365)
        ttl_sec = max(300, ttl_d * 86400)
        if enforced is None:
            enforced = bool(cfg.get("enforce_provider_ranges", False))
    elif enforced is None:
        enforced = True

    now = _now()
    nft_ok = False
    new_block = False

    with _LOCK:
        data = _load()
        subnets: dict[str, Any] = dict(data.get("subnets") or {})
        entry = subnets.get(cidr) or {"hits": 0, "first_seen": now}
        entry["hits"] = int(entry.get("hits") or 0) + hits
        entry["last_seen"] = now
        entry["reason"] = reason
        entry["tier"] = tier
        entry["source"] = source
        entry["expires"] = max(float(entry.get("expires") or 0), now + ttl_sec)
        entry["ttl_days"] = ttl_d
        entry["enforced"] = bool(enforced)
        was_active = float(entry.get("expires") or 0) > now and entry.get("hits", 0) > 1
        subnets[cidr] = entry
        max_n = max(32, int(cfg.get("max_active_subnets") or 512))
        if len(subnets) > max_n:
            ranked = sorted(
                subnets.items(),
                key=lambda kv: (float(kv[1].get("hits") or 0), float(kv[1].get("last_seen") or 0)),
            )
            subnets = dict(ranked[-max_n:])
        data["subnets"] = subnets
        _save(data)
        new_block = not was_active
        if enforced:
            ensure_nft_infrastructure()
            nft_ok = _nft_add_subnet(cidr, ttl_sec)

    try:
        from . import session_events

        session_events.append(
            "subnet.block",
            detail=f"blocked {cidr}",
            meta={"reason": reason, "tier": tier, "source": source, "ttl_days": ttl_d},
        )
    except ImportError:
        pass

    return {
        "ok": True,
        "cidr": cidr,
        "blocked": True,
        "enforced": bool(enforced),
        "nft_applied": nft_ok,
        "new_block": new_block,
        "ttl_days": ttl_d,
        "reason": reason,
        "tier": tier,
        "source": source,
    }


def block_from_ip(
    ip: str,
    *,
    reason: str = "vps-probe-mesh",
    source: str = "sentinel",
    prefix_len: int | None = None,
) -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("enabled", True) or not cfg.get("auto_block_on_vps_mesh", True):
        return {"ok": True, "skipped": True, "reason": "auto_block_on_vps_mesh_disabled"}
    cidr = ip_to_subnet(ip, prefix_len=prefix_len)
    if not cidr:
        return {"ok": True, "skipped": True, "reason": "no_subnet", "ip": ip}
    result = add_subnet(cidr, reason=reason, tier="dynamic", source=source)
    result["ip"] = ip
    return result


def block_from_ips(
    ips: list[str],
    *,
    reason: str = "vps-probe-mesh",
    source: str = "sentinel",
) -> dict[str, Any]:
    results = []
    for ip in ips:
        results.append(block_from_ip(ip, reason=reason, source=source))
    applied = sum(1 for r in results if r.get("nft_applied"))
    return {"ok": True, "count": len(results), "nft_applied": applied, "results": results}


def remove_subnet(cidr: str) -> dict[str, Any]:
    cidr = str(cidr or "").strip()
    with _LOCK:
        data = _load()
        subnets: dict[str, Any] = dict(data.get("subnets") or {})
        removed = cidr in subnets
        subnets.pop(cidr, None)
        data["subnets"] = subnets
        _save(data)
    nft_ok = _nft_remove_subnet(cidr) if removed else False
    return {"ok": True, "removed": removed, "cidr": cidr, "nft_removed": nft_ok}


def apply_all() -> dict[str, Any]:
    """Re-apply all enforced subnets to nft (after shield rebuild)."""
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {"ok": True, "applied": 0, "skipped": True}
    infra = ensure_nft_infrastructure()
    if not infra.get("ok"):
        return {"ok": False, "applied": 0, "infra": infra}
    prune()
    data = _load()
    now = _now()
    applied = 0
    failed: list[str] = []
    for cidr, meta in (data.get("subnets") or {}).items():
        if not meta.get("enforced", True):
            continue
        if float(meta.get("expires") or 0) <= now:
            continue
        ttl_sec = max(60, int(float(meta.get("expires") or 0) - now))
        if _nft_add_subnet(cidr, ttl_sec):
            applied += 1
        else:
            failed.append(cidr)
    return {"ok": not failed, "applied": applied, "failed": failed}


def prune() -> dict[str, Any]:
    data = _load()
    now = _now()
    kept: dict[str, Any] = {}
    removed = 0
    for cidr, meta in (data.get("subnets") or {}).items():
        if float((meta or {}).get("expires") or 0) > now:
            kept[cidr] = meta
        else:
            removed += 1
            _nft_remove_subnet(cidr)
    data["subnets"] = kept
    _save(data)
    return {"ok": True, "removed": removed, "active": len(kept)}


def active_subnets() -> list[dict[str, Any]]:
    prune()
    data = _load()
    out: list[dict[str, Any]] = []
    for cidr, meta in sorted((data.get("subnets") or {}).items()):
        row = dict(meta or {})
        row["cidr"] = cidr
        out.append(row)
    return out


def merge_provider_catalog(provider: str, cidrs: list[str]) -> dict[str, Any]:
    with _LOCK:
        data = _load()
        catalog: dict[str, Any] = dict(data.get("provider_catalog") or {})
        catalog[provider] = {
            "cidrs": sorted(set(cidrs)),
            "fetched": _now(),
            "count": len(set(cidrs)),
        }
        data["provider_catalog"] = catalog
        _save(data)
    return {"ok": True, "provider": provider, "count": len(set(cidrs))}


def enforce_provider_catalog(*, provider: str | None = None) -> dict[str, Any]:
    """Optionally block all cataloged provider CIDRs (policy enforce_provider_ranges)."""
    cfg = _cfg()
    data = _load()
    catalog = data.get("provider_catalog") or {}
    added = 0
    targets = [provider] if provider else list(catalog.keys())
    for name in targets:
        block = catalog.get(name) or {}
        for cidr in block.get("cidrs") or []:
            r = add_subnet(
                str(cidr),
                reason=f"provider:{name}",
                tier="provider",
                source="provider_catalog",
                enforced=bool(cfg.get("enforce_provider_ranges", False)),
            )
            if r.get("nft_applied") or r.get("enforced"):
                added += 1
    return {"ok": True, "enforced": added, "providers": targets}


def fetch_provider_cidrs(url: str) -> list[str]:
    import urllib.request

    cidrs: list[str] = []
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except OSError:
        return cidrs
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if _valid_cidr(line):
            cidrs.append(line)
    return sorted(set(cidrs))


def fetch_all_providers(urls: dict[str, str] | None = None) -> dict[str, list[str]]:
    cfg = _cfg()
    merged = dict(DEFAULT_PROVIDERS)
    merged.update(cfg.get("providers") or {})
    if urls:
        merged.update(urls)
    out: dict[str, list[str]] = {}
    for name, url in merged.items():
        if not url:
            continue
        out[name] = fetch_provider_cidrs(str(url))
    return out


def refresh_providers() -> dict[str, Any]:
    """Fetch provider CIDR lists and update catalog (+ optional enforce)."""
    cfg = _cfg()
    fetched = fetch_all_providers()
    total = 0
    for name, cidrs in fetched.items():
        merge_provider_catalog(name, cidrs)
        total += len(cidrs)
    enforced = enforce_provider_catalog() if cfg.get("enforce_provider_ranges") else {"enforced": 0}
    return {
        "ok": True,
        "providers": list(fetched.keys()),
        "cidr_count": total,
        "catalog_updated": True,
        "enforced": enforced.get("enforced", 0),
    }


def status() -> dict[str, Any]:
    cfg = _cfg()
    data = _load()
    active = active_subnets()
    catalog = data.get("provider_catalog") or {}
    catalog_counts = {k: (v.get("count") if isinstance(v, dict) else len(v or [])) for k, v in catalog.items()}
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "config": cfg,
        "active_count": len(active),
        "active": active[:200],
        "provider_catalog": catalog_counts,
        "last_updated": data.get("last_updated"),
        "state_path": str(BLOCKLIST_PATH),
        "set": f"{TABLE} {CHAIN_TABLE} {SET_NAME}",
    }
