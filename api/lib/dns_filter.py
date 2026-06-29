"""DNS filtering: blocklists via dnsmasq, force LAN DNS, block DoH/DoT bypass."""
from __future__ import annotations

import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import policies

BLOCKLIST_CONF = Path("/etc/dnsmasq.d/array-firewall-blocklist.conf")
STATE_FILE = Path("/var/lib/array-firewall/dns-blocklist.json")

DEFAULT_FEEDS = (
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
)

# Minimal fallback when feeds are unreachable.
FALLBACK_DOMAINS = (
    "doubleclick.net",
    "googlesyndication.com",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "ads.yahoo.com",
    "telemetry.microsoft.com",
    "vortex.data.microsoft.com",
)

# Common DoH resolver endpoints (LAN clients bypassing dnsmasq).
DOH_RESOLVERS = (
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
)

_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$|^[a-z0-9]$", re.I)


def _cfg() -> dict[str, Any]:
    data = policies.load()
    base = {
        "enabled": False,
        "force_lan_dns": True,
        "block_doh_dot": True,
        "feeds": list(DEFAULT_FEEDS),
        "custom_domains": [],
        "local_domains": [],
    }
    raw = data.get("dns_filter") or {}
    base.update(raw)
    legacy = data.get("blocklists") or {}
    for dom in legacy.get("dns") or []:
        if dom and dom not in base["custom_domains"]:
            base["custom_domains"].append(dom)
    if data.get("defaults", {}).get("dns_filter") == "on":
        base["enabled"] = True
    return base


def _normalize_domain(raw: str) -> str | None:
    dom = raw.strip().lower()
    if dom.startswith("#") or not dom:
        return None
    if dom.startswith("0.0.0.0") or dom.startswith("127.0.0.1"):
        parts = dom.split()
        if len(parts) >= 2:
            dom = parts[1]
        else:
            return None
    dom = dom.lstrip("*.")
    if not dom or dom in {"localhost", "local", "broadcasthost"}:
        return None
    if not _DOMAIN_RE.match(dom):
        return None
    return dom


def _fetch_feed(url: str, timeout: float = 20.0) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "array-firewall-dns/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    domains: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        dom = _normalize_domain(line)
        if dom:
            domains.append(dom)
    return domains


def _collect_domains(cfg: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    errors: list[str] = []

    for dom in cfg.get("custom_domains") or []:
        norm = _normalize_domain(str(dom))
        if norm and norm not in seen:
            seen.add(norm)
            ordered.append(norm)

    for url in cfg.get("feeds") or []:
        try:
            for dom in _fetch_feed(str(url)):
                if dom not in seen:
                    seen.add(dom)
                    ordered.append(dom)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            errors.append(f"{url}: {exc}")

    if not ordered:
        for dom in FALLBACK_DOMAINS:
            if dom not in seen:
                seen.add(dom)
                ordered.append(dom)

    return ordered


def _write_blocklist(domains: list[str]) -> None:
    lines = [
        "# array-firewall DNS blocklist — managed via dashboard/API",
        f"# domains={len(domains)} updated={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
    ]
    for dom in domains:
        lines.append(f"address=/{dom}/0.0.0.0")
    BLOCKLIST_CONF.parent.mkdir(parents=True, exist_ok=True)
    BLOCKLIST_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _save_state(payload: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(__import__("json").dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(STATE_FILE)


def sync(*, apply_nft: bool = True) -> dict[str, Any]:
    cfg = _cfg()
    if not cfg.get("enabled"):
        if BLOCKLIST_CONF.is_file():
            BLOCKLIST_CONF.write_text("# DNS filter disabled\n", encoding="utf-8")
        _save_state({"enabled": False, "domain_count": 0, "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        if apply_nft:
            from . import nft

            nft.apply_ruleset()
        subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True, timeout=15)
        return {"ok": True, "enabled": False, "domain_count": 0}

    domains = _collect_domains(cfg)
    _write_blocklist(domains)
    result = {
        "ok": True,
        "enabled": True,
        "domain_count": len(domains),
        "force_lan_dns": bool(cfg.get("force_lan_dns", True)),
        "block_doh_dot": bool(cfg.get("block_doh_dot", True)),
        "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sample": domains[:12],
    }
    _save_state(result)
    subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True, timeout=15)
    if apply_nft:
        from . import nft

        nft.apply_ruleset()
    return result


def set_config(
    *,
    enabled: bool | None = None,
    force_lan_dns: bool | None = None,
    block_doh_dot: bool | None = None,
    custom_domains: list[str] | None = None,
    feeds: list[str] | None = None,
) -> dict[str, Any]:
    data = policies.load()
    cfg = dict(data.get("dns_filter") or {})
    if enabled is not None:
        cfg["enabled"] = bool(enabled)
    if force_lan_dns is not None:
        cfg["force_lan_dns"] = bool(force_lan_dns)
    if block_doh_dot is not None:
        cfg["block_doh_dot"] = bool(block_doh_dot)
    if custom_domains is not None:
        cfg["custom_domains"] = [str(d).strip() for d in custom_domains if str(d).strip()]
    if feeds is not None:
        cfg["feeds"] = [str(u).strip() for u in feeds if str(u).strip()]
    data["dns_filter"] = cfg
    policies.save(data)
    return sync()


def render_nft(lan_if: str, lan_cidr: str, gw_ip: str) -> tuple[str, str]:
    """Return (set definitions + chain, forward hook jump line)."""
    cfg = _cfg()
    if not cfg.get("enabled") and not cfg.get("force_lan_dns") and not cfg.get("block_doh_dot"):
        return "", ""

    doh_ips = ", ".join(DOH_RESOLVERS)
    set_block = ""
    if cfg.get("block_doh_dot", True):
        set_block = f"""
  set doh_resolvers {{
    type ipv4_addr
    flags constant
    elements = {{ {doh_ips} }}
  }}"""

    rules: list[str] = []
    if cfg.get("force_lan_dns", True):
        rules += [
            f"    ip daddr {gw_ip} udp dport 53 accept comment \"dns-gateway\"",
            f"    ip daddr {gw_ip} tcp dport 53 accept comment \"dns-gateway\"",
            "    udp dport 53 drop comment \"force-lan-dns\"",
            "    tcp dport 53 drop comment \"force-lan-dns\"",
        ]
    if cfg.get("block_doh_dot", True):
        rules += [
            "    tcp dport 853 drop comment \"block-dot\"",
            "    udp dport 853 drop comment \"block-dot\"",
            "    ip daddr @doh_resolvers tcp dport 443 drop comment \"block-doh\"",
        ]

    body = "\n".join(rules)
    chain = f"""
  chain dns_enforce {{
{body}
    return
  }}"""
    hook = f'    iifname "{lan_if}" oifname "eth*" ip saddr {lan_cidr} jump dns_enforce\n'
    # eth* won't work in nft - use wan_if passed separately. Fix in nft.py caller.
    return set_block + chain, hook


def render_nft_hook(lan_if: str, wan_if: str, lan_cidr: str, gw_ip: str) -> tuple[str, str]:
    cfg = _cfg()
    if not cfg.get("enabled") and not cfg.get("force_lan_dns") and not cfg.get("block_doh_dot"):
        return "", ""

    doh_ips = ", ".join(DOH_RESOLVERS)
    set_block = ""
    if cfg.get("block_doh_dot", True):
        set_block = f"""
  set doh_resolvers {{
    type ipv4_addr
    flags constant
    elements = {{ {doh_ips} }}
  }}"""

    rules: list[str] = []
    if cfg.get("force_lan_dns", True):
        rules += [
            f"    ip daddr {gw_ip} udp dport 53 accept comment \"dns-gateway\"",
            f"    ip daddr {gw_ip} tcp dport 53 accept comment \"dns-gateway\"",
            "    udp dport 53 drop comment \"force-lan-dns\"",
            "    tcp dport 53 drop comment \"force-lan-dns\"",
        ]
    if cfg.get("block_doh_dot", True):
        rules += [
            "    tcp dport 853 drop comment \"block-dot\"",
            "    udp dport 853 drop comment \"block-dot\"",
            "    ip daddr @doh_resolvers tcp dport 443 drop comment \"block-doh\"",
        ]

    body = "\n".join(rules)
    chain = f"""
  chain dns_enforce {{
{body}
    return
  }}"""
    hook = f'    iifname "{lan_if}" oifname "{wan_if}" ip saddr {lan_cidr} jump dns_enforce\n'
    return set_block + chain, hook


def status() -> dict[str, Any]:
    cfg = _cfg()
    state: dict[str, Any] = {}
    if STATE_FILE.is_file():
        try:
            state = __import__("json").loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state = {}
    active = BLOCKLIST_CONF.is_file() and "address=/" in BLOCKLIST_CONF.read_text(encoding="utf-8")
    return {
        "ok": True,
        "config": cfg,
        "enabled": bool(cfg.get("enabled")),
        "force_lan_dns": bool(cfg.get("force_lan_dns", True)),
        "block_doh_dot": bool(cfg.get("block_doh_dot", True)),
        "domain_count": state.get("domain_count", 0),
        "synced_at": state.get("synced_at"),
        "blocklist_active": active,
        "feeds": cfg.get("feeds") or [],
        "custom_domains": cfg.get("custom_domains") or [],
        "doh_resolvers_blocked": list(DOH_RESOLVERS),
    }
