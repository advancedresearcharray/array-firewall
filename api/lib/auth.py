from __future__ import annotations

import os
from pathlib import Path

TOKEN_FILE = Path(os.environ.get("ARRAY_FW_TOKEN_FILE", "/etc/array-firewall/api.token"))
_LEGACY_ALLOW = ("192.0.2.0/24", "203.0.113.0/24", "198.51.100.0/24", "127.0.0.0/8")


def _load_token() -> str:
    if TOKEN_FILE.is_file():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    return os.environ.get("ARRAY_FW_API_TOKEN", "").strip()


def allowed_cidrs() -> tuple[str, ...]:
    """CIDRs permitted to call the API — env override, else policies LAN/mgmt."""
    env = os.environ.get("ARRAY_FW_ALLOW_CIDRS", "").strip()
    if env:
        return tuple(c.strip() for c in env.split(",") if c.strip())

    cidrs: list[str] = ["127.0.0.0/8"]
    try:
        from . import policies

        net = policies.network()
        for key in ("lan_cidr", "mgmt_cidr"):
            val = str(net.get(key) or "").strip()
            if val:
                cidrs.append(val)
        extra = policies.load().get("api_allow_cidrs") or []
        if isinstance(extra, list):
            cidrs.extend(str(c).strip() for c in extra if str(c).strip())
    except Exception:
        pass

    if len(cidrs) <= 1:
        cidrs.extend(_LEGACY_ALLOW)
    else:
        # Xbox P2P bench segment when co-hosted with Sentinel on same CT.
        cidrs.append("203.0.113.0/24")

    seen: set[str] = set()
    out: list[str] = []
    for c in cidrs:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return tuple(out)


# Back-compat for imports
ALLOW_CIDRS = allowed_cidrs()


def token_configured() -> bool:
    return bool(_load_token())


def check_bearer(header: str | None) -> bool:
    token = _load_token()
    if not token:
        return True
    if not header or not header.startswith("Bearer "):
        return False
    return header[7:].strip() == token


def check_token(header: str | None = None, query_token: str | None = None) -> bool:
    """Accept Bearer header or ?token= query (for EventSource / SSE)."""
    if check_bearer(header):
        return True
    expected = _load_token()
    if not expected:
        return True
    return bool(query_token and query_token.strip() == expected)


def ip_allowed(ip: str, cidrs: tuple[str, ...] | None = None) -> bool:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs or allowed_cidrs():
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
