from __future__ import annotations

import os
from pathlib import Path

TOKEN_FILE = Path(os.environ.get("ARRAY_FW_TOKEN_FILE", "/etc/array-firewall/api.token"))
ALLOW_CIDRS = tuple(
    c.strip()
    for c in os.environ.get(
        "ARRAY_FW_ALLOW_CIDRS",
        "192.168.167.0/24,192.168.5.0/24,10.99.0.0/24,127.0.0.0/8",
    ).split(",")
    if c.strip()
)


def _load_token() -> str:
    if TOKEN_FILE.is_file():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    return os.environ.get("ARRAY_FW_API_TOKEN", "").strip()


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
    for cidr in cidrs or ALLOW_CIDRS:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
