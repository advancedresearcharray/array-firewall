from __future__ import annotations

import os
import re
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import devices, policies

CONF_PATH = Path("/etc/array-firewall/array-firewall.conf")
RULESET = Path(os.environ.get("ARRAY_FW_RULESET", "/var/lib/array-firewall/ruleset.nft"))
WAN_NAT_RULESET = Path("/var/lib/array-firewall/wan-nat.nft")
GAMING_TABLE = "inet gaming"

_apply_ruleset_lock = threading.RLock()
_apply_ruleset_depth = 0


@contextmanager
def ruleset_lock() -> Iterator[None]:
    """Serialize nft ruleset / WAN NAT applies (ThreadingHTTPServer safe)."""
    _apply_ruleset_lock.acquire()
    try:
        yield
    finally:
        _apply_ruleset_lock.release()


def apply_nft_file(path: Path, *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    """Apply an nftables file under the global ruleset lock."""
    with ruleset_lock():
        return subprocess.run(["nft", "-f", str(path)], capture_output=True, text=True, timeout=timeout)


def apply_nft_file_unlocked(path: Path, *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    """Apply nftables when caller already holds ruleset_lock."""
    return subprocess.run(["nft", "-f", str(path)], capture_output=True, text=True, timeout=timeout)


def ruleset_apply_depth() -> int:
    return _apply_ruleset_depth


def _conf() -> dict[str, str]:
    out: dict[str, str] = {}
    if not CONF_PATH.is_file():
        return out
    for line in CONF_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"')
    return out


def _ifaces() -> dict[str, str]:
    c = _conf()
    pol = policies.network()
    role = policies.role() if policies.gateway_topology() or policies.role() == "gateway" else "lab"
    if policies.gateway_topology():
        lan_if = pol.get("lan_if") or c.get("LAN_IF", "eth0")
        uplink_if = pol.get("uplink_if") or c.get("UPLINK_IF", c.get("WAN_IF", "eth1"))
        wan_if = pol.get("wan_if") or uplink_if
        # Collapse to one iface only when LAN and uplink share the same port.
        if pol.get("wan_mode") == "upstream" and role != "xbox_router":
            wan_if = lan_if
        elif role == "xbox_router" and lan_if != uplink_if:
            wan_if = uplink_if
        elif role == "xbox_router" and pol.get("wan_mode") == "upstream" and lan_if == uplink_if:
            wan_if = lan_if
        return {
            "role": role,
            "mgmt_if": c.get("MGMT_IF", "eth0"),
            "lan_if": lan_if,
            "wan_if": wan_if,
            "lan_cidr": pol.get("lan_cidr") or c.get("LAN_CIDR", "192.168.167.0/24"),
            "mgmt_cidr": pol.get("mgmt_cidr") or c.get("MGMT_CIDR", "192.168.167.0/24"),
            "gw_ip": pol.get("gateway_ip") or c.get("LAN_GATEWAY_IP", "192.168.167.1"),
        }
    # Lab bench: clients on eth1, uplink via eth0 to existing LAN
    return {
        "role": "lab",
        "mgmt_if": c.get("MGMT_IF", "eth0"),
        "lan_if": c.get("LAN_IF", c.get("LAB_IF", "eth1")),
        "wan_if": c.get("UPLINK_IF", c.get("MGMT_IF", "eth0")),
        "lan_cidr": c.get("LAN_CIDR", c.get("LAB_CIDR", "10.99.0.0/24")),
        "mgmt_cidr": c.get("MGMT_CIDR", "192.168.167.0/24"),
        "gw_ip": c.get("LAB_GATEWAY_IP", "10.99.0.1"),
    }


def _mac_elements(macs: list[str]) -> str:
    return ", ".join(macs) if macs else ""


def _iface_ipv4(ifname: str) -> str:
    """Primary IPv4 on interface (first global address)."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", ifname, "scope", "global"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and "/" in parts[3]:
                return parts[3].split("/", 1)[0]
    except Exception:
        pass
    return ""


def _build_nat_table(
    *,
    ifaces: dict[str, str],
    nat_on: bool,
    xbox_router: bool,
    xbox_ip: str,
    lan_if: str,
    wan_if: str,
    lan_cidr: str,
    wan_ip: str,
    prerouting: str,
) -> str:
    if nat_on:
        return f"""
table ip nat {{{prerouting}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    iifname "{lan_if}" oifname "{wan_if}" ip saddr {lan_cidr} masquerade
  }}
}}"""
    if xbox_router and xbox_ip:
        # Masquerade follows DHCP WAN address changes; static snat to wan_ip breaks
        # when eth1 renews (e.g. .23 -> .24) until rules are regenerated.
        snat_rule = (
            f'    iifname "{lan_if}" oifname "{wan_if}" ip saddr {xbox_ip} masquerade '
            f'comment "xbox-wan-snat"\n'
        )
        return f"""
table ip nat {{{prerouting}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
{snat_rule}  }}
}}"""
    return ""


def render_wan_nat_fragment() -> str:
    """nft -f fragment restoring ip nat prerouting/postrouting without touching other tables."""
    ifaces = _ifaces()
    c = _conf()
    lan_if = ifaces["lan_if"]
    wan_if = ifaces["wan_if"]
    lan_cidr = ifaces["lan_cidr"]
    xbox_ip = str(policies.gaming().get("xbox_ip") or c.get("XBOX_IP") or "").strip()
    xbox_router = ifaces["role"] == "xbox_router"
    nat_on = policies.nat_enabled() and not xbox_router
    wan_ip = _iface_ipv4(wan_if) or c.get("WAN_IP", "")
    prerouting = ""
    if nat_on or (xbox_router and policies.xbox_inbound_nat_enabled()):
        try:
            from . import nat as nat_mod

            prerouting = nat_mod.render_prerouting_rules()
        except Exception:
            prerouting = ""
    nat_table = _build_nat_table(
        ifaces=ifaces,
        nat_on=nat_on,
        xbox_router=xbox_router,
        xbox_ip=xbox_ip,
        lan_if=lan_if,
        wan_if=wan_if,
        lan_cidr=lan_cidr,
        wan_ip=wan_ip,
        prerouting=prerouting,
    )
    if not nat_table.strip():
        return ""
    return f"#!/usr/sbin/nft -f\n{nat_table}\n"


def render_ruleset(*, flowtable: bool = True) -> str:
    c = _conf()
    ifaces = _ifaces()
    lan_if = ifaces["lan_if"]
    wan_if = ifaces["wan_if"]
    mgmt_if = ifaces["mgmt_if"]
    lan_cidr = ifaces["lan_cidr"]
    mgmt_cidr = ifaces["mgmt_cidr"]
    api_port = c.get("API_PORT", "8090")
    sentinel_port = c.get("SENTINEL_PORT", "8098")
    role = ifaces["role"]
    macs = devices.allowed_macs()
    mac_set = _mac_elements(macs)
    xbox_ip = policies.gaming().get("xbox_ip") or c.get("XBOX_IP", "")
    xbox_router = role == "xbox_router"
    nat_on = policies.nat_enabled() and not xbox_router
    if xbox_router:
        flowtable = False
    wan_ip = _iface_ipv4(wan_if) or c.get("WAN_IP", "")

    mac_block = ""
    if mac_set and not xbox_router:
        mac_block = f"""
  set allowed_macs {{
    type ether_addr
    flags constant
    elements = {{ {mac_set} }}
  }}"""

    xbox_rule = ""
    if xbox_ip:
        xbox_rule = f"""
    ip daddr {xbox_ip} jump xbox_in"""

    if xbox_router and xbox_ip:
        lan_out_chain = f"""
  chain lan_out {{
    ip saddr {xbox_ip} accept
    drop
  }}"""
    elif mac_set:
        lan_out_chain = """
  chain lan_out {
    ether saddr @allowed_macs accept
    drop
  }"""
    else:
        lan_out_chain = """
  chain lan_out {
    drop
  }"""

    flow_block = ""
    flow_rule = ""
    if flowtable:
        flow_block = f"""
  flowtable fastpath {{
    hook ingress priority filter
    devices = {{ "{lan_if}", "{wan_if}" }}
  }}"""
        flow_rule = "\n    ct state established,related flow add @fastpath"

    inbound_forward = ""
    prerouting = ""
    inbound_nat = nat_on or (xbox_router and policies.xbox_inbound_nat_enabled())
    if inbound_nat:
        try:
            from . import nat as nat_mod

            inbound_forward = nat_mod.render_forward_inbound_rules()
            prerouting = nat_mod.render_prerouting_rules()
        except Exception:
            pass

    wan_inbound = f"\n{inbound_forward}" if inbound_forward else ""

    zone_block = ""
    zone_forward = ""
    if not xbox_router:
        zone_forward = f'    iifname "{lan_if}" oifname "{lan_if}" drop\n'
        try:
            from . import zones as zones_mod

            gw_ip = ifaces.get("gw_ip") or policies.network().get("gateway_ip") or c.get("LAN_GATEWAY_IP", "192.168.167.1")
            zone_block, zone_forward = zones_mod.render_forward_zones(lan_if, gw_ip)
        except Exception:
            gw_ip = ifaces.get("gw_ip") or policies.network().get("gateway_ip") or c.get("LAN_GATEWAY_IP", "192.168.167.1")
    else:
        gw_ip = ifaces.get("gw_ip") or policies.network().get("gateway_ip") or c.get("LAN_GATEWAY_IP", "192.168.167.3")

    google_dhcp_block = ""
    google_dhcp_forward = ""
    try:
        from . import groups as grp_mod
        from . import zones as zones_mod

        zcfg = zones_mod.config()
        google_ip = zcfg.get("google_router_ip") or "192.168.167.2"
        mesh_macs: list[str] = []
        pol = policies.load()
        for gid in ("google-mesh", "wireless-infra"):
            grp = (pol.get("device_groups") or {}).get(gid) or {}
            mesh_macs.extend(grp.get("members") or [])
        mesh_macs = sorted({m.lower() for m in mesh_macs if m})
        mesh_set = _mac_elements(mesh_macs)
        if mesh_set:
            google_dhcp_block = f"""
  set google_mesh_macs {{
    type ether_addr
    flags constant
    elements = {{ {mesh_set} }}
  }}"""
            google_dhcp_forward = (
                f'    iifname "{lan_if}" oifname "{lan_if}" udp sport 67 ip saddr {google_ip} '
                f'ether daddr != @google_mesh_macs drop comment "google-dhcp-wired-block"\n'
            )
    except Exception:
        pass

    mgmt_input = ""
    if mgmt_if != lan_if:
        mgmt_input = f"""
    iifname "{mgmt_if}" ip saddr {mgmt_cidr} udp dport {{ 53, {api_port}, {sentinel_port} }} accept
    iifname "{mgmt_if}" ip saddr {mgmt_cidr} tcp dport {{ 22, {api_port}, {sentinel_port} }} accept
    iifname "{mgmt_if}" ip saddr {mgmt_cidr} icmp type echo-request accept"""
    elif xbox_router and mgmt_cidr != lan_cidr:
        # Same NIC (eth0): mgmt 192.168.167.x and Xbox 192.168.5.x — allow both to reach API/sentinel.
        mgmt_input = f"""
    iifname "{lan_if}" ip saddr {mgmt_cidr} udp dport {{ 53, {api_port}, {sentinel_port} }} accept
    iifname "{lan_if}" ip saddr {mgmt_cidr} tcp dport {{ 22, {api_port}, {sentinel_port} }} accept
    iifname "{lan_if}" ip saddr {mgmt_cidr} icmp type echo-request accept"""

    dns_block = ""
    dns_forward = ""
    if not xbox_router:
        try:
            from . import dns_filter as dns_mod

            dns_block, dns_forward = dns_mod.render_nft_hook(lan_if, wan_if, lan_cidr, gw_ip)
        except Exception:
            pass

    ids_block = ""
    ids_forward = ""
    if not xbox_router:
        try:
            from . import ids_enforce as ids_mod

            ids_block, ids_forward = ids_mod.render_nft()
        except Exception:
            pass

    wan_return = ""
    if xbox_router and xbox_ip:
        try:
            from . import nat as nat_mod

            dmz_cfg = nat_mod.dmz()
            if dmz_cfg.get("enabled") and str(dmz_cfg.get("host_ip") or "") == xbox_ip:
                wan_return = (
                    f'    iifname "{wan_if}" oifname "{lan_if}" ip daddr {xbox_ip} accept '
                    f'comment "xbox-wan-dmz"\n'
                )
            else:
                wan_return = (
                    f'    iifname "{wan_if}" oifname "{lan_if}" drop comment "unsolicited-wan-deny"\n'
                )
        except Exception:
            wan_return = f'    iifname "{wan_if}" oifname "{lan_if}" drop comment "unsolicited-wan-deny"\n'
    else:
        wan_return = f'    iifname "{wan_if}" oifname "{lan_if}" drop\n'

    mgmt_forward = ""
    if not xbox_router and mgmt_if != lan_if:
        mgmt_forward = f'    iifname "{mgmt_if}" oifname "{lan_if}" ip saddr {mgmt_cidr} accept\n'

    nat_table = _build_nat_table(
        ifaces=ifaces,
        nat_on=nat_on,
        xbox_router=xbox_router,
        xbox_ip=xbox_ip,
        lan_if=lan_if,
        wan_if=wan_if,
        lan_cidr=lan_cidr,
        wan_ip=wan_ip,
        prerouting=prerouting,
    )

    xbox_input = ""
    if xbox_router and xbox_ip:
        xbox_input = f"""
    iifname "{lan_if}" ip saddr {xbox_ip} udp dport {{ 1900, 5351 }} accept comment "xbox-upnp"
    iifname "{lan_if}" ip daddr 239.255.255.250 udp dport 1900 accept comment "ssdp-multicast"
    iifname "{lan_if}" ip saddr {lan_cidr} udp dport 1900 accept comment "ssdp-lan"
"""

    return f"""#!/usr/sbin/nft -f
{nat_table}
table inet filter {{{flow_block}{mac_block}{zone_block}{dns_block}{ids_block}{google_dhcp_block}

  chain input {{
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    iifname "{lan_if}" udp dport {{ 67, 68 }} accept
    iifname "{lan_if}" ip saddr {lan_cidr} udp dport {{ 53, {api_port}, {sentinel_port} }} accept
    iifname "{lan_if}" ip saddr {lan_cidr} tcp dport {{ 22, {api_port}, {sentinel_port} }} accept
    iifname "{lan_if}" ip saddr {lan_cidr} icmp type echo-request accept
    iifname "{lan_if}" ip daddr {gw_ip} icmp type echo-request accept{xbox_input}{mgmt_input}
    iifname "{wan_if}" ct state established,related accept
    iifname "{wan_if}" drop
  }}

  chain forward {{
    type filter hook forward priority filter; policy drop;{flow_rule}
    ct state established,related accept{wan_inbound}
{ids_forward}{dns_forward}{google_dhcp_forward}    iifname "{lan_if}" oifname "{wan_if}" jump lan_out
{zone_forward}{mgmt_forward}{wan_return}    drop
  }}{lan_out_chain}
}}
table {GAMING_TABLE} {{
  chain xbox_shield {{
    type filter hook forward priority filter - 10; policy accept;{xbox_rule}
  }}

  chain xbox_in {{
    ct state established,related accept
  }}
}}
"""


def apply_ruleset() -> dict[str, Any]:
    global _apply_ruleset_depth
    ifaces = _ifaces()
    RULESET.parent.mkdir(parents=True, exist_ok=True)
    flowtable = False
    with ruleset_lock():
        _apply_ruleset_depth += 1
        try:
            subprocess.run(["nft", "delete", "table", "inet", "filter"], capture_output=True, timeout=5, check=False)
            for use_ft in (False, True):
                text = render_ruleset(flowtable=use_ft)
                tmp = RULESET.with_suffix(".tmp")
                tmp.write_text(text, encoding="utf-8")
                proc = apply_nft_file_unlocked(tmp, timeout=15)
                if proc.returncode == 0:
                    flowtable = use_ft
                    tmp.replace(RULESET)
                    break
                tmp.unlink(missing_ok=True)
            else:
                raise subprocess.CalledProcessError(proc.returncode, proc.args, proc.stdout, proc.stderr)
            # Re-apply packet shield if active (filter/nat reset clears gaming table hooks)
            shield_state = Path("/var/lib/array-firewall/packet-shield.state")
            if shield_state.is_file():
                shield_text = shield_state.read_text(encoding="utf-8")
                if "mode=shield" in shield_text:
                    level = "normal"
                    for line in shield_text.splitlines():
                        if line.startswith("level="):
                            level = line.split("=", 1)[1].strip() or "normal"
                            break
                    try:
                        from . import peer_blocklist

                        proc_result = peer_blocklist.sync_shield(level=level)
                        if not proc_result.get("ok"):
                            err = str(proc_result.get("stderr") or proc_result.get("stdout") or "shield sync failed")
                            raise RuntimeError(f"packet shield re-apply failed: {err[-400:]}")
                    except ImportError:
                        shield = Path("/opt/array-firewall/scripts/packet-shield-nft.sh")
                        if shield.is_file():
                            proc = subprocess.run(
                                [str(shield), "shield", level],
                                capture_output=True,
                                text=True,
                                timeout=30,
                                check=False,
                            )
                            if proc.returncode != 0:
                                err = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
                                raise RuntimeError(f"packet shield re-apply failed: {err[-400:]}")
            elif policies.role() == "xbox_router":
                idle = str(policies.gaming().get("packet_shield_idle_level") or "console")
                if idle not in {"off", "relax", "none"}:
                    try:
                        from . import peer_blocklist

                        peer_blocklist.sync_shield(level=idle)
                    except Exception:
                        pass
            dscp_state = Path("/var/lib/array-firewall/dscp-gaming.state")
            if dscp_state.is_file() and "active=true" in dscp_state.read_text(encoding="utf-8"):
                moca = Path("/opt/array-firewall/gaming-tools/gaming-moca-tune.sh")
                if moca.is_file():
                    subprocess.run([str(moca), "apply"], check=False, timeout=30)
            try:
                from . import telemetry

                telemetry.ensure_device_counters(force=True)
            except ImportError:
                pass
            try:
                from . import qos as qos_mod

                proc = subprocess.run(
                    ["nft", "list", "table", "inet", "qos"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if proc.returncode != 0 and qos_mod.config().get("enabled", True):
                    mangle = qos_mod.render_nft_mangle()
                    if mangle:
                        mangle_path = Path("/var/lib/array-firewall/qos-mangle.nft")
                        mangle_path.write_text(mangle, encoding="utf-8")
                        subprocess.run(["nft", "-f", str(mangle_path)], check=False, timeout=15)
            except Exception:
                pass
            try:
                from . import nat as nat_mod

                nat_mod.sync_services()
            except Exception:
                pass
        finally:
            _apply_ruleset_depth -= 1
    return {
        "ok": True,
        "ruleset": str(RULESET),
        "role": ifaces["role"],
        "cutover": policies.cutover_enabled(),
        "lan_if": ifaces["lan_if"],
        "wan_if": ifaces["wan_if"],
        "lan_cidr": ifaces["lan_cidr"],
        "allowed_macs": devices.allowed_macs(),
        "quarantine_macs": devices.quarantine_macs(),
        "quarantine_count": len(devices.quarantine_macs()),
        "zones": _zones_summary(),
        "nat": policies.nat_enabled(),
        "default_deny": True,
        "flowtable": flowtable,
    }


def _zones_summary() -> dict[str, Any]:
    try:
        from . import zones as zones_mod

        s = zones_mod.status()
        return {
            "enabled": s.get("enabled"),
            "barrier": s.get("barrier"),
            "google_router_ip": s.get("google_router_ip"),
            "counts": {k: len(v) for k, v in (s.get("devices_by_zone") or {}).items()},
        }
    except Exception:
        return {"enabled": False}


def status() -> dict[str, Any]:
    ifaces = _ifaces()
    shield_state = Path("/var/lib/array-firewall/packet-shield.state")
    shield: dict[str, Any] = {"active": False}
    if shield_state.is_file():
        shield = dict(
            line.split("=", 1)
            for line in shield_state.read_text(encoding="utf-8").splitlines()
            if "=" in line
        )
        shield["active"] = shield.get("mode") == "shield"

    try:
        nft_out = subprocess.check_output(["nft", "list", "ruleset"], text=True, timeout=10)
    except subprocess.CalledProcessError:
        nft_out = ""

    wan_up = Path(f"/sys/class/net/{ifaces['wan_if']}/operstate").read_text().strip() == "up" if Path(
        f"/sys/class/net/{ifaces['wan_if']}/operstate"
    ).is_file() else False

    def _qos_summary() -> dict[str, Any]:
        try:
            from . import qos as qos_mod

            s = qos_mod.status()
            return {
                "enabled": s.get("enabled"),
                "mode": s.get("mode"),
                "classification": s.get("classification"),
                "xbox_rate": s.get("config", {}).get("xbox_rate"),
                "tc_upload": s.get("tc", {}).get("upload"),
                "tc_download": s.get("tc", {}).get("download"),
            }
        except Exception:
            return {"enabled": False}

    nat_summary: dict[str, Any] = {}
    try:
        from . import nat as nat_mod

        nat_summary = nat_mod.status()
    except Exception:
        nat_summary = {}

    return {
        "nat": policies.nat_enabled(),
        "inbound_nat": nat_summary,
        "role": ifaces["role"],
        "cutover": policies.cutover_enabled(),
        "target": "xbox_router" if ifaces["role"] == "xbox_router" else "gateway_exit",
        "lan_if": ifaces["lan_if"],
        "wan_if": ifaces["wan_if"],
        "wan_link_up": wan_up,
        "lan_cidr": ifaces["lan_cidr"],
        "default_deny_forward": True,
        "default_deny_input": True,
        "unsolicited_wan": "denied",
        "allowed_macs": devices.allowed_macs(),
        "quarantine_macs": devices.quarantine_macs(),
        "quarantine_count": len(devices.quarantine_macs()),
        "device_count": len(devices.list_devices()),
        "packet_shield": shield,
        "flowtable": "flowtable fastpath" in nft_out,
        "qos": _qos_summary(),
        "ruleset_lines": len(nft_out.splitlines()),
        "policies_file": str(policies.POLICIES_PATH),
    }


def sync_shield_peers(peers: list[str]) -> dict[str, Any]:
    """Update inet gaming suspicious_peers set without rebuilding the full shield."""
    valid = [ip.strip() for ip in peers if ip.strip()]
    try:
        subprocess.run(
            ["nft", "flush", "set", GAMING_TABLE, "suspicious_peers"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        added = 0
        for ip in valid:
            proc = subprocess.run(
                ["nft", "add", "element", GAMING_TABLE, "suspicious_peers", "{", ip, "}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0:
                added += 1
        return {"ok": True, "peers": added, "fast_path": True}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "fast_path": True}


def sync_shield_fast(*, level: str, peers: list[str] | None = None) -> dict[str, Any]:
    """Fast shield peer refresh — full script only when shield inactive or level changes."""
    state_path = Path("/var/lib/array-firewall/packet-shield.state")
    current_level = "normal"
    active = False
    if state_path.is_file():
        for line in state_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("level="):
                current_level = line.split("=", 1)[1].strip() or "normal"
            if line.startswith("mode=shield"):
                active = True
    level = policies.effective_shield_level(level)
    peer_list = list(dict.fromkeys(peers or []))
    if active and current_level == level:
        peer_sync = sync_shield_peers(peer_list)
        return {
            "ok": bool(peer_sync.get("ok")),
            "level": level,
            "peer_count": len(peer_list),
            "fast_path": True,
            "peer_sync": peer_sync,
        }
    from . import gaming as gaming_mod

    if level in ("console", "in-match"):
        if level == "in-match":
            result = gaming_mod.apply_in_match_mode(enabled=True, peer_ips=peer_list)
        else:
            result = gaming_mod.apply_console_mode(enabled=True, peer_ips=peer_list)
    else:
        result = gaming_mod.apply_packet_shield(level)
        if peer_list:
            sync_shield_peers(peer_list)
    result["fast_path"] = False
    return result
