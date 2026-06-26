from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from . import devices, policies

CONF_PATH = Path("/etc/array-firewall/array-firewall.conf")
RULESET = Path(os.environ.get("ARRAY_FW_RULESET", "/var/lib/array-firewall/ruleset.nft"))
GAMING_TABLE = "inet gaming"


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
    role = policies.role() if policies.cutover_enabled() or policies.role() == "gateway" else "lab"
    if role == "gateway" and policies.cutover_enabled():
        return {
            "role": "gateway",
            "mgmt_if": c.get("MGMT_IF", "eth0"),
            "lan_if": pol.get("lan_if") or c.get("LAN_IF", "eth0"),
            "wan_if": pol.get("wan_if") or c.get("WAN_IF", "eth1"),
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

    mac_block = ""
    if mac_set:
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

    if mac_set:
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
    try:
        from . import nat as nat_mod

        inbound_forward = nat_mod.render_forward_inbound_rules()
        prerouting = nat_mod.render_prerouting_rules()
    except Exception:
        pass

    wan_inbound = f"\n{inbound_forward}" if inbound_forward else ""

    zone_block = ""
    zone_forward = f'    iifname "{lan_if}" oifname "{lan_if}" drop\n'
    try:
        from . import zones as zones_mod

        gw_ip = ifaces.get("gw_ip") or policies.network().get("gateway_ip") or c.get("LAN_GATEWAY_IP", "192.168.167.1")
        zone_block, zone_forward = zones_mod.render_forward_zones(lan_if, gw_ip)
    except Exception:
        pass

    return f"""#!/usr/sbin/nft -f
flush ruleset

table inet filter {{{flow_block}{mac_block}{zone_block}

  chain input {{
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    iifname "{lan_if}" udp dport {{ 67, 68 }} accept
    iifname "{lan_if}" ip saddr {lan_cidr} udp dport {{ 53, {api_port}, {sentinel_port} }} accept
    iifname "{lan_if}" ip saddr {lan_cidr} tcp dport {{ 22, {api_port}, {sentinel_port} }} accept
    iifname "{lan_if}" ip saddr {lan_cidr} icmp type echo-request accept
    iifname "{mgmt_if}" ip saddr {mgmt_cidr} tcp dport {{ 22, {api_port}, {sentinel_port} }} accept
    iifname "{mgmt_if}" ip saddr {mgmt_cidr} icmp type echo-request accept
    iifname "{wan_if}" ct state established,related accept
    iifname "{wan_if}" drop
  }}

  chain forward {{
    type filter hook forward priority filter; policy drop;{flow_rule}
    ct state established,related accept{wan_inbound}
    iifname "{lan_if}" oifname "{wan_if}" jump lan_out
{zone_forward}    iifname "{mgmt_if}" oifname "{lan_if}" ip saddr {mgmt_cidr} accept
    iifname "{wan_if}" oifname "{lan_if}" drop
    drop
  }}{lan_out_chain}
}}

table ip nat {{{prerouting}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    iifname "{lan_if}" oifname "{wan_if}" ip saddr {lan_cidr} masquerade
  }}
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
    ifaces = _ifaces()
    RULESET.parent.mkdir(parents=True, exist_ok=True)
    flowtable = False
    for use_ft in (False, True):
        text = render_ruleset(flowtable=use_ft)
        RULESET.write_text(text, encoding="utf-8")
        proc = subprocess.run(["nft", "-f", str(RULESET)], capture_output=True, text=True, timeout=15)
        if proc.returncode == 0:
            flowtable = use_ft
            break
    else:
        raise subprocess.CalledProcessError(proc.returncode, proc.args, proc.stdout, proc.stderr)
    # Re-apply packet shield if active (flush ruleset clears gaming table)
    shield_state = Path("/var/lib/array-firewall/packet-shield.state")
    if shield_state.is_file():
        shield_text = shield_state.read_text(encoding="utf-8")
        if "mode=shield" in shield_text:
            level = "normal"
            for line in shield_text.splitlines():
                if line.startswith("level="):
                    level = line.split("=", 1)[1].strip() or "normal"
                    break
            shield = Path("/opt/array-firewall/scripts/packet-shield-nft.sh")
            if shield.is_file():
                subprocess.run([str(shield), "shield", level], check=False, timeout=30)
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
        "nat": True,
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
        "nat": True,
        "inbound_nat": nat_summary,
        "role": ifaces["role"],
        "cutover": policies.cutover_enabled(),
        "target": "gateway_exit",
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
