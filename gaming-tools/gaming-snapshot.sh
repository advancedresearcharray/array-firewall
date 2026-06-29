#!/usr/bin/env bash
# One-shot JSON snapshot for Xbox traffic monitoring (runs on array-firewall gateway).
set -euo pipefail

TOOLS_DIR="${TOOLS_DIR:-/opt/array-firewall/gaming-tools}"
CONF="${TOOLS_DIR}/gaming.conf"
if [[ -f "$CONF" ]]; then
  # shellcheck disable=SC1090
  source "$CONF"
fi

TARGET_IP="${1:-${XBOX_IP:-}}"
LAN="${LAN_IF:-br2}"
UPLOAD_IF="${UPLOAD_IF:-ifb0}"
DOWNLOAD_IF="${DOWNLOAD_IF:-ifb1}"

if [[ -z "$TARGET_IP" ]]; then
  echo '{"error":"XBOX_IP not configured"}'
  exit 2
fi

shift || true

exec python3 - "$TARGET_IP" "$LAN" "$UPLOAD_IF" "$DOWNLOAD_IF" "${XBOX_NAME:-Xbox}" "${XBOX_MAC:-}" "$TOOLS_DIR" "${WAN_PROBE_HOST:-one.one.one.one}" "$@" <<'PY'
import json
import ipaddress
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

sys.path.insert(0, "/opt/warzone-lobby-sentinel")
try:
    from sentinel.enrich import classify_endpoint as classify_remote_role
except ImportError:
    classify_remote_role = None

target_ip, lan, upload_if, download_if, xbox_name, xbox_mac, tools_dir, wan_probe_host = sys.argv[1:9]
extra_args = sys.argv[9:]
wire_mode = "--wire" in extra_args
minimal_mode = "--minimal" in extra_args
critical_mode = "--critical" in extra_args
deep_packets = "--deep-packets" in extra_args
xbox_mac = (xbox_mac or "").upper().replace("-", ":")
TCPDUMP_COUNT = 400 if deep_packets else 250
PACKET_RECORD_LIMIT = 200 if deep_packets else 100


def read_mem_available_mb():
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        return None


mem_available_mb = read_mem_available_mb()
if critical_mode:
    pressure_mode = "critical"
elif minimal_mode:
    pressure_mode = "minimal"
else:
    pressure_mode = "normal"

if pressure_mode == "normal" and mem_available_mb is not None:
    if mem_available_mb < 400:
        pressure_mode = "critical"
    elif mem_available_mb < 512:
        pressure_mode = "minimal"

LIMITS = {
    "normal": {
        "conn": 96,
        "dest": 80,
        "flows": 32,
        "top": 20,
        "ping": 999,
        "tcpdump": True,
        "conntrack": True,
        "redis_flows": 32,
    },
    "minimal": {
        "conn": 32,
        "dest": 24,
        "flows": 12,
        "top": 8,
        "ping": 8,
        "tcpdump": False,
        "conntrack": True,
        "redis_flows": 12,
    },
    "critical": {
        "conn": 8,
        "dest": 8,
        "flows": 0,
        "top": 0,
        "ping": 0,
        "tcpdump": False,
        "conntrack": False,
        "redis_flows": 0,
    },
}
lim = LIMITS[pressure_mode]
if deep_packets and pressure_mode == "minimal":
    lim = dict(lim)
    lim["tcpdump"] = True

NETBOT_URL = os.environ.get("NETBOT_BRIDGE_URL", "http://127.0.0.1:8836")


def netbot_invoke(mtype, data, target=None):
    body = {"mtype": mtype, "data": data or {}}
    if target:
        body["target"] = target
    out = run(
        [
            "curl",
            "-sS",
            "-m",
            "20",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            json.dumps(body),
            f"{NETBOT_URL.rstrip('/')}/invoke",
        ],
        timeout=25,
    )
    if not out:
        return None
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return None
    if not payload.get("ok"):
        return None
    result = payload.get("result") or {}
    if result.get("code", 500) >= 400:
        return None
    return result.get("data")


def netbot_hosts():
    data = netbot_invoke("get", {"item": "hosts"})
    if not data:
        return []
    hosts = data.get("hosts", [])
    if isinstance(hosts, dict):
        return list(hosts.values())
    return hosts if isinstance(hosts, list) else []


def resolve_host_record(ip, mac):
    want_mac = (mac or "").upper()
    for host in netbot_hosts():
        if host.get("ip") == ip:
            return host
        if want_mac and (host.get("mac") or "").upper() == want_mac:
            return host
    return None


def netbot_flows(host_mac, count, direction=None):
    if not host_mac or count <= 0:
        return []
    value = {"count": count, "apiVer": 3}
    if direction:
        value["direction"] = direction
    data = netbot_invoke("get", {"item": "flows", "value": value}, target=host_mac)
    if not data:
        return []
    flows = data.get("flows", [])
    if isinstance(flows, dict):
        return flows.get("recent", []) or []
    return flows if isinstance(flows, list) else []


def map_netbot_flow(flow):
    ip = flow.get("ip") or ""
    port = flow.get("port") or ""
    remote = f"{ip}:{port}" if port else ip
    fd = flow.get("fd") or "out"
    direction = "out" if fd == "out" else "in" if fd == "in" else fd
    hostname = flow.get("host") or ""
    info = enrich_remote(remote, hostname)
    return {
        "direction": direction,
        "remote": remote,
        "upload": flow.get("upload", flow.get("ob", 0)),
        "download": flow.get("download", flow.get("rb", 0)),
        "duration": flow.get("duration", flow.get("du", 0)),
        "timestamp": flow.get("ts", flow.get("_ts", 0)),
        "category": flow.get("category", ""),
        **info,
    }


def trim_host_profile(host):
    if not host:
        return None
    return {
        "ip": host.get("ip"),
        "mac": host.get("mac"),
        "bname": host.get("bname"),
        "names": host.get("names") or [],
        "macVendor": host.get("macVendor"),
        "lastActive": host.get("lastActive"),
        "detect": host.get("detect"),
    }


def trim_conn(c):
    return {
        "proto": c.get("proto"),
        "state": c.get("state"),
        "local": c.get("local"),
        "remote": c.get("remote"),
        "direction": c.get("direction"),
        "hostname": c.get("hostname"),
        "label": c.get("label"),
        "ip": c.get("ip"),
        "port": c.get("port"),
        "scope": c.get("scope"),
        "roleId": c.get("roleId", ""),
        "latencyMs": c.get("latencyMs"),
    }


def fold_conn_row(c):
    return [
        c.get("ip") or "",
        c.get("label") or c.get("hostname") or "",
        c.get("proto") or "",
        c.get("state") or "",
        c.get("latencyMs"),
    ]


def fold_dest_row(d):
    return [
        d.get("ip") or "",
        d.get("label") or "",
        d.get("kind") or "",
        d.get("latencyMs"),
    ]

def run(cmd, timeout=5):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        ).stdout.strip()
    except Exception:
        return ""

def ping_ok(host):
    r = subprocess.run(
        ["ping", "-c", "1", "-W", "1", host],
        capture_output=True,
        timeout=3,
        check=False,
    )
    return r.returncode == 0

def is_private_ip(value):
    raw = value.split("%")[0]
    try:
        ip = ipaddress.ip_address(raw)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return True

def split_remote(remote):
    if remote.startswith("["):
        m = re.match(r"^\[(.+)\]:(\d+)$", remote)
        if m:
            return m.group(1), m.group(2)
    if remote.count(":") > 1:
        host, port = remote.rsplit(":", 1)
        return host, port
    if ":" in remote:
        host, port = remote.rsplit(":", 1)
        return host, port
    return remote, ""

def parse_ping_ms(output):
    for line in output.splitlines():
        if "time=" in line:
            m = re.search(r"time[=<]([\d.]+)", line)
            if m:
                return float(m.group(1))
        if "min/avg" in line or "rtt min/avg" in line:
            try:
                return float(line.split("=")[1].split("/")[1])
            except (IndexError, ValueError):
                pass
    return None

def ping_host(ip, timeout=2):
    if not ip or is_private_ip(ip):
        return None
    try:
        version = ipaddress.ip_address(ip.split("%")[0]).version
    except ValueError:
        return None
    cmd = (
        ["ping", "-6", "-c", "1", "-W", "1", ip]
        if version == 6
        else ["ping", "-c", "1", "-W", "1", ip]
    )
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return parse_ping_ms(proc.stdout)

def measure_latencies(ips, max_hosts=18):
    unique = []
    seen = set()
    for ip in ips:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        unique.append(ip)
        if len(unique) >= max_hosts:
            break
    results = {}
    if not unique:
        return results
    with ThreadPoolExecutor(max_workers=min(8, len(unique))) as pool:
        futures = {pool.submit(ping_host, ip): ip for ip in unique}
        for future in as_completed(futures, timeout=6):
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = None
    return results

def attach_latency(entry, latency_map):
    ip = entry.get("ip")
    if ip and ip in latency_map:
        entry["latencyMs"] = latency_map[ip]
        return
    ips = entry.get("ips") or []
    samples = [latency_map[i] for i in ips if i in latency_map and latency_map[i] is not None]
    entry["latencyMs"] = min(samples) if samples else None

hostname_cache = {}

def resolve_hostname(ip):
    if not ip or is_private_ip(ip):
        return ""
    if ip in hostname_cache:
        return hostname_cache[ip]
    host = run(["redis-cli", "hget", f"host:ext.x509:{ip}", "server_name"], timeout=2)
    if not host:
        host = run(["redis-cli", "hget", f"host:ext.x509:{ip}", "host"], timeout=2)
    hostname_cache[ip] = host or ""
    return hostname_cache[ip]

def enrich_remote(remote, host="", service="", proto=""):
    ip, port = split_remote(remote)
    hostname = host or resolve_hostname(ip)
    scope = "local" if is_private_ip(ip) else "wan"
    label = hostname or ip or remote
    port_num = int(port) if str(port or "").isdigit() else None
    role_id = ""
    if classify_remote_role:
        role_id = classify_remote_role(
            remote,
            hostname or host,
            port_num,
            proto or service or "",
        )
    return {
        "remote": remote,
        "ip": ip,
        "port": port,
        "hostname": hostname,
        "label": label,
        "service": service,
        "scope": scope,
        "roleId": role_id,
    }

def discover_ipv6(mac, dev):
    if not mac:
        return ""
    want = mac.lower()
    out = run(["ip", "-6", "neigh", "show", "dev", dev], timeout=4)
    for line in out.splitlines():
        if "lladdr" not in line:
            continue
        parts = line.split()
        ip6 = parts[0]
        try:
            lladdr = parts[parts.index("lladdr") + 1].lower()
        except (ValueError, IndexError):
            continue
        if lladdr == want and not ip6.startswith("fe80:"):
            return ip6
    return ""

def addr_match(value, addrs):
    if not value:
        return False
    base = value.split("%")[0]
    return base in addrs

def parse_conn_key(key):
    m = re.match(r"^conn:(tcp|udp):", key)
    if not m:
        return None
    proto = m.group(1)
    for addr in sorted(target_addrs, key=len, reverse=True):
        prefix = f"conn:{proto}:{addr}:"
        if not key.startswith(prefix):
            continue
        tail = key[len(prefix):]
        rport_m = re.search(r":(\d+)$", tail)
        if not rport_m:
            continue
        remote_port = rport_m.group(1)
        mid = tail[: rport_m.start()]
        lpm = re.match(r"^(\d+):(.+)$", mid)
        if not lpm:
            continue
        local_port, remote_ip = lpm.group(1), lpm.group(2)
        direction = "out"
        return {
            "proto": proto,
            "state": "tracked",
            "local": f"{addr}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "direction": direction,
        }
    return None

def parse_tcpdump_endpoint(raw):
    raw = raw.rstrip(":")
    if "." in raw and ":" not in raw.split(".")[-1]:
        return raw.rsplit(".", 1)[0]
    if raw.count(":") > 1 and raw.rsplit(":", 1)[-1].isdigit():
        return raw.rsplit(":", 1)[0]
    return raw


def parse_tcpdump_host_port(raw):
    raw = raw.rstrip(":")
    host = parse_tcpdump_endpoint(raw)
    port = None
    if "." in raw and ":" not in raw.split(".")[-1]:
        tail = raw.rsplit(".", 1)[-1]
        if tail.isdigit():
            port = int(tail)
    elif raw.count(":") > 1 and raw.rsplit(":", 1)[-1].isdigit():
        port = int(raw.rsplit(":", 1)[-1])
    return host, port


def parse_tcpdump_line(line, target_addrs):
    is_v4 = " IP " in line
    is_v6 = " IP6 " in line
    if not is_v4 and not is_v6:
        return None
    parts = line.split()
    if len(parts) < 6:
        return None
    try:
        length = int(parts[-1])
    except ValueError:
        length = 0
    src_raw, dst_raw = parts[2], parts[4]
    src_host, src_port = parse_tcpdump_host_port(src_raw)
    dst_host, dst_port = parse_tcpdump_host_port(dst_raw)
    tail = " ".join(parts[5:-2]) if len(parts) > 6 else ""
    proto = "unknown"
    flags = ""
    if " UDP" in tail or tail.startswith("UDP"):
        proto = "udp"
    elif " TCP" in tail or tail.startswith("TCP"):
        proto = "tcp"
        fm = re.search(r"\[([^\]]+)\]", tail)
        if fm:
            flags = fm.group(1)
    elif " ICMP" in tail or tail.startswith("ICMP"):
        proto = "icmp"
    direction = None
    remote = None
    local_port = None
    remote_port = None
    if addr_match(src_host, target_addrs) or addr_match(src_raw, target_addrs):
        direction = "out"
        remote = dst_host
        local_port = src_port
        remote_port = dst_port
    elif addr_match(dst_host, target_addrs) or addr_match(dst_raw, target_addrs):
        direction = "in"
        remote = src_host
        local_port = dst_port
        remote_port = src_port
    else:
        return None
    return {
        "direction": direction,
        "proto": proto,
        "flags": flags,
        "length": length,
        "remote": remote,
        "localPort": local_port,
        "remotePort": remote_port,
        "src": src_host,
        "dst": dst_host,
    }

target_ipv6 = discover_ipv6(xbox_mac, lan)
target_addrs = [target_ip]
if target_ipv6:
    target_addrs.append(target_ipv6)

now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
netbot_host = resolve_host_record(target_ip, xbox_mac)
if netbot_host and not xbox_mac:
    xbox_mac = (netbot_host.get("mac") or "").upper()
if netbot_host and netbot_host.get("ip") and netbot_host.get("ip") != target_ip:
    target_ip = netbot_host.get("ip")
    target_addrs = [target_ip]
    if target_ipv6:
        target_addrs.append(target_ipv6)

online = ping_ok(target_ip) or bool(target_ipv6)
if netbot_host and netbot_host.get("lastActive"):
    try:
        online = online or (float(netbot_host["lastActive"]) > (datetime.now().timestamp() - 120))
    except (TypeError, ValueError):
        pass

arp_line = run(["ip", "neigh", "show", target_ip, "dev", lan])
arp_parts = arp_line.split()
arp_mac = arp_parts[4] if len(arp_parts) >= 5 else ""
arp_state = arp_parts[5] if len(arp_parts) >= 6 else ""

def redis_hgetall(key):
    out = run(["redis-cli", "hgetall", key], timeout=3)
    if not out:
        return {}
    lines = out.splitlines()
    data = {}
    for i in range(0, len(lines) - 1, 2):
        data[lines[i]] = lines[i + 1]
    return data

connections = []
seen = set()
for addr in target_addrs:
    keys_out = run(["redis-cli", "--scan", "--pattern", f"conn:*{addr}*"], timeout=8)
    for key in keys_out.splitlines():
        if not key or key.startswith("conn:dns:") or key in seen:
            continue
        seen.add(key)
        parsed = parse_conn_key(key)
        if not parsed:
            continue
        meta = redis_hgetall(key)
        parsed["host"] = meta.get("host", "")
        parsed["service"] = meta.get("proto", "")
        info = enrich_remote(parsed["remote"], parsed["host"], parsed["service"], parsed.get("proto", ""))
        parsed.update(info)
        connections.append(parsed)

def parse_conntrack_tuples(line):
    return re.findall(
        r"src=(\S+)\s+dst=(\S+)(?:\s+sport=(\S+)\s+dport=(\S+))?",
        line,
    )


def append_conntrack_connection(proto, state, local, remote, direction):
    dedupe = (proto, local, remote, direction, state)
    if dedupe in seen:
        return
    seen.add(dedupe)
    info = enrich_remote(remote, proto=proto)
    connections.append({
        "proto": proto,
        "state": state,
        "local": local,
        "remote": remote,
        "direction": direction,
        "host": info["hostname"],
        "service": "",
        **info,
    })

grep_re = "|".join(re.escape(addr) for addr in target_addrs)
if lim["conntrack"]:
    ct_out = run(["bash", "-lc", f"conntrack -L 2>/dev/null | grep -E '{grep_re}'"], timeout=10)
    for line in ct_out.splitlines():
        if not any(addr in line for addr in target_addrs):
            continue
        parts = line.split()
        if not parts or parts[0] in ("unknown",):
            continue
        proto = parts[0]
        state = ""
        if proto == "tcp" and len(parts) > 3 and "=" not in parts[3]:
            state = parts[3]
        tuples = parse_conntrack_tuples(line)
        if not tuples:
            continue

        orig_src, orig_dst, orig_sport, orig_dport = tuples[0]
        xbox_is_orig_src = addr_match(orig_src, target_addrs)
        xbox_is_orig_dst = addr_match(orig_dst, target_addrs)

        if xbox_is_orig_src:
            remote = f"{orig_dst}:{orig_dport}" if orig_dport else orig_dst
            local = f"{orig_src}:{orig_sport}" if orig_sport else orig_src
            append_conntrack_connection(proto, state, local, remote, "out")

        if xbox_is_orig_dst:
            remote = f"{orig_src}:{orig_sport}" if orig_sport else orig_src
            local = f"{orig_dst}:{orig_dport}" if orig_dport else orig_dst
            append_conntrack_connection(proto, state, local, remote, "in")

        # NAT reply tuple (WAN-side dst) — orig was Xbox outbound, reply is inbound.
        if xbox_is_orig_src and len(tuples) >= 2:
            rep_src, rep_dst, rep_sport, rep_dport = tuples[1]
            if rep_src and rep_dport:
                remote = f"{rep_src}:{rep_sport}" if rep_sport else rep_src
                local = f"{orig_src}:{rep_dport}"
                append_conntrack_connection(proto, state, local, remote, "in")

dns_destinations = []
dns_by_host = {}
if xbox_mac:
    dns_keys = run(["redis-cli", "--scan", "--pattern", f"conn:dns:{xbox_mac}:*"], timeout=8)
    for key in dns_keys.splitlines():
        if not key:
            continue
        meta = redis_hgetall(key)
        ip = meta.get("ip", "")
        host = meta.get("host", "")
        if not ip:
            continue
        info = enrich_remote(f"{ip}", host, meta.get("proto", "dns"))
        if info["scope"] != "wan":
            continue
        label = host or info["hostname"] or ip
        bucket = dns_by_host.setdefault(label, {
            "kind": "dns",
            "label": label,
            "hostname": host or info["hostname"],
            "ips": [],
            "proto": "dns",
            "state": "resolved",
            "service": meta.get("proto", "dns"),
        })
        if ip not in bucket["ips"]:
            bucket["ips"].append(ip)
    dns_destinations = list(dns_by_host.values())

recent_flows = []
flow_source = "none"
host_mac = (netbot_host or {}).get("mac") or xbox_mac
if lim["redis_flows"] > 0 and host_mac:
    for direction in ("out", "in"):
        per_dir = max(1, lim["redis_flows"] // 2)
        for flow in netbot_flows(host_mac, per_dir, direction=direction):
            recent_flows.append(map_netbot_flow(flow))
    if recent_flows:
        flow_source = "netbot"

if lim["redis_flows"] > 0 and not recent_flows:
    flow_source = "redis"
    for addr in target_addrs:
        for direction, zkey in (("out", f"flow:conn:out:{addr}"), ("in", f"flow:conn:in:{addr}")):
            rows = run(["redis-cli", "zrevrange", zkey, "0", str(lim["redis_flows"])], timeout=4)
            for row in rows.splitlines():
                if not row.strip():
                    continue
                try:
                    flow = json.loads(row)
                except json.JSONDecodeError:
                    continue
                remote = flow.get("sh") or flow.get("dh") or flow.get("lh") or "?"
                if addr_match(str(remote), target_addrs):
                    remote = flow.get("dh") or flow.get("sh") or "?"
                info = enrich_remote(str(remote))
                recent_flows.append({
                    "direction": direction,
                    "remote": str(remote),
                    "upload": flow.get("ob", 0),
                    "download": flow.get("rb", 0),
                    "duration": flow.get("du", 0),
                    "timestamp": flow.get("_ts", 0),
                    "hostname": info["hostname"],
                    "label": info["label"],
                    "ip": info["ip"],
                    "scope": info["scope"],
                })

connections.sort(key=lambda c: (0 if c.get("state") == "ESTABLISHED" else 1, c.get("scope") != "wan", c.get("label", "")))

destinations = []
dest_seen = set()

def add_destination(entry):
    key = (entry.get("kind"), entry.get("label"), entry.get("ip"), entry.get("remote", ""))
    if key in dest_seen:
        return
    dest_seen.add(key)
    destinations.append(entry)

for conn in connections:
    if conn.get("scope") != "wan":
        continue
    add_destination({
        "kind": "active",
        "label": conn.get("label") or conn.get("remote"),
        "hostname": conn.get("hostname", ""),
        "ip": conn.get("ip", ""),
        "port": conn.get("port", ""),
        "proto": conn.get("proto", ""),
        "state": conn.get("state", ""),
        "service": conn.get("service", ""),
        "remote": conn.get("remote", ""),
    })

for flow in recent_flows:
    if flow.get("scope") != "wan":
        continue
    add_destination({
        "kind": "recent",
        "label": flow.get("label") or flow.get("remote"),
        "hostname": flow.get("hostname", ""),
        "ip": flow.get("ip", ""),
        "proto": "flow",
        "state": "recent",
        "upload": flow.get("upload", 0),
        "download": flow.get("download", 0),
    })

for dns in dns_destinations:
    ips = dns.get("ips") or []
    add_destination({
        "kind": "dns",
        "label": dns.get("label"),
        "hostname": dns.get("hostname", ""),
        "ip": ips[0] if ips else "",
        "ips": ips[:6],
        "ipCount": len(ips),
        "proto": "dns",
        "state": "resolved",
        "service": dns.get("service", "dns"),
    })

destinations.sort(key=lambda d: ({"active": 0, "recent": 1, "dns": 2}.get(d.get("kind"), 9), d.get("label", "")))

sample_packets = 0
sample_bytes = 0
sample_in = 0
sample_out = 0
flow_map = {}
flow_packets = {}
flow_proto = {}
packet_records = []
inbound_remotes = set()
outbound_remotes = set()

if online and lim["tcpdump"]:
    host_filter = " or ".join(f"host {addr}" for addr in target_addrs)
    tcpdump_cmd = ["sudo", "-n", "tcpdump", "-ni", lan, "-q", "-c", str(TCPDUMP_COUNT), host_filter]
    try:
        proc = subprocess.run(
            tcpdump_cmd, capture_output=True, text=True, timeout=5, check=False
        )
        dump_lines = proc.stdout.splitlines()
    except Exception:
        dump_lines = []

    for line in dump_lines:
        pkt = parse_tcpdump_line(line, target_addrs)
        if not pkt:
            continue
        length = pkt["length"]
        direction = pkt["direction"]
        remote = pkt["remote"] or "unknown"
        sample_packets += 1
        sample_bytes += length
        if direction == "out":
            sample_out += length
            outbound_remotes.add(remote)
        else:
            sample_in += length
            inbound_remotes.add(remote)
        key = (direction, remote)
        flow_map[key] = flow_map.get(key, 0) + length
        flow_packets[key] = flow_packets.get(key, 0) + 1
        flow_proto[key] = pkt["proto"]
        if len(packet_records) < PACKET_RECORD_LIMIT:
            rec = {
                "dir": direction,
                "proto": pkt["proto"],
                "len": length,
                "remote": remote,
                "remotePort": pkt["remotePort"],
                "localPort": pkt["localPort"],
            }
            if classify_remote_role:
                from sentinel.enrich import classify_inbound_endpoint

                if direction == "in":
                    rec["roleId"] = classify_inbound_endpoint(
                        remote,
                        "",
                        pkt.get("remotePort"),
                        pkt.get("proto") or "",
                    )
                else:
                    rec["roleId"] = classify_remote_role(
                        remote,
                        "",
                        pkt.get("remotePort"),
                        pkt.get("proto") or "",
                    )
            if pkt["flags"]:
                rec["flags"] = pkt["flags"]
            packet_records.append(rec)

    tiny_in = sum(1 for p in packet_records if p["dir"] == "in" and p["len"] < 80)
    large_in = sum(1 for p in packet_records if p["dir"] == "in" and p["len"] > 1200)
    tiny_out = sum(1 for p in packet_records if p["dir"] == "out" and p["len"] < 80)
    udp_in = sum(1 for p in packet_records if p["dir"] == "in" and p["proto"] == "udp")
    tcp_syn_in = sum(
        1
        for p in packet_records
        if p["dir"] == "in" and p["proto"] == "tcp" and "S" in p.get("flags", "")
    )
    in_lens = [p["len"] for p in packet_records if p["dir"] == "in"]
    out_lens = [p["len"] for p in packet_records if p["dir"] == "out"]
    packet_stats = {
        "total": sample_packets,
        "inbound": sum(1 for p in packet_records if p["dir"] == "in"),
        "outbound": sum(1 for p in packet_records if p["dir"] == "out"),
        "tinyInbound": tiny_in,
        "tinyOutbound": tiny_out,
        "largeInbound": large_in,
        "uniqueInboundRemotes": len(inbound_remotes),
        "uniqueOutboundRemotes": len(outbound_remotes),
        "udpInbound": udp_in,
        "tcpSynInbound": tcp_syn_in,
        "avgInboundSize": round(sum(in_lens) / len(in_lens), 1) if in_lens else 0,
        "avgOutboundSize": round(sum(out_lens) / len(out_lens), 1) if out_lens else 0,
    }
else:
    packet_stats = {"total": 0, "enabled": False}

top_flows = sorted(
    [
        {
            "direction": d,
            "endpoint": ep,
            "bytes": b,
            "packets": flow_packets.get((d, ep), 0),
            "proto": flow_proto.get((d, ep), "unknown"),
            "avgSize": round(b / max(flow_packets.get((d, ep), 1), 1)),
            **enrich_remote(parse_tcpdump_endpoint(ep)),
        }
        for (d, ep), b in flow_map.items()
    ],
    key=lambda x: x["bytes"],
    reverse=True,
)[:15]

ping_targets = []
if lim["ping"] > 0:
    for conn in connections:
        if conn.get("scope") == "wan" and conn.get("ip"):
            ping_targets.append(conn["ip"])
    for item in top_flows:
        if item.get("scope") == "wan" and item.get("ip"):
            ping_targets.append(item["ip"])
    for dest in destinations:
        if dest.get("kind") == "active" and dest.get("ip"):
            ping_targets.append(dest["ip"])
        elif dest.get("kind") == "dns":
            ips = dest.get("ips") or ([dest["ip"]] if dest.get("ip") else [])
            if ips:
                ping_targets.append(ips[0])
    ping_targets = list(dict.fromkeys(ping_targets))[: lim["ping"]]

latency_map = measure_latencies(ping_targets) if ping_targets else {}
for conn in connections:
    attach_latency(conn, latency_map)
for dest in destinations:
    attach_latency(dest, latency_map)
for item in top_flows:
    attach_latency(item, latency_map)
for flow in recent_flows:
    attach_latency(flow, latency_map)

destinations.sort(
    key=lambda d: (
        {"active": 0, "recent": 1, "dns": 2}.get(d.get("kind"), 9),
        d.get("latencyMs") if d.get("latencyMs") is not None else 9999,
        d.get("label", ""),
    )
)

cake_upload = run(["tc", "qdisc", "show", "dev", upload_if]).splitlines()
cake_download = run(["tc", "qdisc", "show", "dev", download_if]).splitlines()

def _pick_qdisc(lines):
    for tag in ("cake", "htb", "fq_codel"):
        hit = next((l.strip() for l in lines if tag in l), "")
        if hit:
            return hit
    return next((l.strip() for l in lines if l.strip()), "")

cake_upload = _pick_qdisc(cake_upload)
cake_download = _pick_qdisc(cake_download)


def normalize_mac(mac):
    return (mac or "").upper().replace("-", ":")


def redis_hget(key, field):
    out = run(["redis-cli", "HGET", key, field], timeout=3)
    return out.strip() if out else ""


def detect_gaming_mode(mac, policies_data=None):
    """Read Firewalla device QoS policies via netbot (official PolicyManager2 path)."""
    import os

    legacy = f"{tools_dir}/.gaming-mode.state"
    if os.path.isfile(legacy):
        return "on", "companion-state"

    norm_mac = normalize_mac(mac)
    if not norm_mac:
        return "unknown", "no-mac-configured"

    policies = []
    if isinstance(policies_data, dict):
        policies = policies_data.get("policies") or []

    upload_qos = False
    download_qos = False
    pids = []
    for policy in policies:
        if str(policy.get("action", "")).lower() != "qos":
            continue
        if str(policy.get("disabled", "0")) not in ("0", ""):
            continue
        notes = policy.get("notes") or ""
        if notes.startswith("xbox-monitor:bandwidth:"):
            continue
        scope = policy.get("scope") or []
        if norm_mac not in {normalize_mac(s) for s in scope}:
            continue
        pid = policy.get("pid")
        if pid is not None:
            pids.append(str(pid))
        direction = policy.get("trafficDirection") or ""
        if direction == "upload":
            upload_qos = True
        elif direction == "download":
            download_qos = True

    if upload_qos and download_qos:
        return "on", f"firewalla-qos {','.join(sorted(set(pids)))}"
    if upload_qos or download_qos:
        return "partial", f"firewalla-qos-one-way {','.join(sorted(set(pids)))}"

    if policies_data is not None:
        traffic_state = f"{tools_dir}/.traffic-profile.state"
        if os.path.isfile(traffic_state):
            try:
                with open(traffic_state, encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("profile="):
                            profile = line.split("=", 1)[1].strip()
                            if profile and profile != "balanced":
                                return "on", f"companion-{profile}"
            except OSError:
                pass
        return "off", "firewalla-qos-inactive"

    policy_keys = run(["redis-cli", "--scan", "--pattern", "policy:*"], timeout=12).splitlines()
    for key in policy_keys:
        if not key.startswith("policy:"):
            continue
        pid = key.rsplit(":", 1)[-1]
        if not pid.isdigit():
            continue
        if redis_hget(key, "action") != "qos":
            continue
        disabled = redis_hget(key, "disabled")
        if disabled not in ("0", ""):
            continue
        scope = redis_hget(key, "scope")
        if norm_mac not in scope.upper():
            continue
        notes = redis_hget(key, "notes")
        if notes.startswith("xbox-monitor:bandwidth:"):
            continue
        direction = redis_hget(key, "trafficDirection")
        pids.append(pid)
        if direction == "upload":
            upload_qos = True
        elif direction == "download":
            download_qos = True

    if upload_qos and download_qos:
        return "on", f"firewalla-qos {','.join(sorted(set(pids)))}"
    if upload_qos or download_qos:
        return "partial", f"firewalla-qos-one-way {','.join(sorted(set(pids)))}"

    traffic_state = f"{tools_dir}/.traffic-profile.state"
    if os.path.isfile(traffic_state):
        try:
            with open(traffic_state, encoding="utf-8") as f:
                for line in f:
                    if line.startswith("profile="):
                        profile = line.split("=", 1)[1].strip()
                        if profile and profile != "balanced":
                            return "on", f"companion-{profile}"
        except OSError:
            pass

    return "off", "firewalla-qos-inactive"


_qos_policies_data = netbot_invoke("get", {"item": "policies"})
gaming_mode, gaming_mode_detail = detect_gaming_mode(xbox_mac, _qos_policies_data)
qos_via_netbot = _qos_policies_data is not None

wan_latency_ms = None
if wan_probe_host:
    ping_out = run(["ping", "-c", "1", "-W", "2", wan_probe_host], timeout=4)
    for line in ping_out.splitlines():
        if "min/avg" in line or "rtt min/avg" in line:
            try:
                wan_latency_ms = float(line.split("=")[1].split("/")[1])
            except (IndexError, ValueError):
                pass

conn_slice = connections[: lim["conn"]]
dest_slice = destinations[: lim["dest"]]
conn_items = [trim_conn(c) for c in conn_slice] if pressure_mode != "normal" else list(conn_slice)
conn_truncated = len(connections) > len(conn_items)

payload = {
    "timestamp": now,
    "preabstract": {
        "mode": pressure_mode,
        "memAvailableMb": mem_available_mb,
        "folded": pressure_mode != "normal",
        "wire": (
            "fld1"
            if pressure_mode == "critical" and wire_mode
            else ("gz1" if wire_mode else "json")
        ),
    },
    "xbox": {
        "name": (netbot_host or {}).get("bname") or xbox_name,
        "ip": target_ip,
        "ipv6": target_ipv6,
        "mac": xbox_mac,
        "online": online,
        "arpMac": arp_mac,
        "arpState": arp_state,
        "path": "wired-moca",
        "pathLabel": "Wired · MoCA",
        "lanLatencyMs": latency_map.get(target_ip),
        "netbot": trim_host_profile(netbot_host),
    },
    "sample": {
        "windowSec": 3 if lim["tcpdump"] else 0,
        "packets": sample_packets,
        "bytes": sample_bytes,
        "bytesIn": sample_in,
        "bytesOut": sample_out,
        "stack": "ipv4+ipv6" if lim["tcpdump"] else "skipped",
    },
    "connections": {
        "count": len(connections),
        "itemsShown": len(conn_items),
        "truncated": conn_truncated,
        "items": conn_items,
        "source": "redis+conntrack" if lim["conntrack"] else "redis",
    },
    "recentFlows": recent_flows[: lim["flows"]],
    "flowSource": flow_source,
    "destinations": dest_slice if pressure_mode == "normal" else [],
    "topFlows": top_flows[: lim["top"]],
    "packetCapture": {
        "enabled": bool(lim["tcpdump"]),
        "records": packet_records[: min(PACKET_RECORD_LIMIT, 80 if not deep_packets else 160)],
        "stats": packet_stats,
        "deep": deep_packets,
    },
    "sqm": {
        "uploadQdisc": cake_upload,
        "downloadQdisc": cake_download,
        "gamingMode": gaming_mode,
        "gamingModeDetail": gaming_mode_detail,
        "qosSource": "array-firewall",
    },
    "wan": {
        "latencyMs": wan_latency_ms,
    },
}

if pressure_mode != "normal":
    payload["connections"]["folded"] = [fold_conn_row(c) for c in conn_slice]
    payload["destinationsFolded"] = [fold_dest_row(d) for d in dest_slice]

text = json.dumps(payload, separators=(",", ":"))
if wire_mode:
    import base64
    import gzip

    if pressure_mode == "critical":
        print("FLD1:" + text)
    else:
        blob = gzip.compress(text.encode("utf-8"), compresslevel=6)
        print("GZ1:" + base64.b64encode(blob).decode("ascii"))
else:
    print(text)
PY
