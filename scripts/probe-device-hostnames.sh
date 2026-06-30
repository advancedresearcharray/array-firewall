#!/usr/bin/env bash
# Probe Proxmox CT/VM hostnames + mDNS names for devices missing DHCP hostnames.
set -euo pipefail

OUT="${1:-/var/lib/array-firewall/probed-hostnames.json}"
PROXMOX_NODES="${ARRAY_FW_PROXMOX_NODES:-}"
MDNS_NODE="${ARRAY_FW_MDNS_NODE:-}"
TMP="$(mktemp)"
ROWS="$TMP.rows"

: >"$ROWS"

ssh_node() {
  local node="$1"
  ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new "root@${node}" "$2"
}

for node in $PROXMOX_NODES; do
  ssh_node "$node" 'python3 -'" <<'PY' >>"$ROWS"
import glob, json, re, subprocess, socket

def clean(name):
    name = (name or "").strip().rstrip(".")
    if not name or name == "*":
        return ""
    return name.split(".")[0]

rows = []
for path in sorted(glob.glob("/etc/pve/lxc/*.conf")):
    text = open(path, encoding="utf-8").read()
    mac = re.search(r"hwaddr=([0-9A-F:]+)", text, re.I)
    ipm = re.search(r"ip=([0-9.]+)", text)
    hn = re.search(r"^hostname:\s*(\S+)", text, re.M)
    vmid = path.split("/")[-1].split(".")[0]
    if not mac:
        continue
    ip = ipm.group(1) if ipm else ""
    hostname = clean(hn.group(1) if hn else "")
    if vmid.isdigit():
        try:
            live = subprocess.check_output(["pct", "exec", vmid, "--", "hostname", "-s"], text=True, timeout=8).strip()
            hostname = clean(live) or hostname
        except Exception:
            pass
    if hostname:
        rows.append({"mac": mac.group(1).lower(), "ip": ip, "hostname": hostname, "source": "proxmox-lxc"})

for path in sorted(glob.glob("/etc/pve/qemu-server/*.conf")):
    text = open(path, encoding="utf-8").read()
    mac = re.search(r"hwaddr=([0-9A-F:]+)", text, re.I)
    ipm = re.search(r"ip=([0-9.]+)", text)
    name = re.search(r"^name:\s*(\S+)", text, re.M)
    if not mac:
        continue
    ip = ipm.group(1) if ipm else ""
    hostname = clean(name.group(1) if name else "")
    if hostname:
        rows.append({"mac": mac.group(1).lower(), "ip": ip, "hostname": hostname, "source": "proxmox-vm"})

host = clean(socket.gethostname())
if host:
    rows.append({"mac": "", "ip": "", "hostname": host, "source": "proxmox-host", "node": "'"${node}"'"})
print(json.dumps(rows))
PY
done

# Optional hypervisor rows: export ARRAY_FW_HYPERVISOR_JSON='[{"mac":"...","ip":"...","hostname":"..."}]'
if [[ -n "${ARRAY_FW_HYPERVISOR_JSON:-}" ]]; then
  python3 -c 'import json,sys; [print(json.dumps(r)) for r in json.loads(sys.argv[1])]' "$ARRAY_FW_HYPERVISOR_JSON" >>"$ROWS"
fi

# mDNS for devices missing hostnames (requires ARRAY_FW_MDNS_NODE)
if [[ -f /var/lib/array-firewall/devices.json ]]; then
  python3 - /var/lib/array-firewall/devices.json >>"$ROWS" <<'PY'
import json, subprocess, sys
data = json.load(open(sys.argv[1]))
ips = set()
for dev in data.get("devices", {}).values():
    ip = str(dev.get("ip") or "")
    label = str(dev.get("label") or "")
    host = str(dev.get("hostname") or "")
    if "." in ip and (not host or label == ip):
        ips.add(ip)
for ip in sorted(ips):
    print(ip)
PY
  while read -r ip; do
    [[ -z "$ip" ]] && continue
    name="$(ssh_node "$MDNS_NODE" "avahi-resolve -a '${ip}' 2>/dev/null | awk '{print \$2}'" || true)"
    name="${name%.local}"
    [[ -z "$name" || "$name" == "$ip" ]] && continue
    echo "{\"ip\":\"${ip}\",\"hostname\":\"${name}\",\"source\":\"mdns\"}"
  done < <(python3 - /var/lib/array-firewall/devices.json <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
for dev in data.get("devices", {}).values():
    ip = str(dev.get("ip") or "")
    label = str(dev.get("label") or "")
    host = str(dev.get("hostname") or "")
    if "." in ip and (not host or label == ip):
        print(ip)
PY
) >>"$ROWS"
fi

python3 - "$OUT" "$ROWS" <<'PY'
import json, sys, time
from pathlib import Path

out_path = Path(sys.argv[1])
rows_path = Path(sys.argv[2])
by_mac = {}
by_ip = {}
for line in rows_path.read_text().splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        continue
    mac = str(row.get("mac") or "").lower()
    ip = str(row.get("ip") or "").strip()
    hostname = str(row.get("hostname") or "").strip().split(".")[0]
    if not hostname:
        continue
    if mac:
        by_mac[mac] = {**row, "mac": mac, "hostname": hostname, "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if ip:
        by_ip[ip] = {"ip": ip, "hostname": hostname, "source": row.get("source", "probe"), "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

# Attach mdns-only rows to MACs from devices.json when possible
devices_path = Path("/var/lib/array-firewall/devices.json")
if devices_path.is_file():
    data = json.loads(devices_path.read_text())
    for mac, dev in data.get("devices", {}).items():
        mac = mac.lower()
        if mac in by_mac:
            continue
        ip = str(dev.get("ip") or "")
        if ip in by_ip:
            by_mac[mac] = {"mac": mac, "ip": ip, **by_ip[ip]}

payload = {"version": 1, "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "by_mac": by_mac, "by_ip": by_ip}
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print(json.dumps({"ok": True, "count": len(by_mac), "path": str(out_path)}))
PY

rm -f "$TMP" "$ROWS"
