#!/usr/bin/env bash
set -euo pipefail
INSTALL_ROOT="/opt/array-firewall"
ENV_SENTINEL="/etc/default/warzone-lobby-sentinel"
TOKEN_FILE="/etc/array-firewall/api.token"
DEVICES_FILE="/var/lib/array-firewall/devices.json"
ADMIN_MAC="${ARRAY_FW_ADMIN_MAC:-}"

# Load admin MAC from secrets if present
if [[ -z "$ADMIN_MAC" && -f /etc/array-firewall/admin.env ]]; then
  # shellcheck disable=SC1091
  source /etc/array-firewall/admin.env
  ADMIN_MAC="${ADMIN_LAPTOP_MAC:-}"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>/dev/null || true
apt-get install -y -qq nftables iproute2 conntrack tcpdump curl ca-certificates python3 dnsmasq isc-dhcp-client ethtool miniupnpd iptables >/dev/null 2>&1 || \
  apt-get install -y -qq nftables iproute2 conntrack curl ca-certificates python3 dnsmasq miniupnpd >/dev/null 2>&1 || \
  apt-get install -y -qq nftables iproute2 conntrack curl ca-certificates python3 dnsmasq >/dev/null 2>&1 || \
  apt-get install -y -qq nftables iproute2 curl ca-certificates python3 >/dev/null

chmod +x "$INSTALL_ROOT/gaming-tools/"*.sh 2>/dev/null || true
chmod +x "$INSTALL_ROOT/scripts/run-gaming.sh" 2>/dev/null || true
chmod +x "$INSTALL_ROOT/scripts/perf-tune.sh" 2>/dev/null || true
ln -sf "$INSTALL_ROOT/scripts/run-gaming.sh" /usr/local/bin/run-gaming 2>/dev/null || true

if command -v dnsmasq >/dev/null 2>&1; then
  "$INSTALL_ROOT/scripts/setup-dnsmasq.sh"
fi

mkdir -p /etc/array-firewall /var/lib/array-firewall /var/lib/misc
install -m 0644 "$INSTALL_ROOT/config/array-firewall.conf" /etc/array-firewall/array-firewall.conf
if [[ ! -f /var/lib/array-firewall/policies.json ]]; then
  install -m 0644 "$INSTALL_ROOT/config/policies.json.example" /var/lib/array-firewall/policies.json
fi

if [[ -n "$ADMIN_MAC" ]]; then
  if grep -q '^ADMIN_LAPTOP_MAC=' /etc/array-firewall/array-firewall.conf; then
    sed -i "s|^ADMIN_LAPTOP_MAC=.*|ADMIN_LAPTOP_MAC=${ADMIN_MAC}|" /etc/array-firewall/array-firewall.conf
  else
    echo "ADMIN_LAPTOP_MAC=${ADMIN_MAC}" >> /etc/array-firewall/array-firewall.conf
  fi
fi

if [[ ! -f "$TOKEN_FILE" ]]; then
  TOKEN="$(openssl rand -hex 24 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(24))')"
  install -m 0600 /dev/null "$TOKEN_FILE"
  echo "$TOKEN" > "$TOKEN_FILE"
  echo "[install] API token written to $TOKEN_FILE"
fi

if [[ ! -f "$DEVICES_FILE" ]]; then
  python3 - <<'PY'
import json, os, re, time
from pathlib import Path
conf = Path("/etc/array-firewall/array-firewall.conf")
admin = ""
if conf.is_file():
    for line in conf.read_text().splitlines():
        if line.startswith("ADMIN_LAPTOP_MAC="):
            admin = line.split("=",1)[1].strip()
devices = {"version": 1, "admin_laptop_mac": admin, "devices": {}}
if admin:
    mac = admin.lower()
    devices["devices"][mac] = {
        "mac": mac,
        "allowed": True,
        "label": "Admin laptop",
        "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
Path("/var/lib/array-firewall/devices.json").write_text(json.dumps(devices, indent=2) + "\n")
PY
fi

chmod +x "$INSTALL_ROOT/scripts/"*.sh
ln -sf "$INSTALL_ROOT/scripts/array-firewall-ctl.sh" /usr/local/bin/array-firewall-ctl
ln -sf "$INSTALL_ROOT/scripts/packet-shield-nft.sh" /usr/local/bin/packet-shield-nft
ln -sf "$INSTALL_ROOT/scripts/apply-firewall.sh" /usr/local/bin/apply-array-firewall

if command -v dnsmasq >/dev/null 2>&1; then
  systemctl enable dnsmasq 2>/dev/null || true
  systemctl restart dnsmasq 2>/dev/null || true
fi

cat > /etc/sysctl.d/99-array-firewall.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
EOF
sysctl -p /etc/sysctl.d/99-array-firewall.conf >/dev/null 2>&1 || true

install -m 0644 "$INSTALL_ROOT/systemd/array-firewall.service" /etc/systemd/system/array-firewall.service
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-api.service" /etc/systemd/system/array-firewall-api.service
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-probe-sink.service" /etc/systemd/system/array-firewall-probe-sink.service
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-arp-watch.service" /etc/systemd/system/array-firewall-arp-watch.service
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-wan-scan-capture.service" /etc/systemd/system/array-firewall-wan-scan-capture.service
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-afld-rollup.service" /etc/systemd/system/array-firewall-afld-rollup.service
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-afld-rollup.timer" /etc/systemd/system/array-firewall-afld-rollup.timer
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-ai-ops.service" /etc/systemd/system/array-firewall-ai-ops.service
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-ai-ops.timer" /etc/systemd/system/array-firewall-ai-ops.timer
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-fleet-sync.service" /etc/systemd/system/array-firewall-fleet-sync.service
install -m 0644 "$INSTALL_ROOT/systemd/array-firewall-fleet-sync.timer" /etc/systemd/system/array-firewall-fleet-sync.timer
chmod +x "$INSTALL_ROOT/scripts/arp-watch.sh" 2>/dev/null || true
chmod +x "$INSTALL_ROOT/scripts/wan-scan-capture.py" 2>/dev/null || true
chmod +x "$INSTALL_ROOT/scripts/afld-rollup.py" 2>/dev/null || true
chmod +x "$INSTALL_ROOT/scripts/ai-ops-tick.py" 2>/dev/null || true
chmod +x "$INSTALL_ROOT/scripts/fleet-sync.py" 2>/dev/null || true
chmod +x "$INSTALL_ROOT/gaming-tools/probe-sink-listener.py" 2>/dev/null || true

systemctl daemon-reload
systemctl enable array-firewall.service array-firewall-api.service array-firewall-probe-sink.service array-firewall-arp-watch.service array-firewall-wan-scan-capture.service array-firewall-afld-rollup.timer array-firewall-ai-ops.timer array-firewall-fleet-sync.timer
systemctl restart array-firewall.service
systemctl restart array-firewall-api.service
systemctl restart array-firewall-probe-sink.service 2>/dev/null || true
systemctl restart array-firewall-arp-watch.service 2>/dev/null || true
systemctl restart array-firewall-wan-scan-capture.service 2>/dev/null || true
systemctl restart array-firewall-afld-rollup.timer 2>/dev/null || true
systemctl restart array-firewall-ai-ops.timer 2>/dev/null || true
systemctl restart array-firewall-fleet-sync.timer 2>/dev/null || true

"$INSTALL_ROOT/scripts/perf-tune.sh" apply 2>/dev/null || true

if [[ -f /opt/warzone-lobby-sentinel/install-in-ct.sh ]]; then
  chmod +x /opt/warzone-lobby-sentinel/install-in-ct.sh
  if [[ ! -f "$ENV_SENTINEL" ]]; then
    install -m 0644 /opt/warzone-lobby-sentinel/warzone-lobby-sentinel.env.example "$ENV_SENTINEL"
  fi
  sed -i 's|^WZ_FIREWALLA_API_URL=.*|WZ_FIREWALLA_API_URL=http://127.0.0.1:8090|' "$ENV_SENTINEL" 2>/dev/null || true
  bash /opt/warzone-lobby-sentinel/install-in-ct.sh || true
  bash "$INSTALL_ROOT/scripts/sync-sentinel-config.sh" || true
fi

echo ""
echo "=== array-firewall ready ==="
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):8090/"
echo "API token: $TOKEN_FILE"
array-firewall-ctl status 2>/dev/null || true
