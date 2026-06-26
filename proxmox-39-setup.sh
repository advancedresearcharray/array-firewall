#!/usr/bin/env bash
# Provision array-firewall on Proxmox thirtynince (192.168.167.39)
# Uses privileged LXC (VM 639 uses 32GB RAM — not enough headroom for another VM).
set -euo pipefail

CTID="${ARRAY_FW_CTID:-940}"
VM_IP="${ARRAY_FW_IP:-192.168.167.241}"
LAB_CIDR="${ARRAY_FW_LAB_IP:-10.99.0.1/24}"
GW="${ARRAY_FW_GW:-192.168.167.1}"
SSH_PUB="${ARRAY_FW_SSH_PUB:-/root/.ssh/id_rsa.pub}"
TEMPLATE="${ARRAY_FW_TEMPLATE:-/var/lib/vz/template/cache/debian-12-standard_12.12-1_amd64.tar.zst}"

if [[ ! -f "$SSH_PUB" ]]; then
  echo "Missing SSH public key: $SSH_PUB" >&2
  exit 1
fi

# vmbr1 → nic2 (Intel 1Gb WAN — separate from house LAN on nic0/vmbr0)
# thirtynince ROG STRIX X570-E: nic0=Realtek 2.5G LAN, nic2=Intel I211 WAN, nic1=Aquantia spare
if ! grep -q '^auto vmbr1' /etc/network/interfaces; then
  cat >> /etc/network/interfaces <<'EOF'

auto vmbr1
iface vmbr1 inet manual
	mtu 1500
	bridge-ports nic2
	bridge-stp off
	bridge-fd 0
EOF
  echo "[array-firewall] Added vmbr1 → nic2 (WAN, isolated from vmbr0/LAN)"
fi

cat > /etc/sysctl.d/99-array-firewall-host.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system >/dev/null 2>&1 || true
ifreload -a 2>/dev/null || true
ip link set nic2 up 2>/dev/null || true
ip link set vmbr1 up 2>/dev/null || true
# nic1 (Aquantia) intentionally unused — WAN/LAN must stay on separate bridges
ip link set nic1 down 2>/dev/null || true

if [[ ! -f "$TEMPLATE" ]]; then
  echo "Missing template: $TEMPLATE" >&2
  exit 1
fi

if pct status "$CTID" &>/dev/null; then
  echo "[array-firewall] CT $CTID already exists"
else
  pct create "$CTID" "$TEMPLATE" \
    --hostname array-firewall \
    --memory 1024 \
    --swap 512 \
    --cores 2 \
    --rootfs local-lvm:16 \
    --ostype debian \
    --features nesting=1,keyctl=1 \
    --unprivileged 0 \
    --onboot 1 \
    --nameserver "$GW" \
    --searchdomain array.local \
    --net0 "name=eth0,bridge=vmbr0,gw=${GW},ip=${VM_IP}/24,type=veth" \
    --net1 "name=eth1,bridge=vmbr1,ip=${LAB_CIDR},type=veth" \
    --ssh-public-keys "$SSH_PUB"

  echo "[array-firewall] Created CT $CTID"
fi

pct start "$CTID" 2>/dev/null || true
sleep 3

pct exec "$CTID" -- bash -s -- "$VM_IP" <<'INNER'
set -euo pipefail
VM_IP="$1"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nftables iproute2 conntrack tcpdump curl ca-certificates git vim

cat > /etc/sysctl.d/99-array-firewall.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF

cat > /etc/nftables.conf <<'NFT'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    ip saddr 192.168.167.0/24 tcp dport { 22, 8098 } accept
    ip saddr 192.168.167.0/24 icmp type echo-request accept
    ip saddr 10.99.0.0/24 icmp type echo-request accept
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
  chain output {
    type filter hook output priority filter; policy accept;
  }
}
NFT

mkdir -p /etc/array-firewall
cat > /etc/array-firewall/README <<EOF
array-firewall — Proxmox LXC on thirtynince (192.168.167.39)
eth0 (${VM_IP}): LAN management + future API
eth1 (10.99.0.1): second NIC via vmbr1/nic1 — no WAN yet
EOF

sysctl -p /etc/sysctl.d/99-array-firewall.conf 2>/dev/null || true
nft -f /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables
INNER

echo "[array-firewall] Verifying..."
pct exec "$CTID" -- bash -c 'hostname; ip -br addr; nft list chain inet filter input; systemctl is-active nftables'

echo ""
echo "array-firewall ready:"
echo "  Proxmox: 192.168.167.39 (CT${CTID})"
echo "  SSH:     root@${VM_IP}"
echo "  Lab NIC: eth1 ${LAB_CIDR} on vmbr1 → nic1"
