#!/usr/bin/env bash
# Deploy array-firewall + Warzone Lobby Sentinel to CT940 on Proxmox thirtynince (.39).
#
#   ./deploy.sh
#   ARRAY_FW_CTID=940 PROXMOX_NODE=192.168.167.39 ./deploy.sh
#
set -euo pipefail

CTID="${ARRAY_FW_CTID:-940}"
PROXMOX="${PROXMOX_NODE:-192.168.167.39}"
PROXMOX_REMOTE="root@${PROXMOX}"
CT_IP="${ARRAY_FW_IP:-192.168.167.241}"
MEM_MB="${ARRAY_FW_MEMORY:-2048}"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SENTINEL_DIR="$(cd "$ROOT_DIR/../warzone-lobby-sentinel" && pwd)"
FW_BUNDLE="/tmp/array-firewall.tgz"
SENTINEL_BUNDLE="/tmp/warzone-lobby-sentinel.tgz"
TOKEN_SRC="${WZ_TOKEN_SRC:-/root/.secrets/firewalla-api.env}"
XBOX_TOKEN_SRC="${WZ_XBOX_TOKEN_SRC:-/root/.secrets/xbox-notify.json}"
ADMIN_MAC_SRC="${ARRAY_FW_ADMIN_MAC:-}"
ADMIN_ENV="${ARRAY_FW_ADMIN_ENV:-/root/.secrets/array-firewall.env}"

bundle_firewall() {
  tar czf "$FW_BUNDLE" -C "$ROOT_DIR" \
    config scripts nft systemd api docs gaming-tools gpu-services
}

bundle_sentinel() {
  echo "Building Rust sentinel..."
  (cd "$SENTINEL_DIR/rust" && cargo build --release)
  mkdir -p "$SENTINEL_DIR/bin"
  cp "$SENTINEL_DIR/rust/target/release/warzone-sentinel" "$SENTINEL_DIR/bin/warzone-sentinel"
  tar czf "$SENTINEL_BUNDLE" \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='rust/target' \
    -C "$(dirname "$SENTINEL_DIR")" \
    "$(basename "$SENTINEL_DIR")"
}

push_tokens() {
  ssh -o BatchMode=yes "$PROXMOX_REMOTE" "pct exec $CTID -- mkdir -p /etc/warzone-sentinel"
  if [[ -f "$TOKEN_SRC" ]]; then
    local tmp
    tmp="$(mktemp)"
    grep -E '^FIREWALLA_API_TOKEN=' "$TOKEN_SRC" > "$tmp" || true
    if [[ -s "$tmp" ]]; then
      scp -o BatchMode=yes "$tmp" "${PROXMOX_REMOTE}:/tmp/firewalla.token"
      ssh -o BatchMode=yes "$PROXMOX_REMOTE" \
        "pct push $CTID /tmp/firewalla.token /etc/warzone-sentinel/firewalla.token && \
         pct exec $CTID -- chmod 600 /etc/warzone-sentinel/firewalla.token && \
         rm -f /tmp/firewalla.token"
    fi
    rm -f "$tmp"
  fi
  if [[ -f "$XBOX_TOKEN_SRC" ]]; then
    scp -o BatchMode=yes "$XBOX_TOKEN_SRC" "${PROXMOX_REMOTE}:/tmp/xbox_notify.json"
    ssh -o BatchMode=yes "$PROXMOX_REMOTE" \
      "pct push $CTID /tmp/xbox_notify.json /etc/warzone-sentinel/xbox_notify.json && \
       pct exec $CTID -- chmod 600 /etc/warzone-sentinel/xbox_notify.json && \
       rm -f /tmp/xbox_notify.json"
  fi
}

deploy() {
  bundle_firewall
  bundle_sentinel

  echo "Enabling kernel modules in CT${CTID} (BBR + cake)..."
  bash "$ROOT_DIR/scripts/proxmox-enable-ct-modules.sh" || echo "WARN: ct-modules step failed (run manually)"

  echo "Installing GPU perf analyzer on .221..."
  bash "$ROOT_DIR/scripts/install-gpu-perf-on-221.sh" || echo "WARN: gpu-perf install failed"

  echo "Bumping CT${CTID} memory to ${MEM_MB} MB..."
  ssh -o BatchMode=yes "$PROXMOX_REMOTE" "pct set $CTID -memory $MEM_MB && pct start $CTID 2>/dev/null || true"

  scp -o BatchMode=yes "$FW_BUNDLE" "$SENTINEL_BUNDLE" \
    "$ROOT_DIR/scripts/install-on-ct.sh" \
    "${PROXMOX_REMOTE}:/tmp/"

  push_tokens

  if [[ -z "$ADMIN_MAC_SRC" && -f "$ADMIN_ENV" ]]; then
    ADMIN_MAC_SRC="$(grep -E '^ADMIN_LAPTOP_MAC=' "$ADMIN_ENV" | head -1 | cut -d= -f2- | tr -d '"')"
  fi
  if [[ -z "$ADMIN_MAC_SRC" ]]; then
    ADMIN_MAC_SRC="$(ip link show 2>/dev/null | awk '/link\/ether/{print $2; exit}')"
  fi

  ssh -o BatchMode=yes "$PROXMOX_REMOTE" env CTID="$CTID" ADMIN_MAC="${ADMIN_MAC_SRC}" bash -s <<'REMOTE'
set -euo pipefail
pct push "$CTID" /tmp/array-firewall.tgz /tmp/array-firewall.tgz
pct push "$CTID" /tmp/warzone-lobby-sentinel.tgz /tmp/warzone-lobby-sentinel.tgz
pct push "$CTID" /tmp/install-on-ct.sh /tmp/install-array-firewall.sh
if [[ -n "${ADMIN_MAC:-}" ]]; then
  echo "ADMIN_LAPTOP_MAC=${ADMIN_MAC}" > /tmp/array-fw-admin.env
  pct push "$CTID" /tmp/array-fw-admin.env /etc/array-firewall/admin.env
  rm -f /tmp/array-fw-admin.env
fi
pct exec "$CTID" -- bash -c '
  rm -rf /opt/array-firewall /opt/warzone-lobby-sentinel
  mkdir -p /opt/array-firewall /etc/array-firewall
  tar xzf /tmp/array-firewall.tgz -C /opt/array-firewall
  tar xzf /tmp/warzone-lobby-sentinel.tgz -C /opt
  rm -f /tmp/array-firewall.tgz /tmp/warzone-lobby-sentinel.tgz
'
pct exec "$CTID" -- env ARRAY_FW_ADMIN_MAC="${ADMIN_MAC:-}" bash /tmp/install-array-firewall.sh
rm -f /tmp/install-on-ct.sh
REMOTE

  rm -f "$FW_BUNDLE" "$SENTINEL_BUNDLE"
}

deploy

PORT=8090
echo ""
echo "array-firewall deployed to CT${CTID} @ ${CT_IP}"
echo "  dashboard:        http://${CT_IP}:${PORT}/"
echo "  API:              http://${CT_IP}:${PORT}/api/v1/*"
echo "  API token:        ssh root@${CT_IP} cat /etc/array-firewall/api.token"
echo "  firewall status:  ssh root@${CT_IP} array-firewall-ctl status"
echo "  sentinel dash:    http://${CT_IP}:8098/"
echo "  lab NIC:          eth1 10.99.0.1/24 (vmbr1 → nic1)"
echo ""
echo "Set admin laptop MAC: ARRAY_FW_ADMIN_MAC=aa:bb:cc:dd:ee:ff ./deploy.sh"
echo ""
