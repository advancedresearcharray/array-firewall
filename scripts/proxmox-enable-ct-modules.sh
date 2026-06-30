#!/usr/bin/env bash
# Copy BBR + cake kernel modules from Proxmox host into array-firewall CT (bind-mount blocked on /lib symlink).
set -euo pipefail

: "${ARRAY_FW_CTID:?Set ARRAY_FW_CTID}"
CTID="${ARRAY_FW_CTID}"
PROXMOX="${PROXMOX_NODE:?Set PROXMOX_NODE}"

ssh -o BatchMode=yes "root@${PROXMOX}" bash -s <<REMOTE
set -euo pipefail
CTID=${CTID}
KVER=\$(uname -r)
SRC="/usr/lib/modules/\${KVER}"
DST="/lib/modules/\${KVER}"

echo "[ct-modules] CT\${CTID} install modules for \${KVER}"

modprobe tcp_bbr 2>/dev/null || true
modprobe sch_cake 2>/dev/null || true

pct exec "\$CTID" -- mkdir -p "\${DST}/kernel/net/ipv4" "\${DST}/kernel/net/sched"

for rel in kernel/net/ipv4/tcp_bbr.ko kernel/net/sched/sch_cake.ko; do
  pct push "\$CTID" "\${SRC}/\${rel}" "\${DST}/\${rel}"
done

for meta in modules.dep modules.alias modules.symbols modules.builtin.modinfo; do
  [[ -f "\${SRC}/\${meta}" ]] && pct push "\$CTID" "\${SRC}/\${meta}" "\${DST}/\${meta}" || true
done

pct exec "\$CTID" -- bash -c "
  modprobe tcp_bbr && echo BBR=ok || echo BBR=fail
  modprobe sch_cake && echo CAKE=ok || echo CAKE=fail
  sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || true
  sysctl net.ipv4.tcp_available_congestion_control
  tc qdisc add dev lo root cake 2>/dev/null && tc qdisc del dev lo root && echo CAKE_TC=ok || echo CAKE_TC=fail
"
REMOTE

echo "[ct-modules] done"
