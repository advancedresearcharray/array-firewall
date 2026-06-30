#!/usr/bin/env bash
# Install GPU packet analyzer on fleet GPU host (192.0.2.221).
set -euo pipefail

HOST="${GPU_HOST:-192.0.2.221}"
USER="${GPU_USER:-ck}"
REMOTE_ROOT="\${HOME}/opt/array-firewall-gpu"
PORT="${GPU_PERF_PORT:-8795}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

echo "[install-gpu-perf] target ${USER}@${HOST}:~/opt/array-firewall-gpu"

scp -o BatchMode=yes \
  "$SRC/gpu-services/analyze_server.py" \
  "${USER}@${HOST}:~/opt/array-firewall-gpu/analyze_server.py"

ssh -o BatchMode=yes "${USER}@${HOST}" bash -s <<REMOTE
set -euo pipefail
mkdir -p ~/opt/array-firewall-gpu
chmod 755 ~/opt/array-firewall-gpu/analyze_server.py
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/array-firewall-gpu-perf.service <<'UNIT'
[Unit]
Description=array-firewall GPU packet analyzer
After=network.target

[Service]
Type=simple
Environment=CUDA_VISIBLE_DEVICES=0
Environment=GPU_PERF_PORT=${PORT}
ExecStart=/usr/bin/python3 %h/opt/array-firewall-gpu/analyze_server.py
Restart=on-failure
RestartSec=3
WorkingDirectory=%h/opt/array-firewall-gpu

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable array-firewall-gpu-perf.service
loginctl enable-linger "\$(whoami)" 2>/dev/null || true
systemctl --user restart array-firewall-gpu-perf.service
sleep 2
curl -sf http://127.0.0.1:${PORT}/health && echo
REMOTE

echo "[install-gpu-perf] done — http://${HOST}:${PORT}/health"
