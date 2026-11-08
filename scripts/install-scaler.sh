#!/usr/bin/env bash
# Build xbase-scaler and install it as a systemd service (autoscaling loop).
#   sudo ./scripts/install-scaler.sh [/etc/xbase/scaler.json]
# Deploys then use the same binary: xbase-scaler deploy -build saas-api-1
set -euo pipefail
CONFIG="${1:-/etc/xbase/scaler.json}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

[[ $EUID -eq 0 ]] || { echo "run as root (installs /usr/local/bin + systemd unit)" >&2; exit 1; }
command -v go >/dev/null || { echo "go toolchain required to build scaler/" >&2; exit 1; }

(cd "$ROOT/scaler" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/local/bin/xbase-scaler .)

mkdir -p "$(dirname "$CONFIG")"
if [[ ! -f "$CONFIG" ]]; then
  sed "s#/opt/xbase/docker#$ROOT/docker#" "$ROOT/scaler/scaler.example.json" > "$CONFIG"
  echo "wrote $CONFIG from the example: review the services and capacity before starting"
fi

# Refuse to install a plan that cannot fit Postgres.
XBASE_SCALER_CONFIG="$CONFIG" /usr/local/bin/xbase-scaler plan || {
  echo "capacity plan does not fit; fix $CONFIG, then re-run" >&2; exit 1; }

cat > /etc/systemd/system/xbase-scaler.service <<UNIT
[Unit]
Description=xbase autoscaler
After=docker.service
Requires=docker.service

[Service]
Environment=XBASE_SCALER_CONFIG=$CONFIG
RuntimeDirectory=xbase-scaler
ExecStart=/usr/local/bin/xbase-scaler run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now xbase-scaler
echo "xbase-scaler running. status: XBASE_SCALER_CONFIG=$CONFIG xbase-scaler status"
