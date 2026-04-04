#!/usr/bin/env bash
# CertHound Agent Installer — Linux
# Usage: curl -sSL https://raw.githubusercontent.com/deadbolthq/certhound-agent/main/scripts/install.sh | sudo bash -s -- --key ch_xxx --endpoint https://your-api/ingest
set -euo pipefail

RELEASES_URL="https://github.com/deadbolthq/certhound-agent/releases/latest/download"
INSTALL_PATH="/usr/local/bin/certhound-agent"
SERVICE_NAME="certhound-agent"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

KEY=""
ENDPOINT=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --key)      KEY="$2";      shift 2 ;;
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$KEY" ]]; then
  echo "Error: --key is required." >&2
  echo "Get your API key and install command from the CertHound dashboard." >&2
  exit 1
fi

if [[ -z "$ENDPOINT" ]]; then
  echo "Error: --endpoint is required." >&2
  echo "Get your API key and install command from the CertHound dashboard." >&2
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Error: this script must be run as root (use sudo)." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH="amd64"  ;;
  aarch64) ARCH="arm64"  ;;
  *)
    echo "Error: unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

echo "==> Installing CertHound agent (linux/$ARCH)"

# ---------------------------------------------------------------------------
# Download binary
# ---------------------------------------------------------------------------

BINARY_URL="${RELEASES_URL}/certhound-agent-linux-${ARCH}"
echo "==> Downloading from $BINARY_URL"
curl -sSfL "$BINARY_URL" -o "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"
echo "==> Binary installed to $INSTALL_PATH"

# ---------------------------------------------------------------------------
# Provision (writes key + config to /etc/certhound/)
# ---------------------------------------------------------------------------

echo "==> Provisioning agent..."
"$INSTALL_PATH" --provision --key "$KEY" --endpoint "$ENDPOINT"

# ---------------------------------------------------------------------------
# Install and start systemd service
# ---------------------------------------------------------------------------

cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=CertHound Agent
Documentation=https://certhound.com/docs
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${INSTALL_PATH} --watch
Restart=on-failure
RestartSec=30
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo ""
echo "==> CertHound agent installed and running."
echo "    Check status:  systemctl status $SERVICE_NAME"
echo "    View logs:     journalctl -u $SERVICE_NAME -f"
echo "    Stop agent:    systemctl stop $SERVICE_NAME"
