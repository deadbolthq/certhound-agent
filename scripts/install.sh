#!/usr/bin/env bash
# CertHound Agent Installer — Linux
#
# Managed install (posts to CertHound dashboard):
#   curl -sSL https://raw.githubusercontent.com/deadbolthq/certhound-agent/main/scripts/install.sh | sudo bash -s -- --key ch_xxx --endpoint https://api.certhound.dev/v1/ingest
#
# Standalone install (local scan only, no dashboard):
#   curl -sSL https://raw.githubusercontent.com/deadbolthq/certhound-agent/main/scripts/install.sh | sudo bash
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

if [[ "$EUID" -ne 0 ]]; then
  echo "Error: this script must be run as root (use sudo)." >&2
  exit 1
fi

# --key and --endpoint are both required together, or both omitted (standalone mode)
if [[ -n "$KEY" && -z "$ENDPOINT" ]] || [[ -z "$KEY" && -n "$ENDPOINT" ]]; then
  echo "Error: --key and --endpoint must be provided together." >&2
  echo "For standalone mode (no dashboard), omit both flags." >&2
  exit 1
fi

if [[ -z "$KEY" ]]; then
  echo "==> Standalone mode: agent will scan locally and not report to any endpoint."
  echo "    To connect to the CertHound dashboard, re-run with --key and --endpoint."
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
# Download binary + checksums and verify before installing
# ---------------------------------------------------------------------------

BINARY_NAME="certhound-agent-linux-${ARCH}"
BINARY_URL="${RELEASES_URL}/${BINARY_NAME}"
CHECKSUM_URL="${RELEASES_URL}/checksums.txt"
TMP_BINARY=$(mktemp)
TMP_CHECKSUMS=$(mktemp)

cleanup() {
  rm -f "$TMP_BINARY" "$TMP_CHECKSUMS"
}
trap cleanup EXIT

echo "==> Downloading binary from $BINARY_URL"
curl -sSfL "$BINARY_URL" -o "$TMP_BINARY"

echo "==> Downloading checksums from $CHECKSUM_URL"
curl -sSfL "$CHECKSUM_URL" -o "$TMP_CHECKSUMS"

echo "==> Verifying SHA-256 checksum..."
EXPECTED=$(grep "${BINARY_NAME}$" "$TMP_CHECKSUMS" | awk '{print $1}')
if [[ -z "$EXPECTED" ]]; then
  echo "Error: no checksum entry found for ${BINARY_NAME} in checksums.txt" >&2
  exit 1
fi

ACTUAL=$(sha256sum "$TMP_BINARY" | awk '{print $1}')
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
  echo "Error: checksum mismatch!" >&2
  echo "  Expected: $EXPECTED" >&2
  echo "  Got:      $ACTUAL" >&2
  exit 1
fi
echo "==> Checksum verified OK ($ACTUAL)"

# Install binary
install -m 0755 "$TMP_BINARY" "$INSTALL_PATH"
echo "==> Binary installed to $INSTALL_PATH"

# ---------------------------------------------------------------------------
# Provision (writes key + config to /etc/certhound/) — only in managed mode
# ---------------------------------------------------------------------------

if [[ -n "$KEY" ]]; then
  echo "==> Provisioning agent..."
  "$INSTALL_PATH" --provision --key "$KEY" --endpoint "$ENDPOINT"
else
  echo "==> Skipping provisioning (standalone mode)."
fi

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
if [[ -z "$KEY" ]]; then
  echo ""
  echo "    Running in standalone mode. To connect to the dashboard later:"
  echo "    certhound-agent --provision --key ch_xxx --endpoint https://api.certhound.dev/v1/ingest"
  echo "    systemctl restart $SERVICE_NAME"
fi
