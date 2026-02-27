#!/usr/bin/env bash
set -euo pipefail

# Lockwave Daemon Installer
# Usage: curl -fsSL https://lockwave.io/install.sh | sudo bash -s -- \
#   --token <enrollment_token> \
#   --api-url <api_url> \
#   --os-user deploy[,user2,...] \
#   [--authorized-keys-path /path1[,/path2,...]] \
#   [--poll-seconds 60]
# Installs binary, registers host, writes config, and starts systemd service (no further steps).

BINARY_URL="${LOCKWAVE_BINARY_URL:-https://releases.lockwave.io/lockwaved/latest}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/lockwave"

# Parse arguments
TOKEN=""
API_URL=""
OS_USER=""
AUTHORIZED_KEYS_PATH=""
POLL_SECONDS=60

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            TOKEN="$2"; shift 2 ;;
        --api-url)
            API_URL="$2"; shift 2 ;;
        --os-user)
            OS_USER="$2"; shift 2 ;;
        --authorized-keys-path)
            AUTHORIZED_KEYS_PATH="$2"; shift 2 ;;
        --poll-seconds)
            POLL_SECONDS="$2"; shift 2 ;;
        *)
            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Default API URL if not provided
API_URL="${API_URL:-https://lockwave.io}"

if [[ -z "$TOKEN" || -z "$OS_USER" ]]; then
    echo "Error: --token and --os-user are required (--api-url defaults to https://lockwave.io)" >&2
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

echo "==> Installing lockwaved (${OS}/${ARCH})..."

# Download binary
DOWNLOAD_URL="${BINARY_URL}/lockwaved-${OS}-${ARCH}"
curl -fsSL "$DOWNLOAD_URL" -o "${INSTALL_DIR}/lockwaved"
chmod +x "${INSTALL_DIR}/lockwaved"

echo "==> Binary installed to ${INSTALL_DIR}/lockwaved"

# Create config directory
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Register with server
echo "==> Registering with Lockwave server..."
REGISTER_ARGS=(
    --token "$TOKEN"
    --api-url "$API_URL"
    --os-user "$OS_USER"
    --poll-seconds "$POLL_SECONDS"
    --config "${CONFIG_DIR}/config.yaml"
)
[[ -n "$AUTHORIZED_KEYS_PATH" ]] && REGISTER_ARGS+=(--authorized-keys-path "$AUTHORIZED_KEYS_PATH")

"${INSTALL_DIR}/lockwaved" register "${REGISTER_ARGS[@]}"

# Install systemd unit
if command -v systemctl &>/dev/null; then
    echo "==> Installing systemd service..."
    cat > /etc/systemd/system/lockwaved.service << 'UNIT'
[Unit]
Description=Lockwave SSH Key Management Daemon
Documentation=https://lockwave.io/docs/daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lockwaved run --config /etc/lockwave/config.yaml
Restart=always
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=no
ReadWritePaths=/home /etc/lockwave
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lockwaved

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable lockwaved
    systemctl start lockwaved

    echo "==> lockwaved service enabled and started"
    echo "    Check status: systemctl status lockwaved"
    echo "    View logs:    journalctl -u lockwaved -f"
else
    echo "==> systemd not found. Start manually: lockwaved run"
fi

echo "==> Installation complete!"
