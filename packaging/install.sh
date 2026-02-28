#!/usr/bin/env bash
set -euo pipefail

# Lockwave Daemon Installer
# Usage:
#   Fresh install (register + start):
#     curl -fsSL https://lockwave.io/install.sh | sudo bash -s -- \
#       --token <enrollment_token> \
#       --api-url <api_url> \
#       --os-user deploy[,user2,...] \
#       [--authorized-keys-path /path1[,/path2,...]] \
#       [--poll-seconds 60]
#
#   Upgrade existing installation:
#     curl -fsSL https://lockwave.io/install.sh | sudo bash -s -- --upgrade
#
#   Uninstall:
#     curl -fsSL https://lockwave.io/install.sh | sudo bash -s -- --uninstall

BINARY_URL="${LOCKWAVE_BINARY_URL:-https://releases.lockwave.io/lockwaved/latest}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/lockwave"
SERVICE_NAME="lockwaved"

# Parse arguments
TOKEN=""
API_URL=""
OS_USER=""
AUTHORIZED_KEYS_PATH=""
POLL_SECONDS=60
UPGRADE=false
UNINSTALL=false

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
        --upgrade)
            UPGRADE=true; shift ;;
        --uninstall)
            UNINSTALL=true; shift ;;
        *)
            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Default API URL if not provided
API_URL="${API_URL:-https://lockwave.io}"

# Normalize to HTTPS (HTTP→HTTPS redirects convert POST to GET, breaking registration)
if [[ "$API_URL" =~ ^http:// ]] && [[ ! "$API_URL" =~ ^http://(localhost|127\.0\.0\.1) ]]; then
    API_URL="${API_URL/http:\/\//https:\/\/}"
fi

# Detect architecture
detect_platform() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        arm64)   ARCH="arm64" ;;
        *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
}

# Check if lockwaved is already installed
is_installed() {
    [[ -x "${INSTALL_DIR}/${SERVICE_NAME}" ]]
}

# Stop systemd service if running
stop_service() {
    if command -v systemctl &>/dev/null && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "==> Stopping ${SERVICE_NAME} service..."
        systemctl stop "$SERVICE_NAME"
    fi
}

# Start/restart systemd service
start_service() {
    if command -v systemctl &>/dev/null; then
        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME"
        systemctl start "$SERVICE_NAME"
        echo "==> ${SERVICE_NAME} service started"
        echo "    Check status: systemctl status ${SERVICE_NAME}"
        echo "    View logs:    journalctl -u ${SERVICE_NAME} -f"
    else
        echo "==> systemd not found. Start manually: lockwaved run"
    fi
}

# Download and install the binary
install_binary() {
    detect_platform
    echo "==> Downloading lockwaved (${OS}/${ARCH})..."
    DOWNLOAD_URL="${BINARY_URL}/lockwaved-${OS}-${ARCH}"
    curl -fsSL "$DOWNLOAD_URL" -o "${INSTALL_DIR}/${SERVICE_NAME}"
    chmod +x "${INSTALL_DIR}/${SERVICE_NAME}"
    echo "==> Binary installed to ${INSTALL_DIR}/${SERVICE_NAME}"
}

# Install systemd unit file
install_systemd_unit() {
    if command -v systemctl &>/dev/null; then
        echo "==> Installing systemd service..."
        cat > "/etc/systemd/system/${SERVICE_NAME}.service" << 'UNIT'
[Unit]
Description=Lockwave SSH Key Management Daemon
Documentation=https://lockwave.io/docs/daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/lockwaved check --config /etc/lockwave/config.yaml
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
    fi
}

# ── Uninstall ──
if [[ "$UNINSTALL" == "true" ]]; then
    echo "==> Uninstalling lockwaved..."
    stop_service

    if command -v systemctl &>/dev/null; then
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
        echo "==> Removed systemd service"
    fi

    rm -f "${INSTALL_DIR}/${SERVICE_NAME}"
    echo "==> Removed binary"

    # Remove sshd drop-in config
    if [[ -f "/etc/ssh/sshd_config.d/99-lockwave.conf" ]]; then
        rm -f "/etc/ssh/sshd_config.d/99-lockwave.conf"
        echo "==> Removed sshd drop-in config"
        if command -v systemctl &>/dev/null; then
            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
            echo "==> Reloaded sshd"
        fi
    fi

    # Remove config directory (contains credentials)
    rm -rf "$CONFIG_DIR"
    echo "==> Removed config directory (${CONFIG_DIR})"

    echo "==> Uninstall complete! All Lockwave files have been removed."
    exit 0
fi

# ── Upgrade ──
if [[ "$UPGRADE" == "true" ]]; then
    if ! is_installed; then
        echo "Error: lockwaved is not installed. Use a fresh install instead." >&2
        exit 1
    fi

    echo "==> Upgrading lockwaved..."
    CURRENT_VERSION=$("${INSTALL_DIR}/${SERVICE_NAME}" version 2>/dev/null || echo "unknown")
    echo "    Current: ${CURRENT_VERSION}"

    stop_service
    install_binary

    NEW_VERSION=$("${INSTALL_DIR}/${SERVICE_NAME}" version 2>/dev/null || echo "unknown")
    echo "    New:     ${NEW_VERSION}"

    start_service
    echo "==> Upgrade complete!"
    exit 0
fi

# ── Fresh Install ──
if [[ -z "$TOKEN" || -z "$OS_USER" ]]; then
    echo "Error: --token and --os-user are required for fresh install (or use --upgrade / --uninstall)" >&2
    echo ""
    echo "Usage:"
    echo "  Fresh install:  install.sh --token <token> --os-user <user>"
    echo "  Upgrade:        install.sh --upgrade"
    echo "  Uninstall:      install.sh --uninstall"
    exit 1
fi

# Warn if already installed
if is_installed; then
    echo "==> lockwaved is already installed. Stopping existing service for re-install..."
    stop_service
fi

install_binary

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

"${INSTALL_DIR}/${SERVICE_NAME}" register "${REGISTER_ARGS[@]}"

install_systemd_unit
start_service

echo "==> Installation complete!"
