#!/usr/bin/env bash
set -euo pipefail

# Lockwave Daemon Uninstaller
# One-liner: curl -fsSL https://lockwave.io/uninstall.sh | sudo bash [-- -y]
#
# Options:
#   --yes, -y   Remove config directory /etc/lockwave without prompting

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/lockwave"
SERVICE_NAME="lockwaved"

REMOVE_CONFIG=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)
            REMOVE_CONFIG=true; shift ;;
        *)
            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

is_installed() {
    [[ -x "${INSTALL_DIR}/${SERVICE_NAME}" ]] || [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]
}

stop_service() {
    if command -v systemctl &>/dev/null && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "==> Stopping ${SERVICE_NAME} service..."
        systemctl stop "$SERVICE_NAME"
    fi
}

echo "==> Uninstalling lockwaved..."
if ! is_installed; then
    echo "==> lockwaved is not installed (binary and systemd unit missing). Nothing to do."
    exit 0
fi

stop_service

if command -v systemctl &>/dev/null; then
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    echo "==> Removed systemd service"
fi

rm -f "${INSTALL_DIR}/${SERVICE_NAME}"
echo "==> Removed binary"

if [[ -d "$CONFIG_DIR" ]]; then
    if [[ "$REMOVE_CONFIG" == "true" ]]; then
        rm -rf "$CONFIG_DIR"
        echo "==> Removed config directory"
    elif [[ -t 0 ]]; then
        read -rp "Remove config directory ${CONFIG_DIR}? [y/N] " confirm
        if [[ "${confirm:-}" =~ ^[Yy]$ ]]; then
            rm -rf "$CONFIG_DIR"
            echo "==> Removed config directory"
        else
            echo "==> Config directory preserved"
        fi
    else
        echo "==> Config directory preserved (use --yes to remove when non-interactive)"
    fi
fi

echo "==> Uninstall complete!"
