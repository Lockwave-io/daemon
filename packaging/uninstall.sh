#!/usr/bin/env bash
set -euo pipefail

# Lockwave Daemon Uninstaller
# One-liner: curl -fsSL https://lockwave.io/uninstall.sh | sudo bash
#
# Options:
#   --yes, -y   Skip all confirmation prompts (fully automatic)

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/lockwave"
SERVICE_NAME="lockwaved"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN_FILE="99-lockwave.conf"

AUTO_YES=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)
            AUTO_YES=true; shift ;;
        *)
            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

is_installed() {
    [[ -x "${INSTALL_DIR}/${SERVICE_NAME}" ]] || \
    [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] || \
    [[ -d "$CONFIG_DIR" ]] || \
    [[ -f "${SSHD_DROPIN_DIR}/${SSHD_DROPIN_FILE}" ]]
}

stop_service() {
    if command -v systemctl &>/dev/null && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "==> Stopping ${SERVICE_NAME} service..."
        systemctl stop "$SERVICE_NAME"
    fi
}

echo "==> Uninstalling lockwaved..."
if ! is_installed; then
    echo "==> lockwaved is not installed. Nothing to do."
    exit 0
fi

# Stop and remove systemd service
stop_service

if command -v systemctl &>/dev/null; then
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    echo "==> Removed systemd service"
fi

# Remove binary
rm -f "${INSTALL_DIR}/${SERVICE_NAME}"
echo "==> Removed binary"

# Remove sshd drop-in config and reload sshd
if [[ -f "${SSHD_DROPIN_DIR}/${SSHD_DROPIN_FILE}" ]]; then
    rm -f "${SSHD_DROPIN_DIR}/${SSHD_DROPIN_FILE}"
    echo "==> Removed sshd drop-in config (${SSHD_DROPIN_FILE})"
    # Reload sshd to apply the removal
    if command -v systemctl &>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        echo "==> Reloaded sshd"
    fi
fi

# Remove config directory (contains credentials)
if [[ -d "$CONFIG_DIR" ]]; then
    if [[ "$AUTO_YES" == "true" ]]; then
        rm -rf "$CONFIG_DIR"
        echo "==> Removed config directory (${CONFIG_DIR})"
    elif [[ -t 0 ]]; then
        read -rp "Remove config directory ${CONFIG_DIR}? (contains host credentials) [Y/n] " confirm
        if [[ ! "${confirm:-}" =~ ^[Nn]$ ]]; then
            rm -rf "$CONFIG_DIR"
            echo "==> Removed config directory"
        else
            echo "==> Config directory preserved at ${CONFIG_DIR}"
        fi
    else
        # Non-interactive: remove everything by default
        rm -rf "$CONFIG_DIR"
        echo "==> Removed config directory (${CONFIG_DIR})"
    fi
fi

echo "==> Uninstall complete! All Lockwave files have been removed."
