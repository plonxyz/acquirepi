#!/bin/bash
#
# acquirepi Agent - Uninstall Script
# Removes the agent client and service
#
# Usage: sudo bash uninstall-agent.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/usr/local/bin"
AGENT_SCRIPT="acquirepi-agent.py"
SERVICE_FILE="acquirepi-agent.service"
VENV_DIR="/opt/acquirepi-agent-venv"

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

echo "=========================================="
echo "  acquirepi Agent - Uninstall"
echo "=========================================="
echo

read -p "Remove agent and all associated files? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

# Stop service
log_info "Stopping service..."
systemctl stop $SERVICE_FILE || true
systemctl disable $SERVICE_FILE || true

# Remove systemd service
log_info "Removing systemd service..."
rm -f /etc/systemd/system/$SERVICE_FILE
systemctl daemon-reload

# Remove agent script
log_info "Removing agent script..."
rm -f $INSTALL_DIR/$AGENT_SCRIPT

# Remove imaging scripts
log_info "Removing imaging scripts..."
rm -f $INSTALL_DIR/disk_mount.sh
rm -f $INSTALL_DIR/nfs-imager.sh
rm -f $INSTALL_DIR/s3-imager.sh
rm -f $INSTALL_DIR/imager.sh
rm -f $INSTALL_DIR/usb-handler.sh

# Remove USB handler service
log_info "Removing USB handler service..."
systemctl stop usb-handler.service || true
systemctl disable usb-handler.service || true
rm -f /etc/systemd/system/usb-handler.service
systemctl daemon-reload

# Remove virtual environment
log_info "Removing virtual environment..."
rm -rf $VENV_DIR

# Remove udev rules
log_info "Removing USB udev rules..."
rm -f /etc/udev/rules.d/51-android.rules
rm -f /etc/udev/rules.d/39-usbmuxd.rules
rm -f /etc/udev/rules.d/99-automount.rules
udevadm control --reload-rules

log_success "Uninstall complete"
echo
echo "System dependencies (Python, ADB, libimobiledevice) were left installed."
echo "Remove them manually if desired."
