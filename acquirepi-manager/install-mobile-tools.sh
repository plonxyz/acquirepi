#!/bin/bash
#
# Install mobile forensics tools for iOS/Android extraction
# Installs libimobiledevice and ADB on both manager and agents
#

set -e

echo "============================================"
echo "acquirepi Mobile Forensics Tools Installer"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "[1/4] Updating package lists..."
apt-get update -qq

echo "[2/4] Installing libimobiledevice (iOS support)..."
# libimobiledevice - communicate with iOS devices
# usbmuxd - USB multiplexer daemon for iOS
# libimobiledevice-utils - command-line tools (ideviceinfo, idevicebackup2, etc.)
# ideviceinstaller - install/uninstall apps on iOS devices

# Try newer package name first (Debian 13/Trixie), fall back to older (Debian 12/Bookworm)
if apt-cache show libimobiledevice-1.0-6 >/dev/null 2>&1; then
    LIBIMOBILE_PKG="libimobiledevice-1.0-6"
elif apt-cache show libimobiledevice6 >/dev/null 2>&1; then
    LIBIMOBILE_PKG="libimobiledevice6"
else
    echo "ERROR: libimobiledevice not found in repositories"
    exit 1
fi

apt-get install -y \
    $LIBIMOBILE_PKG \
    libimobiledevice-utils \
    usbmuxd \
    ideviceinstaller \
    ifuse \
    libplist-utils

echo "[3/4] Installing ADB (Android support)..."
# android-tools-adb - Android Debug Bridge
# android-tools-fastboot - Android fastboot protocol
apt-get install -y \
    android-tools-adb \
    android-tools-fastboot

echo "[4/4] Installing Python dependencies..."
# Python libraries for mobile forensics
# Install in virtual environment if available
if [ -d "/opt/acquirepi-manager/venv" ]; then
    echo "  Installing in virtual environment..."
    /opt/acquirepi-manager/venv/bin/pip install --quiet \
        pymobiledevice3 \
        biplist || echo "  Note: Some Python packages may already be included"
else
    echo "  No virtual environment found, skipping Python packages"
fi

echo ""
echo "============================================"
echo "Installation Complete!"
echo "============================================"
echo ""
echo "Installed tools:"
echo "  iOS:"
echo "    - libimobiledevice (USB communication)"
echo "    - idevice_id (list connected devices)"
echo "    - ideviceinfo (get device information)"
echo "    - idevicebackup2 (create backups)"
echo "    - ideviceinstaller (manage apps)"
echo "    - ifuse (mount iOS file system)"
echo ""
echo "  Android:"
echo "    - adb (Android Debug Bridge)"
echo "    - fastboot (bootloader communication)"
echo ""
echo "Testing iOS tools..."
echo "Connected iOS devices:"
idevice_id -l || echo "  No iOS devices connected"
echo ""
echo "Testing Android tools..."
echo "Connected Android devices:"
adb devices || echo "  ADB not initialized yet"
echo ""
echo "Installation successful! Ready for mobile device forensics."
