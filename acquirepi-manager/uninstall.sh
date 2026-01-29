#!/bin/bash
################################################################################
# acquirepi Manager - Uninstall Script
#
# This script removes the acquirepi Manager installation
#
# Usage: sudo ./uninstall.sh [--purge]
#
# Options:
#   --purge    Remove all data including database and logs
################################################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default configuration
INSTALL_DIR="/opt/acquirepi-manager"
SERVICE_USER="acquirepi"
PURGE_DATA="no"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "${RED}================================${NC}"
    echo -e "${RED}$1${NC}"
    echo -e "${RED}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo "  $1"
}

################################################################################
# Parse Arguments
################################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        --purge)
            PURGE_DATA="yes"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: sudo ./uninstall.sh [--purge]"
            exit 1
            ;;
    esac
done

################################################################################
# Pre-flight Checks
################################################################################

print_header "acquirepi Manager Uninstallation"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root (use sudo)"
    exit 1
fi

# Confirm uninstallation
echo ""
print_warning "This will remove acquirepi Manager from your system"
if [ "$PURGE_DATA" = "yes" ]; then
    print_warning "Data purge enabled: All databases and logs will be removed!"
fi
echo ""
read -p "Are you sure you want to continue? (type 'yes' to confirm): " -r
if [[ ! $REPLY = "yes" ]]; then
    echo "Uninstallation cancelled"
    exit 0
fi

################################################################################
# Stop Services
################################################################################

print_header "Stopping Services"

if systemctl is-active --quiet acquirepi-manager.service; then
    print_info "Stopping acquirepi-manager service..."
    systemctl stop acquirepi-manager.service
    print_success "Service stopped"
fi

if systemctl is-active --quiet acquirepi-mdns.service; then
    print_info "Stopping acquirepi-mdns service..."
    systemctl stop acquirepi-mdns.service
    print_success "Service stopped"
fi

################################################################################
# Disable Services
################################################################################

print_header "Disabling Services"

if systemctl is-enabled --quiet acquirepi-manager.service 2>/dev/null; then
    print_info "Disabling acquirepi-manager service..."
    systemctl disable acquirepi-manager.service
    print_success "Service disabled"
fi

if systemctl is-enabled --quiet acquirepi-mdns.service 2>/dev/null; then
    print_info "Disabling acquirepi-mdns service..."
    systemctl disable acquirepi-mdns.service
    print_success "Service disabled"
fi

################################################################################
# Remove Services
################################################################################

print_header "Removing Service Files"

if [ -f /etc/systemd/system/acquirepi-manager.service ]; then
    print_info "Removing acquirepi-manager.service..."
    rm -f /etc/systemd/system/acquirepi-manager.service
    print_success "Service file removed"
fi

if [ -f /etc/systemd/system/acquirepi-mdns.service ]; then
    print_info "Removing acquirepi-mdns.service..."
    rm -f /etc/systemd/system/acquirepi-mdns.service
    print_success "Service file removed"
fi

systemctl daemon-reload

################################################################################
# Remove Application
################################################################################

print_header "Removing Application Files"

if [ -d "$INSTALL_DIR" ]; then
    if [ "$PURGE_DATA" = "yes" ]; then
        print_info "Removing all files including data..."
        rm -rf "$INSTALL_DIR"
        print_success "Application and data removed"
    else
        print_info "Removing application (preserving data)..."
        # Backup data
        mkdir -p /tmp/acquirepi-backup
        if [ -f "$INSTALL_DIR/db.sqlite3" ]; then
            cp "$INSTALL_DIR/db.sqlite3" /tmp/acquirepi-backup/
        fi
        if [ -d "$INSTALL_DIR/logs" ]; then
            cp -r "$INSTALL_DIR/logs" /tmp/acquirepi-backup/
        fi
        if [ -f "$INSTALL_DIR/.db_credentials" ]; then
            cp "$INSTALL_DIR/.db_credentials" /tmp/acquirepi-backup/
        fi

        rm -rf "$INSTALL_DIR"
        print_success "Application removed (data backed up to /tmp/acquirepi-backup)"
    fi
else
    print_info "Installation directory not found, skipping..."
fi

################################################################################
# Database Cleanup
################################################################################

if [ "$PURGE_DATA" = "yes" ]; then
    print_header "Removing Database"

    # Check if PostgreSQL database exists
    if command -v psql &> /dev/null; then
        if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw acquirepi_manager; then
            print_info "Dropping PostgreSQL database..."
            sudo -u postgres psql -c "DROP DATABASE IF EXISTS acquirepi_manager;"
            sudo -u postgres psql -c "DROP USER IF EXISTS acquirepi_user;"
            print_success "PostgreSQL database removed"
        fi
    fi
fi

################################################################################
# User Cleanup
################################################################################

print_header "User Cleanup"

if id "$SERVICE_USER" &>/dev/null; then
    read -p "Remove service user '$SERVICE_USER'? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Removing user $SERVICE_USER..."
        userdel -r $SERVICE_USER 2>/dev/null || userdel $SERVICE_USER
        print_success "User removed"
    else
        print_info "User preserved"
    fi
fi

################################################################################
# Firewall Cleanup
################################################################################

print_header "Firewall Cleanup"

if command -v ufw &> /dev/null; then
    read -p "Remove firewall rules for acquirepi Manager? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Removing firewall rules..."
        ufw delete allow 8000/tcp 2>/dev/null || true
        ufw delete allow 5353/udp 2>/dev/null || true
        print_success "Firewall rules removed"
    else
        print_info "Firewall rules preserved"
    fi
fi

################################################################################
# Optional Package Removal
################################################################################

print_header "Optional Package Removal"

echo ""
print_info "The following packages were installed by acquirepi Manager:"
echo "  - redis-server"
echo "  - postgresql (if production mode was used)"
echo "  - avahi-daemon"
echo ""
read -p "Remove these packages? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Removing packages..."
    apt-get remove -y redis-server avahi-daemon avahi-utils
    apt-get autoremove -y
    print_success "Packages removed"
else
    print_info "Packages preserved (may be used by other applications)"
fi

################################################################################
# Summary
################################################################################

print_header "Uninstallation Complete"

echo ""
echo "acquirepi Manager has been removed from your system."
echo ""

if [ "$PURGE_DATA" != "yes" ]; then
    echo "Data has been backed up to: /tmp/acquirepi-backup"
    echo "You can safely delete this directory if you don't need the data."
fi

echo ""
print_success "Uninstallation completed successfully"
