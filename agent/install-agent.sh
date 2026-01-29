#!/bin/bash
#
# acquirepi Agent - Installation Script
# Installs the agent client on Raspberry Pi forensic imaging devices
#
# Usage: sudo bash install-agent.sh [--manager-url URL]
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/bin"
AGENT_SCRIPT="acquirepi-agent.py"
SERVICE_FILE="acquirepi-agent.service"
PYTHON_VERSION="python3"
MANAGER_URL=""
VENV_DIR="/opt/acquirepi-agent-venv"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --manager-url)
            MANAGER_URL="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect if running on Raspberry Pi
detect_hardware() {
    log_info "Detecting hardware..."

    if [[ -f /proc/cpuinfo ]]; then
        if grep -q "Raspberry Pi" /proc/cpuinfo; then
            HARDWARE="Raspberry Pi"
            log_success "Detected: Raspberry Pi"
        else
            HARDWARE="Generic Linux"
            log_warning "Not a Raspberry Pi, continuing anyway..."
        fi
    else
        HARDWARE="Unknown"
        log_warning "Cannot detect hardware"
    fi
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq

    # Core dependencies
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        git \
        curl \
        wget \
        usbutils \
        pciutils \
        avahi-utils

    # Mobile forensics dependencies
    log_info "Installing mobile forensics tools..."

    # iOS dependencies (libimobiledevice)
    # Note: Package names vary by distribution version
    apt-get install -y -qq \
        libimobiledevice-utils \
        usbmuxd \
        libplist-utils \
        ideviceinstaller \
        ifuse || log_warning "Some iOS tools may not be available (will use pymobiledevice3)"

    # Build dependencies for pymobiledevice3
    apt-get install -y -qq \
        libusb-1.0-0 \
        libusb-1.0-0-dev \
        libssl-dev \
        libffi-dev

    # Disk imaging tools
    apt-get install -y -qq \
        libewf2 \
        libewf-dev \
        ewf-tools \
        pv \
        pigz

    # Network/storage tools
    apt-get install -y -qq \
        nfs-common \
        cifs-utils \
        wireguard \
        wireguard-tools

    # Optional: LCD display support (for acquirepi hardware)
    apt-get install -y -qq \
        python3-smbus \
        i2c-tools || log_warning "I2C tools not available (LCD support may not work)"

    # Install yq for YAML parsing in imaging scripts
    log_info "Installing yq (YAML processor)..."
    YQ_VERSION="v4.40.5"
    YQ_BINARY="yq_linux_arm64"

    # Detect architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" == "aarch64" ]]; then
        YQ_BINARY="yq_linux_arm64"
    elif [[ "$ARCH" == "armv7l" ]] || [[ "$ARCH" == "armv6l" ]]; then
        YQ_BINARY="yq_linux_arm"
    elif [[ "$ARCH" == "x86_64" ]]; then
        YQ_BINARY="yq_linux_amd64"
    fi

    wget -q "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BINARY}" -O /usr/local/bin/yq
    chmod +x /usr/local/bin/yq

    if [[ -x /usr/local/bin/yq ]]; then
        log_success "yq installed: $(/usr/local/bin/yq --version)"
    else
        log_warning "yq installation may have failed"
    fi

    log_success "System dependencies installed"
}

# Setup Python virtual environment
setup_venv() {
    log_info "Creating Python virtual environment..."

    if [[ -d "$VENV_DIR" ]]; then
        log_warning "Virtual environment exists, recreating..."
        rm -rf "$VENV_DIR"
    fi

    $PYTHON_VERSION -m venv $VENV_DIR

    # Upgrade pip
    $VENV_DIR/bin/pip install --upgrade pip setuptools wheel

    log_success "Virtual environment created"
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."

    # Core dependencies (--ignore-installed avoids conflicts with system packages)
    $VENV_DIR/bin/pip install --ignore-installed \
        requests \
        pyyaml \
        zeroconf \
        websocket-client

    # iOS mobile forensics
    log_info "Installing pymobiledevice3 (this may take a while)..."
    $VENV_DIR/bin/pip install --ignore-installed pymobiledevice3

    # Optional: LCD display
    $VENV_DIR/bin/pip install --ignore-installed smbus2 RPLCD || log_warning "LCD libraries not installed"

    log_success "Python dependencies installed"
}

# Discover manager via mDNS
discover_manager() {
    if [[ -n "$MANAGER_URL" ]]; then
        log_info "Using provided manager URL: $MANAGER_URL"
        return
    fi

    log_info "Attempting to discover manager via mDNS..."

    # Try to find _acquirepi._tcp service
    if command -v avahi-browse &> /dev/null; then
        MDNS_RESULT=$(timeout 10 avahi-browse -t _acquirepi._tcp -r -p 2>/dev/null | grep "^=" | head -n1 || true)

        if [[ -n "$MDNS_RESULT" ]]; then
            # Parse mDNS result: =;eth0;IPv4;acquirepi-manager;_acquirepi._tcp;local;manager.local;192.168.1.100;8000;
            MANAGER_IP=$(echo "$MDNS_RESULT" | cut -d';' -f8)
            MANAGER_PORT=$(echo "$MDNS_RESULT" | cut -d';' -f9)
            MANAGER_URL="http://$MANAGER_IP:$MANAGER_PORT"
            log_success "Discovered manager at: $MANAGER_URL"
        else
            log_warning "mDNS discovery failed"
        fi
    else
        log_warning "avahi-browse not available"
    fi

    # If still no manager URL, ask user
    if [[ -z "$MANAGER_URL" ]]; then
        echo
        log_info "mDNS discovery did not find a manager"
        log_info "The agent will use mDNS discovery at runtime, but you can configure a fallback URL"
        echo
        read -p "Enter fallback manager URL (or press Enter to skip): " MANAGER_URL

        if [[ -z "$MANAGER_URL" ]]; then
            log_warning "No fallback URL configured - agent will rely on mDNS discovery only"
            MANAGER_URL=""
        else
            log_success "Fallback URL set to: $MANAGER_URL"
        fi
    fi
}

# Install agent script
install_agent() {
    log_info "Installing agent script..."

    if [[ ! -f "$AGENT_SCRIPT" ]]; then
        log_error "Agent script not found: $AGENT_SCRIPT"
        log_error "Please ensure $AGENT_SCRIPT is in the current directory"
        exit 1
    fi

    # Update fallback URL in agent script
    if [[ -n "$MANAGER_URL" ]]; then
        log_info "Configuring fallback manager URL: $MANAGER_URL"
        sed -i "s|fallback_url = \".*\"|fallback_url = \"$MANAGER_URL\"|" "$AGENT_SCRIPT"
    else
        log_info "No fallback URL - removing fallback from agent"
        sed -i "s|fallback_url = \".*\"|fallback_url = None|" "$AGENT_SCRIPT"
    fi

    cp "$AGENT_SCRIPT" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$AGENT_SCRIPT"

    log_success "Agent script installed to $INSTALL_DIR/$AGENT_SCRIPT"
}

# Install imaging scripts
install_imaging_scripts() {
    log_info "Installing forensic imaging scripts..."

    # Check if scripts directory exists
    if [[ -d "scripts" ]]; then
        # Copy all imaging scripts to /usr/local/bin
        for script in scripts/*.sh; do
            if [[ -f "$script" ]]; then
                cp "$script" "$INSTALL_DIR/"
                chmod +x "$INSTALL_DIR/$(basename $script)"
                log_info "Installed: $(basename $script)"
            fi
        done
        log_success "Imaging scripts installed"
    else
        log_warning "Scripts directory not found - skipping imaging scripts"
        log_info "The agent will work but standalone imaging scripts won't be available"
    fi
}

# Install system init service for LED/LCD feedback
install_system_init() {
    log_info "Installing system init service..."

    # Install system init service (LED blink, LCD init, wireguard, etc.)
    if [[ -f "etc/systemd/system/systeminit.service" ]]; then
        cp etc/systemd/system/systeminit.service /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable systeminit.service
        log_success "System init service installed"
    else
        log_warning "systeminit.service not found - skipping"
    fi

    # NOTE: usb-handler and 99-automount.rules are NOT installed
    # The agent handles standalone/airgap mode directly via check_usb_config_stick()
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."

    cat > /etc/systemd/system/$SERVICE_FILE <<EOF
[Unit]
Description=acquirepi Agent - Forensic Imaging Agent Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$VENV_DIR/bin/python3 $INSTALL_DIR/$AGENT_SCRIPT
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service installed"
}

# Configure USB permissions for iOS devices
enable_usb() {
    log_info "Configuring USB permissions..."

    # Add udev rules for iOS devices
    cat > /etc/udev/rules.d/39-usbmuxd.rules <<'EOF'
# iOS devices (usbmuxd)
SUBSYSTEM=="usb", ATTR{idVendor}=="05ac", ATTR{idProduct}=="12[9a][0-9a-f]", MODE="0666", GROUP="plugdev"
EOF

    udevadm control --reload-rules
    udevadm trigger

    # Ensure plugdev group exists
    groupadd -f plugdev

    # Start usbmuxd for iOS
    systemctl enable usbmuxd || true
    systemctl start usbmuxd || true

    log_success "USB permissions configured"
}

# Start service
start_service() {
    log_info "Starting acquirepi agent service..."

    systemctl enable $SERVICE_FILE
    systemctl start $SERVICE_FILE

    log_success "Service started"
}

# Show status
show_status() {
    echo
    echo "=========================================="
    echo "  acquirepi Agent Installation Complete"
    echo "=========================================="
    echo
    log_success "Agent installed: $INSTALL_DIR/$AGENT_SCRIPT"
    log_success "Virtual environment: $VENV_DIR"
    log_success "Manager URL: $MANAGER_URL"
    echo
    echo "Service status:"
    systemctl status $SERVICE_FILE --no-pager -l || true
    echo
    echo "View logs:"
    echo "  sudo journalctl -u $SERVICE_FILE -f"
    echo
    echo "The agent should now register with the manager."
    echo "Approve it in the manager web interface."
    echo
}

# Main installation flow
main() {
    echo "=========================================="
    echo "  acquirepi Agent - Installation Script"
    echo "=========================================="
    echo

    check_root
    detect_hardware
    install_dependencies
    setup_venv
    install_python_deps
    discover_manager
    install_agent
    install_imaging_scripts
    install_system_init
    install_systemd_service
    enable_usb
    start_service
    show_status

    log_success "Installation completed successfully!"
}

# Run main installation
main
