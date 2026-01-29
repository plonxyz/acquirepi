#!/bin/bash

################################################################################
# acquirepi Forensic Imaging System - Unified Installer
#
# This script installs the acquirepi Manager, Agent, or both on Debian-based systems
# (Debian, Ubuntu, Raspberry Pi OS)
#
# Usage:
#   sudo bash install-acquirepi.sh              # Interactive mode
#   sudo bash install-acquirepi.sh --manager    # Install manager only
#   sudo bash install-acquirepi.sh --agent      # Install agent only
#   sudo bash install-acquirepi.sh --all        # Install both
#
# Requirements:
#   - Debian/Ubuntu/Raspberry Pi OS
#   - Root access (sudo)
#   - Internet connection
#   - 4GB+ RAM (Manager), 2GB+ RAM (Agent)
#   - 20GB+ free disk space
#
################################################################################

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

# Version
VERSION="1.0.0"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Installation paths
MANAGER_DIR="/opt/acquirepi-manager"
AGENT_DIR="/usr/local/bin"
AGENT_VENV="/opt/acquirepi-agent-venv"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Installation flags
INSTALL_MANAGER=false
INSTALL_AGENT=false
INTERACTIVE=true
SKIP_SYSTEM_UPDATE=false

# System info
OS_ID=""
OS_VERSION=""
ARCH=""
MEMORY_MB=0
DISK_FREE_GB=0

################################################################################
# Logging Functions
################################################################################

log_header() {
    echo ""
    echo -e "${CYAN}${BOLD}========================================${NC}"
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${CYAN}${BOLD}========================================${NC}"
    echo ""
}

log_step() {
    echo -e "${BLUE}==>${NC} ${BOLD}$1${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_fatal() {
    echo -e "${RED}${BOLD}[FATAL]${NC} $1"
    exit 1
}

################################################################################
# System Detection & Requirements Check
################################################################################

detect_system() {
    log_step "Detecting system information..."

    # Check OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_VERSION=$VERSION_ID
        log_info "OS: $PRETTY_NAME"
    else
        log_fatal "Cannot detect operating system. /etc/os-release not found."
    fi

    # Check if Debian-based
    if [[ ! "$OS_ID" =~ ^(debian|ubuntu|raspbian)$ ]]; then
        log_warning "Detected non-Debian OS: $OS_ID"
        log_warning "This installer is designed for Debian/Ubuntu/Raspberry Pi OS"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Check architecture
    ARCH=$(uname -m)
    log_info "Architecture: $ARCH"

    # Check if Raspberry Pi
    if [ -f /proc/cpuinfo ] && grep -q "Raspberry Pi" /proc/cpuinfo; then
        log_success "Detected Raspberry Pi hardware"
    fi

    # Check memory
    MEMORY_MB=$(free -m | awk '/^Mem:/{print $2}')
    log_info "Memory: ${MEMORY_MB}MB"

    # Check disk space
    DISK_FREE_GB=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    log_info "Free disk space: ${DISK_FREE_GB}GB"

    echo ""
}

check_requirements() {
    log_step "Checking system requirements..."

    local errors=0

    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use: sudo bash install-acquirepi.sh)"
        ((errors++))
    fi

    # Check memory
    if $INSTALL_MANAGER && [ "$MEMORY_MB" -lt 2048 ]; then
        log_warning "Manager requires at least 4GB RAM (detected: ${MEMORY_MB}MB)"
        log_warning "Installation may fail or system may be unstable"
    fi

    if $INSTALL_AGENT && [ "$MEMORY_MB" -lt 1024 ]; then
        log_warning "Agent requires at least 2GB RAM (detected: ${MEMORY_MB}MB)"
    fi

    # Check disk space
    if [ "$DISK_FREE_GB" -lt 10 ]; then
        log_error "Insufficient disk space. Need at least 20GB free (found: ${DISK_FREE_GB}GB)"
        ((errors++))
    fi

    # Check internet connectivity
    if ! ping -c 1 -W 5 8.8.8.8 &> /dev/null; then
        log_error "No internet connection detected"
        log_info "Internet is required to download dependencies"
        ((errors++))
    fi

    # Check if Python 3 is available
    if ! command -v python3 &> /dev/null; then
        log_warning "Python 3 not found. Will be installed."
    else
        local python_version=$(python3 --version 2>&1 | awk '{print $2}')
        log_info "Python version: $python_version"
    fi

    if [ $errors -gt 0 ]; then
        log_fatal "System requirements check failed with $errors error(s)"
    fi

    log_success "System requirements check passed"
    echo ""
}

################################################################################
# Interactive Menu
################################################################################

show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo -e "${BOLD}acquirepi Forensic Imaging System${NC}"
    echo -e "Installer v${VERSION}"
    echo ""
}

show_menu() {
    show_banner

    echo -e "${BOLD}What would you like to install?${NC}"
    echo ""
    echo "  1) Manager Only     - Central web application (Django + PostgreSQL)"
    echo "  2) Agent Only       - Raspberry Pi imaging client"
    echo "  3) Complete System  - Both Manager and Agent (for testing/single machine)"
    echo "  4) Exit"
    echo ""
    read -p "Enter your choice [1-4]: " choice

    case $choice in
        1)
            INSTALL_MANAGER=true
            INSTALL_AGENT=false
            ;;
        2)
            INSTALL_MANAGER=false
            INSTALL_AGENT=true
            ;;
        3)
            INSTALL_MANAGER=true
            INSTALL_AGENT=true
            ;;
        4)
            log_info "Installation cancelled"
            exit 0
            ;;
        *)
            log_error "Invalid choice"
            sleep 2
            show_menu
            ;;
    esac
}

confirm_installation() {
    echo ""
    log_step "Installation Summary"
    echo ""
    echo "  Install Manager: $(if $INSTALL_MANAGER; then echo -e "${GREEN}Yes${NC}"; else echo -e "${RED}No${NC}"; fi)"
    echo "  Install Agent:   $(if $INSTALL_AGENT; then echo -e "${GREEN}Yes${NC}"; else echo -e "${RED}No${NC}"; fi)"
    echo ""
    echo "  Manager Path: $MANAGER_DIR"
    echo "  Agent Path:   $AGENT_DIR"
    echo ""

    read -p "Proceed with installation? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi
}

################################################################################
# Manager Installation
################################################################################

install_manager() {
    log_header "Installing acquirepi Manager"

    # Update system
    if ! $SKIP_SYSTEM_UPDATE; then
        log_step "[1/10] Updating system packages..."
        apt-get update -qq
        apt-get upgrade -y -qq
        log_success "System updated"
    fi

    # Install dependencies
    log_step "[2/10] Installing system dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        postgresql \
        postgresql-contrib \
        redis-server \
        nginx \
        git \
        curl \
        rsync \
        build-essential \
        libpq-dev \
        avahi-daemon \
        avahi-utils \
        libnss-mdns \
        supervisor
    log_success "Dependencies installed"

    # Enable services
    log_step "[3/10] Enabling system services..."
    systemctl enable postgresql --quiet
    systemctl start postgresql
    systemctl enable redis-server --quiet
    systemctl start redis-server
    systemctl enable avahi-daemon --quiet
    systemctl start avahi-daemon
    log_success "Services enabled"

    # Setup installation directory
    log_step "[4/10] Setting up installation directory..."
    if [ -d "$MANAGER_DIR" ]; then
        log_warning "Manager already installed at $MANAGER_DIR"
        read -p "Backup and reinstall? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            BACKUP_DIR="$MANAGER_DIR-backup-$(date +%Y%m%d_%H%M%S)"
            log_info "Backing up to $BACKUP_DIR"
            cp -r "$MANAGER_DIR" "$BACKUP_DIR"
            rm -rf "$MANAGER_DIR"
        else
            log_fatal "Installation cancelled"
        fi
    fi
    mkdir -p "$MANAGER_DIR"

    # Copy application files
    if [ ! -f "$SOURCE_DIR/acquirepi-manager/manage.py" ]; then
        log_fatal "Manager source files not found in $SOURCE_DIR/acquirepi-manager/"
    fi

    log_info "Copying application files..."
    rsync -a --exclude='*.pyc' --exclude='__pycache__' --exclude='venv' \
        "$SOURCE_DIR/acquirepi-manager/" "$MANAGER_DIR/"
    log_success "Files copied"

    # Create virtual environment
    log_step "[5/10] Creating Python virtual environment..."
    cd "$MANAGER_DIR"
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
    log_success "Virtual environment created"

    # Setup database
    log_step "[6/10] Configuring PostgreSQL database..."
    sudo -u postgres psql -c "CREATE DATABASE forensics;" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE USER acquirepi WITH PASSWORD 'forensics';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER ROLE acquirepi SET client_encoding TO 'utf8';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER ROLE acquirepi SET default_transaction_isolation TO 'read committed';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER ROLE acquirepi SET timezone TO 'UTC';" 2>/dev/null || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE forensics TO acquirepi;" 2>/dev/null || true
    log_success "Database configured"

    # Run migrations
    log_step "[7/10] Running database migrations..."
    python manage.py migrate --noinput
    log_success "Migrations completed"

    # Collect static files
    log_step "[8/10] Collecting static files..."
    python manage.py collectstatic --noinput -c
    log_success "Static files collected"

    # Create systemd service
    log_step "[9/10] Installing systemd service..."
    cat > /etc/systemd/system/acquirepi-manager.service << EOF
[Unit]
Description=acquirepi Manager ASGI Server
After=network.target postgresql.service redis.service
Requires=postgresql.service redis.service

[Service]
Type=simple
User=root
WorkingDirectory=$MANAGER_DIR
Environment="PATH=$MANAGER_DIR/venv/bin"
ExecStart=$MANAGER_DIR/venv/bin/daphne -b 0.0.0.0 -p 8000 manager.asgi:application
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # mDNS service
    cat > /etc/systemd/system/acquirepi-mdns.service << EOF
[Unit]
Description=acquirepi mDNS Service Advertisement
After=network.target avahi-daemon.service acquirepi-manager.service
Requires=avahi-daemon.service

[Service]
Type=simple
User=root
WorkingDirectory=$MANAGER_DIR
Environment="PATH=$MANAGER_DIR/venv/bin"
ExecStart=$MANAGER_DIR/venv/bin/python manage.py mdns_advertise
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable acquirepi-manager --quiet
    systemctl enable acquirepi-mdns --quiet
    systemctl start acquirepi-manager
    systemctl start acquirepi-mdns
    log_success "Services installed and started"

    # Create superuser
    log_step "[10/10] Creating admin user..."
    echo ""
    echo -e "${YELLOW}Please create an admin user for the web interface:${NC}"
    python manage.py createsuperuser

    log_success "Manager installation complete!"
    echo ""
    log_info "Manager is now running at: http://$(hostname -I | awk '{print $1}'):8000"
    log_info "mDNS service name: http://$(hostname).local:8000"
    echo ""
}

################################################################################
# Agent Installation
################################################################################

install_agent() {
    log_header "Installing acquirepi Agent"

    # Update system
    if ! $SKIP_SYSTEM_UPDATE; then
        log_step "[1/8] Updating system packages..."
        apt-get update -qq
        log_success "System updated"
    fi

    # Install dependencies
    log_step "[2/8] Installing system dependencies..."
    export DEBIAN_FRONTEND=noninteractive
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
        avahi-daemon \
        avahi-utils \
        libnss-mdns \
        ewf-tools \
        nfs-common \
        libimobiledevice-utils \
        libusbmuxd-tools \
        usbmuxd \
        i2c-tools \
        python3-smbus

    # NOTE: Android/ADB support not implemented - removed to avoid unnecessary dependencies

    # Install yq (YAML processor) - not in apt repos
    if ! command -v yq &> /dev/null; then
        log_info "Installing yq..."
        YQ_VERSION="v4.40.5"
        case $(uname -m) in x86_64) YQ_ARCH="amd64";; aarch64) YQ_ARCH="arm64";; armv7l) YQ_ARCH="arm";; *) YQ_ARCH="amd64";; esac
        wget -qO /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${YQ_ARCH}" && chmod +x /usr/local/bin/yq || log_warning "Failed to install yq"
    fi

    log_success "Dependencies installed"

    # Enable Avahi
    log_step "[3/8] Enabling mDNS/Avahi..."
    systemctl enable avahi-daemon --quiet
    systemctl start avahi-daemon
    log_success "Avahi enabled"

    # Create virtual environment
    log_step "[4/8] Creating Python virtual environment..."
    if [ -d "$AGENT_VENV" ]; then
        rm -rf "$AGENT_VENV"
    fi
    python3 -m venv "$AGENT_VENV"
    source "$AGENT_VENV/bin/activate"
    pip install --upgrade pip -q
    pip install requests pyyaml zeroconf psutil pymobiledevice3 smbus2 -q
    log_success "Virtual environment created"

    # Install agent script
    log_step "[5/8] Installing agent script..."
    if [ ! -f "$SOURCE_DIR/agent/acquirepi-agent.py" ]; then
        log_fatal "Agent source files not found in $SOURCE_DIR/agent/"
    fi

    cp "$SOURCE_DIR/agent/acquirepi-agent.py" "$AGENT_DIR/"
    chmod +x "$AGENT_DIR/acquirepi-agent.py"

    # Install imaging scripts
    if [ -d "$SOURCE_DIR/agent/scripts" ]; then
        cp "$SOURCE_DIR/agent/scripts/"* "$AGENT_DIR/" 2>/dev/null || true
        chmod +x "$AGENT_DIR/"*.sh 2>/dev/null || true
    fi
    log_success "Agent scripts installed"

    # Create mount points
    log_step "[6/8] Creating mount points..."
    mkdir -p /mnt/usb
    mkdir -p /mnt/destination
    mkdir -p /mnt/nfs-share
    log_success "Mount points created"

    # Install systemd service
    log_step "[7/8] Installing systemd service..."
    cat > /etc/systemd/system/acquirepi-agent.service << EOF
[Unit]
Description=acquirepi Forensic Imaging Agent
After=network-online.target avahi-daemon.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
Environment="PATH=$AGENT_VENV/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=$AGENT_VENV/bin/python3 $AGENT_DIR/acquirepi-agent.py
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable acquirepi-agent --quiet
    systemctl start acquirepi-agent
    log_success "Service installed and started"

    # Show agent status
    log_step "[8/8] Checking agent status..."
    sleep 3
    if systemctl is-active --quiet acquirepi-agent; then
        log_success "Agent is running"
    else
        log_warning "Agent service failed to start. Check: journalctl -u acquirepi-agent"
    fi

    log_success "Agent installation complete!"
    echo ""
    log_info "Agent will auto-discover the manager via mDNS"
    log_info "Check status with: systemctl status acquirepi-agent"
    log_info "View logs with: sudo journalctl -u acquirepi-agent -f"
    echo ""
}

################################################################################
# Post-Installation
################################################################################

show_next_steps() {
    log_header "Installation Complete!"

    echo -e "${GREEN}${BOLD}Next Steps:${NC}"
    echo ""

    if $INSTALL_MANAGER; then
        echo -e "${BOLD}Manager:${NC}"
        echo "  1. Access web interface: http://$(hostname -I | awk '{print $1}'):8000"
        echo "  2. Login with the admin credentials you created"
        echo "  3. Navigate to Agents section and approve pending agents"
        echo ""
    fi

    if $INSTALL_AGENT; then
        echo -e "${BOLD}Agent:${NC}"
        echo "  1. Agent will auto-discover manager via mDNS"
        echo "  2. Approve the agent in the manager web interface"
        echo "  3. Agent will appear as 'Online' once approved"
        echo ""
    fi

    echo -e "${BOLD}Useful Commands:${NC}"
    if $INSTALL_MANAGER; then
        echo "  Manager status:  sudo systemctl status acquirepi-manager"
        echo "  Manager logs:    sudo journalctl -u acquirepi-manager -f"
        echo "  Restart manager: sudo systemctl restart acquirepi-manager"
        echo ""
    fi

    if $INSTALL_AGENT; then
        echo "  Agent status:  sudo systemctl status acquirepi-agent"
        echo "  Agent logs:    sudo journalctl -u acquirepi-agent -f"
        echo "  Restart agent: sudo systemctl restart acquirepi-agent"
        echo ""
    fi

    echo -e "${BOLD}Documentation:${NC}"
    echo "  README:   $SOURCE_DIR/README.md"
    echo ""

    log_success "Installation successful!"
}

################################################################################
# Main
################################################################################

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --manager)
                INSTALL_MANAGER=true
                INTERACTIVE=false
                shift
                ;;
            --agent)
                INSTALL_AGENT=true
                INTERACTIVE=false
                shift
                ;;
            --all)
                INSTALL_MANAGER=true
                INSTALL_AGENT=true
                INTERACTIVE=false
                shift
                ;;
            --skip-update)
                SKIP_SYSTEM_UPDATE=true
                shift
                ;;
            --help|-h)
                echo "Usage: sudo bash install-acquirepi.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --manager      Install manager only"
                echo "  --agent        Install agent only"
                echo "  --all          Install both manager and agent"
                echo "  --skip-update  Skip system package update"
                echo "  --help         Show this help message"
                echo ""
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Show banner
    if $INTERACTIVE; then
        show_menu
    fi

    # Detect system
    detect_system

    # Check requirements
    check_requirements

    # Confirm
    if $INTERACTIVE; then
        confirm_installation
    fi

    # Install components
    if $INSTALL_MANAGER; then
        install_manager
    fi

    if $INSTALL_AGENT; then
        install_agent
    fi

    # Show next steps
    show_next_steps
}

# Run main function
main "$@"
