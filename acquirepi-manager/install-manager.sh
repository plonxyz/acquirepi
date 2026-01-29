#!/bin/bash

################################################################################
# acquirepi Manager Installation Script
# Installs the acquirepi Manager web application on a fresh Debian/Ubuntu system
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation directory
INSTALL_DIR="/opt/acquirepi-manager"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}acquirepi Manager Installation${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
else
    echo -e "${RED}Error: Cannot detect OS${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS $OS_VERSION${NC}"
echo ""

# Update system
echo -e "${YELLOW}[1/11] Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

# Install system dependencies
echo -e "${YELLOW}[2/11] Installing system dependencies...${NC}"
apt-get install -y \
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
    libnss-mdns

# Enable and start services
echo -e "${YELLOW}[3/11] Enabling system services...${NC}"
systemctl enable postgresql
systemctl start postgresql
systemctl enable redis-server
systemctl start redis-server
systemctl enable avahi-daemon
systemctl start avahi-daemon

# Detect source directory (where this script is located)
SOURCE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Source directory: $SOURCE_DIR"

# Create installation directory if it doesn't exist
echo -e "${YELLOW}[4/11] Setting up installation directory...${NC}"
if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
    echo "Created directory: $INSTALL_DIR"
else
    echo "Directory already exists: $INSTALL_DIR"
fi

# Copy application files if source and destination are different
if [ "$SOURCE_DIR" != "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Copying application files from $SOURCE_DIR to $INSTALL_DIR...${NC}"

    # Check if source has required files
    if [ ! -f "$SOURCE_DIR/manage.py" ]; then
        echo -e "${RED}Error: manage.py not found in source directory: $SOURCE_DIR${NC}"
        echo "Please run this script from the extracted distribution package directory"
        exit 1
    fi

    # Copy files, excluding development/build artifacts
    rsync -av \
        --exclude='.git' \
        --exclude='venv' \
        --exclude='venv.old.*' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='*.pyo' \
        --exclude='db.sqlite3' \
        --exclude='*.log' \
        --exclude='.db_credentials' \
        --exclude='staticfiles' \
        --exclude='*.tar.gz' \
        --exclude='*-filelist.txt' \
        --exclude='*-checksums.txt' \
        --exclude='SESSION_SUMMARY.md' \
        --exclude='TODO_REMAINING_TASKS.md' \
        --exclude='DISTRIBUTION_*.md' \
        "$SOURCE_DIR/" "$INSTALL_DIR/"

    echo "Application files copied successfully"
else
    echo "Source and destination are the same, skipping copy"
fi

cd "$INSTALL_DIR"

# Verify required files exist
if [ ! -f "$INSTALL_DIR/manage.py" ]; then
    echo -e "${RED}Error: manage.py not found after setup${NC}"
    exit 1
fi

# Create acquirepi user
echo -e "${YELLOW}[5/11] Creating acquirepi user...${NC}"
if ! id -u acquirepi > /dev/null 2>&1; then
    useradd -r -s /bin/bash -d "$INSTALL_DIR" -m acquirepi
    echo "Created user: acquirepi"
else
    echo "User acquirepi already exists"
fi

# Set ownership
chown -R acquirepi:acquirepi "$INSTALL_DIR"

# Create Python virtual environment
echo -e "${YELLOW}[6/11] Creating Python virtual environment...${NC}"
if [ ! -d "$INSTALL_DIR/venv" ]; then
    sudo -u acquirepi python3 -m venv "$INSTALL_DIR/venv"
    echo "Virtual environment created"
else
    echo "Virtual environment already exists"
fi

# Install Python dependencies
echo -e "${YELLOW}[7/11] Installing Python dependencies...${NC}"
sudo -u acquirepi "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
sudo -u acquirepi "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Setup PostgreSQL database
echo -e "${YELLOW}[8/11] Setting up PostgreSQL database...${NC}"
DB_NAME="forensic_manager"
DB_USER="forensic_user"
DB_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')

# Create database and user
sudo -u postgres psql <<EOF
-- Create user if not exists
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = '$DB_USER') THEN
    CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
  ELSE
    ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
  END IF;
END
\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE $DB_NAME OWNER $DB_USER'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB_NAME')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
EOF

# Save database credentials
cat > "$INSTALL_DIR/.db_credentials" <<EOF
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_HOST=localhost
DB_PORT=5432
EOF

chmod 600 "$INSTALL_DIR/.db_credentials"
chown acquirepi:acquirepi "$INSTALL_DIR/.db_credentials"

echo "Database created: $DB_NAME"
echo "Database user: $DB_USER"
echo "Database credentials saved to: $INSTALL_DIR/.db_credentials"

# Update Django settings for production
echo -e "${YELLOW}[9/11] Configuring Django settings...${NC}"

# Generate SECRET_KEY
SECRET_KEY=$(openssl rand -base64 50 | tr -d '\n')

# Update settings.py with database credentials
sudo -u acquirepi cat > "$INSTALL_DIR/manager/settings_local.py" <<EOF
# Local settings for production
import os
from pathlib import Path

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '$SECRET_KEY'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['*']  # Update with your domain/IP

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': '$DB_NAME',
        'USER': '$DB_USER',
        'PASSWORD': '$DB_PASSWORD',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

# Static files
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
EOF

# Import local settings in main settings.py if not already done
if ! grep -q "settings_local" "$INSTALL_DIR/manager/settings.py"; then
    echo "" >> "$INSTALL_DIR/manager/settings.py"
    echo "# Import local settings" >> "$INSTALL_DIR/manager/settings.py"
    echo "try:" >> "$INSTALL_DIR/manager/settings.py"
    echo "    from .settings_local import *" >> "$INSTALL_DIR/manager/settings.py"
    echo "except ImportError:" >> "$INSTALL_DIR/manager/settings.py"
    echo "    pass" >> "$INSTALL_DIR/manager/settings.py"
fi

# Run Django migrations
echo -e "${YELLOW}[10/11] Running database migrations...${NC}"
sudo -u acquirepi "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/manage.py" migrate

# Collect static files
echo -e "${YELLOW}Collecting static files...${NC}"
sudo -u acquirepi "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/manage.py" collectstatic --noinput

# Create Django superuser (optional, can be done later)
echo -e "${YELLOW}Creating Django superuser...${NC}"
echo "Please enter superuser credentials (or press Ctrl+C to skip and create later):"
set +e  # Temporarily disable exit on error
sudo -u acquirepi "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/manage.py" createsuperuser
SUPERUSER_EXIT=$?
set -e  # Re-enable exit on error
if [ $SUPERUSER_EXIT -ne 0 ]; then
    echo -e "${YELLOW}Skipped superuser creation. You can create one later with:${NC}"
    echo "  sudo -u acquirepi $INSTALL_DIR/venv/bin/python $INSTALL_DIR/manage.py createsuperuser"
fi

# Install systemd services
echo -e "${YELLOW}[11/11] Installing systemd services...${NC}"

# acquirepi-manager service (Daphne ASGI server)
cat > /etc/systemd/system/acquirepi-manager.service <<EOF
[Unit]
Description=acquirepi Manager ASGI Server
After=network-online.target postgresql.service redis-server.service
Wants=network-online.target

[Service]
Type=simple
User=acquirepi
Group=acquirepi
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/daphne -b 0.0.0.0 -p 8000 manager.asgi:application
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# acquirepi-mdns service (mDNS advertisement)
cat > /etc/systemd/system/acquirepi-mdns.service <<EOF
[Unit]
Description=acquirepi Manager mDNS Service Discovery
After=network-online.target avahi-daemon.service
Wants=network-online.target

[Service]
Type=simple
User=acquirepi
Group=acquirepi
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/manage.py mdns_advertise
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create integrity monitor service
cat > /etc/systemd/system/acquirepi-integrity-monitor.service << 'EOF'
[Unit]
Description=AcquirePi Forensic Integrity Monitor
After=network.target acquirepi-manager.service
Wants=acquirepi-manager.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/acquirepi-manager
ExecStart=/opt/acquirepi-manager/venv/bin/python manage.py integrity_monitor --daemon --quiet
Restart=always
RestartSec=30
StandardOutput=append:/var/log/acquirepi/integrity-monitor.log
StandardError=append:/var/log/acquirepi/integrity-monitor.log

[Install]
WantedBy=multi-user.target
EOF

# Create log directory for integrity monitor
mkdir -p /var/log/acquirepi
chmod 755 /var/log/acquirepi

# Reload systemd and enable services
systemctl daemon-reload
systemctl enable acquirepi-manager.service
systemctl enable acquirepi-mdns.service
systemctl enable acquirepi-integrity-monitor.service

# Start services
systemctl start acquirepi-manager.service
systemctl start acquirepi-mdns.service
systemctl start acquirepi-integrity-monitor.service

# Configure firewall (if ufw is installed)
if command -v ufw &> /dev/null; then
    echo -e "${YELLOW}Configuring firewall...${NC}"
    ufw allow 8000/tcp comment 'acquirepi Manager Web UI'
    ufw allow 5353/udp comment 'acquirepi mDNS'
fi

# Create logs directory
mkdir -p "$INSTALL_DIR/logs"
chown -R acquirepi:acquirepi "$INSTALL_DIR/logs"

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "Manager URL: ${GREEN}http://$(hostname -I | awk '{print $1}'):8000${NC}"
echo ""
echo "To manage the services:"
echo "  sudo systemctl status acquirepi-manager"
echo "  sudo systemctl status acquirepi-mdns"
echo "  sudo systemctl status acquirepi-integrity-monitor"
echo "  sudo systemctl restart acquirepi-manager"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u acquirepi-manager -f"
echo "  sudo journalctl -u acquirepi-mdns -f"
echo "  cat /var/log/acquirepi/integrity-monitor.log"
echo ""
echo "Database credentials: $INSTALL_DIR/.db_credentials"
echo ""
echo -e "${YELLOW}IMPORTANT: Please update ALLOWED_HOSTS in manager/settings_local.py${NC}"
echo ""
