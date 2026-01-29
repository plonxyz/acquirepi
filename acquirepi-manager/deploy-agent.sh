#!/bin/bash
# Script to deploy the acquirepi agent to a acquirepi device

set -e

echo "acquirepi Agent Deployment Script"
echo "==============================="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y python3 python3-pip

pip3 install requests zeroconf pyyaml

# Copy agent script
echo "Installing agent script..."
cp acquirepi-agent.py /usr/local/bin/
chmod +x /usr/local/bin/acquirepi-agent.py

# Install systemd service
echo "Installing systemd service..."
cp acquirepi-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable acquirepi-agent.service

echo
echo "Installation complete!"
echo
echo "To start the agent, run:"
echo "  systemctl start acquirepi-agent.service"
echo
echo "To view agent logs, run:"
echo "  journalctl -u acquirepi-agent.service -f"
echo
