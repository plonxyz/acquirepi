# acquirepi Forensic Imaging System - Installation Guide

## Quick Start

The easiest way to install acquirepi is using the unified installer:

```bash
# Clone or download the repository
cd /home/pi/pi

# Run the interactive installer
sudo bash install-acquirepi.sh
```

The installer will guide you through:
1. Choosing what to install (Manager, Agent, or both)
2. System requirements check
3. Automatic installation of all dependencies
4. Service configuration and startup

---

## Installation Options

### Option 1: Interactive Installation (Recommended)

```bash
sudo bash install-acquirepi.sh
```

You'll see a menu:
```
What would you like to install?

  1) Manager Only     - Central web application (Django + PostgreSQL)
  2) Agent Only       - Raspberry Pi imaging client
  3) Complete System  - Both Manager and Agent (for testing/single machine)
  4) Exit
```

### Option 2: Command-Line Installation

**Install Manager Only:**
```bash
sudo bash install-acquirepi.sh --manager
```

**Install Agent Only:**
```bash
sudo bash install-acquirepi.sh --agent
```

**Install Both:**
```bash
sudo bash install-acquirepi.sh --all
```

**Skip System Update (faster, but not recommended):**
```bash
sudo bash install-acquirepi.sh --manager --skip-update
```

---

## System Requirements

### Manager Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Debian 11+, Ubuntu 20.04+, Raspberry Pi OS (64-bit) |
| **CPU** | 2+ cores recommended |
| **RAM** | 4GB minimum, 8GB recommended |
| **Disk** | 20GB+ free space |
| **Network** | Internet connection for installation |

### Agent Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Debian 11+, Ubuntu 20.04+, Raspberry Pi OS (64-bit) |
| **Hardware** | Raspberry Pi 4/5 (4GB+ RAM) recommended |
| **RAM** | 2GB minimum, 4GB recommended |
| **Disk** | 10GB+ free space |
| **USB** | USB 3.0 ports for disk imaging |
| **Network** | Network connectivity to manager |

---

## Deployment Scenarios

### Scenario 1: Separate Manager + Multiple Agents (Recommended)

**Manager Server** (Central location, always-on):
```bash
# On a server or desktop computer
sudo bash install-acquirepi.sh --manager
```

**Agent(s)** (Raspberry Pi devices in the field):
```bash
# On each Raspberry Pi
sudo bash install-acquirepi.sh --agent
```

Agents will automatically discover the manager via mDNS.

### Scenario 2: All-in-One (Testing/Demo)

Install both on a single Raspberry Pi:
```bash
sudo bash install-acquirepi.sh --all
```

Good for testing, but not recommended for production due to resource constraints.

### Scenario 3: Cloud Manager + Local Agents

**Cloud Server** (AWS, DigitalOcean, etc.):
```bash
sudo bash install-acquirepi.sh --manager
```

**Local Agents** (Raspberry Pi devices):
```bash
# Configure agent with manager URL
export MANAGER_URL=http://your-server-ip:8000
sudo bash install-acquirepi.sh --agent
```

---

## Post-Installation

### Manager

1. **Access Web Interface:**
   ```
   http://<manager-ip>:8000
   ```

2. **Login with Admin Credentials:**
   - Username: Created during installation
   - Password: Created during installation

3. **Approve Agents:**
   - Navigate to "Agents" section
   - Find pending agents
   - Click "Approve"

4. **Configure NFS Servers (Optional):**
   - Settings → NFS Servers
   - Add pre-configured NFS storage

5. **Configure Webhooks (Optional):**
   - Settings → Webhooks
   - Add Slack/Teams notifications

### Agent

1. **Check Agent Status:**
   ```bash
   sudo systemctl status acquirepi-agent
   ```

2. **View Logs:**
   ```bash
   sudo journalctl -u acquirepi-agent -f
   ```

3. **Wait for Approval:**
   - Agent automatically registers with manager
   - Admin must approve in web interface
   - Once approved, agent shows as "Online"

4. **Connect Devices:**
   - Connect USB drives, SATA drives, or mobile devices
   - Devices auto-detected within 30 seconds

---

## Troubleshooting

### Manager Won't Start

**Check service status:**
```bash
sudo systemctl status acquirepi-manager
sudo journalctl -u acquirepi-manager -n 100 --no-pager
```

**Common issues:**
- PostgreSQL not running: `sudo systemctl start postgresql`
- Redis not running: `sudo systemctl start redis-server`
- Port 8000 already in use: Check with `sudo netstat -tulpn | grep 8000`

### Agent Can't Find Manager

**Check mDNS discovery:**
```bash
avahi-browse -a
```

You should see `_acquirepi._tcp` service listed.

**Manual configuration:**
```bash
# Edit agent service
sudo systemctl edit acquirepi-agent

# Add:
[Service]
Environment="MANAGER_URL=http://<manager-ip>:8000"

# Restart
sudo systemctl restart acquirepi-agent
```

### Database Connection Errors

**Reset database:**
```bash
cd /opt/acquirepi-manager
source venv/bin/activate
python manage.py migrate --run-syncdb
```

### Permission Errors

**Fix ownership:**
```bash
# Manager
sudo chown -R root:root /opt/acquirepi-manager

# Agent
sudo chown -R root:root /usr/local/bin/acquirepi-agent.py
```

---

## Updating/Upgrading

### Manager Update

```bash
cd /opt/acquirepi-manager
git pull origin main  # If using git
source venv/bin/activate
pip install -r requirements.txt --upgrade
python manage.py migrate
python manage.py collectstatic --noinput
sudo systemctl restart acquirepi-manager
```

### Agent Update

```bash
# Download new agent
sudo systemctl stop acquirepi-agent
sudo cp new-agent/acquirepi-agent.py /usr/local/bin/
sudo systemctl start acquirepi-agent
```

---

## Uninstallation

### Remove Manager

```bash
sudo systemctl stop acquirepi-manager acquirepi-mdns
sudo systemctl disable acquirepi-manager acquirepi-mdns
sudo rm /etc/systemd/system/acquirepi-manager.service
sudo rm /etc/systemd/system/acquirepi-mdns.service
sudo rm -rf /opt/acquirepi-manager
sudo -u postgres psql -c "DROP DATABASE forensics;"
sudo -u postgres psql -c "DROP USER acquirepi;"
```

### Remove Agent

```bash
sudo systemctl stop acquirepi-agent
sudo systemctl disable acquirepi-agent
sudo rm /etc/systemd/system/acquirepi-agent.service
sudo rm /usr/local/bin/acquirepi-agent.py
sudo rm /usr/local/bin/*.sh  # Imaging scripts
sudo rm -rf /opt/acquirepi-agent-venv
```

---

## Security Considerations

### Manager Security

1. **Change Default Port:**
   - Edit `/etc/systemd/system/acquirepi-manager.service`
   - Change `-p 8000` to another port

2. **Enable Firewall:**
   ```bash
   sudo ufw allow 8000/tcp
   sudo ufw enable
   ```

3. **Use Strong Passwords:**
   - Admin account should use strong password
   - Change default PostgreSQL password in settings

4. **Enable HTTPS:**
   - Configure Nginx reverse proxy with SSL certificate
   - Use Let's Encrypt for free SSL

### Agent Security

1. **Restrict Network Access:**
   - Agents should only communicate with manager
   - Use firewall rules to block unnecessary ports

2. **Physical Security:**
   - Secure Raspberry Pi devices
   - Use secure boot if available

---

## Getting Help

- **Documentation:** See README.md and this installation guide
- **Logs:** `sudo journalctl -u acquirepi-manager -f` or `sudo journalctl -u acquirepi-agent -f`
- **Issues:** Check system requirements and logs first

---

## Advanced Configuration

### Custom Installation Paths

Edit the installer script variables:
```bash
MANAGER_DIR="/custom/path/manager"
AGENT_DIR="/custom/path/agent"
```

### Database Configuration

Use external PostgreSQL:
```bash
# Edit /opt/acquirepi-manager/manager/settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'forensics',
        'USER': 'acquirepi',
        'PASSWORD': 'your_password',
        'HOST': 'external-db.example.com',
        'PORT': '5432',
    }
}
```

### NFS Configuration

Pre-configure NFS mounts in `/etc/fstab`:
```
nfs-server:/exports/forensics  /mnt/nfs-share  nfs  defaults,noauto  0  0
```

---

## System Architecture

```
┌─────────────────────────────────────┐
│         acquirepi Manager               │
│  (Central Web Application)          │
│                                     │
│  - Django Web UI                    │
│  - PostgreSQL Database              │
│  - Redis (WebSocket support)        │
│  - mDNS Service Discovery           │
│  - REST API                         │
└──────────────┬──────────────────────┘
               │
               │ mDNS Discovery
               │ REST API (HTTP)
               │ WebSocket (Real-time)
               │
    ┌──────────┴──────────┬──────────────┬──────────────┐
    │                     │              │              │
┌───▼────┐          ┌────▼───┐      ┌───▼────┐     ┌───▼────┐
│ Agent  │          │ Agent  │      │ Agent  │     │ Agent  │
│  (Pi)  │          │  (Pi)  │      │  (Pi)  │     │  (Pi)  │
└───┬────┘          └────┬───┘      └───┬────┘     └───┬────┘
    │                    │              │              │
┌───▼────────┐     ┌────▼──────┐  ┌───▼──────┐  ┌───▼──────┐
│ Evidence   │     │ Evidence  │  │ Mobile   │  │ Evidence │
│ Disk       │     │ Disk      │  │ Device   │  │ Disk     │
└────────────┘     └───────────┘  └──────────┘  └──────────┘
```

---

**Installation complete! Happy forensic imaging! 🔍**
