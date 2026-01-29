# acquirepi

> Forensic disk imaging and iOS extraction system for Raspberry Pi

| | |
|---|---|
| **Version** | 1.0.0 |
| **Release** | January 29, 2026 |
| **Platform** | Raspberry Pi / Linux |
| **License** | GPL v3 |

---

## Disclaimer

This software is provided as-is for professional use by trained forensic practitioners. Users are solely responsible for validating its suitability for their specific forensic requirements. Always verify hash values and forensic artifacts independently before relying on them for legal proceedings. The authors assume no liability for evidence challenges or legal consequences arising from use of this software. See [LICENSE](https://github.com/plonxyz/acquirepi/blob/main/LICENSE) for full terms.

---

## Features

| Feature | Description |
|---------|-------------|
| **Disk Imaging** | E01 format with MD5 + SHA1 + SHA256 simultaneous hashing |
| **iOS Extraction** | Logical backup via pymobiledevice3 |
| **Chain of Custody** | Immutable audit logs with SHA256 hash chains |
| **Real-time Dashboard** | WebSocket-powered monitoring |
| **Integrity Monitoring** | Periodic tamper detection with webhook alerts |


---

## Quick Start

### All-in-One Installation (Recommended)

```bash
# Clone or extract the release
cd acquirepi

# Run interactive installer
sudo ./install-acquirepi.sh

# Or use flags
sudo ./install-acquirepi.sh --all       # Manager + Agent
sudo ./install-acquirepi.sh --manager   # Manager only
sudo ./install-acquirepi.sh --agent     # Agent only
```

### Manual Installation

```bash
# Manager
cd acquirepi-manager
sudo ./install-manager.sh

# Agent
cd agent
sudo ./install-agent.sh
```

### First Run

1. Create admin account:
   ```bash
   cd /opt/acquirepi-manager
   source venv/bin/activate
   python manage.py createsuperuser
   ```

2. Access web UI: `http://<manager-ip>:8000`

3. Approve agents: Navigate to Agents → Approve pending agents

---

## System Requirements

### Manager (Central Server)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Debian 11+ / Ubuntu 20.04+ | Raspberry Pi OS 64-bit |
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Storage | 20 GB | 50+ GB |

### Agent (Raspberry Pi)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Hardware | Raspberry Pi 4 (2GB) | Raspberry Pi 5 (2GB) |
| OS | Raspberry Pi OS Lite | Raspberry Pi OS 64-bit |
| Storage | 32 GB microSD | 64+ GB or NVMe SSD |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         MANAGER                             │
│  Django + PostgreSQL + Redis + WebSocket + mDNS             │
└─────────────────────────────────────────────────────────────┘
                              │
                    Network / mDNS Discovery
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
  ┌───────────┐         ┌───────────┐         ┌───────────┐
  │   Agent   │         │   Agent   │         │   Agent   │
  │  (Pi #1)  │         │  (Pi #2)  │         │  (Pi #N)  │
  └───────────┘         └───────────┘         └───────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| **Manager** | Django web app for job management, monitoring, and forensic tracking |
| **Agent** | Python daemon on Raspberry Pi for imaging and extraction |

### Communication Flow

1. Agent discovers Manager via mDNS (`_acquirepi._tcp.local.`)
2. Agent registers → Admin approves → Agent receives API token
3. Agent polls for jobs → Executes imaging → Reports progress
4. Manager verifies hashes → Logs chain of custody → Sends alerts

---

## Deployment Scenarios

### Forensic Lab (Distributed)

```bash
# On central server
sudo ./install-acquirepi.sh --manager

# On each Raspberry Pi
sudo ./install-acquirepi.sh --agent
```

### Standalone

```bash
# Single Pi running both
sudo ./install-acquirepi.sh --all
```

### Airgapped Operation

Use USB config stick for offline imaging without network connectivity.

---

## Project Structure

```
acquirepi/
├── install-acquirepi.sh        # All-in-one installer
├── README.md                   # This file
├── LICENSE                     # GPL License
├── CHANGELOG.md                # Version history
│
├── acquirepi-manager/          # Central server
│   ├── imager/                 # Django application
│   ├── manager/                # Django settings
│   └── install-manager.sh      # Installer
│
├── agent/                      # Raspberry Pi client
│   ├── acquirepi-agent.py      # Main daemon
│   ├── scripts/                # Imaging scripts
│   └── install-agent.sh        # Installer
│
└── documentation/
    └── INSTALL.md              # Detailed guide
```

---

## Troubleshooting

### Manager Issues

```bash
# Check service
sudo systemctl status acquirepi-manager
sudo journalctl -u acquirepi-manager -f

# Check dependencies
sudo systemctl status postgresql redis
```

### Agent Issues

```bash
# Check service
sudo systemctl status acquirepi-agent
sudo journalctl -u acquirepi-agent -f

# Check mDNS discovery
avahi-browse -a | grep acquirepi
```

### iOS Device Not Detected

```bash
# Check usbmuxd
sudo systemctl status usbmuxd
idevice_id -l

# Pair device
idevicepair pair
```

---

## Quick Reference

### Service Commands

```bash
# Manager
sudo systemctl start|stop|restart|status acquirepi-manager

# Agent
sudo systemctl start|stop|restart|status acquirepi-agent

# Integrity Monitor
sudo systemctl start|stop|restart|status acquirepi-integrity-monitor
```

### Important Paths

| Component | Path |
|-----------|------|
| Manager install | `/opt/acquirepi-manager/` |
| Manager config | `/opt/acquirepi-manager/manager/settings.py` |
| Agent script | `/usr/local/bin/acquirepi-agent.py` |
| Agent logs | `/var/log/acquirepi-agent.log` |
| Imaging logs | `/var/log/acquire.log` |

### Django Commands

```bash
cd /opt/acquirepi-manager && source venv/bin/activate

python manage.py createsuperuser          # Create admin
python manage.py migrate                  # Run migrations
python manage.py verify_forensic_integrity # Check hash chains
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Quick start and overview (this file) |
| [INSTALL.md](documentation/INSTALL.md) | Detailed installation guide |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | Technical architecture |
| [LICENSE](LICENSE) | GNU License |

---

## Support

### Reporting Issues

Include the following when reporting bugs:

- OS and hardware info
- Component (Manager/Agent)
- Error messages from logs
- Steps to reproduce

### Resources

- [GitHub Issues](https://github.com/plonxyz/acquirepi/issues)
- [Documentation](documentation/INSTALL.md)

---

## Credits

**acquirepi** - Forensic Imaging System

Developed by [plonxyz](https://x.com/plonxyz)

### Technologies

| Category | Technologies |
|----------|--------------|
| Backend | Django 4.2, Django REST Framework, Django Channels |
| Database | PostgreSQL, Redis |
| Forensics | ewf-tools, pymobiledevice3, libimobiledevice |
| Hardware | Raspberry Pi 4/5 |

---

## License

GPL v3 License - See [LICENSE](https://github.com/plonxyz/acquirepi/blob/main/LICENSE) for details.

---

*acquirepi v1.0.0 - January 29, 2026*
