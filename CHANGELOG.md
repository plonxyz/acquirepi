# acquirepi Changelog

All notable changes to this project will be documented in this file.

---

## v1.0.0 (January 29, 2026)

### Initial Public Release

**Core Features:**

- **Forensic Disk Imaging**
  - E01 format via ewfacquire
  - Multi-hash verification (MD5, SHA1, SHA256 simultaneous)
  - Disk-to-disk and NFS upload methods
  - Configurable compression and segment sizes

- **iOS Mobile Device Extraction**
  - Logical backup via pymobiledevice3
  - Encrypted backup support with password
  - NFS support for network-based backups

- **Manager (Django Web Application)**
  - Web-based dashboard with real-time updates (WebSocket + AJAX)
  - Job creation and management
  - Agent registration and approval
  - Case and evidence tracking
  - Remote console access to agents

- **Agent (Raspberry Pi Client)**
  - mDNS service discovery
  - Standalone/airgap mode with USB config stick
  - Automatic job polling and execution
  - Progress reporting and heartbeat
  - Support for Raspberry Pi 4 and 5

- **Chain of Custody**
  - Immutable audit logs with SHA256 hash chains
  - Evidence handling event timeline
  - Digital signature support (optional)
  - QR code evidence labels (optional)
  - PDF report generation

- **Integrity Monitoring**
  - Periodic tamper detection service
  - Webhook alerts (Slack, Discord, Teams)
  - Email notifications
  - Cryptographic verification of all log chains

- **Installation**
  - All-in-one interactive installer
  - Separate installers for Manager and Agent
  - Systemd service configuration
  - PostgreSQL and Redis setup

### System Requirements

**Manager:**
- Debian 11+ / Ubuntu 20.04+ / Raspberry Pi OS (64-bit)
- Python 3.9+, PostgreSQL 13+, Redis 6+

**Agent:**
- Raspberry Pi 4 (2GB+) or Raspberry Pi 5
- Raspberry Pi OS (64-bit)
- ewf-tools, libimobiledevice, pymobiledevice3

---

## Future Releases

See [GitHub Issues](https://github.com/plonxyz/acquirepi/issues) for planned features and known issues.
