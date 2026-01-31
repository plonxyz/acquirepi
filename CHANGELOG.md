# acquirepi Changelog

All notable changes to this project will be documented in this file.

---

## v1.0.2 (January 31, 2026)

### Bug Fixes

**Installer:**

- **PostgreSQL password fix** - Fixed issue where PostgreSQL user password was not set when the user already existed from a previous installation. Now uses `ALTER USER` as fallback when `CREATE USER` fails.

- **PostgreSQL 15+ compatibility** - Added schema permissions (`GRANT ALL ON SCHEMA public`) and database ownership for PostgreSQL 15+ which restricts public schema access by default.

- **Admin user creation** - Fixed superuser creation failing in non-interactive mode. Now auto-generates admin credentials with secure random password and displays them at installation completion.

**Agent:**

- **Disk imager hash capture** - Fixed disk-to-disk imaging not capturing or reporting hashes. Now captures MD5, SHA1, and SHA256 from ewfacquire output, matching NFS imager behavior. Hashes are included in job completion data and displayed in the manager UI.

### New Features

**Installer:**

- **External PostgreSQL support** - Added option to connect to an external/remote PostgreSQL server. Installer now offers three database choices:
  1. SQLite (simple, for testing)
  2. PostgreSQL (local) - auto-configured
  3. PostgreSQL (remote) - prompts for host, port, database, user, password with connection testing

---

## v1.0.1 (January 30, 2026)

### Bug Fixes

**Manager:**

- **Cancel button fix** - Fixed issue where cancelling a job didn't work because the agent's progress updates were overwriting the cancelled status. The progress endpoint now rejects updates for cancelled/completed jobs and returns `is_cancelled` flag to the agent.

- **Log output jumping fix** - Fixed job detail page where log output would jump around during refresh. Replaced full page reload with AJAX partial updates to preserve scroll position.

- **Dashboard auto-refresh** - Fixed dashboard not automatically showing new agents/jobs. Added detection for new agents and jobs in both WebSocket and polling modes, triggering page reload when new items appear.

- **Jobs page auto-refresh** - Fixed WebSocket handler bug where socket handlers were defined before socket was created. Added proper polling fallback.

- **Agents page auto-refresh** - Same WebSocket fix applied to agents list page.

- **Dashboard API** - Added missing `total_agents` to the dashboard API response for proper stat card updates.

**Agent:**

- **ACT LED in standalone mode** - Fixed ACT LED to turn off when booting in standalone/airgapped mode with config stick (indicates ready state).

- **LED logic in bash scripts** - Fixed inverted LED logic in `imager.sh` and `nfs-imager.sh`. Pi 5 ACT LED is active-low (1=OFF, 0=ON).

- **Config stick source detection** - Fixed standalone mode detecting the config stick as a source device. Now excludes the config stick (UUID: 937C-8BC2) from source device detection.

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
