# acquirepi Forensic Imaging System

> A distributed forensic disk imaging and iOS device extraction system for digital forensics professionals.

| | |
|---|---|
| **Version** | 1.0.0 |
| **Release** | January 29, 2026 |
| **Platform** | Raspberry Pi / Linux |
| **License** | GPL v3 |

---

## Overview

acquirepi provides court-admissible evidence collection with:

- Forensic disk imaging (E01 format) with multi-hash verification
- iOS logical extraction via pymobiledevice3
- Full chain-of-custody tracking with cryptographic hash chains
- Real-time monitoring dashboard
- Distributed architecture supporting multiple imaging agents

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MANAGER (Central Server)                 │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Django    │  │  REST API   │  │     WebSocket       │  │
│  │  Dashboard  │  │  Endpoints  │  │  (Real-time Updates)│  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ PostgreSQL  │  │    Redis    │  │   mDNS Discovery    │  │
│  │  Database   │  │   Broker    │  │                     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                    Network / mDNS Discovery
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
  ┌───────────┐         ┌───────────┐         ┌───────────┐
  │   AGENT   │         │   AGENT   │         │   AGENT   │
  │  (Pi #1)  │         │  (Pi #2)  │         │  (Pi #N)  │
  │           │         │           │         │           │
  │ • ewftools│         │ • ewftools│         │ • ewftools│
  │ • iOS ext │         │ • iOS ext │         │ • iOS ext │
  └───────────┘         └───────────┘         └───────────┘
```

---

## Project Structure

```
acquirepi/
├── install-acquirepi.sh           # All-in-one installer
├── README.md                      # User documentation
├── LICENSE                        # GPL v3 License
├── CHANGELOG.md                   # Version history
│
├── acquirepi-manager/             # Central management server
│   ├── imager/                    # Main Django application
│   │   ├── models.py              # Database models
│   │   ├── views.py               # Views & API endpoints
│   │   ├── consumers.py           # WebSocket handlers
│   │   ├── forensics.py           # Hash verification
│   │   ├── pdf_generator.py       # Report generation
│   │   ├── webhooks.py            # Notifications
│   │   └── templates/             # HTML templates
│   ├── manager/                   # Django project settings
│   ├── requirements.txt           # Python dependencies
│   └── install-manager.sh         # Manager installer
│
├── agent/                         # Raspberry Pi agent
│   ├── acquirepi-agent.py         # Main agent daemon
│   ├── scripts/                   # Imaging scripts
│   │   ├── imager.sh              # Disk imaging
│   │   ├── nfs-imager.sh          # NFS uploads
│   │   └── disk_mount.sh          # Device mounting
│   ├── requirements.txt           # Python dependencies
│   └── install-agent.sh           # Agent installer
│
└── documentation/
    └── INSTALL.md                 # Detailed install guide
```

---

## Technology Stack

### Backend

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.9+ | Primary language |
| Django | 4.2.7 | Web framework |
| Django REST Framework | 3.14.0 | REST API |
| Django Channels | 4.0.0 | WebSocket support |
| PostgreSQL | 13+ | Production database |
| Redis | 6+ | Message broker |

### Forensic Tools

| Tool | Purpose |
|------|---------|
| ewf-tools (libewf) | E01 forensic imaging |
| pymobiledevice3 | iOS device extraction |
| libimobiledevice | iOS communication |

### Key Libraries

| Library | Purpose |
|---------|---------|
| zeroconf | mDNS service discovery |
| paramiko | SSH remote console |
| qrcode | Evidence label generation |
| Pillow | Image processing |

---

## Core Features

### Forensic Disk Imaging

| Feature | Description |
|---------|-------------|
| Format | E01 (Expert Witness Format) |
| Hashing | MD5 + SHA1 + SHA256 (simultaneous) |
| Compression | Best, Fast, or None |
| Upload | Disk-to-disk or NFS network share |

### iOS Mobile Extraction

| Feature | Description |
|---------|-------------|
| Method | Logical backup (iTunes-style) |
| Encryption | Optional encrypted backups |
| Storage | Local disk or NFS share |

### Chain of Custody

| Feature | Description |
|---------|-------------|
| Audit Logs | Immutable with SHA256 hash chains |
| Timeline | Evidence handling events |
| Signatures | Digital signature support |
| Labels | QR code evidence labels |
| Reports | PDF generation |

### Integrity Monitoring

| Feature | Description |
|---------|-------------|
| Detection | Periodic tamper detection |
| Alerts | Slack, Discord, Teams webhooks |
| Verification | Cryptographic hash chain validation |

---

## Database Models

### Core

| Model | Purpose |
|-------|---------|
| `Agent` | Registered Raspberry Pi devices |
| `ImagingJob` | Disk imaging tasks |
| `MobileExtractionJob` | iOS extraction tasks |
| `JobLog` | Job execution logs |

### Forensic

| Model | Purpose |
|-------|---------|
| `AuditLog` | Immutable audit trail |
| `EvidenceHandlingEvent` | Chain of custody events |
| `DigitalSignature` | Evidence signing |
| `WriteBlockerVerification` | Write blocker docs |

### Configuration

| Model | Purpose |
|-------|---------|
| `SystemSettings` | Feature toggles |
| `WebhookConfig` | Notification endpoints |
| `NFSServer` | Network storage |

---

## API Reference

### Agent Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/agents/register/` | Register new agent |
| `GET` | `/api/agents/` | List all agents |
| `POST` | `/api/agents/{id}/approve/` | Approve agent |

### Job Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/jobs/` | Create job |
| `GET` | `/api/jobs/pending/` | Poll for jobs |
| `POST` | `/api/jobs/{id}/progress/` | Update progress |
| `POST` | `/api/jobs/{id}/complete/` | Report completion |

### WebSocket Channels

| Channel | Description |
|---------|-------------|
| `/ws/dashboard/` | Dashboard updates |
| `/ws/jobs/{id}/` | Job-specific updates |

---

## Communication Flow

```
 ┌─────────┐                                    ┌─────────┐
 │  Agent  │                                    │ Manager │
 └────┬────┘                                    └────┬────┘
      │                                              │
      │  1. Discover via mDNS                        │
      │─────────────────────────────────────────────>│
      │                                              │
      │  2. POST /api/agents/register/               │
      │─────────────────────────────────────────────>│
      │                                              │
      │  3. Admin approves in web UI                 │
      │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ -│
      │                                              │
      │  4. GET /api/jobs/pending/ (polling)         │
      │─────────────────────────────────────────────>│
      │                                              │
      │  5. Receive job config (YAML)                │
      │<─────────────────────────────────────────────│
      │                                              │
      │  6. Execute imaging/extraction               │
      │  ┌──────────────────────┐                    │
      │  │ ewfacquire / iOS     │                    │
      │  └──────────────────────┘                    │
      │                                              │
      │  7. POST /api/jobs/{id}/progress/            │
      │─────────────────────────────────────────────>│
      │                                              │
      │  8. POST /api/jobs/{id}/complete/            │
      │─────────────────────────────────────────────>│
      │                                              │
      │                    9. Verify hashes          │
      │                    10. Log chain of custody  │
      │                    11. Send webhook alerts   │
      │                                              │
```

---

## Deployment Modes

| Mode | Description |
|------|-------------|
| **Distributed Lab** | Central manager + multiple Pi agents |
| **All-in-One** | Single Pi running both components |
| **Standalone** | Agent with USB config stick (airgapped) |

---

## Security

### Authentication
- Django session authentication (web UI)
- Token authentication (agent API)
- Role-based access control

### Forensic Integrity
- Immutable audit logs (no modify/delete)
- SHA256 hash chains for tamper detection
- Automatic hash verification
- Full user attribution

---

## Quick Commands

```bash
# Install everything
sudo ./install-acquirepi.sh --all

# Manager only
sudo ./install-acquirepi.sh --manager

# Agent only
sudo ./install-acquirepi.sh --agent

# Check services
sudo systemctl status acquirepi-manager
sudo systemctl status acquirepi-agent

# Verify integrity
cd /opt/acquirepi-manager
source venv/bin/activate
python manage.py verify_forensic_integrity
```

---

## System Requirements

### Manager

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Debian 11+ | Raspberry Pi OS 64-bit |
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Storage | 20 GB | 50+ GB |

### Agent

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Hardware | Raspberry Pi 4 (2GB) | Raspberry Pi 5 (2GB) |
| OS | Raspberry Pi OS Lite | Raspberry Pi OS 64-bit |
| Storage | 32 GB microSD | 64+ GB or NVMe SSD |

---

## License

acquirepi is provided as-is, without any warranty. Its methodology has been vetted by forensic experts to be forensically sound, but always verify the integrity of your images using appropriate forensic tools and procedures.

acquirepi is free software, distributed under the GNU General Public License v3 or later. You can redistribute and/or modify it under the terms of this license. While I hope it's useful, it comes with no warranty or guarantee of fitness for any purpose. For full license details, see https://www.gnu.org/licenses/.



---

*acquirepi v1.0.0 - January 29, 2026*
