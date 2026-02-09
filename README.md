# QuickProbe

**A lightweight desktop app for system administrators to monitor Windows and Linux servers.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://github.com/Swatto86/QuickProbe/releases)

QuickProbe lets you check server health, launch RDP sessions, and manage your fleet—all from one place. It uses WinRM for Windows servers and SSH for Linux hosts, with secure credential storage via Windows Credential Manager.

**[Download](https://github.com/Swatto86/QuickProbe/releases)** | **[Website](https://swatto.co.uk)**

---

## Features

- **Real-time health probes** — CPU, memory, disk, uptime, services, and more
- **Dual-OS support** — Windows (WinRM) and Linux (SSH) targets
- **One-click RDP launch** — Double-click to connect with stored credentials
- **Remote management** — Manage services, processes, PowerShell/SSH, and file shares
- **File share access** — Open Windows Explorer to C$ (or other shares) with stored credentials
- **Active Directory scanning** — Discover servers via LDAP
- **Secure credentials** — Stored in Windows Credential Manager (DPAPI)
- **Local-first** — SQLite database, no cloud required
- **Encrypted backups** — AES-256 encrypted ZIP export/import

## Quick Start

1. **Download** the installer from [Releases](https://github.com/Swatto86/QuickProbe/releases)
2. **Install** — no admin rights needed
3. **Login** — enter your domain credentials (`DOMAIN\username`)
4. **Add servers** — manually or scan your Active Directory
5. **Monitor** — click Refresh and double-click any card to RDP

## Using QuickProbe

### Dashboard Controls

Each server card has two action rows:

**Row 1:**
- **🔄 Refresh** — Update health data for this server
- **⚙️ Actions** — Dropdown menu with management options

**Row 2:**
- **✏️ Edit** — Modify server settings (notes, services, group)

### Actions Menu

The Actions dropdown provides quick access to:

**For Windows servers:**
- **🔑 Set Host Credentials** — Store per-host credentials (overrides global login)
- **📁 Explore C$** — Open Windows Explorer to the administrative C$ share
- **🔧 Manage Services** — View, start, stop, and restart services
- **📊 Manage Processes** — Monitor CPU usage, kill processes
- **💻 Remote PowerShell** — Interactive PowerShell session
- **🖥️ Computer Management** — Native MMC snap-in connected to remote host
- **📋 Event Viewer** — Native MMC snap-in for remote event logs
- **📅 Task Scheduler** — Native MMC snap-in for remote scheduled tasks
- **🗝️ Remote Registry** — Start the RemoteRegistry service and connect regedit
- **🔄 Restart / ⏹️ Shutdown** — Remote power management with countdown safety

**For Linux servers:**
- **🔑 Set Host Credentials** — Store per-host SSH credentials
- **🐧 Manage Services (systemd)** — View and control systemd services
- **🐧 Manage Processes (top)** — Monitor processes
- **🐧 Remote SSH** — Open SSH terminal session

### Credential Hierarchy

QuickProbe uses credentials in this order:
1. **Host-specific credentials** (set via Actions → Set Host Credentials)
2. **Global credentials** (from initial login)

This allows you to use different accounts for specific servers while maintaining a default credential set.

## Requirements

| Component | Requirements |
|-----------|-------------|
| **Your PC** | Windows 10/11 or Server 2012 R2+ |
| **Your PC** | Local Administrator rights for full management features (see below) |
| **Windows targets** | WinRM enabled (`Enable-PSRemoting -Force`) |
| **Linux targets** | SSH server on port 22 |
| **Credentials** | Admin account for Windows, SSH user for Linux |

### Administrator Elevation

QuickProbe works without admin rights for core monitoring (health probes, service status, RDP launch). However, **local Administrator elevation** is required for full host management features:

| Feature | Requires Admin? |
|---------|----------------|
| Health probes (CPU, memory, disk, services) | No |
| RDP launch | No |
| Remote PowerShell / SSH | No |
| Manage Services (start/stop/restart) | No |
| Manage Processes (view/kill) | No |
| Computer Management (MMC) | **Yes** |
| Event Viewer (MMC) | **Yes** |
| Task Scheduler (MMC) | **Yes** |
| Remote Registry | **Yes** |
| Explore C$ share | **Yes** |
| Restart / Shutdown server | No |

When running without elevation, a warning banner appears on the dashboard indicating limited functionality. The MMC snap-in features use `cmdkey` to cache credentials locally, which requires admin rights to function correctly.

## What Does QuickProbe Collect?

| Metric | Windows (WinRM) | Linux (SSH) |
|--------|-----------------|-------------|
| OS info | Version, hostname, domain | Distro, kernel |
| CPU | Load % (normalized) | Load average |
| Memory | Total / Used / Free | Total / Used / Free |
| Disk | All volumes | All mounts (`df`) |
| Uptime | Hours since boot | Hours since boot |
| Services | Specified services | `systemctl` status |
| Processes | Top CPU consumers | Top CPU (`ps`) |
| Pending reboot | Windows Update, CBS | — |
| Network | Adapters, firewall | — |
| Events | System/App log errors | — |

## Building from Source

```bash
# Prerequisites: Rust, Node.js, npm

# Install dependencies
npm install

# Development mode
npm run dev

# Production build
npm run build
```

## Project Structure

```
src-tauri/              # Rust backend (Tauri 2.x)
├── src/
│   ├── main.rs         # Tauri entry + commands
│   ├── lib.rs          # Command exports
│   ├── core/           # Platform-agnostic logic
│   │   ├── session.rs  # RemoteSession trait
│   │   └── probes.rs   # Health probe functions
│   ├── platform/       # OS-specific code
│   │   ├── winrm.rs    # Windows Remote Session
│   │   ├── ssh.rs      # Linux Remote Session
│   │   └── credman.rs  # Credential Manager
│   └── db.rs           # SQLite database
├── Cargo.toml          # Rust dependencies
└── tauri.conf.json     # Tauri configuration

ui/                     # Frontend
├── dashboard-all.html  # Main dashboard
├── hosts.html          # Host editor
├── options.html        # Settings
└── dashboard-utils.js  # Shared utilities
```

## Security

- Credentials stored in Windows Credential Manager (DPAPI encrypted)
- No plaintext secrets in memory, logs, or database
- Backups are AES-256 encrypted
- All data stays local — no cloud, no telemetry

## License

MIT — see [LICENSE](LICENSE) for details.

---

Made by [Swatto](https://github.com/Swatto86)

