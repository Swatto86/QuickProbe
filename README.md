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

## Requirements

| Component | Requirements |
|-----------|-------------|
| **Your PC** | Windows 10/11 or Server 2012 R2+ |
| **Windows targets** | WinRM enabled (`Enable-PSRemoting -Force`) |
| **Linux targets** | SSH server on port 22 |
| **Credentials** | Admin account for Windows, SSH user for Linux |

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

