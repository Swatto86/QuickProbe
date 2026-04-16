# QuickProbe

**A lightweight desktop app for system administrators to monitor Windows and Linux servers.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://github.com/Swatto86/QuickProbe/releases)

QuickProbe lets you check server health, launch RDP sessions, and manage your fleet—all from one place. It uses WinRM for Windows servers and SSH for Linux hosts, with secure credential storage via Windows Credential Manager.

**[Download](https://github.com/Swatto86/QuickProbe/releases)** | **[Website](https://swatto.co.uk)**

---

## Features

- **Real-time health probes** — CPU, memory, disk, uptime, services, and more (consolidated into single WinRM calls with explicit session cleanup)
- **Dual-OS support** — Windows (WinRM) and Linux (SSH) targets
- **One-click RDP launch** — Double-click to connect with stored credentials
- **Remote management** — Manage services, processes, PowerShell/SSH, and file shares
- **File share access** — Open Windows Explorer to C$ (or other shares) with stored credentials
- **Active Directory scanning** — Discover servers via LDAP
- **Secure credentials** — Stored in Windows Credential Manager (DPAPI)
- **Local-first** — SQLite database, no cloud required
- **Local mode** — Operate without domain credentials for lab/workgroup environments
- **Encrypted backups** — AES-256 encrypted ZIP export/import

## Quick Start

1. **Download** the installer from [Releases](https://github.com/Swatto86/QuickProbe/releases)
2. **Install** — no admin rights needed
3. **Login** — enter your domain credentials (`DOMAIN\username`)
4. **Add servers** — manually or scan your Active Directory
5. **Monitor** — click Refresh and double-click any card to RDP

### Local Mode (non-domain machines)

If your machine is **not joined to a domain** (e.g. a Hyper-V lab environment), enable **Local Mode**:

1. Toggle **Local Mode** on the login screen
2. Enter the local admin credentials for your target VMs (e.g. `Administrator`)
3. Login will skip domain validation (format check only) and go straight to the dashboard
4. A **Local Mode** badge appears on the dashboard header
5. AD scan is disabled — add hosts manually

> All other features (RDP, WinRM, SSH, credential storage) work identically in local mode.

## Using QuickProbe

### Dashboard Controls

The dashboard supports three view modes, selectable via the **Cards / Groups / Table** buttons in the header (or set the default in **Options → Default Dashboard View**):

- **Cards** — rich per-server cards with full health details and probe status.
- **Groups** — cards organised by group, click a group to focus.
- **Table** — compact spreadsheet-style grid with sortable, drag-resizable columns — useful for seeing many servers at once. Column widths and sort are remembered per user.

Each server card has two action rows:

**Row 1:**
- **🔄 Refresh** — Update health data for this server
- **⚙️ Actions** — Dropdown menu with management options

**Row 2:**
- **✏️ Edit** — Modify server settings (notes, services, group)

In **Table** view, each row exposes the same actions: 🔄 Refresh, ✏️ Edit, and a ⚙️ menu identical to the card dropdown. Single-click selects a row and triggers a quick probe; double-click launches RDP (Windows) or SSH (Linux).

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

See [docs/BUILD_FROM_SCRATCH.md](docs/BUILD_FROM_SCRATCH.md) for full Windows build instructions.

**Quick start:**

```powershell
# Prerequisites: Rust, Node.js, Strawberry Perl, VS Build Tools
npm ci
pwsh -File scripts/verify.ps1   # format + lint + test + build
npm run dev                     # development mode
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

## WinRM Session Management

QuickProbe is designed to be safe against remote targets, even domain controllers:

- **Explicit session cleanup** — Every `Invoke-Command` creates an explicit `PSSession` that is torn down in a `finally` block via `Remove-PSSession`. This prevents `wsmprovhost.exe` accumulation on target servers.
- **No pre-flight connectivity check on probes** — The `Test-WSMan` validation is only used for user-initiated actions (adding a host, testing credentials), not on the recurring heartbeat path. This halves the per-probe session count.
- **Session caching** — `WindowsRemoteSession` handles are cached per-server with a 5-minute TTL. The cache is invalidated on credential or host config changes.
- **Throttled heartbeat** — The dashboard polls every 120 seconds (with jitter) and enforces a 60-second minimum between quick probes to the same host. A circuit-breaker pattern backs off failing servers exponentially.

## Security

- Credentials stored in Windows Credential Manager (DPAPI encrypted)
- No plaintext secrets in memory, logs, or database
- Backups are AES-256 encrypted
- All data stays local — no cloud, no telemetry

## License

MIT — see [LICENSE](LICENSE) for details.

---

Made by [Swatto](https://github.com/Swatto86)

