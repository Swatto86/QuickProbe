# QuickProbe — Project Atlas

> **Single source of truth** for system architecture, boundaries, and navigation.
> Any change affecting structure, APIs, boundaries, build, or config MUST update this document in the same increment.

---

## 1. System Purpose & Core Domain Concepts

QuickProbe is a **local-first Windows desktop application** for system administrators.
It monitors Windows (WinRM) and Linux (SSH) servers, providing real-time health dashboards,
one-click RDP, service/process management, and encrypted backup/restore — all from a single Tauri v2 app.

### Core Domain Concepts

| Concept | Definition |
|---|---|
| **Host** | A monitored server identified by its normalised (uppercase, short) name. |
| **Probe / Heartbeat** | A periodic or on-demand health interrogation (CPU, RAM, disk, services, etc.). |
| **Session** | A cached `WindowsRemoteSession` or `LinuxRemoteSession` handle (5-min TTL). |
| **Credential Profile** | A named credential entry — either the global login or a per-host override — stored in Windows Credential Manager (DPAPI). |
| **Login Mode** | Either "domain" (default — full `PrincipalContext` validation against a domain controller) or "local" (format-only validation, no DC required). Tracked in the KV store via `qp_login_mode`. |
| **Backup Payload** | A schema-versioned, AES-256-encrypted ZIP containing hosts, KV settings, and runtime mode metadata. |
| **KV Store** | SQLite-backed key-value persistence for dashboard settings, server order, and cached state. |

---

## 2. Architectural Boundaries

```
┌──────────────────────────────────────────────────────────┐
│  UI Layer (ui/)  — HTML + Tailwind/DaisyUI + vanilla JS  │
│  Communicates with backend via Tauri IPC commands         │
├──────────────────────────────────────────────────────────┤
│  Tauri Shell (src-tauri/src/main.rs)                     │
│  57 IPC command handlers, session pool, backup/restore   │
├──────────────────────────────────────────────────────────┤
│  Core Logic (src-tauri/src/core/)  — platform-agnostic   │
│  session.rs trait, probes.rs, credential.rs, validation  │
├──────────────────────────────────────────────────────────┤
│  Platform Adapters (src-tauri/src/platform/)             │
│  winrm.rs, ssh.rs, credman.rs, registry.rs              │
├──────────────────────────────────────────────────────────┤
│  Persistence (db.rs, backup.rs, kv_store)                │
│  SQLite WAL-mode, AES-256 encrypted ZIPs                 │
├──────────────────────────────────────────────────────────┤
│  Cross-cutting (logger.rs, constants.rs, utils/)         │
│  Structured logging, retry, error types                  │
└──────────────────────────────────────────────────────────┘
```

**Key boundary rules:**

- `core/` MUST NOT import from `platform/` — it defines traits that platform adapters implement.
- `platform/` MUST NOT import from `main.rs` — only from `core/`, `models/`, and `utils/`.
- `main.rs` is the only crate that wires platform adapters to core traits.
- UI communicates exclusively through Tauri IPC; no direct Rust FFI.

---

## 3. Repository Structure & Responsibilities

```
QuickProbe/
├── .github/
│   ├── copilot-instructions.md   # Agent collaboration policy
│   ├── pull_request_template.md  # PR checklist
│   └── workflows/
│       ├── ci.yml                # Push/PR quality gate (verify.ps1)
│       └── release.yml           # Tag-triggered NSIS installer build
├── docs/
│   ├── BUILD_FROM_SCRATCH.md     # Full Windows build guide
│   └── RELEASING.md              # Release process
├── e2e/                           # WebdriverIO E2E test specs
│   ├── app-launch.spec.js
│   ├── dashboard.spec.js
│   ├── hosts.spec.js
│   └── options.spec.js
├── scripts/
│   └── verify.ps1                # THE single gate: fmt → clippy → test → build
├── src-tauri/
│   ├── Cargo.toml                # Rust deps & features
│   ├── build.rs                  # Tauri build script
│   ├── tauri.conf.json           # App windows, bundle, CSP, updater
│   ├── capabilities/default.json # Tauri v2 permissions
│   └── src/
│       ├── main.rs               # Tauri entry + 55 IPC command handlers
│       ├── lib.rs                # Public crate root — re-exports
│       ├── core/                 # Platform-agnostic business logic
│       │   ├── mod.rs
│       │   ├── session.rs        # RemoteSession trait + types
│       │   ├── probes.rs         # Health probe orchestration
│       │   ├── credential.rs     # CredentialStore trait
│       │   ├── validation.rs     # Credential validation rules
│       │   └── mock_session.rs   # Test double
│       ├── models/               # Domain value objects
│       │   ├── mod.rs
│       │   └── credentials.rs    # Username, Credentials, SecureString
│       ├── platform/             # OS-specific adapters
│       │   ├── mod.rs
│       │   ├── winrm.rs          # WindowsRemoteSession (WinRM/PSRemoting)
│       │   ├── ssh.rs            # LinuxRemoteSession (SSH)
│       │   ├── credman.rs        # WindowsCredentialManager (DPAPI)
│       │   └── registry.rs       # WindowsRegistry (auto-start)
│       ├── utils/                # Cross-cutting helpers
│       │   ├── mod.rs
│       │   ├── errors.rs         # ProbeError, SessionError, etc.
│       │   └── retry.rs          # Exponential backoff
│       ├── backup.rs             # Encrypted backup/restore payload
│       ├── constants.rs          # App-wide constants with rationale
│       ├── db.rs                 # SQLite database layer
│       ├── logger.rs             # Structured rotating file logger
│       ├── normalize.rs          # Input normalisation helpers
│       └── updater.rs            # GitHub release update checker
├── ui/                            # Frontend (served by Tauri)
│   ├── login.html                # Initial credential entry
│   ├── dashboard-all.html        # Main dashboard
│   ├── hosts.html                # Host editor
│   ├── options.html              # Settings page
│   ├── about.html                # About dialog
│   ├── update-required.html      # Mandatory update prompt
│   ├── app.js                    # Shared Tauri IPC helpers
│   ├── dashboard-utils.js        # Dashboard utility functions
│   ├── theme.js                  # DaisyUI theme switching
│   └── input.css → styles.css    # Tailwind CSS pipeline
├── claude.md                      # ← THIS FILE (Project Atlas)
├── CHANGELOG.md                   # Keep-a-Changelog format
├── README.md                      # User-facing documentation
├── package.json                   # Node deps + npm scripts
├── wdio.conf.cjs                  # WebdriverIO E2E configuration
├── tailwind.config.js             # Tailwind/DaisyUI config
└── postcss.config.js              # PostCSS pipeline
```

---

## 4. Entry Points, Public APIs & Commands

### Rust crate (`quickprobe`)

- **`lib.rs`** — public crate root; re-exports `core::*`, `models::*`, `utils::*`.
- **`main.rs`** — Tauri binary crate; registers 57 `#[tauri::command]` IPC handlers.

### Key Tauri IPC Commands (frontend → backend)

| Category | Commands |
|---|---|
| **Auth** | `login`, `login_local_mode`, `logout`, `check_saved_credentials`, `login_with_saved_credentials`, `get_login_mode` |
| **Hosts** | `get_hosts`, `set_hosts`, `update_host`, `save_server_notes`, `rename_group` |
| **Probes** | `get_system_health`, `cache_get_dashboard`, `cache_set_dashboard`, `persist_health_snapshot`, `load_health_snapshots` |
| **Remote actions** | `launch_rdp`, `launch_ssh`, `open_explorer_share`, `launch_remote_registry`, `remote_restart`, `remote_shutdown` |
| **Backup** | `export_backup_encrypted`, `import_backup_encrypted`, `export_hosts_csv` |
| **Settings** | `settings_get_all`, `settings_set_all`, `check_autostart`, `toggle_autostart`, `get_start_hidden_setting`, `set_start_hidden_setting` |
| **System** | `get_app_info`, `get_runtime_mode_info`, `enable_options_menu`, `save_rdp_credentials` |

### CLI / Scripts

| Script | Purpose |
|---|---|
| `scripts/verify.ps1` | **Single gate**: `cargo fmt --check` → `cargo clippy --lib -D warnings` → `cargo test --lib` → `cargo build --lib --release` |
| `npm run dev` | Build CSS + Tauri dev mode |
| `npm run build` | Build CSS + full Tauri release build |
| `npm run test:e2e` | WebdriverIO E2E suite against built app |

---

## 5. Build, Test, CI & Release

| Activity | Command / Location |
|---|---|
| **Verify (local)** | `pwsh -File scripts/verify.ps1` |
| **CI** | `.github/workflows/ci.yml` — runs `verify.ps1` on push/PR to `main` |
| **Release** | `.github/workflows/release.yml` — tag `v*` triggers verify → NSIS build → GitHub Release |
| **Rust unit tests** | `cargo test --lib --manifest-path src-tauri/Cargo.toml` |
| **E2E tests** | `npm run test:e2e` (requires built app + msedgedriver) |
| **CSS build** | `npm run build:css` (Tailwind → `ui/styles.css`) |

---

## 6. Configuration Ownership & Schemas

| Config File | Owner | Validated At |
|---|---|---|
| `src-tauri/tauri.conf.json` | Tauri runtime | App startup |
| `src-tauri/Cargo.toml` | Rust build | Compile time |
| `src-tauri/capabilities/default.json` | Tauri v2 permission ACLs | App startup |
| `package.json` | npm scripts + devDeps | `npm ci` |
| `tailwind.config.js` | Tailwind CSS pipeline | CSS build |
| `wdio.conf.cjs` | WebdriverIO E2E config | Test run |
| `%LOCALAPPDATA%/QuickProbe/quickprobe.db` | SQLite (runtime) | `db::open_or_create()` at startup |
| `%LOCALAPPDATA%/QuickProbe/settings.json` | App settings (runtime) | `load_app_settings()` at startup |
| `QP_ENABLE_LOGGING=1` | Env var: enable release-mode file logging | Logger init |
| `QP_LOG_VERBOSE=1` | Env var: enable verbose debug output | Logger init |

---

## 7. Critical Invariants — DO NOT BREAK

1. **`scripts/verify.ps1` is the single source of truth for repo health.** CI runs it; developers must run it locally before claiming work is done.

2. **No `unwrap()` in production paths.** All error cases must be handled explicitly. `unwrap()` is permitted only inside `#[cfg(test)]` blocks.

3. **Explicit WinRM session cleanup.** Every `Invoke-Command` creates an explicit `PSSession` torn down in a `finally` block via `Remove-PSSession`. No bare `Invoke-Command -ComputerName`.

4. **No connectivity pre-checks on the heartbeat path.** `Test-WSMan` is reserved for user-initiated actions only.

5. **Session cache TTL is 300 seconds** (`SESSION_CACHE_TTL_SECS`). Invalidated on credential or host config changes.

6. **Heartbeat interval is 120 seconds.** Never reduce below 60 seconds without considering session load on target servers.

7. **Credentials never appear in logs, database, or error messages.** Only hashed/masked references are permitted.

8. **`core/` must remain platform-agnostic.** No Windows APIs, no `std::os::windows`, no `platform::` imports.

9. **Database operations use immediate transactions.** No read-modify-write patterns that could race.

10. **Backups are always AES-256 encrypted.** Plaintext export is not supported.

11. **Local mode skips domain validation only.** `login_local_mode` uses `validate_credentials_basic` (format check). Credentials are still stored in DPAPI and `execute_remote()` still uses `New-PSSession -Credential`. AD-dependent features (Scan AD) are disabled in the UI when `get_login_mode` returns `"local"`.
