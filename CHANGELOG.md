# Changelog

All notable changes to QuickProbe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.3] - 2026-05-27

### Fixed
- **Default Dashboard View "Table" was silently reverted to "Cards" on save** — `normalize_host_view_mode` only accepted `cards`/`groups`, so selecting Table in Options → Default Dashboard View would persist as "cards" via `settings_set_all`. The validator now accepts `table` correctly; new installs default to Table view (cards/groups remain available from the dashboard view switcher and Options).
- **Remote PowerShell could hang indefinitely on unreachable targets** — `execute_remote` and `validate_connectivity` now enforce hard timeouts (`REMOTE_PS_TIMEOUT_SECS` = 120 s, `CREDENTIAL_VALIDATION_TIMEOUT_SECS` = 10 s). On timeout, the orphan local `powershell.exe` is killed via `taskkill /F /T /PID`, preventing tokio blocking-pool exhaustion when many hosts are down.
- **SSH command execution could hang indefinitely** — `LinuxRemoteSession::exec` and `exec_with_pty` now enforce `REMOTE_SSH_TIMEOUT_SECS` (120 s) via `tokio::time::timeout`.
- **`reg.exe query` in `launch_remote_registry` could hang for minutes** — each of the three connectivity attempts is now bounded by `REG_QUERY_TIMEOUT_SECS` (10 s) via `tokio::time::timeout`, with the retry sleep moved off the OS thread to `tokio::time::sleep`.
- **Password leaked to `net use` command line on Explore C$** — replaced the `net use \\\\server\\C$ <password> /user:` call with a stdin-fed PowerShell script that calls `New-SmbMapping`, so the password is never visible to other local processes via `Win32_Process.CommandLine`.
- **`cmdkey /pass:` exposure in Remote Registry shortened** — credentials are now cached via a stdin-piped PowerShell wrapper (briefly on `cmdkey.exe`'s command line, unavoidable as `cmdkey` has no stdin password mode) and **deleted via `cmdkey /delete:` 15 seconds after regedit launches** (and immediately if regedit fails to spawn) so the cached credential does not persist in the user profile.
- **`Remove-PSSession` failures were silently swallowed** — replaced `-ErrorAction SilentlyContinue` with an explicit try/catch that surfaces cleanup errors on stderr, so leaked `wsmprovhost.exe` processes can be correlated with their cause.
- **Credential Manager could silently drop the last byte of a malformed password blob** — `WindowsCredentialManager::retrieve` now rejects any blob with an odd byte length (which would otherwise truncate via `chunks_exact(2)`) rather than returning a silently-corrupted password.

### Changed
- **Default Dashboard View is now Table** for new installs. Existing users keep their saved preference. Cards and Groups remain available from the header view switcher and Options.

### Added
- `REMOTE_PS_TIMEOUT_SECS`, `REMOTE_SSH_TIMEOUT_SECS`, `REG_QUERY_TIMEOUT_SECS` constants documenting the hard ceilings on remote execution time
- Unit test `settings_set_all_accepts_table_view_mode` covering the previously-broken `table` round-trip

## [2.1.1] - 2026-04-16

### Fixed
- **Table view sticky header was transparent** — DaisyUI v4 stores theme tokens (`--b1`, `--b2`, `--p`, …) as `oklch` components, not `hsl`. Every `hsl(var(--…))` in `dashboard-minimal.css` therefore resolved to an invalid color and rendered transparent, which let scrolled rows bleed over the pinned header. Switched all 34 occurrences to `oklch(var(--…))`; this also repairs a number of subtler color mismatches on hover/selected states elsewhere on the dashboard.
- **Floating actions menu left behind on view switch / re-render** — the body-attached `#qp-floating-actions-menu` is now explicitly closed on view switch and at the start of every `displayAllServers()`, so its document-level listeners don't leak against a detached DOM.
- **RDP launch showed "Allow access to resources" consent dialog on Windows 11** — all non-essential device redirections (printers, smart cards, WebAuthn, audio capture, drives, USB, COM/POS) are now disabled by default in the generated `.rdp`. Authentication level raised from 0 to 2 to stop the "Unknown publisher" banner for properly-configured servers.
- **Clipboard redirection kept enabled** — copy/paste between host and RDP session is a routine admin workflow and remains on by default.

### Added
- Table view: **drag-to-reorder columns** (drop indicators highlight the target position; order persisted to `qp_table_col_order`)
- Table view: **Actions column moved to position 0** by default
- Table view: **sticky-left first column** — the leftmost column (Actions by default) stays visible while scrolling horizontally
- `scripts/verify.ps1` — single source of truth for repo health verification
- `.github/workflows/ci.yml` — Windows CI quality gate using verify.ps1
- `.github/copilot-instructions.md` — agent collaboration policy
- `.github/pull_request_template.md` — PR checklist template
- `docs/BUILD_FROM_SCRATCH.md` — complete Windows build instructions
- `docs/RELEASING.md` — release process documentation
- Unit tests for `backup.rs` (12 tests) and `platform/ssh.rs` (12 tests)
- `.github/workflows/release.yml` — tag-based release pipeline with checksums

### Changed
- CI now uses `scripts/verify.ps1` as the single gate (replaces old `test.yml`)
- README updated with link to build documentation

## [2.1.0] - 2026-04-16

### Added
- **Table (spreadsheet-style) dashboard view** — new third view mode alongside Cards and Groups. Shows many servers at once in a compact grid with:
  - Sortable columns (click any header)
  - Drag-resizable columns (persisted per-user in `localStorage`)
  - Sticky table header that stays pinned while scrolling
  - Full action parity with Cards (Refresh, Edit, Set Host Credentials, Remote PowerShell/SSH, Explore C$, Manage Services, Manage Processes, Remote Registry, Restart, Shutdown, View Details)
  - Single-click selects + quick probe; double-click launches RDP/SSH
  - Uses the same DaisyUI theme tokens as Cards so all 32 themes are supported
- **Default Dashboard View** setting in Options (`cards` / `groups` / `table`) — synced across windows via Tauri event
- Body-attached floating action menu (`#qp-floating-actions-menu`) so row dropdowns are never clipped by the scrollable table wrapper
- `jsconfig.json` now uses `moduleResolution: "bundler"` (replaces deprecated `node10`)

### Fixed
- Table view header now correctly sticks to the top of the scroll container while scrolling rows
- Table view Actions menu no longer renders behind/under the row or clipped by cell overflow — the menu is positioned with `position: fixed`, flipped upward when near the viewport bottom, and closed on outside click / Escape / scroll

## [2.0.4] - 2025-12-01

### Added
- Linux host support via SSH
- Active Directory LDAP scanning
- Encrypted backup/restore (AES-256)
- Session caching with 5-minute TTL
- Circuit-breaker pattern for failing servers

### Fixed
- WinRM session cleanup (explicit PSSession management)
- Credential Manager DPAPI storage

[Unreleased]: https://github.com/Swatto86/QuickProbe/compare/v2.1.3...HEAD
[2.1.3]: https://github.com/Swatto86/QuickProbe/releases/tag/v2.1.3
[2.1.1]: https://github.com/Swatto86/QuickProbe/releases/tag/v2.1.1
[2.1.0]: https://github.com/Swatto86/QuickProbe/releases/tag/v2.1.0
[2.0.4]: https://github.com/Swatto86/QuickProbe/releases/tag/v2.0.4
