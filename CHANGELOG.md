# Changelog

All notable changes to QuickProbe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/Swatto86/QuickProbe/compare/v2.0.4...HEAD
[2.0.4]: https://github.com/Swatto86/QuickProbe/releases/tag/v2.0.4
