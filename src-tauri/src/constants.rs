//! # Application-Wide Constants
//!
//! Centralized configuration values and magic numbers used throughout QuickProbe.
//!
//! ## Design Rationale
//!
//! Constants are defined here (rather than scattered across modules) to:
//! - Make configuration changes easier (single source of truth)
//! - Improve discoverability (grep for constant name finds definition + all uses)
//! - Enable environment-based overrides in the future
//! - Document WHY each value was chosen
//!
//! ## Usage
//!
//! ```rust
//! use quickprobe::constants::*;
//!
//! let timeout = Duration::from_secs(CREDENTIAL_VALIDATION_TIMEOUT_SECS);
//! ```

/// Windows API flag to create a process without a visible console window
///
/// Used when launching mstsc.exe for RDP connections to prevent
/// a flash of command prompt window.
#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x08000000;

// ============================================================================
// Timeouts and Performance Limits
// ============================================================================

/// Maximum time to wait for credential validation before timing out
///
/// **Rationale**: 10 seconds allows for:
/// - Network round-trip to remote server
/// - WinRM/SSH auth handshake
/// - Slow domain controllers
///
///   But prevents indefinite hangs on unreachable hosts.
pub const CREDENTIAL_VALIDATION_TIMEOUT_SECS: u64 = 10;

/// TCP connection timeout for reachability probes (milliseconds)
///
/// **Rationale**: 1200ms (1.2 seconds) is:
/// - Fast enough for responsive UI (users don't wait long)
/// - Slow enough for typical LAN/WAN latency
/// - Balances speed vs. false negatives on slow networks
pub const TCP_PROBE_TIMEOUT_MS: u64 = 1200;

/// Maximum backup file size (bytes)
///
/// **Rationale**: 100 MB limit prevents:
/// - Loading enormous malicious files into memory
/// - Out-of-memory crashes
/// - Accidental import of non-backup files
///
///   Legitimate backups are typically <1 MB.
pub const MAX_BACKUP_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB

// ============================================================================
// Network Defaults
// ============================================================================

/// Default TCP ports to probe for reachability checks
///
/// - **3389**: RDP (Remote Desktop Protocol)
/// - **5985**: WinRM HTTP (PowerShell Remoting)
///
/// These are the two most common ports for Windows server management.
pub const DEFAULT_TCP_PORTS: &[u16] = &[3389, 5985];

/// Default RDP port
///
/// Used when launching RDP connections without explicit port override.
pub const DEFAULT_RDP_PORT: u16 = 3389;

// ============================================================================
// Windows Registry
// ============================================================================

/// Registry key path for Windows auto-start applications
///
/// Located at: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
///
/// QuickProbe writes/deletes a value here to enable "Start with Windows" feature.
pub const REGISTRY_RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

// ============================================================================
// Database / Storage
// ============================================================================

/// Key-value store scope type for global settings
///
/// Used with KV_SCOPE_ID to form composite key for settings storage.
pub const KV_SCOPE_TYPE: &str = "global";

/// Key-value store scope ID for default/global settings
///
/// Combined with KV_SCOPE_TYPE for settings like:
/// - Dashboard cache
/// - Runtime mode tracking
/// - Pre-restore snapshots
pub const KV_SCOPE_ID: &str = "default";

/// KV key that records the current login mode.
///
/// Values: `"domain"` (credentials validated against a DC) or `"local"`
/// (format-only validation for non-domain-joined machines).
/// Cleared on logout so the next session starts fresh.
pub const KV_LOGIN_MODE: &str = "qp_login_mode";

// ============================================================================
// Security / Validation
// ============================================================================

/// Minimum password length for backup encryption
///
/// **Rationale**: 8 characters is:
/// - Industry standard minimum
/// - Prevents trivially weak passwords (e.g., "pass", "1234")
/// - Still allows reasonably memorable passphrases
/// - Note: Backup encryption uses deprecated ZipCrypto (see P0.2 issue)
pub const MIN_BACKUP_PASSWORD_LENGTH: usize = 8;

/// Maximum hostname length (characters)
///
/// **Rationale**: DNS hostnames limited to 253 characters (RFC 1035),
/// but 255 gives buffer for display/UI and matches common validation.
pub const MAX_HOSTNAME_LENGTH: usize = 255;
