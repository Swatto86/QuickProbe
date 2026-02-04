//! # Domain Models
//!
//! Core data structures representing credentials, user profiles, and secure strings.
//!
//! ## Security Design
//!
//! The [`SecureString`] type provides memory-safe credential handling:
//! - Password data is zeroed on drop to prevent leakage via swap/core dumps
//! - Never exposed in `Debug` or `Display` implementations
//! - Uses unsafe code (carefully audited) for memory zeroing
//!
//! Credentials are stored in the Windows Credential Manager on the host machine,
//! never in plaintext files or logs.
//!
//! ## Credential Resolution
//!
//! QuickProbe supports three credential storage profiles:
//! 1. **Default profile** - Used when no specific profile is specified
//! 2. **Host-specific profiles** - Per-server credentials (format: `quickprobe:rdp:<hostname>`)
//! 3. **RDP profile** - Legacy profile for backward compatibility
//!
//! When connecting to a remote host, the system checks profiles in order of specificity:
//! host-specific → RDP profile → default profile.

pub mod credentials;

pub use credentials::{CredentialProfile, Credentials, SecureString, Username};
