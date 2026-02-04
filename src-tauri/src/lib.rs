//! QuickProbe - Windows server interrogation tool
//!
//! Core library exposing platform-agnostic types and traits.

// Public modules
pub mod backup;
pub mod constants;
pub mod core;
pub mod db;
pub mod logger;
pub mod models;
pub mod normalize;
pub mod updater;
pub mod utils;

// Platform-specific modules
#[cfg(windows)]
pub mod platform;

// Re-export commonly used types
pub use core::{validate_credentials, validate_credentials_basic, CredentialStore};
pub use models::{CredentialProfile, Credentials, SecureString, Username};
pub use utils::{CredentialError, ProbeError, SessionError, ValidationError};
