//! # Utilities Module
//!
//! Cross-cutting concerns and shared functionality used throughout the application.
//!
//! ## Modules
//!
//! - [`errors`]: Typed error hierarchy using `thiserror` for domain-specific errors
//! - [`retry`]: Exponential backoff retry logic for transient network failures
//!
//! ## Design Notes
//!
//! Error types are defined in this module to avoid circular dependencies between
//! the `core` and `platform` modules. All domain errors inherit from a common
//! hierarchy to enable consistent error handling at the Tauri command boundary.
//!
//! Retry logic uses tokio's async timer and is configurable per operation type.
//! Transient errors (network timeouts, temporary auth failures) are automatically
//! retried with exponential backoff, while permanent errors (invalid credentials,
//! missing permissions) fail immediately.

pub mod errors;
pub mod retry;

pub use errors::{CredentialError, ProbeError, SessionError, ValidationError};
pub use retry::{is_transient_error, retry_with_backoff, RetryConfig};
