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

/// Replace every occurrence of `secret` in `text` with a redaction marker.
///
/// Returns `text` unchanged when `secret` is empty. `str::replace` with an
/// empty pattern matches between every character, which would otherwise turn a
/// "redacted" error message into garbage (`<redacted>S<redacted>e...`) whenever
/// a credential happens to have an empty password.
pub fn redact_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        text.to_string()
    } else {
        text.replace(secret, "<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::redact_secret;

    #[test]
    fn redact_secret_replaces_non_empty() {
        assert_eq!(
            redact_secret("login as hunter2 failed", "hunter2"),
            "login as <redacted> failed"
        );
    }

    #[test]
    fn redact_secret_empty_password_is_noop() {
        // An empty pattern must not be inserted between every character.
        let msg = "Server DC01 unreachable";
        assert_eq!(redact_secret(msg, ""), msg);
    }
}
