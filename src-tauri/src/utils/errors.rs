//! Error types for QuickProbe
//!
//! All error types use thiserror for clean error handling.
//! SECURITY: Error messages MUST NOT contain passwords or sensitive data.

use std::time::Duration;

/// Top-level error type for probe operations
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("Session error: {0}")]
    Session(#[from] SessionError),

    #[error("Timeout after {0:?}")]
    Timeout(Duration),

    #[error("Parse error: {0}")]
    Parse(String),
}

/// Errors from remote session operations
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Authentication failed")]
    Authentication,

    #[error("WinRM error: {0}")]
    WinRm(String),

    #[error("Command execution failed: {0}")]
    CommandFailed(String),
}

/// Errors from credential storage operations
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("Credential not found: {0}")]
    NotFound(String),

    #[error("Windows Credential Manager error: {0}")]
    Platform(String),

    #[error("Invalid credential format")]
    InvalidFormat,

    #[error("Invalid username format: {0}")]
    InvalidUsername(String),
}

/// Errors from credential validation
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("WinRM not available locally")]
    WinRmUnavailable,

    #[error("Network error: {0}")]
    Network(String),

    #[error("Timeout during validation")]
    Timeout,
}
