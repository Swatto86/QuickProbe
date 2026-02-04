//! Retry logic with exponential backoff for transient failures
//!
//! This module provides utilities to retry operations that may fail due to
//! transient network issues, temporary server unavailability, or other
//! recoverable errors.

use rand::Rng;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (not counting the initial attempt)
    pub max_retries: u32,
    /// Initial delay before the first retry
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Multiplier for exponential backoff (typically 2.0)
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 2,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Create a configuration with no retries (fail fast)
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            initial_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            backoff_multiplier: 1.0,
        }
    }

    /// Create a configuration with aggressive retries for critical operations
    pub fn aggressive() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(4),
            backoff_multiplier: 2.0,
        }
    }
}

/// Retry an async operation with exponential backoff
///
/// # Arguments
///
/// * `config` - Retry configuration
/// * `operation` - Async closure that returns Result<T, E>
/// * `is_retryable` - Function to determine if an error is worth retrying
///
/// # Example
///
/// ```ignore
/// use quickprobe::utils::retry::{retry_with_backoff, RetryConfig};
///
/// let result = retry_with_backoff(
///     RetryConfig::default(),
///     || async { connect_to_server("myserver").await },
///     |err| err.contains("timeout") || err.contains("refused"),
/// ).await;
/// ```
pub async fn retry_with_backoff<T, E, F, Fut, P>(
    config: RetryConfig,
    mut operation: F,
    is_retryable: P,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    P: Fn(&E) -> bool,
    E: std::fmt::Display,
{
    let mut attempt = 0;
    let mut delay = config.initial_delay;

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                attempt += 1;

                // If we've exhausted retries or the error is not retryable, fail
                if attempt > config.max_retries || !is_retryable(&err) {
                    return Err(err);
                }

                // Log retry attempt (in debug mode only to avoid spam)
                if cfg!(debug_assertions) {
                    eprintln!(
                        "[retry] Attempt {}/{} failed: {}. Retrying in {:?}...",
                        attempt,
                        config.max_retries + 1,
                        err,
                        delay
                    );
                }

                // Wait before retrying
                sleep(delay).await;

                // Calculate next delay with exponential backoff and jitter
                // Jitter prevents thundering herd when many operations fail simultaneously
                let next_delay_ms = (delay.as_millis() as f64 * config.backoff_multiplier) as u64;
                let base_delay = Duration::from_millis(next_delay_ms).min(config.max_delay);

                // Add ±20% random jitter
                let mut rng = rand::thread_rng();
                let jitter_factor = rng.gen_range(0.8..=1.2);
                let jittered_delay_ms = (base_delay.as_millis() as f64 * jitter_factor) as u64;
                delay = Duration::from_millis(jittered_delay_ms);
            }
        }
    }
}

/// Determines if a WinRM/SSH error is retryable
///
/// Retryable errors include:
/// - Connection timeouts
/// - Connection refused (server might be starting)
/// - Network unreachable (transient network issues)
/// - DNS resolution failures (transient)
/// - "WinRM service not responding" (temporary overload)
///
/// Non-retryable errors include:
/// - Authentication failures
/// - Access denied
/// - Server not found in TrustedHosts
/// - Invalid credentials
pub fn is_transient_error(error_msg: &str) -> bool {
    let lowercase = error_msg.to_lowercase();

    // Retryable patterns
    let retryable_patterns = [
        "timeout",
        "timed out",
        "connection refused",
        "network unreachable",
        "no route to host",
        "temporarily unavailable",
        "service not responding",
        "connection reset",
        "broken pipe",
        "host is down",
        "dns",
        "name resolution",
        "could not resolve",
    ];

    // Non-retryable patterns (authentication/authorization)
    let non_retryable_patterns = [
        "access denied",
        "access is denied",
        "invalid credentials",
        "authentication failed",
        "trustedhosts",
        "logon failure",
        "permission denied",
        "unauthorized",
    ];

    // First check if it's explicitly non-retryable
    for pattern in &non_retryable_patterns {
        if lowercase.contains(pattern) {
            return false;
        }
    }

    // Then check if it matches retryable patterns
    for pattern in &retryable_patterns {
        if lowercase.contains(pattern) {
            return true;
        }
    }

    // Default to non-retryable for unknown errors
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 2);
        assert_eq!(config.initial_delay, Duration::from_millis(500));
        assert_eq!(config.max_delay, Duration::from_secs(5));
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_no_retry_config() {
        let config = RetryConfig::no_retry();
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_aggressive_config() {
        let config = RetryConfig::aggressive();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay, Duration::from_millis(250));
    }

    #[test]
    fn test_is_transient_error_retryable() {
        assert!(is_transient_error("Connection timeout"));
        assert!(is_transient_error("Connection timed out"));
        assert!(is_transient_error("Connection refused"));
        assert!(is_transient_error("Network unreachable"));
        assert!(is_transient_error("WinRM service not responding"));
        assert!(is_transient_error("DNS resolution failed"));
        assert!(is_transient_error("Could not resolve hostname"));
    }

    #[test]
    fn test_is_transient_error_non_retryable() {
        assert!(!is_transient_error("Access denied"));
        assert!(!is_transient_error("Access is denied"));
        assert!(!is_transient_error("Invalid credentials"));
        assert!(!is_transient_error("Authentication failed"));
        assert!(!is_transient_error("Server not in TrustedHosts"));
        assert!(!is_transient_error("Logon failure"));
        assert!(!is_transient_error("Permission denied"));
    }

    #[test]
    fn test_is_transient_error_case_insensitive() {
        assert!(is_transient_error("CONNECTION TIMEOUT"));
        assert!(!is_transient_error("ACCESS DENIED"));
    }

    #[test]
    fn test_is_transient_error_unknown() {
        // Unknown errors should not be retried
        assert!(!is_transient_error("Something went wrong"));
        assert!(!is_transient_error("Unknown error"));
    }

    #[tokio::test]
    async fn test_retry_succeeds_on_first_attempt() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let call_count = AtomicU32::new(0);
        let result = retry_with_backoff(
            RetryConfig::default(),
            || {
                call_count.fetch_add(1, Ordering::SeqCst);
                async { Ok::<i32, String>(42) }
            },
            |_: &String| true,
        )
        .await;

        assert_eq!(result, Ok(42));
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_failures() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let call_count = AtomicU32::new(0);
        let result = retry_with_backoff(
            RetryConfig::default(),
            || {
                let count = call_count.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if count < 3 {
                        Err("Connection timeout".to_string())
                    } else {
                        Ok::<i32, String>(42)
                    }
                }
            },
            |e: &String| is_transient_error(e),
        )
        .await;

        assert_eq!(result, Ok(42));
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_fails_after_max_retries() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let call_count = AtomicU32::new(0);
        let config = RetryConfig {
            max_retries: 2,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(50),
            backoff_multiplier: 2.0,
        };

        let result = retry_with_backoff(
            config,
            || {
                call_count.fetch_add(1, Ordering::SeqCst);
                async { Err::<i32, String>("Connection timeout".to_string()) }
            },
            |e: &String| is_transient_error(e),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(call_count.load(Ordering::SeqCst), 3); // Initial + 2 retries
    }

    #[tokio::test]
    async fn test_retry_fails_on_non_retryable_error() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let call_count = AtomicU32::new(0);
        let result = retry_with_backoff(
            RetryConfig::default(),
            || {
                call_count.fetch_add(1, Ordering::SeqCst);
                async { Err::<i32, String>("Access denied".to_string()) }
            },
            |e: &String| is_transient_error(e),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(call_count.load(Ordering::SeqCst), 1); // No retries for auth errors
    }

    #[tokio::test]
    async fn test_no_retry_config_async() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let call_count = AtomicU32::new(0);
        let result = retry_with_backoff(
            RetryConfig::no_retry(),
            || {
                call_count.fetch_add(1, Ordering::SeqCst);
                async { Err::<i32, String>("Connection timeout".to_string()) }
            },
            |e: &String| is_transient_error(e),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(call_count.load(Ordering::SeqCst), 1); // No retries
    }
}
