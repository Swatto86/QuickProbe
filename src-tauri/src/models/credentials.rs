//! Domain model types for QuickProbe
//!
//! SECURITY: Credential types implement Drop to clear sensitive data.

use crate::utils::CredentialError;
use std::fmt;

/// Windows username in various formats
///
/// Valid formats:
/// - `user` (local user)
/// - `.\\user` (explicit local user)
/// - `DOMAIN\\user` (domain user)
/// - `user@domain.com` (UPN format)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Username(String);

impl Username {
    /// Create a new username after validation
    pub fn new(username: impl Into<String>) -> Result<Self, CredentialError> {
        let username = username.into();

        if username.is_empty() {
            return Err(CredentialError::InvalidUsername(
                "Username cannot be empty".to_string(),
            ));
        }

        if username.len() > 256 {
            return Err(CredentialError::InvalidUsername(
                "Username exceeds maximum length (256)".to_string(),
            ));
        }

        Ok(Username(username))
    }

    /// Get the username as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for Username {
    type Error = CredentialError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Username::new(value)
    }
}

impl TryFrom<&str> for Username {
    type Error = CredentialError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Username::new(value)
    }
}

/// Password that zeros memory on drop
///
/// SECURITY: This type never implements Display or Debug in a way that reveals the password.
pub struct SecureString(String);

impl Clone for SecureString {
    fn clone(&self) -> Self {
        SecureString(self.0.clone())
    }
}

impl SecureString {
    /// Create a new secure string
    pub fn new(password: impl Into<String>) -> Self {
        SecureString(password.into())
    }

    /// Get the password as a string slice
    ///
    /// Use this sparingly and only when necessary for API calls.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the length of the password
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the password is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Zero the memory
        // SAFETY: We own this String and are zeroing it before drop
        unsafe {
            let bytes = self.0.as_bytes_mut();
            for byte in bytes {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SECURITY: Never reveal the password content
        write!(f, "SecureString(*** {} bytes ***)", self.0.len())
    }
}

/// Domain credentials for Windows authentication
#[derive(Clone, Debug)]
pub struct Credentials {
    username: Username,
    password: SecureString,
}

impl Credentials {
    /// Create new credentials
    pub fn new(username: Username, password: SecureString) -> Self {
        Credentials { username, password }
    }

    /// Get the username
    pub fn username(&self) -> &Username {
        &self.username
    }

    /// Get the password
    pub fn password(&self) -> &SecureString {
        &self.password
    }
}

/// Reference to a stored credential profile
///
/// This is just a name/identifier, not the actual credentials.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CredentialProfile(String);

impl CredentialProfile {
    /// Default profile name
    pub const DEFAULT: &'static str = "QuickProbe:Default";

    /// Create a new credential profile reference
    pub fn new(name: impl Into<String>) -> Self {
        CredentialProfile(name.into())
    }

    /// Get the profile name as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CredentialProfile {
    fn default() -> Self {
        CredentialProfile(Self::DEFAULT.to_string())
    }
}

impl fmt::Display for CredentialProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_validation() {
        assert!(Username::new("user").is_ok());
        assert!(Username::new("DOMAIN\\user").is_ok());
        assert!(Username::new("user@domain.com").is_ok());
        assert!(Username::new(".\\user").is_ok());
        assert!(Username::new("").is_err());
        assert!(Username::new("a".repeat(300)).is_err());
    }

    #[test]
    fn test_secure_string_drops() {
        let password = SecureString::new("secret");
        assert_eq!(password.len(), 6);
        // Drop happens automatically here
    }

    #[test]
    fn test_secure_string_debug_no_leak() {
        let password = SecureString::new("secret123");
        let debug_output = format!("{:?}", password);
        assert!(!debug_output.contains("secret"));
        assert!(debug_output.contains("9 bytes"));
    }
}
