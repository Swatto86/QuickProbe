//! Platform-agnostic credential storage trait

use crate::models::{CredentialProfile, Credentials};
use crate::utils::CredentialError;
use async_trait::async_trait;

/// Platform-agnostic credential storage
///
/// Implementations handle platform-specific secure storage (Windows Credential Manager,
/// macOS Keychain, Linux Secret Service, etc.)
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Store credentials under a profile name
    ///
    /// # Arguments
    /// * `profile` - Profile identifier (e.g., "QuickProbe:Default")
    /// * `creds` - Credentials to store securely
    ///
    /// # Security
    /// - Credentials MUST be stored encrypted
    /// - MUST use OS-provided secure storage
    /// - MUST NOT log password values
    async fn store(
        &self,
        profile: &CredentialProfile,
        creds: &Credentials,
    ) -> Result<(), CredentialError>;

    /// Retrieve credentials by profile
    ///
    /// # Arguments
    /// * `profile` - Profile identifier
    ///
    /// # Returns
    /// * `Ok(Some(credentials))` - If credentials exist
    /// * `Ok(None)` - If no credentials stored (not an error)
    /// * `Err(CredentialError)` - If an error occurred during retrieval
    async fn retrieve(
        &self,
        profile: &CredentialProfile,
    ) -> Result<Option<Credentials>, CredentialError>;

    /// Check if profile exists
    ///
    /// # Arguments
    /// * `profile` - Profile identifier
    async fn exists(&self, profile: &CredentialProfile) -> Result<bool, CredentialError>;

    /// Delete a profile
    ///
    /// # Arguments
    /// * `profile` - Profile identifier
    ///
    /// # Returns
    /// * `Ok(())` - Success (idempotent - succeeds even if profile doesn't exist)
    async fn delete(&self, profile: &CredentialProfile) -> Result<(), CredentialError>;
}
