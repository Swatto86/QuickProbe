//! Windows Credential Manager implementation
//!
//! This module contains all unsafe Windows API code for credential storage.
//! Based on QuickConnect's proven credential manager implementation.

use crate::core::CredentialStore;
use crate::models::{CredentialProfile, Credentials, SecureString, Username};
use crate::utils::CredentialError;
use async_trait::async_trait;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};

/// Windows Credential Manager implementation
///
/// Uses Windows Credential Manager (CredRead/CredWrite/CredDelete APIs) to
/// securely store credentials encrypted by DPAPI.
///
/// # Security
/// - Credentials encrypted at rest using DPAPI
/// - Keys tied to user account
/// - Credentials never logged or exposed
pub struct WindowsCredentialManager;

impl WindowsCredentialManager {
    /// Create a new Windows credential manager instance
    pub fn new() -> Self {
        WindowsCredentialManager
    }
}

impl Default for WindowsCredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialStore for WindowsCredentialManager {
    async fn store(
        &self,
        profile: &CredentialProfile,
        creds: &Credentials,
    ) -> Result<(), CredentialError> {
        // Delegate to synchronous implementation (Windows APIs are synchronous)
        self.store_sync(profile, creds)
    }

    async fn retrieve(
        &self,
        profile: &CredentialProfile,
    ) -> Result<Option<Credentials>, CredentialError> {
        // Delegate to synchronous implementation
        self.retrieve_sync(profile)
    }

    async fn exists(&self, profile: &CredentialProfile) -> Result<bool, CredentialError> {
        Ok(self.retrieve_sync(profile)?.is_some())
    }

    async fn delete(&self, profile: &CredentialProfile) -> Result<(), CredentialError> {
        // Delegate to synchronous implementation
        self.delete_sync(profile)
    }
}

impl WindowsCredentialManager {
    /// Synchronous store implementation
    fn store_sync(
        &self,
        profile: &CredentialProfile,
        creds: &Credentials,
    ) -> Result<(), CredentialError> {
        unsafe {
            // Convert strings to UTF-16 (wide) format required by Windows APIs
            // The chain(std::iter::once(0)) adds a null terminator
            let password_wide: Vec<u16> = OsStr::new(creds.password().as_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let target_name: Vec<u16> = OsStr::new(profile.as_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let username_wide: Vec<u16> = OsStr::new(creds.username().as_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // Build CREDENTIALW structure for Windows Credential Manager
            // SAFETY: All pointers are valid for the duration of the CredWriteW call
            let cred = CREDENTIALW {
                Flags: CRED_FLAGS(0),
                Type: CRED_TYPE_GENERIC,
                TargetName: PWSTR(target_name.as_ptr() as *mut u16),
                Comment: PWSTR::null(),
                LastWritten: FILETIME::default(),
                // Size in BYTES (UTF-16 chars are 2 bytes each)
                CredentialBlobSize: (password_wide.len() * 2) as u32,
                CredentialBlob: password_wide.as_ptr() as *mut u8,
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: std::ptr::null_mut(),
                TargetAlias: PWSTR::null(),
                UserName: PWSTR(username_wide.as_ptr() as *mut u16),
            };

            // Call Windows API to store credential
            CredWriteW(&cred, 0).map_err(|e| {
                CredentialError::Platform(format!(
                    "Failed to save credentials for profile '{}': {:?}",
                    profile.as_str(),
                    e
                ))
            })?;
        }

        Ok(())
    }

    /// Synchronous retrieve implementation
    fn retrieve_sync(
        &self,
        profile: &CredentialProfile,
    ) -> Result<Option<Credentials>, CredentialError> {
        unsafe {
            let target_name: Vec<u16> = OsStr::new(profile.as_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut pcred = std::ptr::null_mut();

            match CredReadW(
                PCWSTR::from_raw(target_name.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut pcred,
            ) {
                Ok(_) => {
                    // SAFETY: pcred is valid after successful CredReadW
                    let cred = &*(pcred as *const CREDENTIALW);

                    // Extract username
                    let username = if !cred.UserName.is_null() {
                        PWSTR::from_raw(cred.UserName.0).to_string().map_err(|e| {
                            CredentialError::Platform(format!(
                                "Failed to decode username for profile '{}': {:?}",
                                profile.as_str(),
                                e
                            ))
                        })?
                    } else {
                        return Err(CredentialError::Platform(
                            "Username is null in stored credential".to_string(),
                        ));
                    };

                    // Extract password from credential blob (stored as UTF-16)
                    let password_bytes = std::slice::from_raw_parts(
                        cred.CredentialBlob,
                        cred.CredentialBlobSize as usize,
                    );

                    // Convert byte pairs to u16 values (UTF-16 characters)
                    let password_wide: Vec<u16> = password_bytes
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();

                    // Decode UTF-16 to Rust String
                    let password = String::from_utf16(&password_wide)
                        .map_err(|e| {
                            CredentialError::Platform(format!(
                                "Failed to decode password for profile '{}': {:?}",
                                profile.as_str(),
                                e
                            ))
                        })?
                        .trim_end_matches('\0')
                        .to_string();

                    // CRITICAL: Free the credential allocated by Windows
                    CredFree(pcred as *const _);

                    Ok(Some(Credentials::new(
                        Username::new(username)?,
                        SecureString::new(password),
                    )))
                }
                Err(_) => {
                    // Credential not found - this is not an error, just None
                    Ok(None)
                }
            }
        }
    }

    /// Synchronous delete implementation
    fn delete_sync(&self, profile: &CredentialProfile) -> Result<(), CredentialError> {
        unsafe {
            let target_name: Vec<u16> = OsStr::new(profile.as_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // CredDeleteW returns error if credential doesn't exist,
            // but we treat this as success (idempotent delete)
            let result = CredDeleteW(PCWSTR::from_raw(target_name.as_ptr()), CRED_TYPE_GENERIC, 0);

            match result {
                Ok(_) => Ok(()),
                Err(e) => {
                    // Check if error is "not found" - treat as success
                    // ERROR_NOT_FOUND = 0x80070490
                    let error_code = e.code().0;
                    if error_code == 0x80070490u32 as i32 {
                        Ok(())
                    } else {
                        Err(CredentialError::Platform(format!(
                            "Failed to delete credentials for profile '{}': {:?}",
                            profile.as_str(),
                            e
                        )))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_credential_roundtrip() {
        let store = WindowsCredentialManager::new();
        let profile = CredentialProfile::new("QuickProbe:Test");

        let creds = Credentials::new(
            Username::new("testuser").unwrap(),
            SecureString::new("testpass123"),
        );

        // Store
        store.store(&profile, &creds).await.unwrap();

        // Retrieve
        let retrieved = store.retrieve(&profile).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.username().as_str(), "testuser");
        assert_eq!(retrieved.password().as_str(), "testpass123");

        // Delete
        store.delete(&profile).await.unwrap();

        // Verify deleted
        let after_delete = store.retrieve(&profile).await.unwrap();
        assert!(after_delete.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_succeeds() {
        let store = WindowsCredentialManager::new();
        let profile = CredentialProfile::new("QuickProbe:NonExistent");

        // Should succeed even if it doesn't exist
        store.delete(&profile).await.unwrap();
    }
}
