//! Authentication commands: login, logout, credential checking, login mode.

use quickprobe::constants::*;
use quickprobe::models::{CredentialProfile, Credentials, SecureString, Username};
use quickprobe::platform::WindowsCredentialManager;
use quickprobe::utils::ValidationError;
use quickprobe::{validate_credentials, validate_credentials_basic, CredentialStore};
use tokio::time::{timeout, Duration};

use super::helpers::kv_get_value;
use super::helpers::kv_set_value;
use super::state::clear_session_cache;
use super::types::*;

// ---------------------------------------------------------------------------
// Login mode helpers
// ---------------------------------------------------------------------------

/// Persist the current login mode (`"domain"` or `"local"`) in the KV store.
pub(crate) fn set_login_mode(mode: &str) -> Result<(), String> {
    kv_set_value(KV_LOGIN_MODE, mode)
}

/// Read the persisted login mode. Returns `"none"` when no mode has been set.
pub(crate) fn read_login_mode() -> String {
    kv_get_value(KV_LOGIN_MODE)
        .ok()
        .flatten()
        .unwrap_or_else(|| "none".to_string())
}

/// Clear the persisted login mode (called on logout).
pub(crate) fn clear_login_mode() -> Result<(), String> {
    kv_set_value(KV_LOGIN_MODE, "none")
}

pub(crate) async fn run_bounded_credential_validation(
    credentials: &Credentials,
    op_label: &str,
) -> Result<(), String> {
    match timeout(
        Duration::from_secs(CREDENTIAL_VALIDATION_TIMEOUT_SECS),
        validate_credentials(credentials),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(ValidationError::InvalidCredentials)) => Err("Invalid credentials".to_string()),
        Ok(Err(e)) => Err(format!(
            "Credential validation failed ({}): {}",
            op_label, e
        )),
        Err(_) => Err("Credential validation timed out".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tauri IPC commands
// ---------------------------------------------------------------------------

/// Login command - validates credentials and saves to Windows Credential Manager
#[tauri::command]
pub(crate) async fn login(username: String, password: String) -> Result<LoginResponse, String> {
    let username = match Username::new(username) {
        Ok(u) => u,
        Err(e) => {
            return Ok(LoginResponse {
                success: false,
                error: Some(format!("Invalid username: {}", e)),
            });
        }
    };

    let credentials = Credentials::new(username.clone(), SecureString::new(password));

    match run_bounded_credential_validation(&credentials, "login").await {
        Ok(_) => {
            let credential_store = WindowsCredentialManager::new();
            let profile = CredentialProfile::default();

            if let Err(e) = credential_store.store(&profile, &credentials).await {
                return Ok(LoginResponse {
                    success: false,
                    error: Some(format!("Failed to save credentials: {}", e)),
                });
            }

            let _ = set_login_mode("domain");
            clear_session_cache().await;

            Ok(LoginResponse {
                success: true,
                error: None,
            })
        }
        Err(e) => Ok(LoginResponse {
            success: false,
            error: Some(e.to_string()),
        }),
    }
}

/// Local-mode login — validates format only, no domain controller required.
#[tauri::command]
pub(crate) async fn login_local_mode(
    username: String,
    password: String,
) -> Result<LoginResponse, String> {
    let username = match validate_credentials_basic(&username, &password) {
        Ok(u) => u,
        Err(e) => {
            return Ok(LoginResponse {
                success: false,
                error: Some(format!("Invalid credentials: {}", e)),
            });
        }
    };

    let credentials = Credentials::new(username, SecureString::new(password));

    let credential_store = WindowsCredentialManager::new();
    let profile = CredentialProfile::default();

    if let Err(e) = credential_store.store(&profile, &credentials).await {
        return Ok(LoginResponse {
            success: false,
            error: Some(format!("Failed to save credentials: {}", e)),
        });
    }

    set_login_mode("local")?;
    clear_session_cache().await;

    crate::logger::log_info(&format!(
        "login_local_mode: stored credentials for user '{}'",
        credentials.username().as_str()
    ));

    Ok(LoginResponse {
        success: true,
        error: None,
    })
}

/// Returns the current login mode: `"domain"`, `"local"`, or `"none"`.
#[tauri::command]
pub(crate) fn get_login_mode() -> Result<String, String> {
    Ok(read_login_mode())
}

/// Logout command - deletes credentials from Windows Credential Manager
#[tauri::command]
pub(crate) async fn logout(app: tauri::AppHandle) -> Result<(), String> {
    let credential_store = WindowsCredentialManager::new();
    let profile = CredentialProfile::default();

    credential_store
        .delete(&profile)
        .await
        .map_err(|e| format!("Failed to delete credentials: {}", e))?;

    let _ = clear_login_mode();
    clear_session_cache().await;

    let _ = &app;

    Ok(())
}

#[allow(dead_code)]
pub(crate) fn has_saved_credentials_sync() -> Result<bool, String> {
    tauri::async_runtime::block_on(async {
        let credential_store = WindowsCredentialManager::new();
        let profile = CredentialProfile::default();

        match credential_store.retrieve(&profile).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(format!("Failed to check credentials: {}", e)),
        }
    })
}

/// Check for saved credentials
#[tauri::command]
pub(crate) async fn check_saved_credentials() -> Result<CredentialsCheckResponse, String> {
    let credential_store = WindowsCredentialManager::new();
    let profile = CredentialProfile::default();
    let mode = read_login_mode();

    match credential_store.retrieve(&profile).await {
        Ok(Some(credentials)) => Ok(CredentialsCheckResponse {
            has_credentials: true,
            username: Some(credentials.username().as_str().to_string()),
            login_mode: mode,
        }),
        Ok(None) => Ok(CredentialsCheckResponse {
            has_credentials: false,
            username: None,
            login_mode: "none".to_string(),
        }),
        Err(e) => Err(format!("Failed to check credentials: {}", e)),
    }
}

/// Auto-login using saved credentials without exposing passwords to the UI
#[tauri::command]
pub(crate) async fn login_with_saved_credentials() -> Result<LoginResponse, String> {
    crate::logger::log_info("login_with_saved_credentials: START");
    let credential_store = WindowsCredentialManager::new();
    let profile = CredentialProfile::default();

    let credentials = match credential_store.retrieve(&profile).await {
        Ok(Some(credentials)) => credentials,
        Ok(None) => {
            crate::logger::log_warn("login_with_saved_credentials: No saved credentials found");
            return Ok(LoginResponse {
                success: false,
                error: Some("No saved credentials found".to_string()),
            });
        }
        Err(e) => {
            crate::logger::log_error(&format!(
                "login_with_saved_credentials: Failed to retrieve credentials: {}",
                e
            ));
            return Err(format!("Failed to retrieve credentials: {}", e));
        }
    };

    let username = credentials.username().as_str();
    crate::logger::log_info(&format!(
        "login_with_saved_credentials: Validating credentials for user: {}",
        username
    ));

    match run_bounded_credential_validation(&credentials, "login_with_saved_credentials").await {
        Ok(_) => {
            crate::logger::log_info(&format!(
                "login_with_saved_credentials: SUCCESS for user: {}",
                username
            ));
            Ok(LoginResponse {
                success: true,
                error: None,
            })
        }
        Err(e) => {
            crate::logger::log_error(&format!(
                "login_with_saved_credentials: FAILED for user: {} - {}",
                username, e
            ));
            Ok(LoginResponse {
                success: false,
                error: Some(e.to_string()),
            })
        }
    }
}
