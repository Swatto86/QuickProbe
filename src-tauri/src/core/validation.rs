//! Credential validation logic
//!
//! Validates Windows credentials using Windows account validation.

use crate::models::{Credentials, Username};
use crate::utils::ValidationError;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

/// Windows flag to create process without a console window
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Validate Windows credentials using Windows account validation
///
/// This uses .NET's PrincipalContext.ValidateCredentials to verify the credentials
/// work for both local machine accounts and domain accounts. Automatically detects
/// the account type based on username format.
///
/// # Arguments
/// * `credentials` - Credentials to validate
///
/// # Returns
/// * `Ok(())` - Credentials are valid
/// * `Err(ValidationError)` - Credentials are invalid or validation failed
///
/// # Security
/// - Credentials are passed to PowerShell via stdin (JSON), not via process arguments
/// - Password is never logged
pub async fn validate_credentials(credentials: &Credentials) -> Result<(), ValidationError> {
    #[derive(serde::Serialize)]
    struct ValidatePayload<'a> {
        username: &'a str,
        password: &'a str,
    }

    let payload = ValidatePayload {
        username: credentials.username().as_str(),
        password: credentials.password().as_str(),
    };

    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| ValidationError::Network(format!("Failed to serialize payload: {}", e)))?;

    // PowerShell script that validates credentials using .NET.
    // SECURITY: Secrets are read from stdin and never appear in command-line arguments.
    let script = r#"
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { throw 'No input provided' }
    $payload = $raw | ConvertFrom-Json

    $username = [string]$payload.username
    $password = [string]$payload.password

    # Determine if this is a domain account or local account
    if ($username -match '@') {
        # UPN format (user@domain.com) - use domain context
        $domain = $username.Split('@')[1]
        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $contextType, $domain
        $isValid = $principalContext.ValidateCredentials($username, $password)
    } elseif ($username -match '\\') {
        # Domain\User format - use domain context
        $parts = $username.Split('\\')
        $domain = $parts[0]
        $user = $parts[1]
        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $contextType, $domain
        $isValid = $principalContext.ValidateCredentials($user, $password)
    } else {
        # No domain specified - assume local machine account
        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $contextType, $env:COMPUTERNAME
        $isValid = $principalContext.ValidateCredentials($username, $password)
    }

    if ($isValid) {
        Write-Output 'SUCCESS'
        exit 0
    } else {
        Write-Error 'Invalid credentials'
        exit 1
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"#;

    // Execute PowerShell - hide window on Windows.
    // Bound the validation to avoid hanging UI when domain lookups are slow.
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| ValidationError::Network(format!("Failed to start PowerShell: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload_json.as_bytes())
            .await
            .map_err(|e| {
                ValidationError::Network(format!("Failed to write to PowerShell stdin: {}", e))
            })?;
    } else {
        return Err(ValidationError::Network(
            "Failed to open PowerShell stdin".to_string(),
        ));
    }

    let output = timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .map_err(|_| ValidationError::Network("Credential validation timed out".to_string()))?
        .map_err(|e| ValidationError::Network(format!("Failed to execute PowerShell: {}", e)))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Log the validation failure for diagnostics
        crate::logger::log_error(&format!(
            "Credential validation failed - PowerShell stderr: {}",
            stderr.trim()
        ));

        // Parse error to determine failure reason
        if stderr.contains("Invalid credentials") {
            Err(ValidationError::InvalidCredentials)
        } else {
            Err(ValidationError::Network(format!(
                "Validation failed: {}",
                stderr.trim()
            )))
        }
    }
}

/// Simpler validation that just checks if username format is valid
/// and password is not empty (for testing without WinRM)
pub fn validate_credentials_basic(
    username: &str,
    password: &str,
) -> Result<Username, ValidationError> {
    if username.is_empty() {
        return Err(ValidationError::InvalidCredentials);
    }

    if password.is_empty() {
        return Err(ValidationError::InvalidCredentials);
    }

    Username::new(username).map_err(|_| ValidationError::InvalidCredentials)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SecureString;

    #[test]
    fn test_basic_validation() {
        assert!(validate_credentials_basic("user", "password").is_ok());
        assert!(validate_credentials_basic("DOMAIN\\user", "password").is_ok());
        assert!(validate_credentials_basic("", "password").is_err());
        assert!(validate_credentials_basic("user", "").is_err());
    }

    #[tokio::test]
    async fn test_invalid_credentials() {
        let creds = Credentials::new(
            Username::new("InvalidUser123456").unwrap(),
            SecureString::new("InvalidPassword123456"),
        );

        let result = validate_credentials(&creds).await;
        assert!(result.is_err());
    }
}
