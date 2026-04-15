//! Remote restart, shutdown, and ad-hoc PowerShell/SSH execution commands.

use quickprobe::core::session::RemoteSession;
use quickprobe::platform::{LinuxRemoteSession, WindowsRemoteSession};
use std::time::SystemTime;

use super::state::*;
use super::types::*;

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Restart a remote server (Windows or Linux)
#[tauri::command]
pub(crate) async fn remote_restart(server_name: String) -> Result<(), String> {
    let server_name = server_name.trim();

    if server_name.is_empty() {
        return Err("Server name is required".to_string());
    }

    crate::logger::log_info(&format!(
        "remote_restart: Initiating restart for '{}'",
        server_name
    ));

    let os_hint = resolve_host_os_type(server_name).await;
    let (credentials, _) = resolve_host_credentials(server_name).await?;

    if os_hint.eq_ignore_ascii_case("linux") {
        let session = LinuxRemoteSession::connect(server_name.to_string(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        let restart_cmd = "sudo shutdown -r now";

        let result = session.execute_command(restart_cmd).await;

        match result {
            Ok(_) => {
                crate::logger::log_info(&format!(
                    "remote_restart: Successfully initiated restart for '{}' (Linux)",
                    server_name
                ));
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to restart Linux server: {}", e);
                crate::logger::log_error(&format!("remote_restart: {}", error_msg));
                Err(error_msg)
            }
        }
    } else {
        let session = WindowsRemoteSession::connect(server_name.to_string(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        let restart_script = "Restart-Computer -Force".to_string();

        let result = session.execute_powershell(&restart_script).await;

        match result {
            Ok(_) => {
                crate::logger::log_info(&format!(
                    "remote_restart: Successfully initiated restart for '{}' (Windows)",
                    server_name
                ));
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to restart Windows server: {}", e);
                crate::logger::log_error(&format!("remote_restart: {}", error_msg));
                Err(error_msg)
            }
        }
    }
}

/// Shutdown a remote server (Windows or Linux)
#[tauri::command]
pub(crate) async fn remote_shutdown(server_name: String) -> Result<(), String> {
    let server_name = server_name.trim();

    if server_name.is_empty() {
        return Err("Server name is required".to_string());
    }

    crate::logger::log_info(&format!(
        "remote_shutdown: Initiating shutdown for '{}'",
        server_name
    ));

    let os_hint = resolve_host_os_type(server_name).await;
    let (credentials, _) = resolve_host_credentials(server_name).await?;

    if os_hint.eq_ignore_ascii_case("linux") {
        let session = LinuxRemoteSession::connect(server_name.to_string(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        let shutdown_cmd = "sudo shutdown -h now";

        let result = session.execute_command(shutdown_cmd).await;

        match result {
            Ok(_) => {
                crate::logger::log_info(&format!(
                    "remote_shutdown: Successfully initiated shutdown for '{}' (Linux)",
                    server_name
                ));
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to shutdown Linux server: {}", e);
                crate::logger::log_error(&format!("remote_shutdown: {}", error_msg));
                Err(error_msg)
            }
        }
    } else {
        let session = WindowsRemoteSession::connect(server_name.to_string(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        let shutdown_script = "Stop-Computer -Force".to_string();

        let result = session.execute_powershell(&shutdown_script).await;

        match result {
            Ok(_) => {
                crate::logger::log_info(&format!(
                    "remote_shutdown: Successfully initiated shutdown for '{}' (Windows)",
                    server_name
                ));
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to shutdown Windows server: {}", e);
                crate::logger::log_error(&format!("remote_shutdown: {}", error_msg));
                Err(error_msg)
            }
        }
    }
}

/// Execute a PowerShell command on a remote Windows host
#[tauri::command]
pub(crate) async fn execute_remote_powershell(
    server_name: String,
    command: String,
) -> Result<RemotePowerShellResponse, String> {
    let start = SystemTime::now();
    crate::logger::log_debug(&format!(
        "execute_remote_powershell: START '{}' command='{}'",
        server_name,
        command.chars().take(100).collect::<String>()
    ));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }
    if command.trim().is_empty() {
        return Err("Command cannot be empty".to_string());
    }

    // Check for potentially dangerous commands and warn in logs
    let command_lower = command.to_lowercase();
    let dangerous_patterns = [
        "remove-item",
        "del ",
        "rm ",
        "format-",
        "clear-disk",
        "stop-computer",
        "restart-computer",
    ];
    for pattern in dangerous_patterns {
        if command_lower.contains(pattern) {
            crate::logger::log_warn(&format!(
                "execute_remote_powershell: Potentially destructive command detected on '{}': {}",
                server_name,
                command.chars().take(200).collect::<String>()
            ));
            break;
        }
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    if os_hint.eq_ignore_ascii_case("linux") {
        return Err("Remote PowerShell is only available for Windows hosts".to_string());
    }

    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    let session = WindowsRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

    // Wrap in try/catch to capture errors gracefully
    let ps_command = format!(
        r#"
$ErrorActionPreference = 'Continue'
try {{
    {}
}} catch {{
    Write-Error $_.Exception.Message
}}
"#,
        command
    );

    match session.execute_powershell(&ps_command).await {
        Ok(output) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            crate::logger::log_debug(&format!(
                "execute_remote_powershell: SUCCESS '{}' {}ms output_len={}",
                server_name,
                elapsed_ms,
                output.len()
            ));

            Ok(RemotePowerShellResponse {
                success: true,
                output,
                error: None,
            })
        }
        Err(e) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            let error_msg = e.to_string();
            crate::logger::log_warn(&format!(
                "execute_remote_powershell: ERROR '{}' {}ms error='{}'",
                server_name, elapsed_ms, error_msg
            ));

            Ok(RemotePowerShellResponse {
                success: false,
                output: String::new(),
                error: Some(error_msg),
            })
        }
    }
}

/// Execute a shell command on a remote Linux host via SSH
#[tauri::command]
pub(crate) async fn execute_remote_ssh(
    server_name: String,
    command: String,
) -> Result<RemoteSshResponse, String> {
    let start = SystemTime::now();
    crate::logger::log_debug(&format!(
        "execute_remote_ssh: START '{}' command='{}'",
        server_name,
        command.chars().take(100).collect::<String>()
    ));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }
    if command.trim().is_empty() {
        return Err("Command cannot be empty".to_string());
    }

    // Check for potentially dangerous commands and warn in logs
    let command_lower = command.to_lowercase();
    let dangerous_patterns = [
        "rm -rf",
        "rm -r",
        "dd if=",
        "mkfs",
        "shutdown",
        "reboot",
        "> /dev/",
        "chmod 777",
        ":(){ :|:& };:",
    ];
    for pattern in dangerous_patterns {
        if command_lower.contains(pattern) {
            crate::logger::log_warn(&format!(
                "execute_remote_ssh: Potentially destructive command detected on '{}': {}",
                server_name,
                command.chars().take(200).collect::<String>()
            ));
            break;
        }
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    if !os_hint.eq_ignore_ascii_case("linux") {
        return Err("Remote SSH is only available for Linux hosts".to_string());
    }

    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

    match session.execute_command(&command).await {
        Ok(output) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            crate::logger::log_debug(&format!(
                "execute_remote_ssh: SUCCESS '{}' {}ms output_len={}",
                server_name,
                elapsed_ms,
                output.len()
            ));

            Ok(RemoteSshResponse {
                success: true,
                output,
                error: None,
            })
        }
        Err(e) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            let error_msg = e.to_string();
            crate::logger::log_warn(&format!(
                "execute_remote_ssh: ERROR '{}' {}ms error='{}'",
                server_name, elapsed_ms, error_msg
            ));

            Ok(RemoteSshResponse {
                success: false,
                output: String::new(),
                error: Some(error_msg),
            })
        }
    }
}

/// Execute a shell command on a remote Linux host via SSH with PTY (terminal) support.
#[tauri::command]
pub(crate) async fn execute_remote_ssh_pty(
    server_name: String,
    command: String,
    cols: Option<u32>,
    rows: Option<u32>,
) -> Result<RemoteSshResponse, String> {
    let start = SystemTime::now();
    let cols = cols.unwrap_or(120);
    let rows = rows.unwrap_or(40);

    crate::logger::log_debug(&format!(
        "execute_remote_ssh_pty: START '{}' command='{}' cols={} rows={}",
        server_name,
        command.chars().take(100).collect::<String>(),
        cols,
        rows
    ));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }
    if command.trim().is_empty() {
        return Err("Command cannot be empty".to_string());
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    if !os_hint.eq_ignore_ascii_case("linux") {
        return Err("Remote SSH is only available for Linux hosts".to_string());
    }

    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

    match session.execute_command_with_pty(&command, cols, rows).await {
        Ok(output) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            crate::logger::log_debug(&format!(
                "execute_remote_ssh_pty: SUCCESS '{}' {}ms output_len={}",
                server_name,
                elapsed_ms,
                output.len()
            ));

            Ok(RemoteSshResponse {
                success: true,
                output,
                error: None,
            })
        }
        Err(e) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            let error_msg = e.to_string();
            crate::logger::log_warn(&format!(
                "execute_remote_ssh_pty: ERROR '{}' {}ms error='{}'",
                server_name, elapsed_ms, error_msg
            ));

            Ok(RemoteSshResponse {
                success: false,
                output: String::new(),
                error: Some(error_msg),
            })
        }
    }
}
