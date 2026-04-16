//! RDP, SSH, Explorer share, and Remote Registry launcher commands.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use quickprobe::models::{CredentialProfile, Credentials, SecureString, Username};
use quickprobe::platform::WindowsCredentialManager;
use quickprobe::CredentialStore;

use super::helpers::*;
use super::state::*;

// ---------------------------------------------------------------------------
// RDP helpers
// ---------------------------------------------------------------------------

/// Validate RDP parameters to prevent CRLF injection attacks
pub(crate) fn validate_rdp_parameter(value: &str, param_name: &str) -> Result<(), String> {
    // Check for CRLF injection attempts (CVE-class vulnerability)
    if value.contains('\r') || value.contains('\n') {
        return Err(format!(
            "Invalid {}: contains newline characters (potential injection attack)",
            param_name
        ));
    }

    // Check for null bytes
    if value.contains('\0') {
        return Err(format!("Invalid {}: contains null bytes", param_name));
    }

    // Check for excessive length (RDP fields have practical limits)
    if value.len() > 256 {
        return Err(format!(
            "Invalid {}: exceeds maximum length of 256 characters",
            param_name
        ));
    }

    // Hostname-specific validation
    if param_name == "hostname" {
        if value.is_empty() {
            return Err("Hostname cannot be empty".to_string());
        }

        // Check for path traversal attempts in hostname (could write to Startup folder)
        if value.contains("..") || value.contains('\\') || value.contains('/') {
            return Err(
                "Invalid hostname: contains path separators or traversal sequences".to_string(),
            );
        }

        // Basic hostname validation: alphanumeric, dots, hyphens, colons (for ports)
        if !value
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == ':')
        {
            return Err("Invalid hostname: contains invalid characters (only alphanumeric, dots, hyphens, and colons allowed)".to_string());
        }
    }

    Ok(())
}

/// Generates RDP file content (.rdp) with optimized settings for server management.
pub(crate) fn build_rdp_content(host: &str, username: &str, domain: &str) -> String {
    let user_field = if domain.is_empty() {
        username.to_string()
    } else {
        format!("{}\\{}", domain, username)
    };

    format!(
        concat!(
            "screen mode id:i:2\r\n",
            "desktopwidth:i:1920\r\n",
            "desktopheight:i:1080\r\n",
            "session bpp:i:32\r\n",
            "full address:s:{host}\r\n",
            "compression:i:1\r\n",
            "keyboardhook:i:2\r\n",
            // Disable audio capture & video playback redirection (these are
            // the primary triggers for the "allow access to microphones /
            // recording devices" consent prompt).
            "audiocapturemode:i:0\r\n",
            "videoplaybackmode:i:0\r\n",
            "connection type:i:2\r\n",
            "networkautodetect:i:1\r\n",
            "bandwidthautodetect:i:1\r\n",
            "enableworkspacereconnect:i:1\r\n",
            "disable wallpaper:i:0\r\n",
            "allow desktop composition:i:0\r\n",
            "allow font smoothing:i:0\r\n",
            "disable full window drag:i:1\r\n",
            "disable menu anims:i:1\r\n",
            "disable themes:i:0\r\n",
            "disable cursor setting:i:0\r\n",
            "bitmapcachepersistenable:i:1\r\n",
            "audiomode:i:0\r\n",
            // Device redirections — all OFF by default to silence the
            // "Allow the remote computer to access the following resources"
            // consent dialog on Windows 11. Users who need printer/clipboard/
            // smartcard redirection can edit the generated .rdp file.
            "redirectprinters:i:0\r\n",
            "redirectcomports:i:0\r\n",
            "redirectsmartcards:i:0\r\n",
            // Clipboard is left ON — copy/paste between host and session is
            // a routine admin workflow. It does still cause Windows 11 to
            // show the resource-access consent dialog on first connect, but
            // only for the clipboard item.
            "redirectclipboard:i:1\r\n",
            "redirectposdevices:i:0\r\n",
            "redirectwebauthn:i:0\r\n",
            "devicestoredirect:s:\r\n",
            "drivestoredirect:s:\r\n",
            "usbdevicestoredirect:s:\r\n",
            "autoreconnection enabled:i:1\r\n",
            // authentication level 2 = Server auth required (no warning if
            // cert is trusted; modern Windows shows a softer prompt for
            // untrusted certs than level 0 does).
            "authentication level:i:2\r\n",
            "prompt for credentials:i:0\r\n",
            "negotiate security layer:i:1\r\n",
            "remoteapplicationmode:i:0\r\n",
            "alternate shell:s:\r\n",
            "shell working directory:s:\r\n",
            "gatewayhostname:s:\r\n",
            "gatewayusagemethod:i:4\r\n",
            "gatewaycredentialssource:i:4\r\n",
            "gatewayprofileusagemethod:i:0\r\n",
            "promptcredentialonce:i:1\r\n",
            "use redirection server name:i:0\r\n",
            "rdgiskdcproxy:i:0\r\n",
            "kdcproxyname:s:\r\n",
            "username:s:{user_field}\r\n",
            "domain:s:{domain}\r\n",
            "enablecredsspsupport:i:1\r\n",
            "public mode:i:0\r\n",
            "cert ignore:i:1\r\n",
            "prompt for credentials on client:i:0\r\n",
            "disableconnectionsharing:i:0\r\n",
        ),
        host = host,
        user_field = user_field,
        domain = domain,
    )
}

pub(crate) fn write_rdp_file(host: &str, username: &str, domain: &str) -> Result<PathBuf, String> {
    // Validate all parameters to prevent CRLF injection and path traversal
    validate_rdp_parameter(host, "hostname")?;
    validate_rdp_parameter(username, "username")?;
    validate_rdp_parameter(domain, "domain")?;

    let app_dir = get_app_data_dir()?;
    let connections_dir = app_dir.join("Connections");
    fs::create_dir_all(&connections_dir)
        .map_err(|e| format!("Failed to create Connections directory: {}", e))?;

    let rdp_path = connections_dir.join(format!("{}.rdp", host));
    let content = build_rdp_content(host, username, domain);
    fs::write(&rdp_path, content.as_bytes())
        .map_err(|e| format!("Failed to write RDP file: {}", e))?;
    Ok(rdp_path)
}

pub(crate) fn launch_mstsc(rdp_path: &Path) -> Result<(), String> {
    Command::new("mstsc.exe")
        .arg(rdp_path)
        .spawn()
        .map_err(|e| format!("Failed to launch mstsc.exe: {}", e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub(crate) async fn save_rdp_credentials(
    server: String,
    username: String,
    password: String,
) -> Result<(), String> {
    let server = server.trim();
    let username = username.trim();

    if server.is_empty() {
        return Err("Server name is required".to_string());
    }
    if username.is_empty() {
        return Err("Username is required".to_string());
    }

    let store = WindowsCredentialManager::new();
    let normalized = normalize_host_name(server)?;
    let host_profile = CredentialProfile::new(format!("QuickProbe:HOST/{}", normalized));
    let rdp_profile = CredentialProfile::new(format!("TERMSRV/{}", server));
    let creds = Credentials::new(
        Username::new(username.to_string()).map_err(|e| e.to_string())?,
        SecureString::new(password),
    );

    store
        .store(&host_profile, &creds)
        .await
        .map_err(|e| e.to_string())?;

    crate::logger::log_info(&format!(
        "save_rdp_credentials: stored creds for '{}' as profile '{}' (user: {})",
        server,
        host_profile.as_str(),
        username
    ));

    // Also persist to TERMSRV for mstsc compatibility
    let _ = store.store(&rdp_profile, &creds).await;

    // Ensure subsequent probes use credentials just saved by the user.
    invalidate_session_cache(&normalized).await;
    Ok(())
}

#[tauri::command]
pub(crate) async fn launch_rdp(server: String) -> Result<(), String> {
    let server = server.trim();
    if server.is_empty() {
        return Err("Server name is required".to_string());
    }

    let store = WindowsCredentialManager::new();
    let (creds, _) = resolve_host_credentials(server).await?;

    let host_profile = CredentialProfile::new(format!("TERMSRV/{}", server));
    let _ = store.store(&host_profile, &creds).await;

    let (domain, user) = split_domain_username(creds.username().as_str());
    let rdp_path = write_rdp_file(server, &user, &domain)?;
    launch_mstsc(&rdp_path)
}

/// Launch SSH connection to a Linux host using Windows Terminal or fallback to cmd.exe
#[tauri::command]
pub(crate) async fn launch_ssh(server: String) -> Result<(), String> {
    let server = server.trim();
    if server.is_empty() {
        return Err("Server name is required".to_string());
    }

    crate::logger::log_info(&format!("launch_ssh: Launching SSH to '{}'", server));

    // Get credentials for the host
    let (creds, _) = resolve_host_credentials(server).await?;
    let username = creds.username().as_str().to_string();

    // Parse host:port if specified
    let (host, port) = if let Some((h, p)) = server.rsplit_once(':') {
        if let Ok(port_num) = p.parse::<u16>() {
            (h.to_string(), Some(port_num))
        } else {
            (server.to_string(), None)
        }
    } else {
        (server.to_string(), None)
    };

    // Build SSH command
    let ssh_target = if username.is_empty() {
        host.clone()
    } else {
        format!("{}@{}", username, host)
    };

    let ssh_cmd = if let Some(p) = port {
        format!("ssh -p {} {}", p, ssh_target)
    } else {
        format!("ssh {}", ssh_target)
    };

    // Try Windows Terminal first (wt.exe), fall back to cmd.exe
    let result = tokio::task::spawn_blocking(move || {
        // Try Windows Terminal first
        let wt_result = Command::new("wt.exe")
            .arg("new-tab")
            .arg("--title")
            .arg(format!("SSH: {}", host))
            .arg("cmd")
            .arg("/k")
            .arg(&ssh_cmd)
            .spawn();

        match wt_result {
            Ok(_) => {
                crate::logger::log_debug(&format!(
                    "launch_ssh: Opened Windows Terminal for '{}'",
                    host
                ));
                Ok(())
            }
            Err(_) => {
                // Fall back to cmd.exe with SSH
                crate::logger::log_debug(
                    "launch_ssh: Windows Terminal not available, trying cmd.exe",
                );
                Command::new("cmd.exe")
                    .arg("/c")
                    .arg("start")
                    .arg("cmd")
                    .arg("/k")
                    .arg(&ssh_cmd)
                    .spawn()
                    .map_err(|e| format!("Failed to launch SSH: {}", e))?;
                Ok(())
            }
        }
    })
    .await
    .map_err(|e| format!("SSH launch task failed: {}", e))?;

    result
}

/// Open Windows Explorer to the C$ administrative share on a remote host
#[cfg(windows)]
#[tauri::command]
pub(crate) async fn open_explorer_share(server: String) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let server = server.trim();
    if server.is_empty() {
        return Err("Server name is required".to_string());
    }

    crate::logger::log_info(&format!(
        "open_explorer_share: Opening Explorer to \\\\{}\\C$",
        server
    ));

    // Get credentials for the host
    let (creds, used_profile) = resolve_host_credentials(server).await?;
    let username = creds.username().as_str();
    let password = creds.password().as_str();

    crate::logger::log_debug(&format!(
        "open_explorer_share: Using credentials from profile '{}' for '{}'",
        used_profile, server
    ));

    // Parse username into domain\user format if needed
    let (domain, user) = split_domain_username(username);
    let full_username = if !domain.is_empty() {
        format!("{}\\{}", domain, user)
    } else {
        user.to_string()
    };

    let unc_path = format!("\\\\{}\\C$", server);

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Use net use to mount the share with credentials
    // /delete first to clear any existing connection
    let _ = Command::new("net")
        .args(["use", &unc_path, "/delete", "/y"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    // Now mount with credentials
    let output = Command::new("net")
        .args([
            "use",
            &unc_path,
            password,
            &format!("/user:{}", full_username),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute net use: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        crate::logger::log_error(&format!(
            "open_explorer_share: net use failed for '{}': {}",
            server, stderr
        ));
        return Err(format!(
            "Failed to connect to share: {}. Please verify credentials and network access.",
            stderr.trim()
        ));
    }

    // Open Explorer to the mounted share
    Command::new("explorer.exe")
        .arg(&unc_path)
        .spawn()
        .map_err(|e| format!("Failed to launch Explorer: {}", e))?;

    crate::logger::log_info(&format!(
        "open_explorer_share: Successfully opened Explorer to '{}'",
        unc_path
    ));

    Ok(())
}

#[cfg(not(windows))]
#[tauri::command]
pub(crate) async fn open_explorer_share(_server: String) -> Result<(), String> {
    Err("Explorer share opening is only supported on Windows".to_string())
}

/// Launch regedit.exe for remote registry connection
#[cfg(windows)]
#[tauri::command]
pub(crate) async fn launch_remote_registry(server: String) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let server = server.trim();

    if server.is_empty() {
        return Err("Server name is required".to_string());
    }

    crate::logger::log_info(&format!(
        "launch_remote_registry: Launching regedit for server '{}'",
        server
    ));

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Retrieve stored credentials and cache them via cmdkey so regedit
    // can authenticate against the remote server without prompting.
    let (credentials, _) = resolve_host_credentials(server).await?;
    let username = credentials.username().as_str();
    let password = credentials.password().as_str();

    let (domain, user) = split_domain_username(username);
    let full_username = if !domain.is_empty() {
        format!("{}\\{}", domain, user)
    } else {
        user.to_string()
    };

    let _ = Command::new("cmdkey")
        .args([
            &format!("/add:{}", server),
            &format!("/user:{}", full_username),
            &format!("/pass:{}", password),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    crate::logger::log_debug(&format!(
        "launch_remote_registry: Cached credentials for '{}'",
        server
    ));

    // Test connectivity to remote registry with retries.
    let mut last_error = String::new();
    let max_retries = 3;
    let mut connected = false;

    for attempt in 1..=max_retries {
        let test_result = Command::new("reg.exe")
            .args(["query", &format!("\\\\{}\\HKLM", server)])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        match test_result {
            Ok(output) if output.status.success() => {
                crate::logger::log_debug(&format!(
                    "launch_remote_registry: Registry connectivity test successful for '{}' (attempt {})",
                    server, attempt
                ));
                connected = true;
                break;
            }
            Ok(output) => {
                last_error = String::from_utf8_lossy(&output.stderr).to_string();
                crate::logger::log_warn(&format!(
                    "launch_remote_registry: Registry connectivity test failed for '{}' (attempt {}): {}",
                    server, attempt, last_error
                ));
            }
            Err(e) => {
                last_error = e.to_string();
                crate::logger::log_warn(&format!(
                    "launch_remote_registry: Could not test registry connectivity (attempt {}): {}",
                    attempt, e
                ));
            }
        }

        if attempt < max_retries {
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
    }

    if !connected {
        return Err(format!(
            "Cannot connect to remote registry on {}. Ensure the RemoteRegistry service is running and you have permissions. Last error: {}",
            server, last_error.trim()
        ));
    }

    // Launch regedit and automate File → Connect Network Registry via SendKeys.
    let safe_name = escape_sendkeys(server);
    let ps_script = format!(
        r#"Start-Process -FilePath 'regedit.exe' -PassThru | Out-Null; Start-Sleep -Milliseconds 1000; Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('%F'); Start-Sleep -Milliseconds 200; [System.Windows.Forms.SendKeys]::SendWait('C'); Start-Sleep -Milliseconds 500; [System.Windows.Forms.SendKeys]::SendWait('{}'); Start-Sleep -Milliseconds 200; [System.Windows.Forms.SendKeys]::SendWait('{{ENTER}}')"#,
        safe_name
    );

    let result = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();

    match result {
        Ok(_) => {
            crate::logger::log_info(&format!(
                "launch_remote_registry: Successfully launched regedit for '{}'",
                server
            ));
            Ok(())
        }
        Err(e) => {
            let error_msg = format!("Failed to launch regedit: {}", e);
            crate::logger::log_error(&format!("launch_remote_registry: {}", error_msg));
            Err(error_msg)
        }
    }
}

#[cfg(not(windows))]
#[tauri::command]
pub(crate) async fn launch_remote_registry(_server: String) -> Result<(), String> {
    Err("Remote Registry is only supported on Windows".to_string())
}
