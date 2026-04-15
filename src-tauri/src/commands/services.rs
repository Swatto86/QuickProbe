//! Remote service and process management commands.

use quickprobe::core::session::{RemoteSession, ServiceInfo};
use quickprobe::platform::{LinuxRemoteSession, WindowsRemoteSession};
use serde::Deserialize;
use std::time::SystemTime;

use super::state::*;
use super::types::*;

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Fetch all services from a remote host for service selection UI
#[tauri::command]
pub(crate) async fn get_remote_services(server_name: String) -> Result<Vec<ServiceInfo>, String> {
    let start = SystemTime::now();
    crate::logger::log_debug_verbose(&format!("get_remote_services: START '{}'", server_name));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    let services = if os_hint.eq_ignore_ascii_case("linux") {
        let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        session
            .get_services(None)
            .await
            .map_err(|e| format!("Failed to retrieve services from {}: {}", server_name, e))?
    } else {
        let session = WindowsRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        session
            .get_services(None)
            .await
            .map_err(|e| format!("Failed to retrieve services from {}: {}", server_name, e))?
    };

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    crate::logger::log_debug(&format!(
        "get_remote_services: SUCCESS '{}' {}ms {} services",
        server_name,
        elapsed_ms,
        services.len()
    ));

    Ok(services)
}

/// Control a Windows service (start, stop, restart)
#[tauri::command]
pub(crate) async fn control_service(
    server_name: String,
    service_name: String,
    action: String,
) -> Result<ServiceControlResponse, String> {
    let start = SystemTime::now();
    crate::logger::log_debug(&format!(
        "control_service: START '{}' service='{}' action='{}'",
        server_name, service_name, action
    ));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }
    if service_name.trim().is_empty() {
        return Err("Service name cannot be empty".to_string());
    }

    // Validate action
    let action_lower = action.to_lowercase();
    if !["start", "stop", "restart"].contains(&action_lower.as_str()) {
        return Err(format!(
            "Invalid action '{}'. Must be one of: start, stop, restart",
            action
        ));
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    if os_hint.eq_ignore_ascii_case("linux") {
        let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        // Escape service name for shell
        let escaped_service = service_name.replace('\'', "'\\''");

        let systemctl_cmd = match action_lower.as_str() {
            "start" => format!(
                "sudo systemctl start '{}' 2>&1 && echo SUCCESS || echo FAILED",
                escaped_service
            ),
            "stop" => format!(
                "sudo systemctl stop '{}' 2>&1 && echo SUCCESS || echo FAILED",
                escaped_service
            ),
            "restart" => format!(
                "sudo systemctl restart '{}' 2>&1 && echo SUCCESS || echo FAILED",
                escaped_service
            ),
            _ => return Err(format!("Invalid action: {}", action)),
        };

        let output = session
            .execute_command(&systemctl_cmd)
            .await
            .map_err(|e| format!("Failed to execute systemctl command: {}", e))?;

        let success = output.trim().ends_with("SUCCESS");
        let message = if success {
            format!("Service {} {} successfully", service_name, action_lower)
        } else {
            format!(
                "Failed to {} service: {}",
                action_lower,
                output.trim().replace("FAILED", "").trim()
            )
        };

        // Get new status
        let status_cmd = format!(
            "systemctl is-active '{}' 2>/dev/null || echo unknown",
            escaped_service
        );
        let new_status = session
            .execute_command(&status_cmd)
            .await
            .ok()
            .map(|s| s.trim().to_string());

        let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
        if success {
            crate::logger::log_info(&format!(
                "control_service: SUCCESS '{}' service='{}' action='{}' new_status='{:?}' {}ms",
                server_name, service_name, action_lower, new_status, elapsed_ms
            ));
        } else {
            crate::logger::log_warn(&format!(
                "control_service: FAILED '{}' service='{}' action='{}' {}ms",
                server_name, service_name, action_lower, elapsed_ms
            ));
        }

        return Ok(ServiceControlResponse {
            success,
            service_name,
            action: action_lower,
            new_status,
            message,
        });
    }

    // Windows: Use WinRM/PowerShell

    let session = WindowsRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

    // Escape the service name to prevent injection
    let escaped_service = service_name
        .replace('\'', "''")
        .replace('`', "``")
        .replace('$', "`$");

    let ps_command = match action_lower.as_str() {
        "start" => format!(
            r#"
$ErrorActionPreference = 'Stop'
try {{
    $svc = Get-Service -Name '{0}' -ErrorAction Stop
    if ($svc.Status -eq 'Running') {{
        @{{ success = $true; status = 'Running'; message = 'Service is already running' }} | ConvertTo-Json -Compress
    }} else {{
        Start-Service -Name '{0}' -ErrorAction Stop
        Start-Sleep -Milliseconds 500
        $svc = Get-Service -Name '{0}'
        @{{ success = $true; status = $svc.Status.ToString(); message = 'Service started successfully' }} | ConvertTo-Json -Compress
    }}
}} catch {{
    @{{ success = $false; status = $null; message = $_.Exception.Message }} | ConvertTo-Json -Compress
}}
"#,
            escaped_service
        ),
        "stop" => format!(
            r#"
$ErrorActionPreference = 'Stop'
try {{
    $svc = Get-Service -Name '{0}' -ErrorAction Stop
    if ($svc.Status -eq 'Stopped') {{
        @{{ success = $true; status = 'Stopped'; message = 'Service is already stopped' }} | ConvertTo-Json -Compress
    }} else {{
        Stop-Service -Name '{0}' -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 500
        $svc = Get-Service -Name '{0}'
        @{{ success = $true; status = $svc.Status.ToString(); message = 'Service stopped successfully' }} | ConvertTo-Json -Compress
    }}
}} catch {{
    @{{ success = $false; status = $null; message = $_.Exception.Message }} | ConvertTo-Json -Compress
}}
"#,
            escaped_service
        ),
        "restart" => format!(
            r#"
$ErrorActionPreference = 'Stop'
try {{
    Restart-Service -Name '{0}' -Force -ErrorAction Stop
    Start-Sleep -Milliseconds 500
    $svc = Get-Service -Name '{0}'
    @{{ success = $true; status = $svc.Status.ToString(); message = 'Service restarted successfully' }} | ConvertTo-Json -Compress
}} catch {{
    @{{ success = $false; status = $null; message = $_.Exception.Message }} | ConvertTo-Json -Compress
}}
"#,
            escaped_service
        ),
        _ => return Err(format!("Invalid action: {}", action)),
    };

    let output = session
        .execute_powershell(&ps_command)
        .await
        .map_err(|e| format!("Failed to execute service control command: {}", e))?;

    let trimmed = output.trim();

    #[derive(Deserialize)]
    struct PsResponse {
        success: bool,
        status: Option<String>,
        message: String,
    }

    let ps_result: PsResponse = serde_json::from_str(trimmed).map_err(|e| {
        format!(
            "Failed to parse service control response: {} - output: {}",
            e, trimmed
        )
    })?;

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();

    if ps_result.success {
        crate::logger::log_info(&format!(
            "control_service: SUCCESS '{}' service='{}' action='{}' new_status='{}' {}ms",
            server_name,
            service_name,
            action_lower,
            ps_result.status.as_deref().unwrap_or("unknown"),
            elapsed_ms
        ));
    } else {
        crate::logger::log_warn(&format!(
            "control_service: FAILED '{}' service='{}' action='{}' error='{}' {}ms",
            server_name, service_name, action_lower, ps_result.message, elapsed_ms
        ));
    }

    Ok(ServiceControlResponse {
        success: ps_result.success,
        service_name: service_name.clone(),
        action: action_lower,
        new_status: ps_result.status,
        message: ps_result.message,
    })
}

/// Fetch all processes from a remote host for process management UI
#[tauri::command]
pub(crate) async fn get_remote_processes(
    server_name: String,
) -> Result<Vec<RemoteProcessInfo>, String> {
    let start = SystemTime::now();
    crate::logger::log_debug_verbose(&format!("get_remote_processes: START '{}'", server_name));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    if os_hint.eq_ignore_ascii_case("linux") {
        let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        let ps_command = "ps -eo pid,comm,%cpu,rss,user --no-headers | head -500";
        let output = session
            .execute_command(ps_command)
            .await
            .map_err(|e| format!("Failed to get processes from {}: {}", server_name, e))?;

        let mut processes = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let pid = parts[0].parse::<u32>().unwrap_or(0);
                let name = parts[1].to_string();
                let cpu_percent = parts[2].parse::<f64>().unwrap_or(0.0);
                let rss_kb = parts[3].parse::<f64>().unwrap_or(0.0);
                let user = parts[4].to_string();

                processes.push(RemoteProcessInfo {
                    pid,
                    name,
                    cpu_percent,
                    memory_mb: (rss_kb / 1024.0 * 10.0).round() / 10.0,
                    user,
                });
            }
        }

        // Sort by memory descending
        processes.sort_by(|a, b| {
            b.memory_mb
                .partial_cmp(&a.memory_mb)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
        crate::logger::log_debug_verbose(&format!(
            "get_remote_processes: SUCCESS '{}' {}ms {} processes",
            server_name,
            elapsed_ms,
            processes.len()
        ));

        return Ok(processes);
    }

    // Windows: Use WinRM/PowerShell
    let session = WindowsRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

    let ps_command = r#"
$ErrorActionPreference = 'Stop'
try {
    $cpuCount = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

    # Get real-time CPU percentages from performance counters
    $perfData = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
        Where-Object { $_.IDProcess -ne 0 -and $_.Name -ne '_Total' -and $_.Name -ne 'Idle' } |
        Select-Object IDProcess, PercentProcessorTime

    $cpuMap = @{}
    foreach ($perf in $perfData) {
        $cpuMap[$perf.IDProcess] = [math]::Round($perf.PercentProcessorTime / $cpuCount, 1)
    }

    # Get process details with user
    $procs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -ne 0 }

    $result = @()
    foreach ($p in $procs) {
        $memMb = [math]::Round($p.WorkingSet64 / 1MB, 1)
        $cpu = if ($cpuMap.ContainsKey($p.Id)) { $cpuMap[$p.Id] } else { 0 }
        $user = if ($p.UserName) { $p.UserName } else { 'SYSTEM' }

        $result += @{
            pid = $p.Id
            name = $p.ProcessName
            cpu_percent = $cpu
            memory_mb = $memMb
            user = $user
        }
    }

    $result | Sort-Object { $_.memory_mb } -Descending | Select-Object -First 500 | ConvertTo-Json -Compress
} catch {
    @{ error = $_.Exception.Message } | ConvertTo-Json -Compress
}
"#;

    let output = session
        .execute_powershell(ps_command)
        .await
        .map_err(|e| format!("Failed to get processes from {}: {}", server_name, e))?;

    let trimmed = output.trim();

    // Check for error response
    if trimmed.contains("\"error\"") {
        #[derive(Deserialize)]
        struct ErrorResponse {
            error: String,
        }
        if let Ok(err) = serde_json::from_str::<ErrorResponse>(trimmed) {
            return Err(format!("PowerShell error: {}", err.error));
        }
    }

    // Parse process array
    let processes: Vec<RemoteProcessInfo> = serde_json::from_str(trimmed).map_err(|e| {
        format!(
            "Failed to parse processes response: {} - output: {}",
            e,
            &trimmed[..trimmed.len().min(200)]
        )
    })?;

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    crate::logger::log_debug_verbose(&format!(
        "get_remote_processes: SUCCESS '{}' {}ms {} processes",
        server_name,
        elapsed_ms,
        processes.len()
    ));

    Ok(processes)
}

/// Kill a process on a remote host
#[tauri::command]
pub(crate) async fn kill_process(
    server_name: String,
    pid: u32,
    process_name: String,
) -> Result<ProcessKillResponse, String> {
    let start = SystemTime::now();
    crate::logger::log_debug(&format!(
        "kill_process: START '{}' pid={} name='{}'",
        server_name, pid, process_name
    ));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }
    if pid == 0 {
        return Err("Cannot kill process with PID 0".to_string());
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    if os_hint.eq_ignore_ascii_case("linux") {
        let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        let kill_cmd = format!("sudo kill {} 2>&1 && echo SUCCESS || echo FAILED", pid);
        let output = session
            .execute_command(&kill_cmd)
            .await
            .map_err(|e| format!("Failed to kill process: {}", e))?;

        let success = output.trim().ends_with("SUCCESS");
        let message = if success {
            format!(
                "Process '{}' (PID {}) terminated successfully",
                process_name, pid
            )
        } else {
            format!(
                "Failed to kill process: {}",
                output.trim().replace("FAILED", "").trim()
            )
        };

        let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
        if success {
            crate::logger::log_info(&format!(
                "kill_process: SUCCESS '{}' pid={} name='{}' {}ms",
                server_name, pid, process_name, elapsed_ms
            ));
        } else {
            crate::logger::log_warn(&format!(
                "kill_process: FAILED '{}' pid={} error='{}' {}ms",
                server_name, pid, message, elapsed_ms
            ));
        }

        return Ok(ProcessKillResponse {
            success,
            pid,
            process_name,
            message,
        });
    }

    // Windows: Use WinRM/PowerShell
    let session = WindowsRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

    let ps_command = format!(
        r#"
$ErrorActionPreference = 'Stop'
try {{
    $proc = Get-Process -Id {0} -ErrorAction Stop
    $procName = $proc.ProcessName
    Stop-Process -Id {0} -Force -ErrorAction Stop
    @{{ success = $true; message = "Process '$procName' (PID {0}) terminated successfully" }} | ConvertTo-Json -Compress
}} catch {{
    @{{ success = $false; message = $_.Exception.Message }} | ConvertTo-Json -Compress
}}
"#,
        pid
    );

    let output = session
        .execute_powershell(&ps_command)
        .await
        .map_err(|e| format!("Failed to kill process: {}", e))?;

    let trimmed = output.trim();

    #[derive(Deserialize)]
    struct PsResponse {
        success: bool,
        message: String,
    }

    let ps_result: PsResponse = serde_json::from_str(trimmed)
        .map_err(|e| format!("Failed to parse kill response: {} - output: {}", e, trimmed))?;

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();

    if ps_result.success {
        crate::logger::log_info(&format!(
            "kill_process: SUCCESS '{}' pid={} name='{}' {}ms",
            server_name, pid, process_name, elapsed_ms
        ));
    } else {
        crate::logger::log_warn(&format!(
            "kill_process: FAILED '{}' pid={} error='{}' {}ms",
            server_name, pid, ps_result.message, elapsed_ms
        ));
    }

    Ok(ProcessKillResponse {
        success: ps_result.success,
        pid,
        process_name,
        message: ps_result.message,
    })
}
