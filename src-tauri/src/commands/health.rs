//! System health probes, quick status, network adapters, OS info, and reachability.

use futures::future::join_all;
use quickprobe::constants::*;
use quickprobe::core::session::{NetAdapterInfo, OsInfo, RemoteSession};
use quickprobe::core::{
    system_health_probe, ReachabilitySummary, SystemHealthSummary, TcpProbeResult,
};
use quickprobe::platform::{LinuxRemoteSession, WindowsRemoteSession};
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use super::state::*;
use super::types::*;

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Get system health summary for a server
#[allow(dead_code)] // Called from JavaScript via Tauri IPC
#[tauri::command]
pub(crate) async fn get_system_health(
    server_name: String,
    disk_threshold: Option<f64>,
    critical_services: Option<Vec<String>>,
    tcp_ports: Option<Vec<u16>>,
) -> Result<SystemHealthSummary, String> {
    let start = SystemTime::now();
    crate::logger::log_debug_verbose(&format!("get_system_health: START '{}'", server_name));

    // Input validation
    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }

    let threshold = disk_threshold.unwrap_or(10.0);
    if !(0.0..=100.0).contains(&threshold) {
        return Err(format!(
            "Invalid disk threshold: {}. Must be between 0 and 100",
            threshold
        ));
    }

    let services: Vec<String> = critical_services.unwrap_or_default();
    let services_slice = if services.is_empty() {
        None
    } else {
        Some(services.as_slice())
    };

    let os_hint = resolve_host_os_type(&server_name).await;
    let tcp_ports: Vec<u16> = if os_hint.eq_ignore_ascii_case("windows") {
        sanitize_tcp_ports(tcp_ports.as_deref().unwrap_or(DEFAULT_TCP_PORTS))
    } else {
        Vec::new()
    };
    let (credentials, _profile) = resolve_host_credentials(&server_name).await?;

    crate::logger::log_debug_verbose(&format!(
        "[HealthCheck] {} - Starting connectivity probes (ping + reachability)...",
        server_name
    ));
    let probe_start = SystemTime::now();
    let ping_ok = ping_host(&server_name).await.unwrap_or(false);
    let reachability =
        Some(probe_reachability(&server_name, &tcp_ports, TCP_PROBE_TIMEOUT_MS).await);
    let probe_ms = probe_start.elapsed().unwrap_or_default().as_millis();
    crate::logger::log_debug_verbose(&format!(
        "[HealthCheck] {} - Connectivity probes completed in {}ms (ping: {}, reachability: {:?})",
        server_name, probe_ms, ping_ok, reachability
    ));
    let server_name_clone = server_name.clone();

    crate::logger::log_debug_verbose(&format!(
        "[HealthCheck] {} - Connecting to remote session (OS: {})...",
        server_name, os_hint
    ));
    let session_start = SystemTime::now();
    let session = match connect_remote_session(server_name.clone(), credentials, &os_hint).await {
        Ok(s) => {
            let session_ms = session_start.elapsed().unwrap_or_default().as_millis();
            crate::logger::log_debug_verbose(&format!(
                "[HealthCheck] {} - Remote session connected in {}ms",
                server_name, session_ms
            ));
            s
        }
        Err(e) => {
            let session_ms = session_start.elapsed().unwrap_or_default().as_millis();
            crate::logger::log_error(&format!(
                "[HealthCheck] {} - Remote session connection failed after {}ms: {}",
                server_name, session_ms, e
            ));
            if os_hint.eq_ignore_ascii_case("linux") {
                return Err(e);
            }
            let mut degraded =
                degraded_summary_or_error(&server_name_clone, e, true, ping_ok).await?;
            degraded.reachability = reachability.clone();
            return Ok(degraded);
        }
    };

    // Windows keeps the fast combined probe path; Linux uses the shared trait path.
    crate::logger::log_debug_verbose(&format!(
        "[HealthCheck] {} - Starting health data collection...",
        server_name
    ));
    let collect_start = SystemTime::now();
    let summary = match &session {
        SessionKind::Windows(win) => {
            match win.collect_system_health(services_slice, threshold).await {
                Ok(summary) => {
                    let collect_ms = collect_start.elapsed().unwrap_or_default().as_millis();
                    crate::logger::log_debug_verbose(&format!(
                        "[HealthCheck] {} - Health data collection succeeded in {}ms",
                        server_name, collect_ms
                    ));
                    Ok(summary)
                }
                Err(fast_err) => {
                    let fast_ms = collect_start.elapsed().unwrap_or_default().as_millis();
                    crate::logger::log_warn(&format!(
                        "[HealthCheck] {} - Fast path failed after {}ms, trying fallback... Error: {}",
                        server_name, fast_ms, fast_err
                    ));
                    let fallback_start = SystemTime::now();
                    match system_health_probe(win.as_ref(), services_slice, threshold).await {
                        Ok(fallback) => {
                            let fallback_ms =
                                fallback_start.elapsed().unwrap_or_default().as_millis();
                            crate::logger::log_debug_verbose(&format!(
                                "[HealthCheck] {} - Fallback probe succeeded in {}ms",
                                server_name, fallback_ms
                            ));
                            Ok(fallback)
                        }
                        Err(_) => Err(fast_err),
                    }
                }
            }
        }
        SessionKind::Linux(_) => {
            system_health_probe(session.as_remote(), services_slice, threshold).await
        }
    };

    match summary {
        Ok(mut summary) => {
            summary.reachability = reachability;
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            crate::logger::log_debug_verbose(&format!(
                "get_system_health: SUCCESS '{}' {}ms",
                server_name, elapsed_ms
            ));
            Ok(summary)
        }
        Err(e) => {
            if session.is_windows() {
                // Attempt a partial recovery before degrading so we don't lose basic facts like OS/memory.
                if let Some(mut recovered) = recover_minimal_health(session.as_remote()).await {
                    recovered.reachability = reachability.clone();
                    recovered.winrm_issue = true;
                    recovered.winrm_error = Some(e.clone());
                    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
                    crate::logger::log_debug_verbose(&format!(
                        "get_system_health: PARTIAL '{}' {}ms",
                        server_name, elapsed_ms
                    ));
                    return Ok(recovered);
                }

                let mut degraded =
                    degraded_summary_or_error(&server_name_clone, e, true, ping_ok).await?;
                degraded.reachability = reachability;
                let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
                crate::logger::log_debug_verbose(&format!(
                    "get_system_health: DEGRADED '{}' {}ms",
                    server_name, elapsed_ms
                ));
                Ok(degraded)
            } else {
                let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
                crate::logger::log_error(&format!(
                    "get_system_health: FAILED '{}' {}ms: {}",
                    server_name, elapsed_ms, e
                ));
                Err(e)
            }
        }
    }
}

/// Quick heartbeat status for high-frequency refresh (no heavy process/disk sampling)
#[tauri::command]
pub(crate) async fn get_quick_status(
    server_name: String,
    services: Option<Vec<String>>,
    tcp_ports: Option<Vec<u16>>,
) -> Result<QuickStatus, String> {
    let start = SystemTime::now();
    crate::logger::log_debug_verbose(&format!("get_quick_status: START '{}'", server_name));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }

    let ping_ok = ping_host(&server_name).await.unwrap_or(false);

    let os_hint = resolve_host_os_type(&server_name).await;
    let tcp_ports: Vec<u16> = if os_hint.eq_ignore_ascii_case("windows") {
        sanitize_tcp_ports(tcp_ports.as_deref().unwrap_or(DEFAULT_TCP_PORTS))
    } else {
        Vec::new()
    };
    let reachability =
        Some(probe_reachability(&server_name, &tcp_ports, TCP_PROBE_TIMEOUT_MS).await);
    let credentials = match resolve_host_credentials(&server_name).await {
        Ok((creds, _)) => creds,
        Err(e) => {
            return Ok(QuickStatus {
                server_name,
                ping_ok,
                winrm_ok: false,
                winrm_error: Some(e),
                reachability,
                uptime_hours: None,
                cpu_load_pct: None,
                memory_used_percent: None,
                total_memory_mb: None,
                used_memory_mb: None,
                process_count: None,
                top_cpu_processes: None,
                service_status: None,
            });
        }
    };

    let server_name_clone = server_name.clone();
    let session = match connect_remote_session(server_name.clone(), credentials, &os_hint).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(QuickStatus {
                server_name: server_name_clone,
                ping_ok,
                winrm_ok: false,
                winrm_error: Some(e),
                reachability,
                uptime_hours: None,
                cpu_load_pct: None,
                memory_used_percent: None,
                total_memory_mb: None,
                used_memory_mb: None,
                process_count: None,
                top_cpu_processes: None,
                service_status: None,
            });
        }
    };

    let service_slice = services.as_deref();

    let result = match &session {
        SessionKind::Windows(win) => match win.collect_quick_probe(service_slice).await {
            Ok(probe) => Ok(QuickStatus {
                server_name: probe.server_name,
                ping_ok,
                winrm_ok: true,
                winrm_error: None,
                reachability,
                uptime_hours: probe.uptime_hours,
                cpu_load_pct: probe.cpu_load_pct,
                memory_used_percent: probe.memory_used_percent,
                total_memory_mb: probe.total_memory_mb,
                used_memory_mb: probe.used_memory_mb,
                process_count: probe.process_count,
                top_cpu_processes: probe.top_cpu_processes,
                service_status: probe.service_status,
            }),
            Err(e) => Ok(QuickStatus {
                server_name: server_name_clone,
                ping_ok,
                winrm_ok: false,
                winrm_error: Some(e),
                reachability,
                uptime_hours: None,
                cpu_load_pct: None,
                memory_used_percent: None,
                total_memory_mb: None,
                used_memory_mb: None,
                process_count: None,
                top_cpu_processes: None,
                service_status: None,
            }),
        },
        SessionKind::Linux(_) => {
            match system_health_probe(session.as_remote(), service_slice, 10.0).await {
                Ok(summary) => Ok(QuickStatus {
                    server_name: summary.server_name,
                    ping_ok,
                    winrm_ok: true,
                    winrm_error: None,
                    reachability,
                    uptime_hours: summary.uptime.as_ref().map(|u| u.uptime_hours),
                    cpu_load_pct: summary.uptime.as_ref().and_then(|u| u.cpu_load_pct),
                    memory_used_percent: Some(summary.memory_used_percent),
                    total_memory_mb: Some(summary.total_memory_mb),
                    used_memory_mb: Some(summary.used_memory_mb),
                    process_count: Some(summary.process_count),
                    top_cpu_processes: Some(summary.high_cpu_processes),
                    service_status: Some(summary.service_status),
                }),
                Err(e) => Ok(QuickStatus {
                    server_name: server_name_clone,
                    ping_ok,
                    winrm_ok: false,
                    winrm_error: Some(e),
                    reachability,
                    uptime_hours: None,
                    cpu_load_pct: None,
                    memory_used_percent: None,
                    total_memory_mb: None,
                    used_memory_mb: None,
                    process_count: None,
                    top_cpu_processes: None,
                    service_status: None,
                }),
            }
        }
    };

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    match &result {
        Ok(status) => crate::logger::log_debug_verbose(&format!(
            "get_quick_status: COMPLETE '{}' {}ms ping={}",
            server_name, elapsed_ms, status.ping_ok
        )),
        Err(e) => crate::logger::log_error(&format!(
            "get_quick_status: FAILED '{}' {}ms: {}",
            server_name, elapsed_ms, e
        )),
    }

    result
}

/// Fetch network adapter info only (debug helper)
#[tauri::command]
pub(crate) async fn fetch_net_adapters(
    server_name: String,
) -> Result<AdapterDebugResponse, String> {
    let start = SystemTime::now();
    crate::logger::log_debug_verbose(&format!("fetch_net_adapters: START '{}'", server_name));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    // Handle Linux hosts via SSH
    if os_hint.eq_ignore_ascii_case("linux") {
        let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {server_name}: {e}"))?;

        let adapters = session
            .get_net_adapters()
            .await
            .map_err(|e| format!("Adapter probe failed: {e}"))?;

        let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
        crate::logger::log_debug_verbose(&format!(
            "fetch_net_adapters: COMPLETE '{}' {}ms {} adapter(s) (Linux)",
            server_name,
            elapsed_ms,
            adapters.len()
        ));

        return Ok(AdapterDebugResponse {
            raw: format!("{} Linux adapters", adapters.len()),
            adapters: Some(adapters),
            parse_error: None,
        });
    }

    // Windows path
    let session = WindowsRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {server_name}: {e}"))?;

    let script = r#"
function Convert-MaskToPrefix($mask) {
    if (-not $mask) { return $null }
    if ($mask -as [int]) {
        $num = [int]$mask
        if ($num -ge 0 -and $num -le 32) { return $num }
    }
    $parts = $mask.ToString().Split('.')
    if ($parts.Count -ne 4) { return $null }
    $bits = 0
    foreach ($p in $parts) {
        $byte = 0
        if (-not [int]::TryParse($p, [ref]$byte)) { return $null }
        $bits += [Convert]::ToString($byte, 2).ToCharArray() | Where-Object { $_ -eq '1' } | Measure-Object | Select-Object -ExpandProperty Count
    }
    return [int]$bits
}

$adapters = @()
try {
    $adapters = Get-NetIPConfiguration -ErrorAction Stop |
        ForEach-Object {
            $ipv4Entries = @()
            foreach ($ip in $_.IPv4Address) {
                if ($ip.IPv4Address) {
                    $prefixVal = if ($ip.PrefixLength -ne $null) { [int]$ip.PrefixLength } else { 0 }
                    $ipv4Entries += [pscustomobject]@{
                        address = $ip.IPv4Address
                        prefix  = $prefixVal
                    }
                }
            }
            $ipv6 = @($_.IPv6Address | ForEach-Object { $_.IPv6Address })
            $dns  = @($_.DNSServer | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
            $gate = @()
            if ($_.IPv4DefaultGateway) {
                $gate = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop } | Where-Object { $_ })
            }
            [pscustomobject]@{
                alias = $_.InterfaceAlias
                description = $_.InterfaceDescription
                ipv4 = $ipv4Entries | ForEach-Object { $_.address }
                ipv4_prefix = $ipv4Entries | ForEach-Object { $_.prefix }
                ipv6 = $ipv6
                dns  = $dns
                gateway = $gate
            }
        }
} catch {
    $adapters = @()
}

if (-not $adapters -or $adapters.Count -eq 0) {
    try {
        $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' |
            ForEach-Object {
                $ipv4 = @()
                $ipv4Prefix = @()
                $ipv6 = @()
                if ($_.IPAddress) {
                    for ($i = 0; $i -lt $_.IPAddress.Count; $i++) {
                        $ip = $_.IPAddress[$i]
                        $mask = if ($_.IPSubnet -and $i -lt $_.IPSubnet.Count) { $_.IPSubnet[$i] } else { $null }
                        if ($ip -like '*.*') {
                            $ipv4 += $ip
                            $prefix = Convert-MaskToPrefix $mask
                            if ($prefix -ne $null) { $ipv4Prefix += [int]$prefix } else { $ipv4Prefix += 0 }
                        } elseif ($ip -like '*:*') {
                            $ipv6 += $ip
                        }
                    }
                }
                $dns  = @($_.DNSServerSearchOrder)
                $gate = @($_.DefaultIPGateway | Where-Object { $_ })
                [pscustomobject]@{
                    alias = $_.Description
                    description = $_.Description
                    ipv4 = $ipv4
                    ipv4_prefix = $ipv4Prefix
                    ipv6 = $ipv6
                    dns  = $dns
                    gateway = $gate
                }
            }
    } catch {
        $adapters = @()
    }
}

if (-not $adapters -or $adapters.Count -eq 0) {
    try {
        $primaryIp = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
            Sort-Object SkipAsSource, InterfaceMetric |
            Select-Object -First 1

        $gwObj = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric |
            Select-Object -First 1

        $dnsList = @()
        try {
            $dnsList = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue
        } catch {
            $dnsList = @()
        }

        if ($primaryIp) {
            $prefix = if ($primaryIp.PrefixLength -ne $null) { [int]$primaryIp.PrefixLength } else { 0 }
            $gateway = @()
            if ($gwObj -and $gwObj.NextHop) {
                $gateway = @($gwObj.NextHop)
            }

            $adapters = @(
                [pscustomobject]@{
                    alias = $primaryIp.InterfaceAlias
                    description = $primaryIp.InterfaceAlias
                    ipv4 = @($primaryIp.IPAddress)
                    ipv4_prefix = @($prefix)
                    ipv6 = @()
                    dns  = @($dnsList)
                    gateway = $gateway
                }
            )
        }
    } catch {
        $adapters = @()
    }
}

if (-not $adapters -or $adapters.Count -eq 0) {
    return @() | ConvertTo-Json -Compress
}

$adapters | Where-Object { $_.ipv4 -or $_.ipv6 } | Select-Object -First 10 | ConvertTo-Json -Compress
"#;

    let raw = session
        .execute_powershell(script)
        .await
        .map_err(|e| format!("Adapter probe failed: {}", e))?;

    let trimmed = raw.trim();
    let parsed: Result<Vec<NetAdapterInfo>, _> = serde_json::from_str(trimmed)
        .or_else(|_| serde_json::from_str(trimmed).map(|one: NetAdapterInfo| vec![one]));

    if let Ok(adapters) = parsed {
        return Ok(AdapterDebugResponse {
            raw: trimmed.to_string(),
            adapters: Some(adapters),
            parse_error: None,
        });
    }

    // Coerce string/single fields into arrays for robustness
    let val: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| e.to_string())?;
    let list: Vec<serde_json::Value> = if val.is_array() {
        val.as_array().cloned().unwrap_or_default()
    } else {
        vec![val]
    };

    let mut adapters = Vec::new();
    for item in list {
        let obj = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        let alias = obj
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let description = obj
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let str_list = |v: &serde_json::Value| -> Vec<String> {
            match v {
                serde_json::Value::String(s) => vec![s.trim().to_string()],
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                    .collect(),
                _ => vec![],
            }
        };
        let num_list = |v: &serde_json::Value| -> Vec<u32> {
            match v {
                serde_json::Value::Number(n) => n.as_u64().map(|u| u as u32).into_iter().collect(),
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .filter_map(|x| {
                        if let Some(u) = x.as_u64() {
                            Some(u as u32)
                        } else if let Some(s) = x.as_str() {
                            s.parse::<u32>().ok()
                        } else {
                            None
                        }
                    })
                    .collect(),
                serde_json::Value::String(s) => s.parse::<u32>().ok().into_iter().collect(),
                _ => vec![],
            }
        };

        adapters.push(NetAdapterInfo {
            alias,
            description,
            ipv4: str_list(obj.get("ipv4").unwrap_or(&serde_json::Value::Null)),
            ipv6: str_list(obj.get("ipv6").unwrap_or(&serde_json::Value::Null)),
            dns: str_list(obj.get("dns").unwrap_or(&serde_json::Value::Null)),
            ipv4_prefix: num_list(obj.get("ipv4_prefix").unwrap_or(&serde_json::Value::Null)),
            gateway: str_list(obj.get("gateway").unwrap_or(&serde_json::Value::Null)),
        });
    }

    if adapters.is_empty() {
        let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
        crate::logger::log_debug_verbose(&format!(
            "fetch_net_adapters: COMPLETE '{}' {}ms 0 adapters (parse error)",
            server_name, elapsed_ms
        ));
        return Ok(AdapterDebugResponse {
            raw: trimmed.to_string(),
            adapters: None,
            parse_error: Some("Unable to coerce adapter payload".to_string()),
        });
    }

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    crate::logger::log_debug_verbose(&format!(
        "fetch_net_adapters: COMPLETE '{}' {}ms {} adapter(s)",
        server_name,
        elapsed_ms,
        adapters.len()
    ));

    Ok(AdapterDebugResponse {
        raw: trimmed.to_string(),
        adapters: Some(adapters),
        parse_error: None,
    })
}

/// Fetch OS info only (lightweight helper when full probe fails)
#[tauri::command]
pub(crate) async fn fetch_os_info(server_name: String) -> Result<OsInfo, String> {
    let start = SystemTime::now();
    crate::logger::log_debug_verbose(&format!("fetch_os_info: START '{}'", server_name));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    let (credentials, _) = resolve_host_credentials(&server_name).await?;
    let session = connect_remote_session(server_name.clone(), credentials, &os_hint).await?;

    let result = match &session {
        SessionKind::Windows(win) => win
            .get_os_info()
            .await
            .map_err(|e| format!("Failed to fetch OS info for {server_name}: {e}")),
        SessionKind::Linux(_) => session
            .as_remote()
            .get_os_info()
            .await
            .map_err(|e| format!("Failed to fetch OS info for {server_name}: {e}")),
    };

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    match &result {
        Ok(_) => crate::logger::log_debug_verbose(&format!(
            "fetch_os_info: SUCCESS '{}' {}ms",
            server_name, elapsed_ms
        )),
        Err(e) => crate::logger::log_error(&format!(
            "fetch_os_info: FAILED '{}' {}ms: {}",
            server_name, elapsed_ms, e
        )),
    }

    result
}

// ---------------------------------------------------------------------------
// Reachability probing
// ---------------------------------------------------------------------------

/// Probe basic reachability via ICMP ping and TCP connect attempts to selected ports.
pub(crate) async fn probe_reachability(
    server_name: &str,
    tcp_ports: &[u16],
    timeout_ms: u64,
) -> ReachabilitySummary {
    let ping_ok = ping_host(server_name).await.unwrap_or(false);

    // Probe all TCP ports in parallel for better performance
    let futures: Vec<_> = tcp_ports
        .iter()
        .copied()
        .filter(|&port| port != 0)
        .map(|port| {
            let server_name = server_name.to_string();
            async move {
                let target = format!("{}:{}", server_name, port);
                let result = timeout(
                    Duration::from_millis(timeout_ms),
                    TcpStream::connect(&target),
                )
                .await;
                match result {
                    Ok(Ok(_)) => TcpProbeResult {
                        port,
                        ok: true,
                        error: None,
                    },
                    Ok(Err(e)) => TcpProbeResult {
                        port,
                        ok: false,
                        error: Some(e.to_string()),
                    },
                    Err(_) => TcpProbeResult {
                        port,
                        ok: false,
                        error: Some("TCP probe timed out".to_string()),
                    },
                }
            }
        })
        .collect();

    let tcp_results = join_all(futures).await;

    ReachabilitySummary {
        ping_ok,
        tcp_ports: tcp_results,
    }
}
