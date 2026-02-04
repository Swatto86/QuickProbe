//! Probe functions for interrogating Windows servers
//!
//! This module provides high-level probe functions that use RemoteSession
//! to gather specific information about servers. Each probe focuses on a
//! particular aspect of server health or configuration.
//!
//! # Architecture
//!
//! Probes are designed to:
//! - Accept a RemoteSession trait object (enabling mocking in tests)
//! - Return structured ProbeResult data
//! - Handle errors gracefully with descriptive messages
//! - Be composable and reusable
//!
//! # Example
//!
//! ```ignore
//! use quickprobe::core::{MockRemoteSession, disk_alert_probe};
//!
//! #[tokio::main]
//! async fn main() {
//!     let session = MockRemoteSession::server2022("TEST-SRV".to_string());
//!     let disks = disk_alert_probe(&session, 10.0).await.unwrap();
//!     println!("Low disk space alerts: {:?}", disks);
//! }
//! ```

use super::session::{
    DiskInfo, FirewallProfile, NetAdapterInfo, OsInfo, PendingRebootStatus, ProcessInfo,
    RecentErrorEntry, RemoteSession, ServiceInfo, SessionOs, UptimeSnapshot, WinRmListener,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

// Default critical services kept minimal to avoid flagging services not present on a host.
// Role-specific services (e.g., SQL, DC) should be provided by the caller.
const DEFAULT_CRITICAL_SERVICES: &[&str] = &["WinRM"];

/// Result of a disk space alert probe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskAlertResult {
    /// Disks that are below the threshold
    pub critical_disks: Vec<DiskInfo>,
    /// All disks inspected
    pub all_disks: Vec<DiskInfo>,
    /// Total number of disks checked
    pub total_disks: usize,
    /// Threshold percentage used
    pub threshold_percent: f64,
}

/// Result of a service health probe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealthResult {
    /// Services that are stopped but should be running
    pub stopped_services: Vec<ServiceInfo>,
    /// Status for each requested service (includes missing as NotFound)
    pub service_status: Vec<ServiceInfo>,
    /// Total services checked
    pub total_checked: usize,
    /// Service names that were requested
    pub requested_services: Vec<String>,
}

/// Overall system health summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthSummary {
    /// Server name
    pub server_name: String,
    /// Indicates WinRM was unavailable and data is limited
    pub winrm_issue: bool,
    /// Optional WinRM error detail when degraded
    pub winrm_error: Option<String>,
    /// Operating system information
    pub os_info: OsInfo,
    /// Disks below threshold
    pub disk_alerts: Vec<DiskInfo>,
    /// Total disks probed
    pub total_disks: usize,
    /// All disks probed
    pub disks: Vec<DiskInfo>,
    /// Number of stopped critical services
    pub service_alerts: usize,
    /// Status for each requested critical service
    pub service_status: Vec<ServiceInfo>,
    /// Total number of running processes
    pub process_count: usize,
    /// High CPU processes above the configured threshold
    pub high_cpu_processes: Vec<ProcessInfo>,
    /// Threshold percentage used to classify high CPU
    pub high_cpu_threshold: f64,
    /// Total physical memory (MB)
    pub total_memory_mb: f64,
    /// Used physical memory (MB)
    pub used_memory_mb: f64,
    /// Percentage of physical memory in use
    pub memory_used_percent: f64,
    /// Uptime and CPU snapshot
    pub uptime: Option<UptimeSnapshot>,
    /// Pending reboot indicators
    pub pending_reboot: Option<PendingRebootStatus>,
    /// WinRM listener configuration
    pub winrm_listeners: Option<Vec<WinRmListener>>,
    /// Firewall profiles
    pub firewall_profiles: Option<Vec<FirewallProfile>>,
    /// Recent error events
    pub recent_errors: Option<Vec<RecentErrorEntry>>,
    /// Network adapters
    pub net_adapters: Option<Vec<NetAdapterInfo>>,
    /// Network reachability (ping + TCP) snapshot
    pub reachability: Option<ReachabilitySummary>,
}

/// Result of probing TCP ports on a host
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpProbeResult {
    /// Port that was probed
    pub port: u16,
    /// Whether a TCP connection succeeded
    pub ok: bool,
    /// Optional error detail when the probe failed
    pub error: Option<String>,
}

/// Summary of reachability for a host
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReachabilitySummary {
    /// ICMP reachability (simple ping)
    pub ping_ok: bool,
    /// Per-port TCP reachability results
    pub tcp_ports: Vec<TcpProbeResult>,
}

async fn run_ps_json<T: DeserializeOwned>(
    session: &dyn RemoteSession,
    script: &str,
    label: &str,
) -> Result<T, String> {
    let raw = session
        .execute_powershell(script)
        .await
        .map_err(|e| format!("{}: {}", label, e))?;

    serde_json::from_str(&raw)
        .map_err(|e| format!("{}: failed to parse JSON: {} (raw: {})", label, e, raw))
}

/// Probe for disks with low free space
///
/// Returns disks where free space percentage is below the threshold.
///
/// # Arguments
///
/// * `session` - RemoteSession implementation (real or mock)
/// * `threshold_percent` - Alert if free space is below this percentage (0-100)
///
/// # Example
///
/// ```ignore
/// let disks = disk_alert_probe(&session, 10.0).await?;
/// if !disks.critical_disks.is_empty() {
///     println!("WARNING: {} disks low on space", disks.critical_disks.len());
/// }
/// ```
pub async fn disk_alert_probe(
    session: &dyn RemoteSession,
    threshold_percent: f64,
) -> Result<DiskAlertResult, String> {
    // Validate threshold
    if !(0.0..=100.0).contains(&threshold_percent) {
        return Err(format!(
            "Invalid threshold: {}. Must be between 0 and 100",
            threshold_percent
        ));
    }

    let all_disks = session
        .get_disks()
        .await
        .map_err(|e| format!("Failed to get disk info: {}", e))?;

    let total_disks = all_disks.len();

    let critical_disks: Vec<DiskInfo> = all_disks
        .iter()
        .filter(|disk| disk.percent_free < threshold_percent)
        .cloned()
        .collect();

    Ok(DiskAlertResult {
        total_disks,
        threshold_percent,
        critical_disks,
        all_disks,
    })
}

/// Probe for critical services that should be running
///
/// Checks specified services and reports which ones are stopped.
///
/// # Arguments
///
/// * `session` - RemoteSession implementation
/// * `service_names` - List of service names to check (e.g., "W32Time", "MSSQLSERVER")
///
/// # Example
///
/// ```ignore
/// let services = vec!["W32Time".to_string(), "MSSQLSERVER".to_string()];
/// let result = service_health_probe(&session, &services).await?;
/// ```
pub async fn service_health_probe(
    session: &dyn RemoteSession,
    service_names: &[String],
) -> Result<ServiceHealthResult, String> {
    // If no services specified, return empty result instead of error
    if service_names.is_empty() {
        return Ok(ServiceHealthResult {
            stopped_services: Vec::new(),
            service_status: Vec::new(),
            total_checked: 0,
            requested_services: Vec::new(),
        });
    }

    let requested_names: HashSet<String> = service_names
        .iter()
        .map(|name| name.to_lowercase())
        .collect();

    let all_services = session
        .get_services(None)
        .await
        .map_err(|e| format!("Failed to get services: {}", e))?;

    // Capture status for every requested service, even if not present on host
    let mut service_status: Vec<ServiceInfo> = all_services
        .iter()
        .filter(|svc| requested_names.contains(&svc.name.to_lowercase()))
        .cloned()
        .collect();

    // Mark any missing services explicitly so callers can surface them
    for name in service_names {
        if !service_status
            .iter()
            .any(|svc| svc.name.eq_ignore_ascii_case(name))
        {
            service_status.push(ServiceInfo {
                name: name.clone(),
                display_name: name.clone(),
                status: "NotFound".to_string(),
                startup_type: "Unknown".to_string(),
                service_account: "Unknown".to_string(),
            });
        }
    }

    let stopped_services: Vec<ServiceInfo> = service_status
        .iter()
        .filter(|svc| !svc.status.eq_ignore_ascii_case("running"))
        .cloned()
        .collect();

    Ok(ServiceHealthResult {
        stopped_services,
        service_status,
        total_checked: service_names.len(),
        requested_services: service_names.to_vec(),
    })
}

/// Comprehensive system health probe
///
/// Gathers overall system information including OS details, disk alerts,
/// service health, and process information.
///
/// # Arguments
///
/// * `session` - RemoteSession implementation
/// * `critical_services` - Services to check (optional, defaults to common Windows services)
/// * `disk_threshold` - Disk space alert threshold percentage
///
/// # Example
///
/// ```ignore
/// let health = system_health_probe(&session, None, 10.0).await?;
/// println!("Server: {}", health.server_name);
/// println!("OS: {} {}", health.os_info.caption, health.os_info.version);
/// println!("Alerts: {} disk, {} service", health.disk_alerts, health.service_alerts);
/// ```
pub async fn system_health_probe(
    session: &dyn RemoteSession,
    critical_services: Option<&[String]>,
    disk_threshold: f64,
) -> Result<SystemHealthSummary, String> {
    const HIGH_CPU_THRESHOLD: f64 = 50.0;
    // Default critical services: Windows uses WinRM; Linux uses no defaults (user must specify).
    // This avoids false "NotFound" alerts when probing Linux with Windows service names.
    let is_windows = matches!(session.os(), SessionOs::Windows);
    let default_services: Vec<String> = if is_windows {
        DEFAULT_CRITICAL_SERVICES
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        Vec::new() // No defaults for Linux - user must configure services to monitor
    };
    let services_to_check = critical_services.unwrap_or(&default_services);

    // Gather all data in parallel (where possible, but keeping it simple for now)
    let server_name = session.server_name();
    let os_info = session
        .get_os_info()
        .await
        .map_err(|e| format!("Failed to get OS info: {}", e))?;

    let disk_result = disk_alert_probe(session, disk_threshold).await?;
    let service_result = service_health_probe(session, services_to_check).await?;
    let memory_info = session
        .get_memory_info()
        .await
        .map_err(|e| format!("Failed to get memory info: {}", e))?;

    let all_processes = session
        .get_processes(None)
        .await
        .map_err(|e| format!("Failed to get processes: {}", e))?;

    // Find high CPU processes
    let mut high_cpu_processes: Vec<ProcessInfo> = all_processes
        .iter()
        .filter(|p| p.cpu_percent > HIGH_CPU_THRESHOLD && !p.cpu_percent.is_nan())
        .cloned()
        .collect();

    high_cpu_processes.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let used_memory_mb = (memory_info.total_mb - memory_info.free_mb).max(0.0);
    let memory_used_percent = if memory_info.total_mb > 0.0 {
        (used_memory_mb / memory_info.total_mb) * 100.0
    } else {
        0.0
    };

    // Optional extended probes (best-effort)
    let is_windows = matches!(session.os(), SessionOs::Windows);
    let (
        uptime,
        pending_reboot,
        winrm_listeners,
        firewall_profiles,
        recent_errors,
        net_adapters,
        adapter_error,
    ) = if is_windows {
        let uptime = run_ps_json::<UptimeSnapshot>(
        session,
        r#"
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
[pscustomobject]@{
    last_boot    = $os.LastBootUpTime
    uptime_hours = [math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours,2)
    cpu_load_pct = $cpu.LoadPercentage
} | ConvertTo-Json -Compress
"#,
        "uptime snapshot",
    )
    .await
    .ok();

        let pending_reboot = run_ps_json::<PendingRebootStatus>(
        session,
        r#"
$signals = @()
if (Test-Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $signals += 'CBS RebootPending' }
if (Test-Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $signals += 'WU RebootRequired' }
if ((Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)) { $signals += 'PendingFileRenameOperations' }
[pscustomobject]@{
    pending = $signals.Count -gt 0
    signals = $signals
} | ConvertTo-Json -Compress
"#,
        "pending reboot",
    )
    .await
    .ok();

        let winrm_listeners = run_ps_json::<Vec<WinRmListener>>(
            session,
            r#"
try {
    $listeners = Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop
} catch {
    $listeners = @()
}
$listeners | ForEach-Object {
    [pscustomobject]@{
        transport = $_.Keys['Transport']
        address   = $_.Keys['Address']
        port      = $_.get_Item('Port')
        enabled   = $_.get_Item('Enabled')
        hostname  = $_.get_Item('Hostname')
        certificate_thumbprint = $_.get_Item('CertificateThumbprint')
    }
} | ConvertTo-Json -Compress
"#,
            "winrm listeners",
        )
        .await
        .ok();

        let firewall_profiles = run_ps_json::<Vec<FirewallProfile>>(
        session,
        r#"
try {
    Get-NetFirewallProfile | Select-Object @{n='name';e={$_.Name}}, @{n='enabled';e={$_.Enabled}}, @{n='default_inbound_action';e={$_.DefaultInboundAction}}, @{n='default_outbound_action';e={$_.DefaultOutboundAction}} | ConvertTo-Json -Compress
} catch {
    @() | ConvertTo-Json -Compress
}
"#,
        "firewall profiles",
    )
    .await
    .ok();

        let recent_errors = run_ps_json::<Vec<RecentErrorEntry>>(
        session,
        r#"
$cutoff = (Get-Date).AddMinutes(-30)
$logs = 'System','Application'
$all = @()
foreach ($log in $logs) {
    try {
        $entries = Get-WinEvent -FilterHashtable @{LogName=$log; Level=@(1,2); StartTime=$cutoff} -MaxEvents 10
        $entries | ForEach-Object {
            $all += [pscustomobject]@{
                log = $log
                time_created = $_.TimeCreated
                id = $_.Id
                provider = $_.ProviderName
                level = $_.LevelDisplayName
                message = $_.Message
            }
        }
    } catch {
        continue
    }
}
$all | Sort-Object -Property time_created -Descending | Select-Object -First 10 | ConvertTo-Json -Compress
"#,
        "recent errors",
    )
    .await
    .ok();

        let mut adapter_error: Option<String> = None;
        let net_adapters = {
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

$debug = @()

# Try Get-NetIPConfiguration first (Server 2012 R2+, Windows 8.1+)
# Provides comprehensive network configuration including IPv4/IPv6, DNS, gateway
try {
    $debug += "Trying Get-NetIPConfiguration"
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
    $debug += "Get-NetIPConfiguration failed: $($_.Exception.Message)"
    $adapters = @()
}

# Early return if modern cmdlet succeeded
if ($adapters -and $adapters.Count -gt 0) {
    $debug += "Get-NetIPConfiguration returned $($adapters.Count) adapters"
    $result = $adapters | Where-Object { $_.ipv4 -or $_.ipv6 } | Select-Object -First 10
    if ($result) {
        $debug += "Filtered to $(@($result).Count) adapters with IP"
        @{ adapters = $result; debug = $debug } | ConvertTo-Json -Compress -Depth 5
    } else {
        $debug += "No adapters with IPv4/IPv6 addresses"
        @{ adapters = @(); debug = $debug } | ConvertTo-Json -Compress -Depth 5
    }
    exit
}

# Fallback to WMI (Server 2008/2012, all Windows versions)
# Legacy method, slower but works when modern cmdlets unavailable
$debug += "Trying WMI Win32_NetworkAdapterConfiguration"
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
    $debug += "WMI query failed: $($_.Exception.Message)"
    $adapters = @()
}

# Return adapters or empty array if both methods failed
if (-not $adapters -or $adapters.Count -eq 0) {
    $debug += "No adapters found from any method"
    @{ adapters = @(); debug = $debug } | ConvertTo-Json -Compress -Depth 5
} else {
    $debug += "WMI returned $($adapters.Count) adapters"
    $result = $adapters | Where-Object { $_.ipv4 -or $_.ipv6 } | Select-Object -First 10
    if ($result) {
        $debug += "Filtered to $(@($result).Count) adapters with IP"
        @{ adapters = $result; debug = $debug } | ConvertTo-Json -Compress -Depth 5
    } else {
        $debug += "No adapters with IPv4/IPv6 addresses"
        @{ adapters = @(); debug = $debug } | ConvertTo-Json -Compress -Depth 5
    }
}
"#;

            let result = session.execute_powershell(script).await;
            let parsed = match result {
                Ok(raw) => {
                    let parsed = coerce_adapters_from_str(&raw);
                    let count = parsed.as_ref().map(|v| v.len()).unwrap_or(0);
                    let preview: String = raw.chars().take(300).collect();
                    crate::logger::log_debug(&format!(
                        "[probe] adapters for {}: payload_len={}, parsed_count={}, preview='{}'",
                        session.server_name(),
                        raw.len(),
                        count,
                        preview.replace('\n', " ").replace('\r', "")
                    ));
                    parsed
                }
                Err(err) => {
                    crate::logger::log_warn(&format!(
                        "[probe] adapter script failed for {}: {}",
                        session.server_name(),
                        err
                    ));
                    adapter_error = Some(err);
                    None
                }
            };
            if parsed.is_none() {
                crate::logger::log_warn(&format!(
                    "[probe] No adapters found for {} after all fallbacks (Get-NetIPConfiguration/WMI)",
                    session.server_name()
                ));
            }
            if parsed.is_none() && adapter_error.is_none() {
                adapter_error = Some("Adapter probe returned no data".to_string());
            }
            parsed
        };

        (
            uptime,
            pending_reboot,
            winrm_listeners,
            firewall_profiles,
            recent_errors,
            net_adapters,
            adapter_error,
        )
    } else {
        // Linux: collect uptime and network adapter info via trait methods
        let uptime = session.get_uptime_snapshot().await.ok();
        let net_adapters = session.get_net_adapters().await.ok();

        crate::logger::log_debug(&format!(
            "[probe] Linux uptime for {}: {:?}",
            session.server_name(),
            uptime
        ));
        crate::logger::log_debug(&format!(
            "[probe] Linux adapters for {}: count={}",
            session.server_name(),
            net_adapters.as_ref().map(|v| v.len()).unwrap_or(0)
        ));

        (uptime, None, None, None, None, net_adapters, None)
    };

    let mut summary = SystemHealthSummary {
        server_name: server_name.to_string(),
        winrm_issue: false,
        winrm_error: None,
        os_info,
        disk_alerts: disk_result.critical_disks,
        total_disks: disk_result.total_disks,
        disks: disk_result.all_disks,
        service_alerts: service_result.stopped_services.len(),
        service_status: service_result.service_status,
        process_count: all_processes.len(),
        high_cpu_processes,
        high_cpu_threshold: HIGH_CPU_THRESHOLD,
        total_memory_mb: memory_info.total_mb,
        used_memory_mb,
        memory_used_percent,
        uptime,
        pending_reboot,
        winrm_listeners,
        firewall_profiles,
        recent_errors,
        net_adapters,
        reachability: None,
    };

    if is_windows {
        let adapters_missing = summary
            .net_adapters
            .as_ref()
            .map(|v| v.is_empty())
            .unwrap_or(true);
        if adapters_missing {
            let reason = adapter_error.unwrap_or_else(|| "no adapters returned".to_string());
            summary.winrm_issue = true;
            summary.winrm_error = Some(format!("Adapter probe failed: {}", reason));
        }
    }

    Ok(summary)
}

fn coerce_adapters_from_str(raw: &str) -> Option<Vec<NetAdapterInfo>> {
    let trimmed = raw.trim();
    let val: Value = serde_json::from_str(trimmed).ok()?;

    let (list, debug_lines): (Vec<Value>, Vec<String>) = match &val {
        Value::Object(map) => {
            if let Some(adapters_val) = map.get("adapters") {
                let debug = map
                    .get("debug")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();
                let adapters_vec = if adapters_val.is_array() {
                    adapters_val.as_array().cloned().unwrap_or_default()
                } else {
                    vec![adapters_val.clone()]
                };
                (adapters_vec, debug)
            } else {
                (vec![val.clone()], vec![])
            }
        }
        Value::Array(_) => (val.as_array().cloned().unwrap_or_default(), vec![]),
        _ => (vec![val.clone()], vec![]),
    };

    fn str_list(v: &Value) -> Vec<String> {
        match v {
            Value::String(s) => vec![s.trim().to_string()],
            Value::Array(arr) => arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                .collect(),
            _ => vec![],
        }
    }

    fn num_list(v: &Value) -> Vec<u32> {
        match v {
            Value::Number(n) => n.as_u64().map(|u| u as u32).into_iter().collect(),
            Value::Array(arr) => arr
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
            Value::String(s) => s.parse::<u32>().ok().into_iter().collect(),
            _ => vec![],
        }
    }

    let mut adapters = Vec::new();
    for item in list {
        let obj = item.as_object()?;
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
        adapters.push(NetAdapterInfo {
            alias,
            description,
            ipv4: str_list(obj.get("ipv4").unwrap_or(&Value::Null)),
            ipv6: str_list(obj.get("ipv6").unwrap_or(&Value::Null)),
            dns: str_list(obj.get("dns").unwrap_or(&Value::Null)),
            ipv4_prefix: num_list(obj.get("ipv4_prefix").unwrap_or(&Value::Null)),
            gateway: str_list(obj.get("gateway").unwrap_or(&Value::Null)),
        });
    }

    if !debug_lines.is_empty() {
        crate::logger::log_debug(&format!(
            "[probe] adapters debug: {}",
            debug_lines.join(" | ")
        ));
    }

    if adapters.is_empty() {
        None
    } else {
        Some(adapters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mock_session::MockRemoteSession;

    // ==================== Disk Alert Probe Tests ====================

    #[tokio::test]
    async fn test_disk_alert_finds_critical_disks_server2022() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        // E: drive has 3.75% free (below 10% threshold)
        let result = disk_alert_probe(&session, 10.0).await.unwrap();

        assert_eq!(result.threshold_percent, 10.0);
        assert!(!result.critical_disks.is_empty(), "Should find E: drive");
        assert_eq!(result.critical_disks[0].drive, "E:");
        assert!(result.critical_disks[0].percent_free < 10.0);
        assert_eq!(result.all_disks.len(), 3);
    }

    #[tokio::test]
    async fn test_disk_alert_finds_critical_disks_server2019() {
        let session = MockRemoteSession::server2019("PROD-DB01".to_string());

        // E: drive has 3.75% free (below 5% threshold)
        let result = disk_alert_probe(&session, 5.0).await.unwrap();

        assert!(!result.critical_disks.is_empty());
        assert_eq!(result.critical_disks[0].drive, "E:");
        assert_eq!(result.all_disks.len(), 3);
    }

    #[tokio::test]
    async fn test_disk_alert_no_alerts_high_threshold() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        // No disks below 1% threshold
        let result = disk_alert_probe(&session, 1.0).await.unwrap();

        assert_eq!(result.critical_disks.len(), 0);
        assert_eq!(result.threshold_percent, 1.0);
        assert_eq!(result.all_disks.len(), 3);
    }

    #[tokio::test]
    async fn test_disk_alert_invalid_threshold_below_zero() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        let result = disk_alert_probe(&session, -5.0).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Must be between 0 and 100"));
    }

    #[tokio::test]
    async fn test_disk_alert_invalid_threshold_above_100() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        let result = disk_alert_probe(&session, 150.0).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Must be between 0 and 100"));
    }

    #[tokio::test]
    async fn test_disk_alert_unreachable_server() {
        let session = MockRemoteSession::unreachable("OFFLINE-SRV".to_string());

        let result = disk_alert_probe(&session, 10.0).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to get disk info"));
    }

    // ==================== Service Health Probe Tests ====================

    #[tokio::test]
    async fn test_service_health_all_running() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        // W32Time, MSSQLSERVER are running in mock
        let services = vec!["W32Time".to_string(), "MSSQLSERVER".to_string()];
        let result = service_health_probe(&session, &services).await.unwrap();

        assert_eq!(result.total_checked, 2);
        assert_eq!(result.stopped_services.len(), 0);
        assert_eq!(result.service_status.len(), 2);
        assert!(result
            .service_status
            .iter()
            .all(|svc| svc.status.eq_ignore_ascii_case("running")));
    }

    #[tokio::test]
    async fn test_service_health_finds_stopped_service() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        // SQLSERVERAGENT is stopped in mock
        let services = vec!["SQLSERVERAGENT".to_string()];
        let result = service_health_probe(&session, &services).await.unwrap();

        assert_eq!(result.total_checked, 1);
        assert_eq!(result.stopped_services.len(), 1);
        assert_eq!(result.stopped_services[0].name, "SQLSERVERAGENT");
        assert_eq!(result.stopped_services[0].status, "Stopped");
        assert_eq!(result.service_status.len(), 1);
        assert_eq!(result.service_status[0].status, "Stopped");
    }

    #[tokio::test]
    async fn test_service_health_mixed_states() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        // Mix of running and stopped
        let services = vec![
            "W32Time".to_string(),        // Running
            "SQLSERVERAGENT".to_string(), // Stopped
            "MSSQLSERVER".to_string(),    // Running
        ];
        let result = service_health_probe(&session, &services).await.unwrap();

        assert_eq!(result.total_checked, 3);
        assert_eq!(result.stopped_services.len(), 1);
        assert_eq!(result.service_status.len(), 3);
        assert!(result
            .service_status
            .iter()
            .any(|svc| svc.name.eq_ignore_ascii_case("SQLSERVERAGENT")
                && !svc.status.eq_ignore_ascii_case("running")));
    }

    #[tokio::test]
    async fn test_service_health_marks_missing_services() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        let services = vec!["DoesNotExist".to_string()];
        let result = service_health_probe(&session, &services).await.unwrap();

        assert_eq!(result.total_checked, 1);
        assert_eq!(result.service_status.len(), 1);
        assert_eq!(result.service_status[0].name, "DoesNotExist");
        assert_eq!(result.service_status[0].status, "NotFound");
        assert_eq!(result.stopped_services.len(), 1);
    }

    #[tokio::test]
    async fn test_service_health_empty_list() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        let result = service_health_probe(&session, &[]).await;

        // Empty list returns Ok with empty results (not an error)
        assert!(result.is_ok());
        let health = result.unwrap();
        assert_eq!(health.total_checked, 0);
        assert!(health.service_status.is_empty());
        assert!(health.stopped_services.is_empty());
    }

    #[tokio::test]
    async fn test_service_health_unreachable_server() {
        let session = MockRemoteSession::unreachable("OFFLINE-SRV".to_string());

        let services = vec!["W32Time".to_string()];
        let result = service_health_probe(&session, &services).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to get services"));
    }

    // ==================== System Health Probe Tests ====================

    #[tokio::test]
    async fn test_system_health_server2022_comprehensive() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        let result = system_health_probe(&session, None, 10.0).await.unwrap();

        assert_eq!(result.server_name, "TEST-SRV");
        assert!(
            result.os_info.os_version.contains("Server 2022")
                || result.os_info.product_type == "Server"
        );
        assert!(!result.disk_alerts.is_empty(), "Should have E: drive alert");
        assert_eq!(result.disks.len(), 3);
        assert_eq!(result.process_count, 6); // Mock has 6 processes
                                             // Chrome has >50% CPU in mock
        assert!(!result.high_cpu_processes.is_empty());
        assert_eq!(result.high_cpu_threshold, 50.0);
        assert!(result.total_memory_mb > 0.0);
        assert!(result.used_memory_mb >= 0.0);
        assert!(result.memory_used_percent >= 0.0 && result.memory_used_percent <= 100.0);
        assert_eq!(result.service_status.len(), DEFAULT_CRITICAL_SERVICES.len());
        assert_eq!(result.service_alerts, 0); // WinRM running in mock
    }

    #[tokio::test]
    async fn test_system_health_server2019_comprehensive() {
        let session = MockRemoteSession::server2019("PROD-DB01".to_string());

        let result = system_health_probe(&session, None, 10.0).await.unwrap();

        assert_eq!(result.server_name, "PROD-DB01");
        assert!(
            result.os_info.os_version.contains("Server 2019")
                || result.os_info.product_type == "Server"
        );
        assert!(!result.disk_alerts.is_empty());
        assert_eq!(result.disks.len(), 3);
        assert_eq!(result.service_status.len(), DEFAULT_CRITICAL_SERVICES.len());
        assert_eq!(result.service_alerts, 0);
    }

    #[tokio::test]
    async fn test_system_health_custom_services() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        let custom_services = vec!["SQLSERVERAGENT".to_string()]; // Stopped in mock
        let result = system_health_probe(&session, Some(&custom_services), 10.0)
            .await
            .unwrap();

        assert_eq!(result.service_alerts, 1); // SQLSERVERAGENT is stopped
        assert_eq!(result.service_status.len(), 1);
        assert!(result
            .service_status
            .iter()
            .all(|svc| svc.name.eq_ignore_ascii_case("SQLSERVERAGENT")));
        assert_eq!(result.disks.len(), 3);
    }

    #[tokio::test]
    async fn test_system_health_high_cpu_detection() {
        let session = MockRemoteSession::server2022("TEST-SRV".to_string());

        let result = system_health_probe(&session, None, 10.0).await.unwrap();

        // Chrome has >90% CPU in mock
        let chrome_process = result
            .high_cpu_processes
            .iter()
            .find(|p| p.name == "chrome.exe");
        assert!(chrome_process.is_some());
        assert!(chrome_process.unwrap().cpu_percent > result.high_cpu_threshold);
        // Ensure sorted descending
        for i in 1..result.high_cpu_processes.len() {
            assert!(
                result.high_cpu_processes[i - 1].cpu_percent
                    >= result.high_cpu_processes[i].cpu_percent
            );
        }
    }

    #[tokio::test]
    async fn test_system_health_unreachable_server() {
        let session = MockRemoteSession::unreachable("OFFLINE-SRV".to_string());

        let result = system_health_probe(&session, None, 10.0).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to get"));
    }
}
