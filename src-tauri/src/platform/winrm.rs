//! Windows Remote Session via WinRM/PSRemoting
//!
//! Provides real WinRM connectivity using PowerShell Remoting.
//! Implements the `RemoteSession` trait for production use.
//!
//! # Session lifecycle
//!
//! Each `execute_remote()` call creates an **explicit** `PSSession` via
//! `New-PSSession`, executes the script with `Invoke-Command -Session`,
//! and tears it down with `Remove-PSSession` inside a `finally` block.
//! This guarantees the remote `wsmprovhost.exe` process is freed
//! immediately, preventing memory accumulation on target servers.
//!
//! `connect()` is lightweight (no network call). The previous
//! `Test-WSMan` pre-check was removed from the hot path to avoid
//! creating a redundant implicit session per probe cycle. Use
//! `validate_reachability()` for explicit checks on user-initiated
//! actions.

use crate::core::{
    session::{
        DiskInfo, FirewallProfile, MemoryInfo, NetAdapterInfo, OsInfo, PendingRebootStatus,
        ProcessInfo, QuickProbeSummary, RecentErrorEntry, RemoteSession, ServiceInfo, SessionOs,
        UptimeSnapshot, WinRmListener,
    },
    SystemHealthSummary,
};
use crate::models::{Credentials, SecureString, Username};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Windows flag to create process without a console window
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Escapes user input for safe embedding in PowerShell -like patterns
///
/// PowerShell -like operator treats certain characters as wildcards or special:
/// - `*` = wildcard (zero or more chars)
/// - `?` = wildcard (single char)
/// - `[...]` = character class
/// - `'` = string delimiter
/// - `}` = script block terminator
/// - `$` = variable expansion
///
/// This function escapes all special characters to prevent command injection.
///
/// # Security
/// This prevents injection attacks when user-provided filter strings are embedded
/// in PowerShell Where-Object clauses. Without proper escaping, an attacker could
/// break out of the -like operator and execute arbitrary commands.
fn escape_powershell_like_pattern(s: &str) -> String {
    s.replace('`', "``") // Backtick must be escaped first (it's the escape char)
        .replace('\'', "''") // Single quotes are doubled (PowerShell string escape)
        .replace('[', "`[") // Square brackets are wildcard class delimiters
        .replace(']', "`]")
        .replace('*', "`*") // Asterisk is wildcard
        .replace('?', "`?") // Question mark is single-char wildcard
        .replace('{', "`{") // Opening brace for script blocks
        .replace('}', "`}") // Closing brace could terminate script block
        .replace('$', "`$") // Dollar sign is variable expansion
        .replace('(', "`(") // Parentheses for subexpressions
        .replace(')', "`)")
        .replace('|', "`|") // Pipe could chain commands
}

/// Windows Remote Session via WinRM
///
/// Connects to remote Windows servers using PowerShell Remoting (WinRM).
/// Requires:
/// - Target server has WinRM enabled (`Enable-PSRemoting`)
/// - Credentials with appropriate permissions
/// - Network connectivity to target server
pub struct WindowsRemoteSession {
    server_name: String,
    username: String,
    #[allow(dead_code)] // Will be used for actual WinRM connection implementation
    password: SecureString,
}

#[derive(Debug, Deserialize)]
struct CombinedHealthPayload {
    server_name: Option<String>,
    os_info: OsInfo,
    disk_alerts: Vec<DiskInfo>,
    total_disks: usize,
    disks: Vec<DiskInfo>,
    service_alerts: usize,
    service_status: Vec<ServiceInfo>,
    process_count: usize,
    high_cpu_processes: Vec<ProcessInfo>,
    high_cpu_threshold: f64,
    total_memory_mb: f64,
    used_memory_mb: f64,
    memory_used_percent: f64,
    uptime: Option<UptimeSnapshot>,
    pending_reboot: Option<PendingRebootStatus>,
    winrm_listeners: Option<Vec<WinRmListener>>,
    firewall_profiles: Option<Vec<FirewallProfile>>,
    recent_errors: Option<Vec<RecentErrorEntry>>,
    net_adapters: Option<Vec<NetAdapterInfo>>,
}

#[derive(Debug, Deserialize)]
struct QuickProbePayload {
    server_name: Option<String>,
    uptime_hours: Option<f64>,
    cpu_load_pct: Option<f64>,
    memory_used_percent: Option<f64>,
    total_memory_mb: Option<f64>,
    used_memory_mb: Option<f64>,
    process_count: Option<u64>,
    top_cpu_processes: Option<Vec<ProcessInfo>>,
    service_status: Option<Vec<ServiceInfo>>,
}

fn adapter_probe_script() -> &'static str {
    r#"
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

$result = $adapters | Where-Object { $_.ipv4 -or $_.ipv6 } | Select-Object -First 10
@($result) | ConvertTo-Json -Compress
"#
}

impl WindowsRemoteSession {
    /// Adds host context to error messages for easier debugging
    ///
    /// All WinRM errors should use this helper to include the target host name.
    /// This makes logs significantly more useful when managing multiple servers.
    fn error_context(&self, msg: &str) -> String {
        format!("[{}] {}", self.server_name, msg)
    }

    /// Helper for JSON parse errors that includes raw output for debugging
    ///
    /// When PowerShell output can't be parsed as expected JSON, this helper:
    /// 1. Includes the host name
    /// 2. Includes the operation that failed
    /// 3. Includes the parse error details
    /// 4. Includes the first 500 chars of raw output (often reveals the issue)
    fn json_parse_error(&self, operation: &str, err: serde_json::Error, raw: &str) -> String {
        self.error_context(&format!(
            "Failed to parse {} JSON: {}. Raw output (first 500 chars): {}",
            operation,
            err,
            &raw.chars().take(500).collect::<String>()
        ))
    }

    fn normalize_array_field(obj: &mut Value, key: &str) {
        let Some(val) = obj.get_mut(key) else {
            return;
        };

        let normalized = match val.take() {
            Value::Array(arr) => arr,
            Value::Null => Vec::new(),
            other => vec![other],
        };

        *val = Value::Array(normalized);
    }

    fn coerce_number_field(obj: &mut Value, key: &str) {
        let Some(val) = obj.get_mut(key) else {
            return;
        };

        if let Some(num) = val
            .as_f64()
            .or_else(|| val.as_str().and_then(|s| s.parse::<f64>().ok()))
            .and_then(Number::from_f64)
        {
            *val = Value::Number(num);
        } else if !val.is_null() {
            *val = Value::Null;
        }
    }

    fn coerce_integer_field(obj: &mut Value, key: &str) {
        let Some(val) = obj.get_mut(key) else {
            return;
        };

        let as_int = val
            .as_i64()
            .or_else(|| val.as_u64().map(|u| u as i64))
            .or_else(|| {
                val.as_f64()
                    .map(|f| if f.is_finite() { f.trunc() as i64 } else { 0 })
            })
            .or_else(|| val.as_str().and_then(|s| s.parse::<i64>().ok()));

        if let Some(num) = as_int {
            *val = Value::Number(Number::from(num));
        } else if !val.is_null() {
            *val = Value::Null;
        }
    }

    fn clamp_percent(obj: &mut Value, key: &str) {
        let Some(val) = obj.get_mut(key) else {
            return;
        };
        if let Some(n) = val.as_f64() {
            let clamped = n.clamp(0.0, 100.0);
            if let Some(num) = Number::from_f64(clamped) {
                *val = Value::Number(num);
            }
        }
    }

    fn clamp_non_negative(obj: &mut Value, key: &str) {
        let Some(val) = obj.get_mut(key) else {
            return;
        };
        if let Some(n) = val.as_f64() {
            let clamped = n.max(0.0);
            if let Some(num) = Number::from_f64(clamped) {
                *val = Value::Number(num);
            }
        }
    }

    fn scrub_process_list(obj: &mut Value, key: &str) {
        let Some(val) = obj.get_mut(key) else {
            return;
        };
        let list = match val.take() {
            Value::Array(arr) => arr,
            Value::Object(map) => vec![Value::Object(map)],
            other => vec![other],
        };

        let mut cleaned = Vec::new();
        for mut item in list {
            Self::coerce_integer_field(&mut item, "pid");
            Self::coerce_number_field(&mut item, "memory_mb");
            Self::clamp_non_negative(&mut item, "memory_mb");
            Self::coerce_number_field(&mut item, "cpu_percent");
            Self::clamp_percent(&mut item, "cpu_percent");
            cleaned.push(item);
        }

        *val = Value::Array(cleaned);
    }

    fn scrub_disk_list(obj: &mut Value, key: &str) {
        let Some(val) = obj.get_mut(key) else {
            return;
        };
        let list = match val.take() {
            Value::Array(arr) => arr,
            Value::Object(map) => vec![Value::Object(map)],
            other => vec![other],
        };

        let mut cleaned = Vec::new();
        for mut item in list {
            if item.is_object() {
                Self::coerce_number_field(&mut item, "total_gb");
                Self::coerce_number_field(&mut item, "free_gb");
                Self::coerce_number_field(&mut item, "used_gb");
                Self::coerce_number_field(&mut item, "percent_free");
                Self::clamp_non_negative(&mut item, "total_gb");
                Self::clamp_non_negative(&mut item, "free_gb");
                Self::clamp_non_negative(&mut item, "used_gb");
                Self::clamp_percent(&mut item, "percent_free");
            }
            cleaned.push(item);
        }

        *val = Value::Array(cleaned);
    }

    fn scrub_service_list(obj: &mut Value, key: &str) {
        let Some(val) = obj.get_mut(key) else {
            return;
        };
        let list = match val.take() {
            Value::Array(arr) => arr,
            Value::Object(map) => vec![Value::Object(map)],
            other => vec![other],
        };

        let mut cleaned = Vec::new();
        for mut item in list {
            if let Some(map) = item.as_object_mut() {
                if let Some(status) = map.get_mut("status") {
                    if let Some(s) = status.as_str() {
                        *status = Value::String(s.trim().to_string());
                    }
                }
                if let Some(name) = map.get_mut("name") {
                    if let Some(s) = name.as_str() {
                        *name = Value::String(s.trim().to_string());
                    }
                }
                cleaned.push(Value::Object(map.clone()));
            } else {
                cleaned.push(item);
            }
        }

        *val = Value::Array(cleaned);
    }

    fn scrub_recent_errors(obj: &mut Value, key: &str) {
        let Some(val) = obj.get_mut(key) else {
            return;
        };
        let list = match val.take() {
            Value::Array(arr) => arr,
            Value::Object(map) => vec![Value::Object(map)],
            other => vec![other],
        };

        let mut cleaned = Vec::new();
        for mut item in list {
            if let Some(map) = item.as_object_mut() {
                for text_key in ["log", "provider", "message", "time_created"] {
                    if let Some(v) = map.get_mut(text_key) {
                        if let Some(s) = v.as_str() {
                            *v = Value::String(s.trim().to_string());
                        }
                    }
                }
            }
            Self::coerce_integer_field(&mut item, "id");
            cleaned.push(item);
        }

        *val = Value::Array(cleaned);
    }

    fn normalize_quick_probe_value(value: &mut Value) {
        Self::normalize_array_field(value, "service_status");
        Self::normalize_array_field(value, "top_cpu_processes");
        Self::coerce_number_field(value, "uptime_hours");
        Self::coerce_number_field(value, "cpu_load_pct");
        Self::coerce_number_field(value, "memory_used_percent");
        Self::coerce_number_field(value, "total_memory_mb");
        Self::coerce_number_field(value, "used_memory_mb");
        Self::coerce_integer_field(value, "process_count");
        Self::clamp_percent(value, "cpu_load_pct");
        Self::clamp_percent(value, "memory_used_percent");
        Self::clamp_non_negative(value, "uptime_hours");
        Self::scrub_service_list(value, "service_status");
        Self::scrub_process_list(value, "top_cpu_processes");
    }

    fn normalize_combined_value(value: &mut Value) {
        for key in [
            "disk_alerts",
            "disks",
            "service_status",
            "high_cpu_processes",
            "winrm_listeners",
            "firewall_profiles",
            "recent_errors",
            "net_adapters",
        ] {
            Self::normalize_array_field(value, key);
        }

        for key in [
            "memory_used_percent",
            "total_memory_mb",
            "used_memory_mb",
            "high_cpu_threshold",
            "total_disks",
            "service_alerts",
        ] {
            Self::coerce_number_field(value, key);
        }
        for key in ["process_count", "total_disks", "service_alerts"] {
            Self::coerce_integer_field(value, key);
        }

        if let Some(uptime) = value.get_mut("uptime") {
            Self::coerce_number_field(uptime, "uptime_hours");
            Self::coerce_number_field(uptime, "cpu_load_pct");
            Self::clamp_non_negative(uptime, "uptime_hours");
            Self::clamp_percent(uptime, "cpu_load_pct");
        }

        Self::clamp_percent(value, "memory_used_percent");
        Self::clamp_percent(value, "high_cpu_threshold");
        Self::clamp_non_negative(value, "total_memory_mb");
        Self::clamp_non_negative(value, "used_memory_mb");
        Self::scrub_process_list(value, "high_cpu_processes");
        Self::scrub_disk_list(value, "disks");
        Self::scrub_disk_list(value, "disk_alerts");
        Self::scrub_service_list(value, "service_status");
        Self::scrub_recent_errors(value, "recent_errors");
        Self::normalize_net_adapters_value(value);
    }

    fn parse_error_with_snippet(label: &str, err: serde_json::Error, raw: &str) -> String {
        let snippet = raw.trim();
        let max_len = 400;
        let preview = if snippet.len() > max_len {
            format!("{}...", &snippet[..max_len])
        } else {
            snippet.to_string()
        };

        if preview.is_empty() {
            format!("{}: {}", label, err)
        } else {
            format!("{}: {} (raw: {})", label, err, preview)
        }
    }

    fn normalize_net_adapters_value(val: &mut Value) {
        let adapters_val = match val.get_mut("net_adapters") {
            Some(v) => v,
            None => return,
        };

        let mut list: Vec<Value> = match adapters_val.take() {
            Value::Array(arr) => arr,
            Value::Null => return,
            other => vec![other],
        };

        for item in list.iter_mut() {
            if let Some(obj) = item.as_object_mut() {
                let to_array = |v: &mut Value| {
                    *v = match v.take() {
                        Value::Array(arr) => Value::Array(
                            arr.into_iter()
                                .filter_map(|x| {
                                    x.as_str().map(|s| Value::String(s.trim().to_string()))
                                })
                                .collect(),
                        ),
                        Value::String(s) => Value::Array(vec![Value::String(s.trim().to_string())]),
                        Value::Null => Value::Array(vec![]),
                        other => Value::Array(vec![other]),
                    };
                };
                let to_num_array = |v: &mut Value| {
                    *v = match v.take() {
                        Value::Array(arr) => Value::Array(
                            arr.into_iter()
                                .filter_map(|x| {
                                    if let Some(u) = x.as_u64() {
                                        Some(Value::Number(serde_json::Number::from(u)))
                                    } else if let Some(s) = x.as_str() {
                                        s.parse::<u32>()
                                            .ok()
                                            .map(|u| Value::Number(serde_json::Number::from(u)))
                                    } else {
                                        None
                                    }
                                })
                                .collect(),
                        ),
                        Value::Number(n) => Value::Array(vec![Value::Number(n)]),
                        Value::String(s) => s
                            .parse::<u32>()
                            .ok()
                            .map(|u| Value::Array(vec![Value::Number(serde_json::Number::from(u))]))
                            .unwrap_or(Value::Array(vec![])),
                        _ => Value::Array(vec![]),
                    };
                };

                if let Some(v) = obj.get_mut("ipv4") {
                    to_array(v);
                }
                if let Some(v) = obj.get_mut("ipv6") {
                    to_array(v);
                }
                if let Some(v) = obj.get_mut("dns") {
                    to_array(v);
                }
                if let Some(v) = obj.get_mut("gateway") {
                    to_array(v);
                }
                if let Some(v) = obj.get_mut("ipv4_prefix") {
                    to_num_array(v);
                }
            }
        }

        *adapters_val = Value::Array(list);
    }

    fn coerce_adapters_from_str(raw: &str) -> Option<Vec<NetAdapterInfo>> {
        let trimmed = raw.trim();
        let val: Value = serde_json::from_str(trimmed).ok()?;
        let list: Vec<Value> = if val.is_array() {
            val.as_array().cloned().unwrap_or_default()
        } else {
            vec![val]
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
            let ipv4 = str_list(obj.get("ipv4").unwrap_or(&Value::Null));
            let ipv6 = str_list(obj.get("ipv6").unwrap_or(&Value::Null));
            let dns = str_list(obj.get("dns").unwrap_or(&Value::Null));
            let gateway = str_list(obj.get("gateway").unwrap_or(&Value::Null));
            let ipv4_prefix = num_list(obj.get("ipv4_prefix").unwrap_or(&Value::Null));

            adapters.push(NetAdapterInfo {
                alias,
                description,
                ipv4,
                ipv6,
                dns,
                ipv4_prefix,
                gateway,
            });
        }

        if adapters.is_empty() {
            None
        } else {
            Some(adapters)
        }
    }

    /// Create a new remote session
    ///
    /// # Arguments
    /// * `server_name` - Hostname or IP address of target server
    /// * `credentials` - Username and password for authentication
    ///
    /// # Returns
    /// `Ok(session)` if connection successful, otherwise error message
    ///
    /// # Connection Process
    /// 1. Returns a session handle (lightweight, no network call)
    /// 2. Actual WinRM connectivity is validated on first `execute_remote()` call
    ///
    /// Note: The previous `Test-WSMan` pre-check was removed to avoid creating
    /// an extra implicit PSSession on the remote server for every probe cycle.
    /// Use `validate_connectivity()` explicitly when you need to verify reachability
    /// (e.g., when the user first adds a host).
    pub async fn connect(server_name: String, credentials: Credentials) -> Result<Self, String> {
        Ok(Self {
            server_name,
            username: credentials.username().to_string(),
            password: credentials.password().clone(),
        })
    }

    /// Explicitly validate that the server is reachable via WinRM.
    ///
    /// Call this for user-initiated actions (e.g., adding a new host, testing credentials)
    /// but NOT on the recurring heartbeat/probe path to avoid session accumulation.
    pub async fn validate_reachability(&self) -> Result<(), String> {
        let username = Username::new(self.username.clone())
            .map_err(|e| format!("Invalid cached username: {}", e))?;
        let creds = Credentials::new(username, self.password.clone());
        Self::validate_connectivity(&self.server_name, &creds).await
    }

    /// Validate server is reachable
    async fn validate_connectivity(
        server_name: &str,
        credentials: &Credentials,
    ) -> Result<(), String> {
        let server = server_name.to_string();
        let username = credentials.username().as_str().to_string();
        let password = credentials.password().as_str().to_string();

        #[derive(Serialize)]
        struct TestPayload {
            server: String,
            username: String,
            password: String,
        }

        let payload_json = serde_json::to_string(&TestPayload {
            server: server.clone(),
            username: username.clone(),
            password: password.clone(),
        })
        .map_err(|e| format!("Failed to serialize connectivity payload: {}", e))?;

        // Quick test: try Test-WSMan with the provided credentials to avoid 401/kerberos failures.
        let output = tokio::task::spawn_blocking(move || {
            use std::io::Write;

            let ps_script = r#"$ErrorActionPreference = 'Stop'
try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { throw 'No payload received' }
    $payload = $raw | ConvertFrom-Json

    $server = [string]$payload.server
    $username = [string]$payload.username
    $pwPlain = [string]$payload.password

    $pwSecure = New-Object System.Security.SecureString
    $pwPlain.ToCharArray() | ForEach-Object { $pwSecure.AppendChar($_) }
    $cred = New-Object System.Management.Automation.PSCredential($username, $pwSecure)

    Test-WSMan -ComputerName $server -Credential $cred -Authentication Default -ErrorAction Stop | Out-Null
} catch {
    Write-Error $_.Exception.Message
    exit 1
}"#;

            let mut cmd = Command::new("powershell.exe");
            cmd.arg("-NoProfile")
                .arg("-NonInteractive")
                .arg("-Command")
                .arg(ps_script)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());

            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);

            let mut child = cmd.spawn()?;
            {
                let mut stdin = child.stdin.take().ok_or_else(|| {
                    std::io::Error::other("Failed to open stdin for connectivity check")
                })?;
                stdin.write_all(payload_json.as_bytes())?;
            }

            child.wait_with_output()
        })
        .await
        .map_err(|e| format!("Failed to spawn connectivity task: {}", e))?
        .map_err(|e| format!("Failed to test connectivity: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let error_msg = if !stderr.is_empty() {
                stderr.replace(&password, "<redacted>")
            } else if !stdout.is_empty() {
                stdout.replace(&password, "<redacted>")
            } else {
                "Unknown error".to_string()
            };
            return Err(format!(
                "Server {} unreachable or WinRM not enabled: {}",
                server_name, error_msg
            ));
        }

        Ok(())
    }

    fn build_summary_from_combined(&self, payload: CombinedHealthPayload) -> SystemHealthSummary {
        let mut high_cpu = payload.high_cpu_processes;
        high_cpu.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        SystemHealthSummary {
            server_name: payload
                .server_name
                .unwrap_or_else(|| self.server_name.clone()),
            winrm_issue: false,
            winrm_error: None,
            os_info: payload.os_info,
            disk_alerts: payload.disk_alerts,
            total_disks: payload.total_disks,
            disks: payload.disks,
            service_alerts: payload.service_alerts,
            service_status: payload.service_status,
            process_count: payload.process_count,
            high_cpu_processes: high_cpu,
            high_cpu_threshold: payload.high_cpu_threshold,
            total_memory_mb: payload.total_memory_mb,
            used_memory_mb: payload.used_memory_mb.max(0.0),
            memory_used_percent: payload.memory_used_percent.clamp(0.0, 100.0),
            uptime: payload.uptime,
            pending_reboot: payload.pending_reboot,
            winrm_listeners: payload.winrm_listeners,
            firewall_profiles: payload.firewall_profiles,
            recent_errors: payload.recent_errors,
            net_adapters: payload.net_adapters,
            reachability: None,
        }
    }

    /// Collect full system health in a single remote PowerShell execution to reduce per-host latency.
    pub async fn collect_system_health(
        &self,
        critical_services: Option<&[String]>,
        disk_threshold: f64,
    ) -> Result<SystemHealthSummary, String> {
        use std::time::Instant;
        let health_start = Instant::now();

        const HIGH_CPU_THRESHOLD: f64 = 50.0;

        let services_vec: Vec<String> = critical_services.map(|s| s.to_vec()).unwrap_or_default();

        let services_json = serde_json::to_string(&services_vec)
            .map_err(|e| format!("Failed to serialize services list: {}", e))?;

        let script = format!(
            r#"$ErrorActionPreference = 'Stop'
$diskThreshold = {disk_threshold};
$highCpuThreshold = {high_cpu};
$criticalServices = @()
try {{
    $criticalServices = ConvertFrom-Json '{services_json}'
}} catch {{
    $criticalServices = @()
}}
if (-not $criticalServices -or $criticalServices.Count -eq 0) {{
    $criticalServices = @('WinRM')
}}

function Get-OsInfo {{
    try {{
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    }} catch {{
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
    }}
    return [pscustomobject]@{{
        hostname = $cs.Name
        os_version = $os.Caption
        build_number = [string]$os.BuildNumber
        product_type = if ($os.ProductType -eq 1) {{ 'Workstation' }} else {{ 'ServerNT' }}
        install_date = $os.InstallDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }}
}}

function Get-Disks {{
    $disks = @()
    try {{
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop | Where-Object {{ $_.DriveType -eq 3 -and $_.Size -gt 0 }}
    }} catch {{}}
    if (-not $disks -or $disks.Count -eq 0) {{
        $disks = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction Stop | Where-Object {{ $_.DriveType -eq 3 -and $_.Size -gt 0 }}
    }}
    if (-not $disks -or $disks.Count -eq 0) {{
        throw 'No disks returned from Win32_LogicalDisk'
    }}
    return $disks | ForEach-Object {{
        $total = [double]$_.Size
        $free = [double]$_.FreeSpace
        $totalGb = if ($total -gt 0) {{ $total / [math]::Pow(1024,3) }} else {{ 0 }}
        $freeGb = if ($free -ge 0) {{ $free / [math]::Pow(1024,3) }} else {{ 0 }}
        $usedGb = [math]::Max($totalGb - $freeGb, 0)
        $pctFree = if ($totalGb -gt 0) {{ ($freeGb / $totalGb) * 100 }} else {{ 0 }}
        [pscustomobject]@{{
            drive = if ($_.DeviceID -and $($_.DeviceID.ToString().EndsWith(':'))) {{ $_.DeviceID }} else {{ "$($_.DeviceID):" }}
            total_gb = $totalGb
            free_gb = $freeGb
            used_gb = $usedGb
            percent_free = $pctFree
        }}
    }}
}}

function Get-Services($names) {{
    $normalized = @($names | Where-Object {{ $_ }} | ForEach-Object {{ $_.ToString() }})
    if (-not $normalized -or $normalized.Count -eq 0) {{ return @() }}
    $result = @()
    foreach ($name in $normalized) {{
        try {{
            $svc = Get-Service -Name $name -ErrorAction Stop
            $result += [pscustomobject]@{{
                name = $svc.Name
                display_name = $svc.DisplayName
                status = $svc.Status.ToString()
                startup_type = $svc.StartType.ToString()
            }}
        }} catch {{
            $result += [pscustomobject]@{{
                name = $name
                display_name = $name
                status = 'NotFound'
                startup_type = 'Unknown'
            }}
        }}
    }}
    return $result
}}

function Get-ProcessSample {{
    $cores = [Environment]::ProcessorCount
    if ($cores -lt 1) {{ $cores = 1 }}

    $first = Get-Process -ErrorAction SilentlyContinue | Select-Object Name, Id, CPU, WorkingSet64
    Start-Sleep -Seconds 2
    $second = Get-Process -ErrorAction SilentlyContinue | Select-Object Name, Id, CPU, WorkingSet64

    $map = @{{}}
    foreach ($p in $first) {{ if ($p.Id) {{ $map[$p.Id] = $p }} }}

    return foreach ($p in $second) {{
        if (-not $p.Id) {{ continue }}
        $cpu1 = $null
        if ($map.ContainsKey($p.Id)) {{ $cpu1 = $map[$p.Id].CPU }}
        $cpu2 = $p.CPU
        $delta = if ($cpu1 -ne $null -and $cpu2 -ne $null) {{ $cpu2 - $cpu1 }} else {{ $null }}
        $pct = if ($delta -ne $null -and $delta -ge 0) {{ [math]::Round((($delta / 2) / $cores) * 100, 2) }} else {{ 0 }}
        [pscustomobject]@{{
            name = $p.Name
            pid = [int]$p.Id
            memory_mb = [math]::Round($p.WorkingSet64 / 1MB, 2)
            cpu_percent = $pct
        }}
    }}
}}

function Get-MemoryInfo {{
    try {{
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    }} catch {{
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
    }}
    if (-not $os -or -not $os.TotalVisibleMemorySize) {{
        throw 'No memory info returned'
    }}
    return [pscustomobject]@{{
        total_mb = [math]::Round($os.TotalVisibleMemorySize / 1024, 2)
        free_mb = [math]::Round($os.FreePhysicalMemory / 1024, 2)
    }}
}}

function Get-Uptime {{
    try {{
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $uptimeSeconds = $null
        try {{
            $perf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_System -ErrorAction Stop
            if ($perf.SystemUpTime) {{ $uptimeSeconds = [double]$perf.SystemUpTime }}
        }} catch {{ }}
        if ($null -eq $uptimeSeconds) {{
            $uptimeSeconds = ((Get-Date).ToUniversalTime() - $os.LastBootUpTime.ToUniversalTime()).TotalSeconds
        }}
        return [pscustomobject]@{{
            last_boot = $os.LastBootUpTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            uptime_hours = [math]::Round($uptimeSeconds / 3600, 2)
            cpu_load_pct = $cpu.LoadPercentage
        }}
    }} catch {{
        return $null
    }}
}}

function Get-PendingReboot {{
    try {{
        $signals = @()
        if (Test-Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {{ $signals += 'CBS RebootPending' }}
        if (Test-Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {{ $signals += 'WU RebootRequired' }}
        if (Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) {{ $signals += 'PendingFileRenameOperations' }}
        return [pscustomobject]@{{ pending = $signals.Count -gt 0; signals = $signals }}
    }} catch {{
        return $null
    }}
}}

function Get-WinRmListeners {{
    try {{
        return Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop | ForEach-Object {{
            [pscustomobject]@{{
                transport = $_.Keys['Transport']
                address   = $_.Keys['Address']
                port      = $_.get_Item('Port')
                enabled   = $_.get_Item('Enabled')
                hostname  = $_.get_Item('Hostname')
                certificate_thumbprint = $_.get_Item('CertificateThumbprint')
            }}
        }}
    }} catch {{
        return @()
    }}
}}

function Get-FirewallProfiles {{
    try {{
        return Get-NetFirewallProfile | Select-Object @{{n='name';e={{$_.Name}}}}, @{{n='enabled';e={{$_.Enabled}}}}, @{{n='default_inbound_action';e={{$_.DefaultInboundAction}}}}, @{{n='default_outbound_action';e={{$_.DefaultOutboundAction}}}}
    }} catch {{
        return @()
    }}
}}

function Get-RecentErrors {{
    try {{
        $cutoff = (Get-Date).AddMinutes(-30)
        $logs = 'System','Application'
        $all = @()
        foreach ($log in $logs) {{
            try {{
                $entries = Get-WinEvent -FilterHashtable @{{LogName=$log; Level=@(1,2); StartTime=$cutoff}} -MaxEvents 10
                $entries | ForEach-Object {{
                    $all += [pscustomobject]@{{
                        log = $log
                        time_created = $_.TimeCreated
                        id = $_.Id
                        provider = $_.ProviderName
                        level = $_.LevelDisplayName
                        message = $_.Message
                    }}
                }}
            }} catch {{ }}
        }}
        return $all | Sort-Object -Property time_created -Descending | Select-Object -First 10
    }} catch {{
        return @()
    }}
}}

function Get-NetAdapters {{
    function Convert-MaskToPrefix($mask) {{
        if (-not $mask) {{ return $null }}
        # If already a number (prefix), just return it
        if ($mask -as [int]) {{
            $num = [int]$mask
            if ($num -ge 0 -and $num -le 32) {{ return $num }}
        }}
        $parts = $mask.ToString().Split('.')
        if ($parts.Count -ne 4) {{ return $null }}
        $bits = 0
        foreach ($p in $parts) {{
            $byte = 0
            if (-not [int]::TryParse($p, [ref]$byte)) {{ return $null }}
            $bits += [Convert]::ToString($byte, 2).ToCharArray() | Where-Object {{ $_ -eq '1' }} | Measure-Object | Select-Object -ExpandProperty Count
        }}
        return [int]$bits
    }}

    # Try Get-NetIPConfiguration first (Server 2012 R2+, Windows 8.1+)
    # Provides comprehensive network configuration including IPv4/IPv6, DNS, gateway
    try {{
        $adapters = Get-NetIPConfiguration -ErrorAction Stop |
            ForEach-Object {{
                $ipv4Entries = @()
                foreach ($ip in $_.IPv4Address) {{
                    if ($ip.IPv4Address) {{
                        $prefixVal = if ($ip.PrefixLength -ne $null) {{ [int]$ip.PrefixLength }} else {{ 0 }}
                        $ipv4Entries += [pscustomobject]@{{
                            address = $ip.IPv4Address
                            prefix  = $prefixVal
                        }}
                    }}
                }}
                $ipv6 = @($_.IPv6Address | ForEach-Object {{ $_.IPv6Address }})
                $dns  = @($_.DNSServer | ForEach-Object {{ $_.ServerAddresses }} | Where-Object {{ $_ }})
                $gate = @()
            if ($_.IPv4DefaultGateway) {{
                $gate = @($_.IPv4DefaultGateway | ForEach-Object {{ $_.NextHop }} | Where-Object {{ $_ }})
            }}
            [pscustomobject]@{{
                alias = $_.InterfaceAlias
                description = $_.InterfaceDescription
                ipv4 = @($ipv4Entries | ForEach-Object {{ $_.address }})
                ipv4_prefix = @($ipv4Entries | ForEach-Object {{ $_.prefix }})
                ipv6 = @($ipv6)
                dns  = @($dns)
                gateway = @($gate)
            }}
        }}
    }} catch {{
        $adapters = @()
    }}

    # Early return if modern cmdlet succeeded
    if ($adapters -and $adapters.Count -gt 0) {{
        $result = $adapters | Where-Object {{ $_.ipv4 -or $_.ipv6 }} | Select-Object -First 10
        return @($result)
    }}

    # Fallback to WMI (Server 2008/2012, all Windows versions)
    # Legacy method, slower but works when modern cmdlets unavailable
    try {{
        $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' |
                ForEach-Object {{
                    $ipv4 = @()
                    $ipv4Prefix = @()
                    $ipv6 = @()
                    if ($_.IPAddress) {{
                        for ($i = 0; $i -lt $_.IPAddress.Count; $i++) {{
                            $ip = $_.IPAddress[$i]
                            $mask = if ($_.IPSubnet -and $i -lt $_.IPSubnet.Count) {{ $_.IPSubnet[$i] }} else {{ $null }}
                            if ($ip -like '*.*') {{
                                $ipv4 += $ip
                                $prefix = Convert-MaskToPrefix $mask
                                if ($prefix -ne $null) {{ $ipv4Prefix += [int]$prefix }} else {{ $ipv4Prefix += 0 }}
                            }} elseif ($ip -like '*:*') {{
                                $ipv6 += $ip
                            }}
                        }}
                    }}
                $dns  = @($_.DNSServerSearchOrder)
                $gate = @($_.DefaultIPGateway | Where-Object {{ $_ }})
                [pscustomobject]@{{
                    alias = $_.Description
                    description = $_.Description
                    ipv4 = @($ipv4)
                    ipv4_prefix = @($ipv4Prefix)
                    ipv6 = @($ipv6)
                    dns  = @($dns)
                    gateway = @($gate)
                }}
            }}
    }} catch {{
        $adapters = @()
    }}
    }}

    # Return adapters or empty array if both methods failed
    if ($adapters -and $adapters.Count -gt 0) {{
        $result = $adapters | Where-Object {{ $_.ipv4 -or $_.ipv6 }} | Select-Object -First 10
        return @($result)
    }}
    
    return @()
}}

$os = Get-OsInfo
$disks = Get-Disks
$diskAlerts = @($disks | Where-Object {{ $_.percent_free -lt $diskThreshold }})
$services = Get-Services $criticalServices
$stopped = @($services | Where-Object {{ $_.status -notin @('Running','running') }})
$memory = Get-MemoryInfo
$usedMemory = [math]::Max($memory.total_mb - $memory.free_mb, 0)
$memPct = if ($memory.total_mb -gt 0) {{ ($usedMemory / $memory.total_mb) * 100 }} else {{ 0 }}
$processes = Get-ProcessSample
$highCpu = $processes | Where-Object {{ $_.cpu_percent -gt $highCpuThreshold }} | Sort-Object cpu_percent -Descending
$uptime = Get-Uptime
$pending = Get-PendingReboot
$winrm = Get-WinRmListeners
$firewall = Get-FirewallProfiles
$recentErrors = Get-RecentErrors
$netAdapters = Get-NetAdapters

[pscustomobject]@{{
    server_name = $env:COMPUTERNAME
    os_info = $os
    disk_alerts = $diskAlerts
    total_disks = $disks.Count
    disks = $disks
    service_alerts = $stopped.Count
    service_status = $services
    process_count = $processes.Count
    high_cpu_processes = $highCpu
    high_cpu_threshold = $highCpuThreshold
    total_memory_mb = $memory.total_mb
    used_memory_mb = $usedMemory
    memory_used_percent = $memPct
    uptime = $uptime
    pending_reboot = $pending
    winrm_listeners = $winrm
    firewall_profiles = $firewall
    recent_errors = $recentErrors
    net_adapters = $netAdapters
}} | ConvertTo-Json -Compress
"#,
            disk_threshold = disk_threshold,
            high_cpu = HIGH_CPU_THRESHOLD,
            services_json = services_json
        );

        let raw = self.execute_remote(&script).await?;
        let trimmed = raw.trim();
        let mut value: Value = serde_json::from_str(trimmed).map_err(|e| {
            Self::parse_error_with_snippet("Combined probe parse failed", e, trimmed)
        })?;
        Self::normalize_combined_value(&mut value);
        let mut payload: CombinedHealthPayload = serde_json::from_value(value).map_err(|e| {
            Self::parse_error_with_snippet("Combined probe parse failed", e, trimmed)
        })?;

        let adapters_missing = payload
            .net_adapters
            .as_ref()
            .map(|v| v.is_empty())
            .unwrap_or(true);

        let mut adapter_error: Option<String> = None;
        if adapters_missing {
            let adapter_script = adapter_probe_script();
            match self.execute_remote(adapter_script).await {
                Ok(adapter_raw) => {
                    if let Some(adapters) = Self::coerce_adapters_from_str(&adapter_raw) {
                        payload.net_adapters = Some(adapters);
                    } else {
                        adapter_error =
                            Some("Adapter probe returned unparseable payload".to_string());
                    }
                }
                Err(err) => {
                    adapter_error = Some(err);
                }
            }
        }

        let mut summary = self.build_summary_from_combined(payload);
        let adapters_still_missing = summary
            .net_adapters
            .as_ref()
            .map(|v| v.is_empty())
            .unwrap_or(true);

        if adapters_still_missing {
            let reason = adapter_error.unwrap_or_else(|| "no adapters returned".to_string());
            summary.winrm_issue = true;
            summary.winrm_error = Some(format!("Adapter probe failed: {}", reason));
        }

        let _total_ms = health_start.elapsed().as_millis();

        Ok(summary)
    }

    /// Lightweight heartbeat probe (uptime + CPU + memory percent) to support high-frequency refreshes.
    pub async fn collect_quick_probe(
        &self,
        critical_services: Option<&[String]>,
    ) -> Result<QuickProbeSummary, String> {
        let services_vec: Vec<String> = critical_services.map(|s| s.to_vec()).unwrap_or_default();

        let services_json = serde_json::to_string(&services_vec)
            .map_err(|e| format!("Failed to serialize services list: {}", e))?;

        let script = r#"# Use Continue instead of Stop for better resilience - individual functions handle their own errors
$ErrorActionPreference = 'Continue'
function Get-QuickMemory {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    } catch {
        try {
            $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        } catch {
            return $null
        }
    }
    if (-not $os -or -not $os.TotalVisibleMemorySize) { return $null }
    try {
        $total = [math]::Round($os.TotalVisibleMemorySize / 1024, 2)
        $free  = [math]::Round($os.FreePhysicalMemory / 1024, 2)
        $used   = [math]::Round([math]::Max($total - $free, 0), 2)
        $usedPct = if ($total -gt 0) { [math]::Round(($used / $total) * 100, 2) } else { 0 }
        return [pscustomobject]@{
            total_mb = $total
            free_mb = $free
            used_mb = $used
            memory_used_percent = $usedPct
        }
    } catch {
        return $null
    }
}

function Get-QuickCpu {
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        return $cpu.LoadPercentage
    } catch {
        return $null
    }
}

function Get-QuickUptime {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    } catch {
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        } catch {
            return $null
        }
    }
    $uptimeSeconds = $null
    try {
        $perf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_System -ErrorAction Stop
        if ($perf.SystemUpTime) { $uptimeSeconds = [double]$perf.SystemUpTime }
    } catch { }
    if ($null -eq $uptimeSeconds) {
        $uptimeSeconds = ((Get-Date).ToUniversalTime() - $os.LastBootUpTime.ToUniversalTime()).TotalSeconds
    }
    return [pscustomobject]@{
        uptime_hours = [math]::Round($uptimeSeconds / 3600, 2)
    }
}

$criticalServices = @()
try {
    $criticalServices = ConvertFrom-Json '@SERVICES_JSON@'
} catch {
    $criticalServices = @()
}
if (-not $criticalServices -or $criticalServices.Count -eq 0) {
    $criticalServices = @('WinRM')
}

function Get-QuickServices($names) {
    if (-not $names -or $names.Count -eq 0) { return @() }
    $result = @()
    foreach ($name in $names) {
        try {
            $svc = Get-Service -Name $name -ErrorAction Stop
            $acct = 'Unknown'
            try {
                $wmi = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction Stop
                if ($wmi -and $wmi.StartName) { $acct = $wmi.StartName }
            } catch { }
            $result += [pscustomobject]@{
                name = $svc.Name
                display_name = $svc.DisplayName
                status = $svc.Status.ToString()
                startup_type = $svc.StartType.ToString()
                service_account = $acct
            }
        } catch {
            $result += [pscustomobject]@{
                name = $name
                display_name = $name
                status = 'NotFound'
                startup_type = 'Unknown'
                service_account = 'Unknown'
            }
        }
    }
    return $result
}

function Get-TopCpuProcesses($limit) {
    $limit = [int]$limit
    if ($limit -le 0) { $limit = 3 }
    $cores = [Environment]::ProcessorCount
    if ($cores -lt 1) { $cores = 1 }

    $first = Get-Process -ErrorAction SilentlyContinue | Select-Object Name, Id, CPU, WorkingSet64
    Start-Sleep -Seconds 1
    $second = Get-Process -ErrorAction SilentlyContinue | Select-Object Name, Id, CPU, WorkingSet64

    $map = @{}
    foreach ($p in $first) { if ($p.Id) { $map[$p.Id] = $p } }

    $result = foreach ($p in $second) {
        if (-not $p.Id) { continue }
        $cpu1 = $null
        if ($map.ContainsKey($p.Id)) { $cpu1 = $map[$p.Id].CPU }
        $cpu2 = $p.CPU
        $delta = if ($cpu1 -ne $null -and $cpu2 -ne $null) { $cpu2 - $cpu1 } else { $null }
        $pct = if ($delta -ne $null -and $delta -ge 0) {
            [math]::Round((($delta / 1) / $cores) * 100, 2)
        } else { 0 }

        [PSCustomObject]@{
            name = $p.Name
            pid = [int]$p.Id
            memory_mb = [Math]::Round($p.WorkingSet64 / 1MB, 2)
            cpu_percent = $pct
        }
    }

    return @($result | Sort-Object cpu_percent -Descending | Select-Object -First $limit)
}

function Get-ProcessCount {
    try {
        return (Get-Process -ErrorAction SilentlyContinue | Measure-Object).Count
    } catch {
        return $null
    }
}

# Collect all metrics with error isolation - each function handles its own errors
$mem = Get-QuickMemory
$cpuLoad = Get-QuickCpu
$uptime = Get-QuickUptime
$quickServices = Get-QuickServices $criticalServices
$topCpu = Get-TopCpuProcesses -limit 3
$processCount = Get-ProcessCount

# Always return valid JSON even if some metrics failed
# Note: Using traditional null checks for PowerShell 5.1 compatibility (null-conditional ?. requires PS7+)
try {
    [pscustomobject]@{
        server_name = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'unknown' }
        uptime_hours = if ($uptime) { $uptime.uptime_hours } else { $null }
        cpu_load_pct = $cpuLoad
        memory_used_percent = if ($mem) { $mem.memory_used_percent } else { $null }
        total_memory_mb = if ($mem) { $mem.total_mb } else { $null }
        used_memory_mb = if ($mem) { $mem.used_mb } else { $null }
        process_count = $processCount
        service_status = if ($quickServices) { $quickServices } else { @() }
        top_cpu_processes = if ($topCpu) { $topCpu } else { @() }
    } | ConvertTo-Json -Compress
} catch {
    # Fallback: return minimal valid JSON if main conversion fails
    '{"server_name":"unknown","uptime_hours":null,"cpu_load_pct":null,"memory_used_percent":null,"total_memory_mb":null,"used_memory_mb":null,"process_count":null,"service_status":[],"top_cpu_processes":[]}'
}
"#;
        let script = script.replace("@SERVICES_JSON@", &services_json);

        let raw = self.execute_remote(&script).await?;
        let trimmed = raw.trim();
        let mut value: Value = serde_json::from_str(trimmed)
            .map_err(|e| Self::parse_error_with_snippet("Quick probe parse failed", e, trimmed))?;
        Self::normalize_quick_probe_value(&mut value);
        let payload: QuickProbePayload = serde_json::from_value(value)
            .map_err(|e| Self::parse_error_with_snippet("Quick probe parse failed", e, trimmed))?;

        let total_memory_mb = payload.total_memory_mb;
        let used_memory_mb = payload.used_memory_mb.or_else(|| {
            total_memory_mb
                .and_then(|total| payload.memory_used_percent.map(|pct| (pct / 100.0) * total))
        });

        Ok(QuickProbeSummary {
            server_name: payload
                .server_name
                .unwrap_or_else(|| self.server_name.clone()),
            uptime_hours: payload.uptime_hours,
            cpu_load_pct: payload.cpu_load_pct,
            memory_used_percent: payload.memory_used_percent,
            total_memory_mb,
            used_memory_mb,
            process_count: payload.process_count.map(|v| v as usize),
            top_cpu_processes: payload.top_cpu_processes,
            service_status: payload.service_status,
        })
    }

    /// Execute a PowerShell command on the remote server
    ///
    /// Internal method used by trait implementations.
    /// Sanitizes command and executes via PowerShell Remoting.
    async fn execute_remote(&self, command: &str) -> Result<String, String> {
        let server = self.server_name.clone();
        let username = self.username.clone();
        let password = self.password.as_str().to_string();
        let command = command.to_string();

        // Write probe script to temp file for debugging (but don't log it to reduce noise)
        #[cfg(debug_assertions)]
        let _ = Self::write_debug_command(&command);

        #[derive(Serialize)]
        struct PsRemotingPayload {
            server: String,
            username: String,
            password: String,
            command_b64: String,
        }

        // SECURITY: Send secrets via stdin so the password never appears in process arguments.
        // Encode the command to avoid ScriptBlock parsing issues from quotes/newlines in payload.
        let payload_json = serde_json::to_string(&PsRemotingPayload {
            server: server.clone(),
            username: username.clone(),
            password: password.clone(),
            command_b64: general_purpose::STANDARD.encode(command.as_bytes()),
        })
        .map_err(|e| format!("Failed to serialize PowerShell payload: {}", e))?;

        let ps_script = r#"$ErrorActionPreference = 'Stop'
$session = $null
try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { throw 'No input provided' }
    $payload = $raw | ConvertFrom-Json

    $server = [string]$payload.server
    $username = [string]$payload.username
    $pwPlain = [string]$payload.password
    $commandTextBytes = [System.Convert]::FromBase64String([string]$payload.command_b64)
    $commandText = [System.Text.Encoding]::UTF8.GetString($commandTextBytes)

    # Build SecureString without relying on module load
    $pwSecure = New-Object System.Security.SecureString
    $pwPlain.ToCharArray() | ForEach-Object { $pwSecure.AppendChar($_) }
    $cred = New-Object System.Management.Automation.PSCredential($username, $pwSecure)

    # Create an explicit PSSession so we can guarantee cleanup via Remove-PSSession.
    # Without this, Invoke-Command -ComputerName creates implicit sessions that rely
    # on WinRM idle timeout (default 2 hours) for cleanup, causing wsmprovhost.exe
    # accumulation and memory leaks on the remote server.
    $session = New-PSSession -ComputerName $server -Credential $cred -ErrorAction Stop

    # Execute inside the remote session by passing the decoded script as an argument to avoid inline quoting issues
    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
        param($scriptText)
        $sb = [ScriptBlock]::Create($scriptText)
        & $sb
    } -ArgumentList $commandText
} catch {
    Write-Error $_.Exception.Message
    exit 1
} finally {
    # Explicitly destroy the remote session to free wsmprovhost.exe on the target server immediately
    if ($session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}"#;

        // Execute in background to avoid blocking.
        let output = tokio::task::spawn_blocking(move || {
            use std::io::Write;

            let mut cmd = Command::new("powershell.exe");
            cmd.arg("-NoProfile")
                .arg("-NonInteractive")
                .arg("-Command")
                .arg(ps_script)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());

            // Hide the PowerShell window on Windows
            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);

            let mut child = cmd.spawn().map_err(|e| {
                std::io::Error::other(format!("Failed to spawn powershell.exe: {}", e))
            })?;

            {
                let mut stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| std::io::Error::other("Failed to open stdin"))?;
                stdin.write_all(payload_json.as_bytes())?;
            }

            child.wait_with_output()
        })
        .await
        .map_err(|e| format!("Task execution failed: {}", e))?
        .map_err(|e| format!("PowerShell execution failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let raw_error = if !stderr.is_empty() {
                stderr.to_string()
            } else if !stdout.is_empty() {
                stdout.to_string()
            } else {
                "Unknown error".to_string()
            };

            // Redact password from any echoed error output
            let redacted_error = raw_error.replace(&password, "<redacted>");

            // Log the full stderr for diagnostics
            crate::logger::log_error(&format!(
                "PowerShell failed for server '{}': {}",
                server, redacted_error
            ));

            // Extract a cleaner error message
            let error_msg = Self::simplify_error_message(&redacted_error);
            return Err(error_msg);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    #[cfg(debug_assertions)]
    fn write_debug_command(command: &str) -> Option<std::path::PathBuf> {
        use std::io::Write;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis();
        let path = std::env::temp_dir().join(format!("quickprobe_ps_{ts}.ps1"));
        if let Ok(mut file) = std::fs::File::create(&path) {
            if file.write_all(command.as_bytes()).is_ok() {
                return Some(path);
            }
        }
        None
    }

    /// Simplify PowerShell error messages to be more user-friendly
    fn simplify_error_message(raw_error: &str) -> String {
        let lower = raw_error.to_lowercase();

        // Check for common WinRM/authentication errors
        if lower.contains("trustedhosts") || lower.contains("authentication scheme") {
            return "WinRM authentication failed. The target server must be in TrustedHosts.\n\
                 Run as admin: Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '*' -Force"
                .to_string();
        }

        if lower.contains("access is denied") || lower.contains("access denied") {
            return "Access denied. Check username and password are correct.".to_string();
        }

        if lower.contains("cannot find the computer") || lower.contains("cannot be resolved") {
            return "Server not found. Check the hostname is correct and reachable.".to_string();
        }

        if lower.contains("winrm cannot complete the operation") {
            return "WinRM service not responding. Ensure WinRM is enabled on the target server."
                .to_string();
        }

        if lower.contains("connection refused") || lower.contains("actively refused") {
            return "Connection refused. WinRM may not be enabled on the target server."
                .to_string();
        }

        if lower.contains("network path was not found") {
            return "Network path not found. Check network connectivity to server.".to_string();
        }

        if lower.contains("the user name or password is incorrect") {
            return "Invalid credentials. Check username and password.".to_string();
        }

        // Fallback: return a trimmed snippet of the raw error (more context for debugging)
        let snippet = raw_error.trim();
        if snippet.is_empty() {
            return "Remote command failed".to_string();
        }

        // Return a longer snippet to aid debugging remote PowerShell errors
        let max_len = 4000;
        if snippet.len() > max_len {
            format!("{}...", &snippet[..max_len])
        } else {
            snippet.to_string()
        }
    }
}

#[async_trait::async_trait]
impl RemoteSession for WindowsRemoteSession {
    fn os(&self) -> SessionOs {
        SessionOs::Windows
    }

    async fn get_os_info(&self) -> Result<OsInfo, String> {
        let command = r#"
$ErrorActionPreference = 'Stop'
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $hostname = $cs.Name
    $installDate = $os.InstallDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

    @{
        hostname = $hostname
        os_version = $os.Caption
        build_number = $os.BuildNumber
        product_type = if ($os.ProductType -eq 1) { 'Workstation' } else { 'ServerNT' }
        install_date = $installDate
    } | ConvertTo-Json -Compress
} catch {
    Write-Error "Failed to get OS info: $_"
    exit 1
}
"#;

        let output = self.execute_remote(command).await?;
        let trimmed = output.trim();
        let json: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| format!("Failed to parse OS info: {}", e))?;

        if json.as_object().map(|o| o.is_empty()).unwrap_or(false) {
            return Err("No OS info returned from remote host".to_string());
        }

        Ok(OsInfo {
            hostname: json["hostname"].as_str().unwrap_or("Unknown").to_string(),
            os_version: json["os_version"].as_str().unwrap_or("Unknown").to_string(),
            build_number: json["build_number"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
            product_type: json["product_type"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
            install_date: json["install_date"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
        })
    }

    async fn get_services(&self, filter: Option<&str>) -> Result<Vec<ServiceInfo>, String> {
        let where_clause = match filter {
            Some(f) => format!(
                " | Where-Object {{ $_.Name -like '*{}*' }}",
                escape_powershell_like_pattern(f)
            ),
            None => String::new(),
        };

        // Use Get-CimInstance Win32_Service to get service account (StartName)
        let command = format!(
            r#"
$ErrorActionPreference = 'Stop'
try {{
    $services = @(Get-CimInstance Win32_Service{} | Select-Object Name, DisplayName, State, StartMode, StartName)
    $services | ConvertTo-Json -Compress
}} catch {{
    Write-Error "Failed to get services: $_"
    exit 1
}}
"#,
            where_clause
        );

        let output = self
            .execute_remote(&command)
            .await
            .map_err(|e| self.error_context(&format!("Failed to execute service query: {}", e)))?;
        let trimmed = output.trim();

        // Handle both array and single object responses
        let json: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| self.json_parse_error("services", e, trimmed))?;

        let mut services = Vec::new();
        let items_vec;
        let items = if let Some(arr) = json.as_array() {
            arr
        } else {
            // Single result, wrap in vector
            items_vec = vec![json.clone()];
            &items_vec
        };

        for item in items {
            services.push(ServiceInfo {
                name: item["Name"].as_str().unwrap_or("Unknown").to_string(),
                display_name: item["DisplayName"]
                    .as_str()
                    .unwrap_or("Unknown")
                    .to_string(),
                status: item["State"].as_str().unwrap_or("Unknown").to_string(),
                startup_type: item["StartMode"].as_str().unwrap_or("Unknown").to_string(),
                service_account: item["StartName"].as_str().unwrap_or("Unknown").to_string(),
            });
        }

        Ok(services)
    }

    async fn get_processes(&self, filter: Option<&str>) -> Result<Vec<ProcessInfo>, String> {
        let where_clause = match filter {
            Some(f) => format!(
                " | Where-Object {{ $_.Name -like '*{}*' }}",
                escape_powershell_like_pattern(f)
            ),
            None => String::new(),
        };

        let sampled_script = r#"
$ErrorActionPreference = 'Stop'
try {
    $cores = [Environment]::ProcessorCount
    if ($cores -lt 1) { $cores = 1 }

    $first = Get-Process{WHERE} | Select-Object Name, Id, CPU, WorkingSet64
    Start-Sleep -Seconds 2
    $second = Get-Process{WHERE} | Select-Object Name, Id, CPU, WorkingSet64

    $map = @{}
    foreach ($p in $first) { $map[$p.Id] = $p }

    $result = foreach ($p in $second) {
        if (-not $p.Id) { continue }
        $cpu1 = $null
        if ($map.ContainsKey($p.Id)) { $cpu1 = $map[$p.Id].CPU }
        $cpu2 = $p.CPU
        $delta = if ($cpu1 -ne $null -and $cpu2 -ne $null) { $cpu2 - $cpu1 } else { $null }
        $pct = if ($delta -ne $null -and $delta -ge 0) {
            [math]::Round((($delta / 2) / $cores) * 100, 2)
        } else { 0 }

        [PSCustomObject]@{
            Name = $p.Name
            Id = [int]$p.Id
            MemoryMB = [Math]::Round($p.WorkingSet64 / 1MB, 2)
            CpuPercent = $pct
        }
    }

    $result | ConvertTo-Json -Compress
} catch {
    Write-Error "Failed to get processes: $_"
    exit 1
}
"#;

        let command_sampled = sampled_script.replace("{WHERE}", &where_clause);

        let output = self.execute_remote(&command_sampled).await?;

        let json: serde_json::Value = serde_json::from_str(output.trim())
            .map_err(|e| format!("Failed to parse processes: {}", e))?;

        let mut processes = Vec::new();
        let items_vec;
        let items = if let Some(arr) = json.as_array() {
            arr
        } else {
            items_vec = vec![json.clone()];
            &items_vec
        };

        for item in items {
            if let (Some(name), Some(id)) = (item["Name"].as_str(), item["Id"].as_i64()) {
                processes.push(ProcessInfo {
                    name: name.to_string(),
                    pid: id as u32,
                    memory_mb: item["MemoryMB"].as_f64().unwrap_or(0.0),
                    cpu_percent: item["CpuPercent"].as_f64().unwrap_or(0.0),
                });
            }
        }

        Ok(processes)
    }

    async fn get_disks(&self) -> Result<Vec<DiskInfo>, String> {
        // Win32_LogicalDisk: try CIM first (faster), fall back to WMI; ensure non-empty result
        let command = r#"
$ErrorActionPreference = 'Stop'

function Get-LocalDisks {
    $disks = @()
    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop | Where-Object {$_.DriveType -eq 3 -and $_.Size -gt 0}
    } catch {
        # ignore and try WMI
    }
    if (-not $disks -or $disks.Count -eq 0) {
        $disks = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction Stop | Where-Object {$_.DriveType -eq 3 -and $_.Size -gt 0}
    }
    if (-not $disks -or $disks.Count -eq 0) {
        throw "No disks returned from Win32_LogicalDisk"
    }
    $disks | Select-Object @{Name='DriveLetter';Expression={$_.DeviceID}}, @{Name='Size';Expression={[int64]$_.Size}}, @{Name='SizeRemaining';Expression={[int64]$_.FreeSpace}}
}

try {
    $disks = @(Get-LocalDisks)
    $disks | ConvertTo-Json -Compress
} catch {
    Write-Error "Failed to get disk info: $_"
    exit 1
}
"#;

        let output = self.execute_remote(command).await?;
        let trimmed = output.trim();

        // Handle both array and single object responses
        let json: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| format!("Failed to parse disks: {}", e))?;

        let mut disks = Vec::new();
        let items_vec;
        let items = if let Some(arr) = json.as_array() {
            arr
        } else {
            items_vec = vec![json.clone()];
            &items_vec
        };

        // Helper to extract numeric values that may arrive as number or string
        fn num_as_f64(val: &serde_json::Value) -> Option<f64> {
            if let Some(n) = val.as_f64() {
                return Some(n);
            }
            if let Some(i) = val.as_i64() {
                return Some(i as f64);
            }
            if let Some(s) = val.as_str() {
                return s.parse::<f64>().ok();
            }
            None
        }

        for item in items {
            let drive = item["DriveLetter"].as_str();
            let total_bytes = num_as_f64(&item["Size"]);
            let free_bytes = num_as_f64(&item["SizeRemaining"]);

            if let (Some(drive), Some(total_bytes), Some(free_bytes)) =
                (drive, total_bytes, free_bytes)
            {
                let drive_str = if drive.ends_with(':') {
                    drive.to_string()
                } else {
                    format!("{}:", drive)
                };
                let total_gb = total_bytes / (1024.0_f64.powi(3));
                let free_gb = free_bytes / (1024.0_f64.powi(3));
                let used_gb = (total_gb - free_gb).max(0.0);
                let percent_free = if total_gb > 0.0 {
                    (free_gb / total_gb) * 100.0
                } else {
                    0.0
                };

                disks.push(DiskInfo {
                    drive: drive_str,
                    total_gb,
                    free_gb,
                    used_gb,
                    percent_free,
                });
            }
        }

        if disks.is_empty() {
            return Err("No disks returned from remote host".to_string());
        }

        Ok(disks)
    }

    async fn get_memory_info(&self) -> Result<MemoryInfo, String> {
        let command = r#"
$ErrorActionPreference = 'Stop'
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $mem = [PSCustomObject]@{
        TotalMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 2)
        FreeMB  = [math]::Round($os.FreePhysicalMemory / 1024, 2)
    }
    $mem | ConvertTo-Json -Compress
} catch {
    # fallback to WMI
    try {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $mem = [PSCustomObject]@{
            TotalMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 2)
            FreeMB  = [math]::Round($os.FreePhysicalMemory / 1024, 2)
        }
        $mem | ConvertTo-Json -Compress
    } catch {
        Write-Error "Failed to get memory info: $_"
        exit 1
    }
}
"#;

        let output = self.execute_remote(command).await?;
        let trimmed = output.trim();

        let json: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| format!("Failed to parse memory info: {}", e))?;

        let total_mb = json["TotalMB"].as_f64().unwrap_or(0.0);
        let free_mb = json["FreeMB"].as_f64().unwrap_or(0.0);

        if total_mb <= 0.0 {
            return Err("Total memory reported as 0".to_string());
        }

        Ok(MemoryInfo { total_mb, free_mb })
    }

    async fn execute_powershell(&self, command: &str) -> Result<String, String> {
        self.execute_remote(command).await
    }

    fn server_name(&self) -> &str {
        &self.server_name
    }
}

#[cfg(test)]
mod tests {
    // Note: These tests require a live WinRM server to run.
    // They are disabled by default and require environment variable WinRM_TEST_SERVER

    use super::*;

    #[test]
    fn adapter_script_has_balanced_quotes() {
        let script = adapter_probe_script();
        let quote_count = script.matches('"').count();
        assert_eq!(
            quote_count % 2,
            0,
            "Adapter script has unbalanced double quotes"
        );
        assert!(
            script.contains("-Filter 'IPEnabled = True'"),
            "Adapter script should use single quotes for WMI filter"
        );
        assert!(
            !script.contains("-Filter \"IPEnabled = True\""),
            "Adapter script should avoid double-quoted WMI filter"
        );
    }

    #[test]
    fn combined_payload_maps_to_summary() {
        let session = WindowsRemoteSession {
            server_name: "HOST1".to_string(),
            username: "user".to_string(),
            password: SecureString::new("pass".to_string()),
        };

        let payload = CombinedHealthPayload {
            server_name: Some("PAYLOAD-SRV".to_string()),
            os_info: OsInfo {
                hostname: "PAYLOAD-SRV".to_string(),
                os_version: "Windows Server 2022".to_string(),
                build_number: "20348".to_string(),
                product_type: "ServerNT".to_string(),
                install_date: "2024-01-01T00:00:00Z".to_string(),
            },
            disk_alerts: vec![DiskInfo {
                drive: "E:".to_string(),
                total_gb: 100.0,
                free_gb: 5.0,
                used_gb: 95.0,
                percent_free: 5.0,
            }],
            total_disks: 2,
            disks: vec![
                DiskInfo {
                    drive: "C:".to_string(),
                    total_gb: 200.0,
                    free_gb: 100.0,
                    used_gb: 100.0,
                    percent_free: 50.0,
                },
                DiskInfo {
                    drive: "E:".to_string(),
                    total_gb: 100.0,
                    free_gb: 5.0,
                    used_gb: 95.0,
                    percent_free: 5.0,
                },
            ],
            service_alerts: 1,
            service_status: vec![
                ServiceInfo {
                    name: "WinRM".to_string(),
                    display_name: "WinRM".to_string(),
                    status: "Running".to_string(),
                    startup_type: "Automatic".to_string(),
                    service_account: "NT AUTHORITY\\NetworkService".to_string(),
                },
                ServiceInfo {
                    name: "SQL".to_string(),
                    display_name: "SQL".to_string(),
                    status: "Stopped".to_string(),
                    startup_type: "Automatic".to_string(),
                    service_account: "NT Service\\MSSQLSERVER".to_string(),
                },
            ],
            process_count: 3,
            high_cpu_processes: vec![
                ProcessInfo {
                    name: "b.exe".to_string(),
                    pid: 2,
                    memory_mb: 50.0,
                    cpu_percent: 40.0,
                },
                ProcessInfo {
                    name: "a.exe".to_string(),
                    pid: 1,
                    memory_mb: 42.0,
                    cpu_percent: 90.0,
                },
            ],
            high_cpu_threshold: 90.0,
            total_memory_mb: 16000.0,
            used_memory_mb: 8000.0,
            memory_used_percent: 105.0, // intentionally over 100 to exercise clamp
            uptime: Some(UptimeSnapshot {
                last_boot: "2024-12-31T12:00:00Z".to_string(),
                uptime_hours: 12.0,
                cpu_load_pct: Some(20.0),
            }),
            pending_reboot: Some(PendingRebootStatus {
                pending: true,
                signals: vec!["WU RebootRequired".to_string()],
            }),
            winrm_listeners: Some(vec![WinRmListener {
                transport: "HTTP".to_string(),
                address: "*".to_string(),
                port: "5985".to_string(),
                enabled: "true".to_string(),
                hostname: None,
                certificate_thumbprint: None,
            }]),
            firewall_profiles: Some(vec![FirewallProfile {
                name: "Domain".to_string(),
                enabled: "True".to_string(),
                default_inbound_action: "Block".to_string(),
                default_outbound_action: "Allow".to_string(),
            }]),
            recent_errors: Some(vec![RecentErrorEntry {
                log: "System".to_string(),
                time_created: "2025-01-01T00:00:00Z".to_string(),
                id: 1001,
                provider: "TestProvider".to_string(),
                level: "Error".to_string(),
                message: "Something failed".to_string(),
            }]),
            net_adapters: Some(vec![NetAdapterInfo {
                alias: "Ethernet0".to_string(),
                description: "Test Adapter".to_string(),
                ipv4: vec!["10.0.0.10".to_string()],
                ipv6: vec![],
                dns: vec!["10.0.0.1".to_string()],
                ipv4_prefix: vec![24],
                gateway: vec!["10.0.0.1".to_string()],
            }]),
        };

        let summary = session.build_summary_from_combined(payload);

        assert_eq!(summary.server_name, "PAYLOAD-SRV");
        assert_eq!(summary.service_alerts, 1);
        assert_eq!(summary.total_disks, 2);
        assert_eq!(summary.disk_alerts.len(), 1);
        assert_eq!(summary.high_cpu_processes.first().unwrap().name, "a.exe"); // sorted desc
        assert!((summary.memory_used_percent - 100.0).abs() < f64::EPSILON);
        assert!(summary
            .pending_reboot
            .as_ref()
            .map(|p| p.pending)
            .unwrap_or(false));
        assert_eq!(
            summary
                .winrm_listeners
                .as_ref()
                .and_then(|l| l.first())
                .map(|l| l.port.as_str()),
            Some("5985")
        );
    }

    #[test]
    fn quick_probe_payload_parses() {
        let json = r#"{
            "server_name":"SRV1",
            "uptime_hours": 12.5,
            "cpu_load_pct": 18,
            "memory_used_percent": 42.2
        }"#;

        let payload: QuickProbePayload =
            serde_json::from_str(json).expect("should parse quick probe payload");
        assert_eq!(payload.server_name.as_deref(), Some("SRV1"));
        assert_eq!(payload.uptime_hours, Some(12.5));
        assert_eq!(payload.cpu_load_pct, Some(18.0));
        assert_eq!(payload.memory_used_percent, Some(42.2));
    }

    #[test]
    fn test_escape_powershell_like_pattern_basic() {
        assert_eq!(escape_powershell_like_pattern("simple"), "simple");
        assert_eq!(escape_powershell_like_pattern("with-dash"), "with-dash");
        assert_eq!(
            escape_powershell_like_pattern("with_underscore"),
            "with_underscore"
        );
    }

    #[test]
    fn test_escape_powershell_like_pattern_wildcards() {
        // Wildcards should be escaped
        assert_eq!(escape_powershell_like_pattern("test*"), "test`*");
        assert_eq!(escape_powershell_like_pattern("test?"), "test`?");
        assert_eq!(escape_powershell_like_pattern("*wildcard*"), "`*wildcard`*");
    }

    #[test]
    fn test_escape_powershell_like_pattern_brackets() {
        // Character class brackets should be escaped
        assert_eq!(escape_powershell_like_pattern("test[abc]"), "test`[abc`]");
        assert_eq!(escape_powershell_like_pattern("[0-9]"), "`[0-9`]");
    }

    #[test]
    fn test_escape_powershell_like_pattern_quotes() {
        // Single quotes should be doubled (PowerShell string escape)
        assert_eq!(escape_powershell_like_pattern("test'name"), "test''name");
        assert_eq!(escape_powershell_like_pattern("it's"), "it''s");
    }

    #[test]
    fn test_escape_powershell_like_pattern_script_terminators() {
        // Script block terminators and variables should be escaped
        assert_eq!(escape_powershell_like_pattern("test}"), "test`}");
        assert_eq!(escape_powershell_like_pattern("$variable"), "`$variable");
        assert_eq!(
            escape_powershell_like_pattern("test$(cmd)"),
            "test`$`(cmd`)"
        );
    }

    #[test]
    fn test_escape_powershell_like_pattern_injection_attempt() {
        // This is a realistic injection attempt - should be completely neutralized
        let injection = "' }} Write-Host 'PWNED' | Where-Object { $_.Name -like '*";
        let escaped = escape_powershell_like_pattern(injection);

        // After escaping, all special chars should be neutralized
        assert_eq!(
            escaped,
            "'' `}`} Write-Host ''PWNED'' `| Where-Object `{ `$_.Name -like ''`*"
        );

        // Verify the escaped string doesn't contain unescaped dangerous patterns
        assert!(!escaped.contains("}}")); // Unescaped closing braces
        assert!(!escaped.contains("${")); // Unescaped variable expansion
    }

    #[test]
    fn test_escape_powershell_like_pattern_backtick() {
        // Backticks (PowerShell escape char) should be doubled
        assert_eq!(
            escape_powershell_like_pattern("test`escape"),
            "test``escape"
        );
    }

    #[test]
    fn test_escape_powershell_like_pattern_empty() {
        assert_eq!(escape_powershell_like_pattern(""), "");
    }

    #[tokio::test]
    #[ignore]
    async fn test_real_winrm_connection() {
        // Only runs if explicitly enabled with: cargo test -- --ignored
        // Requires: WinRM_TEST_SERVER environment variable

        use crate::models::{Credentials, Username};

        let server = std::env::var("WinRM_TEST_SERVER").unwrap_or_else(|_| "SERVER01".to_string());
        let username = std::env::var("WinRM_TEST_USERNAME").unwrap_or_else(|_| "Admin".to_string());
        let password =
            std::env::var("WinRM_TEST_PASSWORD").unwrap_or_else(|_| "Password123!".to_string());

        let creds = Credentials::new(
            Username::new(username).unwrap(),
            SecureString::new(password),
        );

        let session = WindowsRemoteSession::connect(server, creds)
            .await
            .expect("Failed to connect");

        let os_info = session.get_os_info().await.expect("Failed to get OS info");
        println!("Connected to: {}", os_info.hostname);
        assert!(!os_info.hostname.is_empty());
    }
}
