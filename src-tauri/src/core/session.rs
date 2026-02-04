//! Remote session abstraction for WinRM/PSRemoting
//!
//! This trait allows testing without real servers by supporting mock implementations.
//! Platform-specific implementations are in `src/platform/`.

use serde::{Deserialize, Serialize};

/// Operating system family for a remote session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOs {
    Windows,
    Linux,
    Unknown,
}

/// Result of a remote probe operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProbeResult {
    /// Probe name (e.g., "os_info", "services")
    pub name: String,
    /// Success status
    pub success: bool,
    /// Query result or error message
    pub data: serde_json::Value,
    /// Execution time in milliseconds
    pub duration_ms: u64,
}

/// Operating system information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsInfo {
    pub hostname: String,
    pub os_version: String,
    pub build_number: String,
    pub product_type: String,
    pub install_date: String,
}

impl OsInfo {
    /// Convert to JSON value for probe result
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::json!({}))
    }
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub startup_type: String,
    pub service_account: String,
}

/// Physical memory information (MB)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryInfo {
    /// Total visible memory (MB)
    pub total_mb: f64,
    /// Free/available physical memory (MB)
    pub free_mb: f64,
}

/// Process information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub memory_mb: f64,
    pub cpu_percent: f64,
}

/// Uptime and CPU load snapshot
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UptimeSnapshot {
    pub last_boot: String,
    pub uptime_hours: f64,
    pub cpu_load_pct: Option<f64>,
}

/// Pending reboot indicators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingRebootStatus {
    pub pending: bool,
    pub signals: Vec<String>,
}

/// WinRM listener info
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WinRmListener {
    pub transport: String,
    pub address: String,
    pub port: String,
    pub enabled: String,
    pub hostname: Option<String>,
    pub certificate_thumbprint: Option<String>,
}

/// Firewall profile summary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallProfile {
    pub name: String,
    pub enabled: String,
    pub default_inbound_action: String,
    pub default_outbound_action: String,
}

/// Recent error/event entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecentErrorEntry {
    pub log: String,
    pub time_created: String,
    pub id: u32,
    pub provider: String,
    pub level: String,
    pub message: String,
}

/// Network adapter summary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetAdapterInfo {
    pub alias: String,
    pub description: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub dns: Vec<String>,
    #[serde(default)]
    pub ipv4_prefix: Vec<u32>,
    #[serde(default)]
    pub gateway: Vec<String>,
}

/// Available disk information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskInfo {
    pub drive: String,
    pub total_gb: f64,
    pub free_gb: f64,
    pub used_gb: f64,
    pub percent_free: f64,
}

/// Lightweight heartbeat summary for quick status checks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuickProbeSummary {
    pub server_name: String,
    pub uptime_hours: Option<f64>,
    pub cpu_load_pct: Option<f64>,
    pub memory_used_percent: Option<f64>,
    pub total_memory_mb: Option<f64>,
    pub used_memory_mb: Option<f64>,
    pub process_count: Option<usize>,
    pub top_cpu_processes: Option<Vec<ProcessInfo>>,
    pub service_status: Option<Vec<ServiceInfo>>,
}

/// Remote session trait for abstraction over real/mock implementations
///
/// This trait allows the core logic to work with both real WinRM sessions
/// and mock implementations for testing without servers.
#[async_trait::async_trait]
pub trait RemoteSession: Send + Sync {
    /// OS family this session targets (used to branch platform-specific probes)
    fn os(&self) -> SessionOs {
        SessionOs::Unknown
    }

    /// Get OS information from the remote server
    async fn get_os_info(&self) -> Result<OsInfo, String>;

    /// Get list of services matching filter (e.g., "sql*")
    async fn get_services(&self, filter: Option<&str>) -> Result<Vec<ServiceInfo>, String>;

    /// Get list of processes (optionally filtered by name)
    async fn get_processes(&self, filter: Option<&str>) -> Result<Vec<ProcessInfo>, String>;

    /// Get disk information for all drives
    async fn get_disks(&self) -> Result<Vec<DiskInfo>, String>;

    /// Get total/available physical memory in MB
    async fn get_memory_info(&self) -> Result<MemoryInfo, String>;

    /// Execute a raw PowerShell command and return output
    ///
    /// SECURITY: Command must be sanitized by caller. This is for internal use only.
    async fn execute_powershell(&self, command: &str) -> Result<String, String>;

    /// Get the server name this session is connected to
    fn server_name(&self) -> &str;

    /// Get uptime and CPU load snapshot (optional, Linux/cross-platform support)
    async fn get_uptime_snapshot(&self) -> Result<UptimeSnapshot, String> {
        Err("Uptime snapshot not implemented for this session type".to_string())
    }

    /// Get network adapter information (optional, Linux/cross-platform support)
    async fn get_net_adapters(&self) -> Result<Vec<NetAdapterInfo>, String> {
        Err("Network adapter info not implemented for this session type".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_info_serialization() {
        let os_info = OsInfo {
            hostname: "SERVER01".to_string(),
            os_version: "Windows Server 2022".to_string(),
            build_number: "20348".to_string(),
            product_type: "ServerNT".to_string(),
            install_date: "2024-01-15".to_string(),
        };

        let json = os_info.to_value();
        assert_eq!(json["hostname"], "SERVER01");
        assert_eq!(json["os_version"], "Windows Server 2022");
    }

    #[test]
    fn test_probe_result_serialization() {
        let result = ProbeResult {
            name: "os_info".to_string(),
            success: true,
            data: serde_json::json!({
                "hostname": "SERVER01",
                "os_version": "Windows Server 2022"
            }),
            duration_ms: 150,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("os_info"));
        assert!(json.contains("SERVER01"));
    }
}
