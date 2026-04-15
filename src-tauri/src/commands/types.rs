//! Shared types used across command modules.

use quickprobe::core::session::{NetAdapterInfo, ProcessInfo, ServiceInfo};
use serde::{Deserialize, Serialize};

/// Basic app info for About window
#[derive(Debug, Serialize)]
pub(crate) struct AppInfoResponse {
    pub name: String,
    pub version: String,
}

/// Debug response for raw adapters
#[derive(Debug, Serialize)]
pub(crate) struct AdapterDebugResponse {
    pub raw: String,
    pub adapters: Option<Vec<NetAdapterInfo>>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LoginResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CredentialsCheckResponse {
    pub has_credentials: bool,
    pub username: Option<String>,
    /// `"domain"`, `"local"`, or `"none"`.
    pub login_mode: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct ServerInfo {
    pub name: String,
    pub notes: Option<String>,
    pub group: Option<String>,
    pub services: Option<Vec<String>>,
    pub os_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct HostUpdate {
    pub name: String,
    pub notes: Option<String>,
    pub group: Option<String>,
    pub services: Option<Vec<String>>,
    pub os_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NormalizedHost {
    pub name: String,
    pub notes: String,
    pub group: String,
    pub os_type: String,
    pub services: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct AdComputer {
    pub fqdn: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ScanResult {
    pub found: usize,
    pub total: usize,
    pub created: usize,
    pub removed: usize,
}

/// Lightweight heartbeat status returned to the dashboard for high-frequency refreshes
#[derive(Debug, Serialize)]
pub(crate) struct QuickStatus {
    pub server_name: String,
    pub ping_ok: bool,
    pub winrm_ok: bool,
    pub winrm_error: Option<String>,
    pub reachability: Option<quickprobe::core::probes::ReachabilitySummary>,
    pub uptime_hours: Option<f64>,
    pub cpu_load_pct: Option<f64>,
    pub memory_used_percent: Option<f64>,
    pub total_memory_mb: Option<f64>,
    pub used_memory_mb: Option<f64>,
    pub process_count: Option<usize>,
    pub top_cpu_processes: Option<Vec<ProcessInfo>>,
    pub service_status: Option<Vec<ServiceInfo>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RestoreResponse {
    pub local_storage: serde_json::Value,
    pub hosts_written: bool,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub(crate) struct AppSettings {
    #[serde(default)]
    pub start_hidden: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct SettingsBundle {
    pub qp_settings: serde_json::Value,
    pub qp_server_order: serde_json::Value,
    pub qp_host_view_mode: serde_json::Value,
    pub qp_hosts_changed: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SettingsSetPayload {
    pub qp_settings: serde_json::Value,
    pub qp_server_order: serde_json::Value,
    pub qp_host_view_mode: serde_json::Value,
    pub qp_hosts_changed: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct LocalStoreStatus {
    pub mode: String,
    pub db_path: Option<String>,
    pub hosts_count: Option<u64>,
}

/// Comprehensive CSV health fields struct for clean export
#[derive(Default)]
pub(crate) struct CsvHealthFields {
    pub last_probed_at: String,
    pub hostname: String,
    pub os_version: String,
    pub build_number: String,
    pub product_type: String,
    pub install_date: String,
    pub location: String,
    pub ipv4_addresses: String,
    pub ipv6_addresses: String,
    pub subnet_masks: String,
    pub gateways: String,
    pub dns_servers: String,
    pub network_adapters: String,
    pub total_memory_gb: String,
    pub used_memory_gb: String,
    pub memory_used_percent: String,
    pub cpu_load_percent: String,
    pub uptime_hours: String,
    pub uptime_display: String,
    pub last_boot_time: String,
    pub process_count: String,
    pub ping_ok: String,
    pub tcp_ports_status: String,
    pub total_disks: String,
    pub disk_details: String,
    pub disk_alerts: String,
    pub service_status: String,
    pub stopped_services: String,
    pub service_alerts_count: String,
    pub high_cpu_processes: String,
    pub reboot_pending: String,
    pub reboot_signals: String,
    pub recent_errors_count: String,
    pub winrm_issue: String,
}

/// Response from service control operation
#[derive(Debug, Serialize)]
pub(crate) struct ServiceControlResponse {
    pub success: bool,
    pub service_name: String,
    pub action: String,
    pub new_status: Option<String>,
    pub message: String,
}

/// Process information for the process management UI (includes user field)
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RemoteProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_mb: f64,
    pub user: String,
}

/// Response from process kill operation
#[derive(Debug, Serialize)]
pub(crate) struct ProcessKillResponse {
    pub success: bool,
    pub pid: u32,
    pub process_name: String,
    pub message: String,
}

/// Response from remote PowerShell execution
#[derive(Debug, Serialize)]
pub(crate) struct RemotePowerShellResponse {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

/// Response from remote SSH execution
#[derive(Debug, Serialize)]
pub(crate) struct RemoteSshResponse {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StartHiddenArgs {
    #[serde(alias = "startHidden", alias = "start_hidden")]
    pub start_hidden: bool,
}
