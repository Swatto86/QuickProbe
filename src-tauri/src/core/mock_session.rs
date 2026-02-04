//! Mock remote session for testing without real servers
//!
//! Provides realistic test data that simulates WinRM/PSRemoting responses.
//! Used during development to test probe logic without connecting to actual servers.

use super::session::{
    DiskInfo, MemoryInfo, OsInfo, ProcessInfo, RemoteSession, ServiceInfo, SessionOs,
};

/// Mock remote session for testing
///
/// Returns simulated responses matching real Windows server data structures.
/// Useful for development and testing probe logic without WinRM access.
pub struct MockRemoteSession {
    server_name: String,
    os_type: MockOsType,
}

/// Simulation types to test different scenarios
#[derive(Debug, Clone, Copy)]
pub enum MockOsType {
    /// Windows Server 2022 with typical services
    Server2022,
    /// Windows Server 2019 with different configuration
    Server2019,
    /// Generic Linux host
    Linux,
    /// Simulated error condition
    Unreachable,
}

impl MockRemoteSession {
    /// Create a new mock session for the given server
    pub fn new(server_name: String, os_type: MockOsType) -> Self {
        Self {
            server_name,
            os_type,
        }
    }

    /// Create Server 2022 mock by default
    pub fn server2022(server_name: String) -> Self {
        Self::new(server_name, MockOsType::Server2022)
    }

    /// Create Server 2019 mock
    pub fn server2019(server_name: String) -> Self {
        Self::new(server_name, MockOsType::Server2019)
    }

    /// Create unreachable mock (for error testing)
    pub fn unreachable(server_name: String) -> Self {
        Self::new(server_name, MockOsType::Unreachable)
    }
}

#[async_trait::async_trait]
impl RemoteSession for MockRemoteSession {
    fn os(&self) -> SessionOs {
        match self.os_type {
            MockOsType::Linux => SessionOs::Linux,
            _ => SessionOs::Windows,
        }
    }

    async fn get_os_info(&self) -> Result<OsInfo, String> {
        if matches!(self.os_type, MockOsType::Unreachable) {
            return Err("Connection timeout".to_string());
        }

        Ok(match self.os_type {
            MockOsType::Server2022 => OsInfo {
                hostname: self.server_name.clone(),
                os_version: "Windows Server 2022 Datacenter".to_string(),
                build_number: "20348.2582".to_string(),
                product_type: "ServerNT".to_string(),
                install_date: "2024-01-15T10:30:45Z".to_string(),
            },
            MockOsType::Server2019 => OsInfo {
                hostname: self.server_name.clone(),
                os_version: "Windows Server 2019 Standard".to_string(),
                build_number: "17763.4645".to_string(),
                product_type: "ServerNT".to_string(),
                install_date: "2023-06-20T14:15:30Z".to_string(),
            },
            MockOsType::Linux => OsInfo {
                hostname: self.server_name.clone(),
                os_version: "Ubuntu 24.04 LTS".to_string(),
                build_number: "6.8.0-41-generic".to_string(),
                product_type: "Linux".to_string(),
                install_date: "2024-06-01T10:00:00Z".to_string(),
            },
            MockOsType::Unreachable => unreachable!(),
        })
    }

    async fn get_services(&self, filter: Option<&str>) -> Result<Vec<ServiceInfo>, String> {
        if matches!(self.os_type, MockOsType::Unreachable) {
            return Err("Connection timeout".to_string());
        }

        let all_services = vec![
            ServiceInfo {
                name: "W32Time".to_string(),
                display_name: "Windows Time".to_string(),
                status: "Running".to_string(),
                startup_type: "Automatic".to_string(),
                service_account: "LocalSystem".to_string(),
            },
            ServiceInfo {
                name: "DHCP".to_string(),
                display_name: "DHCP Client".to_string(),
                status: "Running".to_string(),
                startup_type: "Automatic".to_string(),
                service_account: "NT Authority\\LocalService".to_string(),
            },
            ServiceInfo {
                name: "Dns".to_string(),
                display_name: "DNS Client".to_string(),
                status: "Running".to_string(),
                startup_type: "Automatic".to_string(),
                service_account: "NT AUTHORITY\\NetworkService".to_string(),
            },
            ServiceInfo {
                name: "lanmanserver".to_string(),
                display_name: "Server".to_string(),
                status: "Running".to_string(),
                startup_type: "Automatic".to_string(),
                service_account: "LocalSystem".to_string(),
            },
            ServiceInfo {
                name: "SQLSERVERAGENT".to_string(),
                display_name: "SQL Server Agent (MSSQLSERVER)".to_string(),
                status: "Stopped".to_string(),
                startup_type: "Automatic".to_string(),
                service_account: "NT Service\\SQLSERVERAGENT".to_string(),
            },
            ServiceInfo {
                name: "MSSQLServer".to_string(),
                display_name: "SQL Server (MSSQLSERVER)".to_string(),
                status: "Running".to_string(),
                startup_type: "Automatic".to_string(),
                service_account: "NT Service\\MSSQLSERVER".to_string(),
            },
            ServiceInfo {
                name: "WinRM".to_string(),
                display_name: "Windows Remote Management (WS-Management)".to_string(),
                status: "Running".to_string(),
                startup_type: "Automatic".to_string(),
                service_account: "NT AUTHORITY\\NetworkService".to_string(),
            },
        ];

        let filtered = match filter {
            None => all_services,
            Some(f) => all_services
                .into_iter()
                .filter(|s| s.name.to_lowercase().contains(&f.to_lowercase()))
                .collect(),
        };

        Ok(filtered)
    }

    async fn get_processes(&self, filter: Option<&str>) -> Result<Vec<ProcessInfo>, String> {
        if matches!(self.os_type, MockOsType::Unreachable) {
            return Err("Connection timeout".to_string());
        }

        let all_processes = vec![
            ProcessInfo {
                name: "System".to_string(),
                pid: 4,
                memory_mb: 150.0,
                cpu_percent: 0.5,
            },
            ProcessInfo {
                name: "svchost.exe".to_string(),
                pid: 1084,
                memory_mb: 45.2,
                cpu_percent: 0.1,
            },
            ProcessInfo {
                name: "sqlservr.exe".to_string(),
                pid: 2856,
                memory_mb: 2048.5,
                cpu_percent: 5.2,
            },
            ProcessInfo {
                name: "lsass.exe".to_string(),
                pid: 712,
                memory_mb: 28.1,
                cpu_percent: 0.0,
            },
            ProcessInfo {
                name: "explorer.exe".to_string(),
                pid: 3456,
                memory_mb: 380.0,
                cpu_percent: 2.3,
            },
            ProcessInfo {
                name: "chrome.exe".to_string(),
                pid: 4012,
                memory_mb: 1205.3,
                cpu_percent: 92.3,
            },
        ];

        let filtered = match filter {
            None => all_processes,
            Some(f) => all_processes
                .into_iter()
                .filter(|p| p.name.to_lowercase().contains(&f.to_lowercase()))
                .collect(),
        };

        Ok(filtered)
    }

    async fn get_disks(&self) -> Result<Vec<DiskInfo>, String> {
        if matches!(self.os_type, MockOsType::Unreachable) {
            return Err("Connection timeout".to_string());
        }

        Ok(vec![
            DiskInfo {
                drive: "C:".to_string(),
                total_gb: 500.0,
                free_gb: 125.5,
                used_gb: 374.5,
                percent_free: 25.1,
            },
            DiskInfo {
                drive: "D:".to_string(),
                total_gb: 2000.0,
                free_gb: 800.0,
                used_gb: 1200.0,
                percent_free: 40.0,
            },
            DiskInfo {
                drive: "E:".to_string(),
                total_gb: 4000.0,
                free_gb: 150.0,
                used_gb: 3850.0,
                percent_free: 3.75,
            },
        ])
    }

    async fn get_memory_info(&self) -> Result<MemoryInfo, String> {
        if matches!(self.os_type, MockOsType::Unreachable) {
            return Err("Connection timeout".to_string());
        }

        // Simulated memory for testing: 64GB total, ~18GB free
        Ok(MemoryInfo {
            total_mb: 65536.0,
            free_mb: 18432.0,
        })
    }
    async fn execute_powershell(&self, _command: &str) -> Result<String, String> {
        if matches!(self.os_type, MockOsType::Unreachable) {
            return Err("Connection timeout".to_string());
        }

        // For mock, return a generic response
        Ok("Mock PowerShell execution result".to_string())
    }

    fn server_name(&self) -> &str {
        &self.server_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server2022_os_info() {
        let session = MockRemoteSession::server2022("SERVER01".to_string());
        let os_info = session.get_os_info().await.unwrap();

        assert_eq!(os_info.hostname, "SERVER01");
        assert_eq!(os_info.os_version, "Windows Server 2022 Datacenter");
        assert!(os_info.build_number.starts_with("20348"));
    }

    #[tokio::test]
    async fn test_mock_server2019_os_info() {
        let session = MockRemoteSession::server2019("SERVER02".to_string());
        let os_info = session.get_os_info().await.unwrap();

        assert_eq!(os_info.hostname, "SERVER02");
        assert_eq!(os_info.os_version, "Windows Server 2019 Standard");
        assert!(os_info.build_number.starts_with("17763"));
    }

    #[tokio::test]
    async fn test_mock_unreachable() {
        let session = MockRemoteSession::unreachable("OFFLINE".to_string());
        let result = session.get_os_info().await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timeout"));
    }

    #[tokio::test]
    async fn test_mock_get_services_all() {
        let session = MockRemoteSession::server2022("SERVER01".to_string());
        let services = session.get_services(None).await.unwrap();

        assert!(services.len() > 0);
        assert!(services.iter().any(|s| s.name == "WinRM"));
    }

    #[tokio::test]
    async fn test_mock_get_services_filtered() {
        let session = MockRemoteSession::server2022("SERVER01".to_string());
        let services = session.get_services(Some("sql")).await.unwrap();

        assert_eq!(services.len(), 2);
        assert!(services
            .iter()
            .all(|s| s.name.to_lowercase().contains("sql")));
    }

    #[tokio::test]
    async fn test_mock_get_processes_filtered() {
        let session = MockRemoteSession::server2022("SERVER01".to_string());
        let processes = session.get_processes(Some("sql")).await.unwrap();

        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].name, "sqlservr.exe");
    }

    #[tokio::test]
    async fn test_mock_get_disks() {
        let session = MockRemoteSession::server2022("SERVER01".to_string());
        let disks = session.get_disks().await.unwrap();

        assert_eq!(disks.len(), 3);
        assert!(disks.iter().any(|d| d.drive == "C:"));
        assert!(disks.iter().any(|d| d.drive == "D:"));
    }

    #[tokio::test]
    async fn test_server_name() {
        let session = MockRemoteSession::server2022("TESTSERVER".to_string());
        assert_eq!(session.server_name(), "TESTSERVER");
    }
}
