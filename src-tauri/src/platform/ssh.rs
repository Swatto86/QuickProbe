//! Linux remote session over SSH
//!
//! Provides a minimal SSH-based `RemoteSession` implementation so the Windows
//! UI can probe Linux hosts without WinRM/PowerShell.

use crate::core::session::{
    DiskInfo, MemoryInfo, NetAdapterInfo, OsInfo, ProcessInfo, RemoteSession, ServiceInfo,
    SessionOs, UptimeSnapshot,
};
use crate::models::{Credentials, SecureString};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

pub struct LinuxRemoteSession {
    server_name: String,
    username: String,
    password: SecureString,
}

impl LinuxRemoteSession {
    /// Establish an SSH session using password authentication.
    pub async fn connect(server_name: String, credentials: Credentials) -> Result<Self, String> {
        crate::logger::log_debug(&format!(
            "LinuxRemoteSession::connect START '{}' user='{}'",
            server_name,
            credentials.username().as_str()
        ));
        let session = Self {
            server_name: server_name.trim().to_string(),
            username: credentials.username().as_str().to_string(),
            password: credentials.password().clone(),
        };

        // Quick connectivity/auth check
        match session.exec("echo ok").await {
            Ok(_) => {
                crate::logger::log_debug(&format!(
                    "LinuxRemoteSession::connect OK '{}'",
                    session.server_name
                ));
                Ok(session)
            }
            Err(e) => {
                crate::logger::log_error(&format!(
                    "LinuxRemoteSession::connect FAILED '{}': {}",
                    session.server_name, e
                ));
                Err(e)
            }
        }
    }

    fn parse_host_port(&self) -> (String, u16) {
        if let Some((host, port)) = self.server_name.rsplit_once(':') {
            if let Ok(port_num) = port.parse::<u16>() {
                return (host.to_string(), port_num);
            }
        }
        (self.server_name.clone(), 22)
    }

    async fn exec(&self, command: &str) -> Result<String, String> {
        let (host, port) = self.parse_host_port();
        let username = self.username.clone();
        let password = self.password.as_str().to_string();
        let command = command.to_string();

        tokio::task::spawn_blocking(move || {
            let tcp = TcpStream::connect((host.as_str(), port))
                .map_err(|e| format!("SSH connect to {}:{} failed: {}", host, port, e))?;
            tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
            tcp.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let mut sess = Session::new().map_err(|e| format!("SSH session init failed: {e}"))?;
            sess.set_tcp_stream(tcp);
            sess.handshake()
                .map_err(|e| format!("SSH handshake failed: {e}"))?;

            sess.userauth_password(&username, &password)
                .map_err(|e| format!("SSH authentication failed: {e}"))?;
            if !sess.authenticated() {
                return Err("SSH authentication failed".to_string());
            }

            let mut channel = sess
                .channel_session()
                .map_err(|e| format!("SSH channel open failed: {e}"))?;
            channel
                .exec(&format!("sh -c {}", shell_escape::escape(command.into())))
                .map_err(|e| format!("SSH exec failed: {e}"))?;

            let mut stdout = String::new();
            channel
                .read_to_string(&mut stdout)
                .map_err(|e| format!("SSH read failed: {e}"))?;
            let mut stderr = String::new();
            let _ = channel.stderr().read_to_string(&mut stderr).map(|_| ());
            let exit_status = channel.exit_status().unwrap_or(0);
            channel.wait_close().ok();

            if exit_status != 0 && stdout.trim().is_empty() {
                return Err(if stderr.trim().is_empty() {
                    format!("SSH command failed with status {exit_status}")
                } else {
                    format!("SSH command failed: {}", stderr.trim())
                });
            }

            Ok(stdout)
        })
        .await
        .map_err(|e| format!("SSH task failed: {e}"))?
    }

    fn parse_os_release(raw: &str) -> (String, String) {
        let mut name = String::new();
        let mut version = String::new();
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("NAME=") {
                name = rest.trim_matches('"').to_string();
            } else if let Some(rest) = line.strip_prefix("VERSION=") {
                version = rest.trim_matches('"').to_string();
            } else if let Some(rest) = line.strip_prefix("VERSION_ID=") {
                version = rest.trim_matches('"').to_string();
            }
        }

        if name.is_empty() {
            name = "Linux".to_string();
        }
        (name, version)
    }

    fn parse_meminfo(raw: &str) -> (f64, f64) {
        let mut total_kb = 0f64;
        let mut avail_kb = 0f64;
        for line in raw.lines() {
            if let Some(val) = line.strip_prefix("MemTotal:") {
                total_kb = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
            } else if let Some(val) = line.strip_prefix("MemAvailable:") {
                avail_kb = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
            }
        }
        (total_kb / 1024.0, avail_kb / 1024.0)
    }

    /// Get uptime and CPU load for Linux hosts
    pub async fn get_uptime_snapshot(&self) -> Result<UptimeSnapshot, String> {
        // Get uptime in seconds from /proc/uptime
        let uptime_raw = self.exec("cat /proc/uptime").await?;
        let uptime_secs: f64 = uptime_raw
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        let uptime_hours = uptime_secs / 3600.0;

        // Get last boot time
        let last_boot = self
            .exec("uptime -s 2>/dev/null || date -d \"$(awk '{print $1}' /proc/uptime) seconds ago\" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo unknown")
            .await?
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();

        // Get CPU load (1-minute average from /proc/loadavg, normalized to percentage)
        let loadavg_raw = self.exec("cat /proc/loadavg").await?;
        let load_1min: f64 = loadavg_raw
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);

        // Get number of CPU cores to normalize load average to percentage
        let nproc_raw = self
            .exec("nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo")
            .await?;
        let num_cpus: f64 = nproc_raw
            .lines()
            .next()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .unwrap_or(1.0)
            .max(1.0);

        // Convert load average to percentage (load / num_cpus * 100)
        let cpu_load_pct = (load_1min / num_cpus * 100.0).min(100.0);

        Ok(UptimeSnapshot {
            last_boot,
            uptime_hours: (uptime_hours * 100.0).round() / 100.0,
            cpu_load_pct: Some(cpu_load_pct.round()), // Round to whole percent
        })
    }

    /// Get network adapter information for Linux hosts
    pub async fn get_net_adapters(&self) -> Result<Vec<NetAdapterInfo>, String> {
        // Use `ip addr` to get interface information - simpler parsing approach
        let output = self.exec("ip -o addr show 2>/dev/null").await?;

        crate::logger::log_debug(&format!(
            "get_net_adapters ip addr output for '{}': {}",
            self.server_name,
            if output.len() > 1000 {
                &output[..1000]
            } else {
                &output
            }
        ));

        // Also get gateway and DNS
        let gateway_output = self
            .exec("ip route show default 2>/dev/null | head -1")
            .await
            .unwrap_or_default();
        let dns_output = self
            .exec("cat /etc/resolv.conf 2>/dev/null")
            .await
            .unwrap_or_default();

        // Parse default gateway
        let default_gateway: Option<String> = gateway_output
            .split_whitespace()
            .skip_while(|s| *s != "via")
            .nth(1)
            .map(|s| s.to_string());

        // Parse DNS servers
        let dns_servers: Vec<String> = dns_output
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with("nameserver") {
                    line.split_whitespace().nth(1).map(|s| s.to_string())
                } else {
                    None
                }
            })
            .take(3)
            .collect();

        // Parse `ip -o addr show` output
        // Format: "2: eth0    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"
        use std::collections::HashMap;
        let mut adapters_map: HashMap<String, NetAdapterInfo> = HashMap::new();

        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            // Get interface name (second field, remove trailing colon if present)
            let iface = parts.get(1).map(|s| s.trim_end_matches(':')).unwrap_or("");
            if iface.is_empty() || iface == "lo" {
                continue;
            }

            // Get address type and value
            let addr_type = parts.get(2).copied().unwrap_or("");
            let addr_value = parts.get(3).copied().unwrap_or("");

            // Get or create adapter entry
            let adapter = adapters_map
                .entry(iface.to_string())
                .or_insert_with(|| NetAdapterInfo {
                    alias: iface.to_string(),
                    description: iface.to_string(),
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
                    dns: dns_servers.clone(),
                    ipv4_prefix: Vec::new(),
                    gateway: default_gateway.clone().into_iter().collect(),
                });

            match addr_type {
                "inet" => {
                    // Parse "192.168.1.100/24" format
                    let addr_parts: Vec<&str> = addr_value.split('/').collect();
                    if !addr_parts.is_empty() && !addr_parts[0].is_empty() {
                        adapter.ipv4.push(addr_parts[0].to_string());
                        if addr_parts.len() > 1 {
                            if let Ok(prefix) = addr_parts[1].parse::<u32>() {
                                adapter.ipv4_prefix.push(prefix);
                            }
                        }
                    }
                }
                "inet6" => {
                    // Skip link-local addresses (fe80::)
                    if !addr_value.starts_with("fe80:") {
                        let addr_clean = addr_value.split('/').next().unwrap_or(addr_value);
                        if !addr_clean.is_empty() {
                            adapter.ipv6.push(addr_clean.to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        // Convert map to vec, filtering out adapters with no addresses
        let adapters: Vec<NetAdapterInfo> = adapters_map
            .into_values()
            .filter(|a| !a.ipv4.is_empty() || !a.ipv6.is_empty())
            .collect();

        crate::logger::log_debug(&format!(
            "get_net_adapters parsed {} adapters for '{}'",
            adapters.len(),
            self.server_name
        ));

        Ok(adapters)
    }

    /// Execute an arbitrary shell command on the remote Linux host.
    /// This is a public wrapper around the internal exec() method for use by Tauri commands.
    pub async fn execute_command(&self, command: &str) -> Result<String, String> {
        self.exec(command).await
    }

    /// Execute a command with PTY (pseudo-terminal) support for curses/ncurses applications.
    /// This allocates a terminal and sets TERM=xterm-256color for proper terminal rendering.
    /// Useful for commands like top, htop, vim, nano, etc.
    pub async fn execute_command_with_pty(
        &self,
        command: &str,
        cols: u32,
        rows: u32,
    ) -> Result<String, String> {
        self.exec_with_pty(command, cols, rows).await
    }

    /// Internal PTY-enabled execution for curses applications
    async fn exec_with_pty(&self, command: &str, cols: u32, rows: u32) -> Result<String, String> {
        let (host, port) = self.parse_host_port();
        let username = self.username.clone();
        let password = self.password.as_str().to_string();
        let command = command.to_string();

        tokio::task::spawn_blocking(move || {
            let tcp = TcpStream::connect((host.as_str(), port))
                .map_err(|e| format!("SSH connect to {}:{} failed: {}", host, port, e))?;
            tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
            tcp.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let mut sess = Session::new().map_err(|e| format!("SSH session init failed: {e}"))?;
            sess.set_tcp_stream(tcp);
            sess.handshake()
                .map_err(|e| format!("SSH handshake failed: {e}"))?;

            sess.userauth_password(&username, &password)
                .map_err(|e| format!("SSH authentication failed: {e}"))?;
            if !sess.authenticated() {
                return Err("SSH authentication failed".to_string());
            }

            let mut channel = sess
                .channel_session()
                .map_err(|e| format!("SSH channel open failed: {e}"))?;

            // Request a PTY with xterm-256color terminal type for curses support
            // Parameters: term, cols, rows, pxwidth, pxheight, modes
            channel
                .request_pty("xterm-256color", None, Some((cols, rows, 0, 0)))
                .map_err(|e| format!("PTY request failed: {e}"))?;

            // Execute the command in the PTY
            channel
                .exec(&command)
                .map_err(|e| format!("SSH exec failed: {e}"))?;

            // Read all output (combined stdout/stderr in PTY mode)
            let mut output = String::new();
            channel
                .read_to_string(&mut output)
                .map_err(|e| format!("SSH read failed: {e}"))?;

            let exit_status = channel.exit_status().unwrap_or(0);
            channel.wait_close().ok();

            // For PTY mode, we return output even if exit status is non-zero
            // (some curses apps may exit with non-zero status normally)
            if exit_status != 0 && output.trim().is_empty() {
                return Err(format!("Command exited with status {exit_status}"));
            }

            Ok(output)
        })
        .await
        .map_err(|e| format!("SSH task failed: {e}"))?
    }
}

#[async_trait::async_trait]
impl RemoteSession for LinuxRemoteSession {
    fn os(&self) -> SessionOs {
        SessionOs::Linux
    }

    async fn get_os_info(&self) -> Result<OsInfo, String> {
        let host = self
            .exec("hostname || uname -n")
            .await?
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();

        let os_release_raw = self.exec("cat /etc/os-release 2>/dev/null || true").await?;
        let (distro_name, distro_version) = Self::parse_os_release(&os_release_raw);
        let kernel = self
            .exec("uname -r")
            .await?
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
        let install_date = self
            .exec("stat -c %w / 2>/dev/null || stat -c %y / 2>/dev/null || echo unknown")
            .await?
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();

        Ok(OsInfo {
            hostname: host,
            os_version: format!("{} {}", distro_name, distro_version)
                .trim()
                .to_string(),
            build_number: kernel,
            product_type: "Linux".to_string(),
            install_date,
        })
    }

    async fn get_services(&self, filter: Option<&str>) -> Result<Vec<ServiceInfo>, String> {
        let output = self
            .exec("systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null")
            .await?;
        let filter_lower = filter.map(|f| f.to_lowercase());
        let mut services = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let name = parts[0].to_string();
            if let Some(f) = &filter_lower {
                if !name.to_lowercase().contains(f) {
                    continue;
                }
            }
            let status = parts[3].to_string(); // SUB column (running/exited)
            services.push(ServiceInfo {
                name: name.clone(),
                display_name: name,
                status,
                startup_type: "Unknown".to_string(),
                service_account: "Unknown".to_string(),
            });
        }
        Ok(services)
    }

    async fn get_processes(&self, filter: Option<&str>) -> Result<Vec<ProcessInfo>, String> {
        let output = self.exec("ps -eo pid,comm,%cpu,rss --no-headers").await?;
        let filter_lower = filter.map(|f| f.to_lowercase());
        let mut processes = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let pid = parts[0].parse::<u32>().unwrap_or(0);
            let name = parts[1].to_string();
            if let Some(f) = &filter_lower {
                if !name.to_lowercase().contains(f) {
                    continue;
                }
            }
            let cpu_percent = parts[2].parse::<f64>().unwrap_or(0.0);
            let rss_kb = parts[3].parse::<f64>().unwrap_or(0.0);
            processes.push(ProcessInfo {
                name,
                pid,
                memory_mb: (rss_kb / 1024.0 * 100.0).round() / 100.0,
                cpu_percent,
            });
        }
        Ok(processes)
    }

    async fn get_disks(&self) -> Result<Vec<DiskInfo>, String> {
        let output = self.exec("df -P -B1 | tail -n +2").await?;
        let mut disks = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            let total_bytes = parts[1].parse::<f64>().unwrap_or(0.0);
            let avail_bytes = parts[3].parse::<f64>().unwrap_or(0.0);
            let used_bytes = (total_bytes - avail_bytes).max(0.0);

            let to_gb = |b: f64| b / 1024.0 / 1024.0 / 1024.0;
            let percent_free = if total_bytes > 0.0 {
                (avail_bytes / total_bytes) * 100.0
            } else {
                0.0
            };

            disks.push(DiskInfo {
                drive: parts[5].to_string(),
                total_gb: to_gb(total_bytes),
                free_gb: to_gb(avail_bytes),
                used_gb: to_gb(used_bytes),
                percent_free,
            });
        }
        Ok(disks)
    }

    async fn get_memory_info(&self) -> Result<MemoryInfo, String> {
        let raw = self.exec("cat /proc/meminfo").await?;
        let (total_mb, free_mb) = Self::parse_meminfo(&raw);
        Ok(MemoryInfo { total_mb, free_mb })
    }

    async fn execute_powershell(&self, _command: &str) -> Result<String, String> {
        Err("PowerShell execution not available for Linux sessions".to_string())
    }

    fn server_name(&self) -> &str {
        &self.server_name
    }

    async fn get_uptime_snapshot(&self) -> Result<UptimeSnapshot, String> {
        // Delegate to the struct method
        LinuxRemoteSession::get_uptime_snapshot(self).await
    }

    async fn get_net_adapters(&self) -> Result<Vec<NetAdapterInfo>, String> {
        // Delegate to the struct method
        LinuxRemoteSession::get_net_adapters(self).await
    }
}
