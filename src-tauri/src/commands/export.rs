//! CSV export commands.

use quickprobe::db;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use super::hosts::read_hosts_from_sqlite;
use super::types::*;

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub(crate) async fn export_hosts_csv(destination: String) -> Result<String, String> {
    let dest_path = PathBuf::from(destination);

    tokio::task::spawn_blocking(move || {
        let hosts = read_hosts_from_sqlite()?;
        let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
        db::init_schema(&conn).map_err(|e| format!("Failed to initialize schema: {}", e))?;

        // Load all health snapshots
        let snapshots = db::load_all_health_snapshots(&conn)
            .map_err(|e| format!("Failed to load health snapshots: {}", e))?;

        // Create a map of server_name -> (health_json, timestamp)
        let mut health_map = std::collections::HashMap::new();
        for (name, json, timestamp) in snapshots {
            health_map.insert(name.to_uppercase(), (json, timestamp));
        }

        let mut writer = BufWriter::new(
            fs::File::create(&dest_path)
                .map_err(|e| format!("Failed to create CSV file: {}", e))?,
        );

        // Write CSV header with comprehensive health fields
        writeln!(writer, "server_name,notes,group_name,os_type,monitored_services,last_probed_at,hostname,os_version,build_number,product_type,install_date,location,ipv4_addresses,ipv6_addresses,subnet_masks,gateways,dns_servers,network_adapters,total_memory_gb,used_memory_gb,memory_used_percent,cpu_load_percent,uptime_hours,uptime_display,last_boot_time,process_count,ping_ok,tcp_ports_status,total_disks,disk_details,disk_alerts,service_status,stopped_services,service_alerts_count,high_cpu_processes,reboot_pending,reboot_signals,recent_errors_count,winrm_issue")
            .map_err(|e| format!("Failed to write CSV header: {}", e))?;

        // Write each host as a CSV row
        for host in hosts {
            let server_name = escape_csv_field(&host.name);
            let notes = escape_csv_field(&host.notes.unwrap_or_default());
            let group_name = escape_csv_field(&host.group.unwrap_or_default());
            let os_type = escape_csv_field(&host.os_type.unwrap_or_default());
            let monitored_services = if let Some(svcs) = host.services {
                escape_csv_field(&svcs.join("; "))
            } else {
                String::from("")
            };

            // Extract comprehensive health data if available
            let fields = if let Some((health_json, timestamp)) =
                health_map.get(&host.name.to_uppercase())
            {
                extract_health_fields_comprehensive(health_json, timestamp)
            } else {
                CsvHealthFields::default()
            };

            writeln!(writer, "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                server_name, notes, group_name, os_type, monitored_services,
                escape_csv_field(&fields.last_probed_at),
                escape_csv_field(&fields.hostname),
                escape_csv_field(&fields.os_version),
                escape_csv_field(&fields.build_number),
                escape_csv_field(&fields.product_type),
                escape_csv_field(&fields.install_date),
                escape_csv_field(&fields.location),
                escape_csv_field(&fields.ipv4_addresses),
                escape_csv_field(&fields.ipv6_addresses),
                escape_csv_field(&fields.subnet_masks),
                escape_csv_field(&fields.gateways),
                escape_csv_field(&fields.dns_servers),
                escape_csv_field(&fields.network_adapters),
                escape_csv_field(&fields.total_memory_gb),
                escape_csv_field(&fields.used_memory_gb),
                escape_csv_field(&fields.memory_used_percent),
                escape_csv_field(&fields.cpu_load_percent),
                escape_csv_field(&fields.uptime_hours),
                escape_csv_field(&fields.uptime_display),
                escape_csv_field(&fields.last_boot_time),
                escape_csv_field(&fields.process_count),
                escape_csv_field(&fields.ping_ok),
                escape_csv_field(&fields.tcp_ports_status),
                escape_csv_field(&fields.total_disks),
                escape_csv_field(&fields.disk_details),
                escape_csv_field(&fields.disk_alerts),
                escape_csv_field(&fields.service_status),
                escape_csv_field(&fields.stopped_services),
                escape_csv_field(&fields.service_alerts_count),
                escape_csv_field(&fields.high_cpu_processes),
                escape_csv_field(&fields.reboot_pending),
                escape_csv_field(&fields.reboot_signals),
                escape_csv_field(&fields.recent_errors_count),
                escape_csv_field(&fields.winrm_issue)
            ).map_err(|e| format!("Failed to write CSV row: {}", e))?;
        }

        writer
            .flush()
            .map_err(|e| format!("Failed to flush CSV file: {}", e))?;

        Ok(dest_path.to_string_lossy().to_string())
    })
    .await
    .map_err(|e| format!("CSV export task failed: {}", e))?
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extracts structured health data fields from JSON for CSV export.
///
/// ## Purpose
///
/// Parses the health snapshot JSON (from `persist_health_snapshot`) and extracts
/// specific fields needed for CSV export via `export_hosts_csv`. This bridges the
/// JSON storage format with the tabular CSV format users request.
#[allow(dead_code)] // Kept for backward compatibility, superseded by extract_health_fields_comprehensive
#[allow(clippy::type_complexity)] // Complex tuple return type, but function is deprecated
pub(crate) fn extract_health_fields(
    health_json: &str,
    timestamp: &str,
) -> (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
) {
    let health: serde_json::Value = match serde_json::from_str(health_json) {
        Ok(v) => v,
        Err(_) => {
            return (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
        }
    };

    // Extract IP addresses from net_adapters
    let mut ipv4_addresses = Vec::new();
    let mut ipv6_addresses = Vec::new();
    if let Some(adapters) = health.get("net_adapters").and_then(|a| a.as_array()) {
        for adapter in adapters {
            if let Some(ipv4_arr) = adapter.get("ipv4").and_then(|a| a.as_array()) {
                for ip in ipv4_arr {
                    if let Some(ip_str) = ip.as_str() {
                        ipv4_addresses.push(ip_str.to_string());
                    }
                }
            }
            if let Some(ipv6_arr) = adapter.get("ipv6").and_then(|a| a.as_array()) {
                for ip in ipv6_arr {
                    if let Some(ip_str) = ip.as_str() {
                        ipv6_addresses.push(ip_str.to_string());
                    }
                }
            }
        }
    }

    // Extract OS info
    let os_version = health
        .get("os_info")
        .and_then(|o| o.get("os_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let build_number = health
        .get("os_info")
        .and_then(|o| o.get("build_number"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Extract memory info
    let total_memory_mb = health
        .get("total_memory_mb")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{:.2}", v))
        .unwrap_or_default();

    let used_memory_mb = health
        .get("used_memory_mb")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{:.2}", v))
        .unwrap_or_default();

    let memory_used_percent = health
        .get("memory_used_percent")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{:.2}", v))
        .unwrap_or_default();

    // Extract uptime info
    let uptime_hours = health
        .get("uptime")
        .and_then(|u| u.get("uptime_hours"))
        .and_then(|v| v.as_f64())
        .map(|v| format!("{:.2}", v))
        .unwrap_or_default();

    // Extract reachability info
    let ping_ok = health
        .get("reachability")
        .and_then(|r| r.get("ping_ok"))
        .and_then(|v| v.as_bool())
        .map(|v| if v { "true" } else { "false" })
        .unwrap_or("")
        .to_string();

    let tcp_ports_status = if let Some(ports) = health
        .get("reachability")
        .and_then(|r| r.get("tcp_ports"))
        .and_then(|p| p.as_array())
    {
        let port_statuses: Vec<String> = ports
            .iter()
            .filter_map(|p| {
                let port = p.get("port").and_then(|v| v.as_u64())?;
                let ok = p.get("ok").and_then(|v| v.as_bool())?;
                Some(format!("{}:{}", port, if ok { "ok" } else { "fail" }))
            })
            .collect();
        port_statuses.join(";")
    } else {
        String::new()
    };

    // Extract disk info
    let disk_count = health
        .get("total_disks")
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_default();

    let disk_alerts_count = health
        .get("disk_alerts")
        .and_then(|v| v.as_array())
        .map(|v| v.len().to_string())
        .unwrap_or_default();

    // Extract service alerts
    let service_alerts_count = health
        .get("service_alerts")
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_default();

    // Extract process count
    let process_count = health
        .get("process_count")
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_default();

    (
        timestamp.to_string(),
        ipv4_addresses.join(", "),
        ipv6_addresses.join(", "),
        os_version,
        build_number,
        total_memory_mb,
        used_memory_mb,
        memory_used_percent,
        uptime_hours,
        ping_ok,
        tcp_ports_status,
        disk_count,
        disk_alerts_count,
        service_alerts_count,
        process_count,
    )
}

/// Extract comprehensive health data for CSV export - all fields shown on host cards
pub(crate) fn extract_health_fields_comprehensive(
    health_json: &str,
    timestamp: &str,
) -> CsvHealthFields {
    let health: serde_json::Value = match serde_json::from_str(health_json) {
        Ok(v) => v,
        Err(_) => return CsvHealthFields::default(),
    };

    let mut fields = CsvHealthFields {
        last_probed_at: timestamp.to_string(),
        ..Default::default()
    };

    // OS Info
    if let Some(os_info) = health.get("os_info") {
        fields.hostname = os_info
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        fields.os_version = os_info
            .get("os_version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        fields.build_number = os_info
            .get("build_number")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        fields.product_type = os_info
            .get("product_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        fields.install_date = os_info
            .get("install_date")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    }

    // Location (stored in _location field)
    fields.location = health
        .get("_location")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Network adapters - extract all network info
    let mut ipv4_list = Vec::new();
    let mut ipv6_list = Vec::new();
    let mut subnet_list = Vec::new();
    let mut gateway_list = Vec::new();
    let mut dns_list = Vec::new();
    let mut adapter_names = Vec::new();

    if let Some(adapters) = health.get("net_adapters").and_then(|a| a.as_array()) {
        for adapter in adapters {
            // Adapter name/alias
            if let Some(alias) = adapter.get("alias").and_then(|v| v.as_str()) {
                if !alias.is_empty() {
                    adapter_names.push(alias.to_string());
                }
            } else if let Some(desc) = adapter.get("description").and_then(|v| v.as_str()) {
                if !desc.is_empty() {
                    adapter_names.push(desc.to_string());
                }
            }

            // IPv4 addresses
            if let Some(ipv4_arr) = adapter.get("ipv4").and_then(|a| a.as_array()) {
                for ip in ipv4_arr {
                    if let Some(ip_str) = ip.as_str() {
                        if !ip_str.is_empty() {
                            ipv4_list.push(ip_str.to_string());
                        }
                    }
                }
            }

            // IPv4 prefix/subnet masks
            if let Some(prefix_arr) = adapter.get("ipv4_prefix").and_then(|a| a.as_array()) {
                for prefix in prefix_arr {
                    let prefix_val = prefix
                        .as_u64()
                        .or_else(|| prefix.as_str().and_then(|s| s.parse().ok()));
                    if let Some(p) = prefix_val {
                        // Convert CIDR prefix to subnet mask
                        if p <= 32 {
                            let mask = if p == 0 { 0u32 } else { !0u32 << (32 - p) };
                            let subnet = format!(
                                "{}.{}.{}.{}",
                                (mask >> 24) & 255,
                                (mask >> 16) & 255,
                                (mask >> 8) & 255,
                                mask & 255
                            );
                            subnet_list.push(subnet);
                        }
                    }
                }
            }

            // IPv6 addresses
            if let Some(ipv6_arr) = adapter.get("ipv6").and_then(|a| a.as_array()) {
                for ip in ipv6_arr {
                    if let Some(ip_str) = ip.as_str() {
                        if !ip_str.is_empty() {
                            ipv6_list.push(ip_str.to_string());
                        }
                    }
                }
            }

            // Gateways
            if let Some(gw_arr) = adapter.get("gateway").and_then(|a| a.as_array()) {
                for gw in gw_arr {
                    if let Some(gw_str) = gw.as_str() {
                        if !gw_str.is_empty() && !gateway_list.contains(&gw_str.to_string()) {
                            gateway_list.push(gw_str.to_string());
                        }
                    }
                }
            }

            // DNS servers
            if let Some(dns_arr) = adapter.get("dns").and_then(|a| a.as_array()) {
                for dns in dns_arr {
                    if let Some(dns_str) = dns.as_str() {
                        if !dns_str.is_empty() && !dns_list.contains(&dns_str.to_string()) {
                            dns_list.push(dns_str.to_string());
                        }
                    }
                }
            }
        }
    }

    fields.ipv4_addresses = ipv4_list.join("; ");
    fields.ipv6_addresses = ipv6_list.join("; ");
    fields.subnet_masks = subnet_list.join("; ");
    fields.gateways = gateway_list.join("; ");
    fields.dns_servers = dns_list.join("; ");
    fields.network_adapters = adapter_names.join("; ");

    // Memory (convert MB to GB for readability)
    let total_mb = health
        .get("total_memory_mb")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let used_mb = health
        .get("used_memory_mb")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let mem_percent = health
        .get("memory_used_percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    if total_mb > 0.0 {
        fields.total_memory_gb = format!("{:.1}", total_mb / 1024.0);
    }
    if used_mb > 0.0 {
        fields.used_memory_gb = format!("{:.1}", used_mb / 1024.0);
    }
    if mem_percent > 0.0 {
        fields.memory_used_percent = format!("{:.1}%", mem_percent);
    }

    // Uptime and CPU
    if let Some(uptime) = health.get("uptime") {
        let uptime_hours = uptime
            .get("uptime_hours")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if uptime_hours > 0.0 {
            fields.uptime_hours = format!("{:.1}", uptime_hours);
            // Human-readable uptime
            let days = (uptime_hours / 24.0).floor() as u64;
            let hours = (uptime_hours % 24.0).floor() as u64;
            if days > 0 {
                fields.uptime_display = format!("{}d {}h", days, hours);
            } else {
                fields.uptime_display = format!("{}h", hours);
            }
        }

        let cpu = uptime
            .get("cpu_load_pct")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if cpu > 0.0 {
            fields.cpu_load_percent = format!("{:.0}%", cpu);
        }

        fields.last_boot_time = uptime
            .get("last_boot")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    }

    // Process count
    if let Some(pc) = health.get("process_count").and_then(|v| v.as_u64()) {
        fields.process_count = pc.to_string();
    }

    // Reachability
    if let Some(reach) = health.get("reachability") {
        fields.ping_ok = reach
            .get("ping_ok")
            .and_then(|v| v.as_bool())
            .map(|v| if v { "Yes" } else { "No" })
            .unwrap_or("")
            .to_string();

        if let Some(ports) = reach.get("tcp_ports").and_then(|p| p.as_array()) {
            let port_statuses: Vec<String> = ports
                .iter()
                .filter_map(|p| {
                    let port = p.get("port").and_then(|v| v.as_u64())?;
                    let ok = p.get("ok").and_then(|v| v.as_bool())?;
                    Some(format!("{}: {}", port, if ok { "OK" } else { "FAIL" }))
                })
                .collect();
            fields.tcp_ports_status = port_statuses.join("; ");
        }
    }

    // Disks
    if let Some(total) = health.get("total_disks").and_then(|v| v.as_u64()) {
        fields.total_disks = total.to_string();
    }

    if let Some(disks) = health.get("disks").and_then(|d| d.as_array()) {
        let disk_info: Vec<String> = disks
            .iter()
            .filter_map(|d| {
                let drive = d.get("drive").and_then(|v| v.as_str()).unwrap_or("?");
                let free_gb = d.get("free_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let total_gb = d.get("total_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let pct_free = d
                    .get("percent_free")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                if total_gb > 0.0 {
                    Some(format!(
                        "{}: {:.0}GB free of {:.0}GB ({:.0}% free)",
                        drive, free_gb, total_gb, pct_free
                    ))
                } else {
                    None
                }
            })
            .collect();
        fields.disk_details = disk_info.join("; ");
    }

    if let Some(alerts) = health.get("disk_alerts").and_then(|a| a.as_array()) {
        let alert_info: Vec<String> = alerts
            .iter()
            .map(|a| {
                let drive = a.get("drive").and_then(|v| v.as_str()).unwrap_or("?");
                let pct_free = a
                    .get("percent_free")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                format!("{}: {:.0}% free (LOW)", drive, pct_free)
            })
            .collect();
        fields.disk_alerts = alert_info.join("; ");
    }

    // Services
    if let Some(services) = health.get("service_status").and_then(|s| s.as_array()) {
        let svc_info: Vec<String> = services
            .iter()
            .filter_map(|s| {
                let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let status = s.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                // Skip NotFound services
                if status.to_lowercase() == "notfound" {
                    return None;
                }
                Some(format!("{}: {}", name, status))
            })
            .collect();
        fields.service_status = svc_info.join("; ");

        let stopped: Vec<String> = services
            .iter()
            .filter_map(|s| {
                let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let status = s
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_lowercase();
                if status != "running" && status != "notfound" {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect();
        fields.stopped_services = stopped.join("; ");
    }

    if let Some(alerts) = health.get("service_alerts").and_then(|v| v.as_u64()) {
        fields.service_alerts_count = alerts.to_string();
    }

    // High CPU processes
    if let Some(procs) = health.get("high_cpu_processes").and_then(|p| p.as_array()) {
        let threshold = health
            .get("high_cpu_threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(50.0);
        let proc_info: Vec<String> = procs
            .iter()
            .filter_map(|p| {
                let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let cpu = p.get("cpu_percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
                if cpu > threshold {
                    Some(format!("{} ({:.0}%)", name, cpu))
                } else {
                    None
                }
            })
            .take(5)
            .collect();
        fields.high_cpu_processes = proc_info.join("; ");
    }

    // Pending reboot
    if let Some(reboot) = health.get("pending_reboot") {
        let pending = reboot
            .get("pending")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        fields.reboot_pending = if pending { "Yes" } else { "No" }.to_string();

        if let Some(signals) = reboot.get("signals").and_then(|s| s.as_array()) {
            let signal_names: Vec<String> = signals
                .iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect();
            fields.reboot_signals = signal_names.join("; ");
        }
    }

    // Recent errors count
    if let Some(errors) = health.get("recent_errors").and_then(|e| e.as_array()) {
        fields.recent_errors_count = errors.len().to_string();
    }

    // WinRM issue (degraded probe indicator — bool in SystemHealthSummary)
    if let Some(issue) = health.get("winrm_issue").and_then(|v| v.as_bool()) {
        fields.winrm_issue = if issue { "Yes" } else { "No" }.to_string();
    }

    fields
}

pub(crate) fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}
