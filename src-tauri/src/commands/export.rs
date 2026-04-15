//! CSV export commands.

use quickprobe::core::SystemHealthSummary;
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

/// Extract comprehensive health data for CSV export — typed deserialization.
///
/// Deserializes the stored JSON into `SystemHealthSummary` (the same struct
/// produced by the health probe) so that field renames or type changes produce
/// compile errors instead of silent data loss.
pub(crate) fn extract_health_fields_comprehensive(
    health_json: &str,
    timestamp: &str,
) -> CsvHealthFields {
    let health: SystemHealthSummary = match serde_json::from_str(health_json) {
        Ok(v) => v,
        Err(_) => return CsvHealthFields::default(),
    };

    let mut fields = CsvHealthFields {
        last_probed_at: timestamp.to_string(),
        ..Default::default()
    };

    // OS Info
    fields.hostname = health.os_info.hostname.clone();
    fields.os_version = health.os_info.os_version.clone();
    fields.build_number = health.os_info.build_number.clone();
    fields.product_type = health.os_info.product_type.clone();
    fields.install_date = health.os_info.install_date.clone();

    // Location — injected by the frontend JS, not part of SystemHealthSummary.
    // Extract from raw JSON as a best-effort field.
    if let Ok(raw) = serde_json::from_str::<serde_json::Value>(health_json) {
        fields.location = raw
            .get("_location")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    }

    // Network adapters
    let mut ipv4_list = Vec::new();
    let mut ipv6_list = Vec::new();
    let mut subnet_list = Vec::new();
    let mut gateway_list = Vec::new();
    let mut dns_list = Vec::new();
    let mut adapter_names = Vec::new();

    if let Some(adapters) = &health.net_adapters {
        for adapter in adapters {
            if !adapter.alias.is_empty() {
                adapter_names.push(adapter.alias.clone());
            } else if !adapter.description.is_empty() {
                adapter_names.push(adapter.description.clone());
            }

            for ip in &adapter.ipv4 {
                if !ip.is_empty() {
                    ipv4_list.push(ip.clone());
                }
            }

            for prefix in &adapter.ipv4_prefix {
                if *prefix <= 32 {
                    let mask = if *prefix == 0 {
                        0u32
                    } else {
                        !0u32 << (32 - prefix)
                    };
                    subnet_list.push(format!(
                        "{}.{}.{}.{}",
                        (mask >> 24) & 255,
                        (mask >> 16) & 255,
                        (mask >> 8) & 255,
                        mask & 255
                    ));
                }
            }

            for ip in &adapter.ipv6 {
                if !ip.is_empty() {
                    ipv6_list.push(ip.clone());
                }
            }

            for gw in &adapter.gateway {
                if !gw.is_empty() && !gateway_list.contains(gw) {
                    gateway_list.push(gw.clone());
                }
            }

            for dns in &adapter.dns {
                if !dns.is_empty() && !dns_list.contains(dns) {
                    dns_list.push(dns.clone());
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
    if health.total_memory_mb > 0.0 {
        fields.total_memory_gb = format!("{:.1}", health.total_memory_mb / 1024.0);
    }
    if health.used_memory_mb > 0.0 {
        fields.used_memory_gb = format!("{:.1}", health.used_memory_mb / 1024.0);
    }
    if health.memory_used_percent > 0.0 {
        fields.memory_used_percent = format!("{:.1}%", health.memory_used_percent);
    }

    // Uptime and CPU
    if let Some(uptime) = &health.uptime {
        if uptime.uptime_hours > 0.0 {
            fields.uptime_hours = format!("{:.1}", uptime.uptime_hours);
            let days = (uptime.uptime_hours / 24.0).floor() as u64;
            let hours = (uptime.uptime_hours % 24.0).floor() as u64;
            fields.uptime_display = if days > 0 {
                format!("{}d {}h", days, hours)
            } else {
                format!("{}h", hours)
            };
        }

        if let Some(cpu) = uptime.cpu_load_pct {
            if cpu > 0.0 {
                fields.cpu_load_percent = format!("{:.0}%", cpu);
            }
        }

        fields.last_boot_time = uptime.last_boot.clone();
    }

    // Process count
    if health.process_count > 0 {
        fields.process_count = health.process_count.to_string();
    }

    // Reachability
    if let Some(reach) = &health.reachability {
        fields.ping_ok = if reach.ping_ok { "Yes" } else { "No" }.to_string();

        let port_statuses: Vec<String> = reach
            .tcp_ports
            .iter()
            .map(|p| format!("{}: {}", p.port, if p.ok { "OK" } else { "FAIL" }))
            .collect();
        fields.tcp_ports_status = port_statuses.join("; ");
    }

    // Disks
    if health.total_disks > 0 {
        fields.total_disks = health.total_disks.to_string();
    }

    let disk_info: Vec<String> = health
        .disks
        .iter()
        .filter(|d| d.total_gb > 0.0)
        .map(|d| {
            format!(
                "{}: {:.0}GB free of {:.0}GB ({:.0}% free)",
                d.drive, d.free_gb, d.total_gb, d.percent_free
            )
        })
        .collect();
    fields.disk_details = disk_info.join("; ");

    let alert_info: Vec<String> = health
        .disk_alerts
        .iter()
        .map(|a| format!("{}: {:.0}% free (LOW)", a.drive, a.percent_free))
        .collect();
    fields.disk_alerts = alert_info.join("; ");

    // Services
    let svc_info: Vec<String> = health
        .service_status
        .iter()
        .filter(|s| s.status.to_lowercase() != "notfound")
        .map(|s| format!("{}: {}", s.name, s.status))
        .collect();
    fields.service_status = svc_info.join("; ");

    let stopped: Vec<String> = health
        .service_status
        .iter()
        .filter(|s| {
            let status = s.status.to_lowercase();
            status != "running" && status != "notfound"
        })
        .map(|s| s.name.clone())
        .collect();
    fields.stopped_services = stopped.join("; ");

    if health.service_alerts > 0 {
        fields.service_alerts_count = health.service_alerts.to_string();
    }

    // High CPU processes
    let proc_info: Vec<String> = health
        .high_cpu_processes
        .iter()
        .filter(|p| p.cpu_percent > health.high_cpu_threshold)
        .take(5)
        .map(|p| format!("{} ({:.0}%)", p.name, p.cpu_percent))
        .collect();
    fields.high_cpu_processes = proc_info.join("; ");

    // Pending reboot
    if let Some(reboot) = &health.pending_reboot {
        fields.reboot_pending = if reboot.pending { "Yes" } else { "No" }.to_string();
        fields.reboot_signals = reboot.signals.join("; ");
    }

    // Recent errors count
    if let Some(errors) = &health.recent_errors {
        fields.recent_errors_count = errors.len().to_string();
    }

    // WinRM issue
    if health.winrm_issue {
        fields.winrm_issue = "Yes".to_string();
    } else {
        fields.winrm_issue = "No".to_string();
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
