#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod logger;
mod normalize;

use chrono::Utc;
use futures::future::join_all;
use quickprobe::constants::*;
use quickprobe::updater::{self, UpdateInfo};
use quickprobe::utils::ValidationError;
use quickprobe::{
    backup::{
        self, BackupPayload, HostBackupRow, ModeDetails, RuntimeModeInfo, APP_NAME, BACKUP_KV_KEYS,
        BACKUP_SCHEMA_VERSION,
    },
    core::session::{NetAdapterInfo, OsInfo},
    core::session::{ProcessInfo, RemoteSession, ServiceInfo},
    core::{system_health_probe, ReachabilitySummary, SystemHealthSummary, TcpProbeResult},
    db,
    models::{CredentialProfile, Credentials, SecureString, Username},
    platform::{
        LinuxRemoteSession, WindowsCredentialManager, WindowsRegistry, WindowsRemoteSession,
    },
    validate_credentials, CredentialStore,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufWriter, Read, Write};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{
    async_runtime,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_global_shortcut::GlobalShortcutExt;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use zip::unstable::write::FileOptionsExt;
use zip::{write::FileOptions, CompressionMethod, ZipArchive, ZipWriter};

/// Sanitize TCP port list ensuring uniqueness and valid range.
fn sanitize_tcp_ports(ports: &[u16]) -> Vec<u16> {
    let mut seen = std::collections::HashSet::new();
    let mut cleaned = Vec::new();
    for &p in ports {
        if p == 0 {
            continue;
        }
        if seen.insert(p) {
            cleaned.push(p);
        }
    }
    if cleaned.is_empty() {
        cleaned.extend_from_slice(DEFAULT_TCP_PORTS);
    }
    cleaned
}

use ldap3::{LdapConnAsync, Scope, SearchEntry};
use rusqlite::TransactionBehavior;
/// Basic app info for About window
#[derive(Debug, Serialize)]
struct AppInfoResponse {
    name: String,
    version: String,
}

/// Debug response for raw adapters
#[derive(Debug, Serialize)]
struct AdapterDebugResponse {
    raw: String,
    adapters: Option<Vec<quickprobe::core::session::NetAdapterInfo>>,
    parse_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginResponse {
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CredentialsCheckResponse {
    has_credentials: bool,
    username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct ServerInfo {
    name: String,
    notes: Option<String>,
    group: Option<String>,
    services: Option<Vec<String>>,
    os_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct HostUpdate {
    name: String,
    notes: Option<String>,
    group: Option<String>,
    services: Option<Vec<String>>,
    os_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct NormalizedHost {
    name: String,
    notes: String,
    group: String,
    os_type: String,
    services: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct AdComputer {
    fqdn: String,
    description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    found: usize,
    total: usize,
    created: usize,
    removed: usize,
}

/// Lightweight heartbeat status returned to the dashboard for high-frequency refreshes
#[derive(Debug, Serialize)]
struct QuickStatus {
    server_name: String,
    ping_ok: bool,
    winrm_ok: bool,
    winrm_error: Option<String>,
    reachability: Option<quickprobe::core::probes::ReachabilitySummary>,
    uptime_hours: Option<f64>,
    cpu_load_pct: Option<f64>,
    memory_used_percent: Option<f64>,
    total_memory_mb: Option<f64>,
    used_memory_mb: Option<f64>,
    process_count: Option<usize>,
    top_cpu_processes: Option<Vec<ProcessInfo>>,
    service_status: Option<Vec<ServiceInfo>>,
}

#[derive(Debug, Serialize)]
struct RestoreResponse {
    local_storage: serde_json::Value,
    hosts_written: bool,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct AppSettings {
    #[serde(default)]
    start_hidden: bool,
}

/// Get the path to the QuickProbe data directory in AppData
///
/// Returns %APPDATA%\QuickProbe on Windows, creating it if it doesn't exist.
fn get_app_data_dir() -> Result<PathBuf, String> {
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "APPDATA environment variable not found".to_string())?;

    let quickprobe_dir = PathBuf::from(app_data).join("QuickProbe");

    // Create directory if it doesn't exist
    if !quickprobe_dir.exists() {
        fs::create_dir_all(&quickprobe_dir)
            .map_err(|e| format!("Failed to create QuickProbe data directory: {}", e))?;
    }

    Ok(quickprobe_dir)
}

fn get_settings_path() -> Result<PathBuf, String> {
    let app_dir = get_app_data_dir()?;
    Ok(app_dir.join("settings.json"))
}

fn load_app_settings() -> Result<AppSettings, String> {
    let path = get_settings_path()?;
    if !path.exists() {
        return Ok(AppSettings::default());
    }

    let contents =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read settings: {}", e))?;
    let parsed: AppSettings =
        serde_json::from_str(&contents).map_err(|e| format!("Failed to parse settings: {}", e))?;
    Ok(parsed)
}

fn save_app_settings(settings: &AppSettings) -> Result<(), String> {
    let path = get_settings_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create settings directory: {}", e))?;
    }
    let contents = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("Failed to serialize settings: {}", e))?;
    fs::write(&path, contents).map_err(|e| format!("Failed to write settings: {}", e))?;
    Ok(())
}

/// Normalize a host string to an uppercase shortname (strip domain suffix)
fn normalize_host_name(raw: &str) -> Result<String, String> {
    normalize::normalize_server_name(raw)
}

fn current_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn server_info_to_updates(servers: Vec<ServerInfo>) -> Vec<HostUpdate> {
    servers
        .into_iter()
        .map(|s| HostUpdate {
            name: s.name,
            notes: s.notes,
            group: s.group,
            services: s.services,
            os_type: s.os_type,
        })
        .collect()
}

fn default_qp_settings_json() -> String {
    serde_json::json!({
        "probeTimeoutSeconds": 60,
        "infoTimeoutMs": 3500,
        "warningTimeoutMs": 4500,
        "errorTimeoutMs": 0,
        "locationMappings": [],
        "theme": "system"
    })
    .to_string()
}

fn kv_default_value(key: &str) -> Option<String> {
    match key {
        "qp_settings" => Some(default_qp_settings_json()),
        "qp_server_order" => Some("[]".to_string()),
        "qp_host_view_mode" => Some("cards".to_string()),
        "qp_hosts_changed" => None,
        _ => None,
    }
}

fn kv_get_value(key: &str) -> Result<Option<String>, String> {
    let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;
    let value = db::kv_get(&conn, KV_SCOPE_TYPE, KV_SCOPE_ID, key)
        .map_err(|e| format!("Failed to read kv value: {}", e))?;
    if value.is_some() {
        Ok(value)
    } else {
        Ok(kv_default_value(key))
    }
}

fn kv_set_value(key: &str, value: &str) -> Result<(), String> {
    let mut conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| format!("Failed to start kv transaction: {}", e))?;
    db::kv_set(&tx, KV_SCOPE_TYPE, KV_SCOPE_ID, key, value)
        .map_err(|e| format!("Failed to persist kv value: {}", e))?;
    tx.commit()
        .map_err(|e| format!("Failed to commit kv value: {}", e))?;
    Ok(())
}

fn bump_hosts_changed_flag() -> Result<(), String> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();
    kv_set_value("qp_hosts_changed", &now_ms)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct SettingsBundle {
    qp_settings: serde_json::Value,
    qp_server_order: serde_json::Value,
    qp_host_view_mode: serde_json::Value,
    qp_hosts_changed: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct SettingsSetPayload {
    qp_settings: serde_json::Value,
    qp_server_order: serde_json::Value,
    qp_host_view_mode: serde_json::Value,
    qp_hosts_changed: Option<serde_json::Value>,
}

fn default_settings_bundle() -> SettingsBundle {
    let qp_settings = serde_json::from_str(&default_qp_settings_json()).unwrap_or_else(|_| {
        // Mirrors UI defaults: ui/dashboard-all.html::defaultSettings and ui/options.html::defaultSettings.
        serde_json::json!({
            "probeTimeoutSeconds": 60,
            "infoTimeoutMs": 3500,
            "warningTimeoutMs": 4500,
            "errorTimeoutMs": 0,
            "locationMappings": [],
            "theme": "system"
        })
    });
    SettingsBundle {
        qp_settings,
        qp_server_order: serde_json::json!([]), // Matches dashboard parseServerOrder fallback.
        qp_host_view_mode: serde_json::json!("cards"), // Matches dashboard default hostViewMode.
        qp_hosts_changed: None,
    }
}

fn kv_value_or_default(conn: &rusqlite::Connection, key: &str) -> Result<Option<String>, String> {
    let value = db::kv_get(conn, KV_SCOPE_TYPE, KV_SCOPE_ID, key)
        .map_err(|e| format!("Failed to read kv value: {}", e))?;
    if value.is_some() {
        Ok(value)
    } else {
        Ok(kv_default_value(key))
    }
}

fn parse_kv_json(raw: Option<String>) -> Option<serde_json::Value> {
    raw.map(|val| serde_json::from_str(&val).unwrap_or(serde_json::Value::String(val)))
}

fn merge_settings_with_defaults(value: serde_json::Value) -> serde_json::Value {
    let defaults = default_settings_bundle().qp_settings;
    match (value, defaults) {
        (serde_json::Value::Object(provided), serde_json::Value::Object(default_map)) => {
            let mut merged = default_map;
            merged.extend(provided);
            serde_json::Value::Object(merged)
        }
        (serde_json::Value::String(s), defaults) => serde_json::from_str(&s)
            .ok()
            .map(merge_settings_with_defaults)
            .unwrap_or(defaults),
        (_, defaults) => defaults,
    }
}

fn settings_bundle_from_conn(conn: &rusqlite::Connection) -> Result<SettingsBundle, String> {
    let defaults = default_settings_bundle();
    let qp_settings_raw = parse_kv_json(kv_value_or_default(conn, "qp_settings")?)
        .unwrap_or_else(|| defaults.qp_settings.clone());
    let qp_settings = merge_settings_with_defaults(qp_settings_raw);
    let qp_server_order = parse_kv_json(kv_value_or_default(conn, "qp_server_order")?)
        .unwrap_or_else(|| defaults.qp_server_order.clone());
    let qp_host_view_mode = parse_kv_json(kv_value_or_default(conn, "qp_host_view_mode")?)
        .unwrap_or_else(|| defaults.qp_host_view_mode.clone());
    let qp_hosts_changed =
        parse_kv_json(kv_value_or_default(conn, "qp_hosts_changed")?).and_then(|val| {
            if val.is_null() {
                None
            } else {
                Some(match val {
                    serde_json::Value::String(_) => val,
                    other => serde_json::Value::String(other.to_string()),
                })
            }
        });

    Ok(SettingsBundle {
        qp_settings,
        qp_server_order,
        qp_host_view_mode,
        qp_hosts_changed,
    })
}

fn normalize_settings_object(value: serde_json::Value) -> serde_json::Value {
    merge_settings_with_defaults(value)
}

fn normalize_server_order(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => serde_json::Value::Array(items),
        serde_json::Value::String(s) => serde_json::from_str(&s)
            .ok()
            .filter(|v: &serde_json::Value| v.is_array())
            .unwrap_or_else(|| serde_json::json!([])),
        _ => serde_json::json!([]),
    }
}

fn normalize_host_view_mode(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            let lower = s.to_ascii_lowercase();
            if lower == "cards" || lower == "groups" {
                serde_json::Value::String(lower)
            } else {
                serde_json::json!("cards")
            }
        }
        serde_json::Value::Null => serde_json::json!("cards"),
        _ => serde_json::json!("cards"),
    }
}

fn normalize_hosts_changed(value: serde_json::Value) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::Null => None,
        other => Some(other),
    }
}

fn persist_settings_bundle(
    tx: &rusqlite::Transaction,
    bundle: &SettingsBundle,
) -> Result<(), String> {
    for (key, value) in [
        ("qp_settings", Some(bundle.qp_settings.clone())),
        ("qp_server_order", Some(bundle.qp_server_order.clone())),
        ("qp_host_view_mode", Some(bundle.qp_host_view_mode.clone())),
        ("qp_hosts_changed", bundle.qp_hosts_changed.clone()),
    ] {
        match value {
            Some(val) if !val.is_null() => {
                let serialized = match key {
                    "qp_settings" | "qp_server_order" => serde_json::to_string(&val)
                        .map_err(|e| format!("Failed to serialize {}: {}", key, e))?,
                    _ => val
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| val.to_string()),
                };
                db::kv_set(tx, KV_SCOPE_TYPE, KV_SCOPE_ID, key, &serialized)
                    .map_err(|e| format!("Failed to persist {}: {}", key, e))?;
            }
            _ => {
                tx.execute(
                    "DELETE FROM kv WHERE scope_type = ?1 AND scope_id = ?2 AND key = ?3",
                    (KV_SCOPE_TYPE, KV_SCOPE_ID, key),
                )
                .map_err(|e| format!("Failed to clear {}: {}", key, e))?;
            }
        }
    }
    Ok(())
}

fn runtime_mode_info_local() -> RuntimeModeInfo {
    let db_path = db::get_db_path()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    RuntimeModeInfo {
        mode: "local".to_string(),
        details: ModeDetails { db_path },
        config_source: "local".to_string(),
    }
}
#[derive(Serialize)]
struct LocalStoreStatus {
    mode: String,
    db_path: Option<String>,
    hosts_count: Option<u64>,
}

#[tauri::command]
fn debug_local_store_status() -> Result<LocalStoreStatus, String> {
    let info = runtime_mode_info_local();
    let db_path = info.details.db_path.clone();
    let conn = db::open_db().map_err(|e| format!("Failed to open db: {}", e))?;
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM hosts", [], |row| row.get(0))
        .map_err(|e| format!("Failed to count hosts: {}", e))?;
    let hosts_count = Some(count);

    Ok(LocalStoreStatus {
        mode: info.mode.clone(),
        db_path,
        hosts_count,
    })
}

fn compute_runtime_mode_info() -> Result<RuntimeModeInfo, String> {
    Ok(runtime_mode_info_local())
}

#[tauri::command]
fn get_runtime_mode_info() -> Result<RuntimeModeInfo, String> {
    compute_runtime_mode_info()
}

fn hosts_for_backup() -> Result<Vec<HostBackupRow>, String> {
    let updates = server_info_to_updates(read_hosts_from_sqlite()?);
    let normalized = normalize_hosts_for_write(&updates)?;
    let mut rows: Vec<HostBackupRow> = normalized
        .into_iter()
        .map(|row| HostBackupRow {
            server_name: row.name,
            notes: if row.notes.is_empty() {
                None
            } else {
                Some(row.notes)
            },
            group: if row.group.is_empty() {
                None
            } else {
                Some(row.group)
            },
            os_type: row.os_type,
            services: if row.services.is_empty() {
                None
            } else {
                Some(row.services)
            },
        })
        .collect();
    rows.sort_by(|a, b| a.server_name.cmp(&b.server_name));
    Ok(rows)
}

fn kv_for_backup() -> Result<std::collections::BTreeMap<String, Option<String>>, String> {
    let mut kv_map = std::collections::BTreeMap::new();
    for key in BACKUP_KV_KEYS {
        kv_map.insert((*key).to_string(), kv_get_value(key)?);
    }
    Ok(kv_map)
}

fn build_backup_payload() -> Result<BackupPayload, String> {
    let mode = runtime_mode_info_local();
    let hosts = hosts_for_backup()?;
    let kv = kv_for_backup()?;

    Ok(backup::build_backup_payload(
        hosts,
        kv,
        mode,
        env!("CARGO_PKG_VERSION"),
    ))
}

fn write_encrypted_backup(
    destination: &Path,
    password: &str,
    payload: &BackupPayload,
) -> Result<String, String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create backup directory: {}", e))?;
    }

    let file =
        fs::File::create(destination).map_err(|e| format!("Failed to create backup: {}", e))?;
    let writer = BufWriter::new(file);
    let mut zip = ZipWriter::new(writer);

    // TODO: Upgrade to AES-256 encryption for better security
    // Current zip crate version (0.6.6) doesn't expose AES encryption API for writing.
    // Consider upgrading to zip 0.7+ or using a different encryption method.
    // For now, using deprecated ZIP encryption which provides basic password protection.
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .with_deprecated_encryption(password.as_bytes());

    let manifest = backup::build_backup_manifest(env!("CARGO_PKG_VERSION"), current_epoch_ms());

    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
    zip.start_file("manifest.json", options)
        .map_err(|e| format!("Failed to add manifest: {}", e))?;
    zip.write_all(&manifest_json)
        .map_err(|e| format!("Failed to write manifest: {}", e))?;

    let payload_json = serde_json::to_vec_pretty(&payload)
        .map_err(|e| format!("Failed to serialize backup payload: {}", e))?;
    zip.start_file("quickprobe-backup.json", options)
        .map_err(|e| format!("Failed to add backup payload: {}", e))?;
    zip.write_all(&payload_json)
        .map_err(|e| format!("Failed to write backup payload: {}", e))?;

    let mut writer = zip
        .finish()
        .map_err(|e| format!("Failed to finalize backup: {}", e))?;
    writer
        .flush()
        .map_err(|e| format!("Failed to flush backup: {}", e))?;

    Ok(destination.to_string_lossy().to_string())
}

fn try_read_zip_entry(
    archive: &mut ZipArchive<fs::File>,
    name: &str,
    password: &str,
) -> Result<Option<String>, String> {
    let file = match archive.by_name_decrypt(name, password.as_bytes()) {
        Ok(inner) => inner,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(e) => {
            return Err(format!(
                "Failed to open {}: {}. This may indicate an invalid password or corrupted file.",
                name, e
            ));
        }
    };
    let mut file = file.map_err(|e| {
        // Decryption errors often indicate wrong password
        format!(
            "Failed to decrypt {}: {}. Please verify your password is correct.",
            name, e
        )
    })?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Failed to read {}: {}", name, e))?;
    Ok(Some(contents))
}

fn read_backup_payload(path: &Path, password: &str) -> Result<Option<BackupPayload>, String> {
    let file = fs::File::open(path).map_err(|e| format!("Failed to open backup: {}", e))?;
    let mut archive =
        ZipArchive::new(file).map_err(|e| format!("Failed to read backup archive: {}", e))?;
    let contents = match try_read_zip_entry(&mut archive, "quickprobe-backup.json", password)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let payload: BackupPayload = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse backup payload: {}", e))?;
    Ok(Some(payload))
}

fn backup_destination_with_suffix(suffix: &str) -> Result<PathBuf, String> {
    let dir = get_app_data_dir()?;
    let timestamp = timestamp_suffix();
    let name = format!("QuickProbe-{}-{}.zip", suffix, timestamp);
    Ok(dir.join(name))
}

fn export_backup(destination: &Path, password: &str) -> Result<String, String> {
    let payload = build_backup_payload()?;
    write_encrypted_backup(destination, password, &payload)
}

fn cleanup_old_pre_restore_backups(keep_count: usize) -> Result<(), String> {
    let dir = get_app_data_dir()?;

    let mut pre_restore_files: Vec<PathBuf> = match fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                let lower = name.to_lowercase();
                lower.starts_with("quickprobe-pre-restore-") && lower.ends_with(".zip")
            })
            .map(|e| e.path())
            .collect(),
        Err(e) => {
            logger::log_warn(&format!("Failed to read app data dir for cleanup: {}", e));
            return Ok(()); // Don't fail restore if cleanup fails
        }
    };

    if pre_restore_files.len() <= keep_count {
        return Ok(()); // Nothing to clean up
    }

    // Sort by filename (which contains timestamp) - oldest first
    pre_restore_files.sort();

    // Delete oldest files, keeping only the most recent keep_count
    let to_delete = pre_restore_files.len() - keep_count;
    let mut deleted = 0;
    for path in pre_restore_files.iter().take(to_delete) {
        match fs::remove_file(path) {
            Ok(_) => {
                deleted += 1;
                logger::log_debug(&format!(
                    "Deleted old pre-restore backup: {}",
                    path.display()
                ));
            }
            Err(e) => {
                logger::log_warn(&format!(
                    "Failed to delete old pre-restore backup {}: {}",
                    path.display(),
                    e
                ));
            }
        }
    }

    if deleted > 0 {
        logger::log_info(&format!(
            "Cleaned up {} old pre-restore backup(s), kept {} most recent",
            deleted, keep_count
        ));
    }

    Ok(())
}

fn restore_to_sqlite(payload: &BackupPayload) -> Result<serde_json::Value, String> {
    let mut conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| format!("Failed to start restore transaction: {}", e))?;
    let now_ms = current_epoch_ms();
    backup::apply_backup_payload(
        &tx,
        payload,
        KV_SCOPE_TYPE,
        KV_SCOPE_ID,
        BACKUP_KV_KEYS,
        now_ms,
    )?;
    tx.commit()
        .map_err(|e| format!("Failed to commit restore: {}", e))?;

    let mut ls = serde_json::Map::new();
    for key in BACKUP_KV_KEYS {
        let value = kv_get_value(key)?;
        if let Some(val) = value {
            match serde_json::from_str(&val) {
                Ok(parsed) => {
                    ls.insert(key.to_string(), parsed);
                }
                Err(_) => {
                    ls.insert(key.to_string(), serde_json::Value::String(val));
                }
            }
        } else if *key == "qp_hosts_changed" {
            ls.insert(
                key.to_string(),
                serde_json::Value::String(now_ms.to_string()),
            );
        }
    }

    Ok(serde_json::Value::Object(ls))
}

fn timestamp_suffix() -> String {
    Utc::now().format("%Y%m%d-%H%M%S").to_string()
}

/// Validates password strength for backup/restore operations.
/// Requirements: minimum 8 characters for security
fn validate_backup_password(password: &str) -> Result<(), String> {
    const MIN_PASSWORD_LENGTH: usize = 8;

    let trimmed = password.trim();

    if trimmed.is_empty() {
        return Err("Password cannot be empty".to_string());
    }

    if trimmed.len() < MIN_PASSWORD_LENGTH {
        return Err(format!(
            "Password must be at least {} characters for security",
            MIN_PASSWORD_LENGTH
        ));
    }

    Ok(())
}

/// Checks if there's sufficient disk space for backup operations.
/// Returns error if available space is less than the estimated requirement.
///
/// Note: Currently performs basic validation only. Full disk space checking
/// would require additional dependencies (e.g., sysinfo crate).
fn check_disk_space_for_backup(destination: &Path, _estimated_size: u64) -> Result<(), String> {
    // Validate the destination path exists and is accessible
    let parent_dir = destination
        .parent()
        .ok_or_else(|| "Invalid backup destination path".to_string())?;

    // Basic check: verify parent directory is accessible
    #[cfg(unix)]
    {
        match fs::metadata(parent_dir) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Cannot access backup directory: {}", e)),
        }
    }

    #[cfg(windows)]
    {
        // Windows-specific check - verify directory exists
        match fs::metadata(parent_dir) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Cannot access backup directory: {}", e)),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        // On other platforms, just verify parent exists
        if parent_dir.exists() {
            Ok(())
        } else {
            Err("Backup directory does not exist".to_string())
        }
    }
}

/// Validates backup file size before loading it into memory.
///
/// Prevents loading extremely large malicious files by rejecting files
/// larger than MAX_BACKUP_FILE_SIZE (100 MB).
fn validate_backup_file_size(path: &Path) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|e| format!("Failed to read backup file metadata: {}", e))?;

    let file_size = metadata.len();

    if file_size > MAX_BACKUP_FILE_SIZE {
        return Err(format!(
            "Backup file too large ({} MB). Maximum allowed: {} MB. This may indicate a corrupted or malicious file.",
            file_size / (1024 * 1024),
            MAX_BACKUP_FILE_SIZE / (1024 * 1024)
        ));
    }

    if file_size == 0 {
        return Err("Backup file is empty or corrupted".to_string());
    }

    Ok(())
}

#[tauri::command]
async fn settings_get_all() -> Result<SettingsBundle, String> {
    let start = SystemTime::now();
    logger::log_debug("settings_get_all: START (local)");

    let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;
    let result = settings_bundle_from_conn(&conn);

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    match &result {
        Ok(_) => logger::log_info(&format!("settings_get_all: SUCCESS {}ms", elapsed_ms)),
        Err(e) => logger::log_error(&format!("settings_get_all: FAILED {}ms: {}", elapsed_ms, e)),
    }

    result
}

#[tauri::command]
async fn settings_set_all(payload: SettingsSetPayload) -> Result<SettingsBundle, String> {
    let start = SystemTime::now();
    logger::log_debug("settings_set_all: START (local)");

    let mut conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| format!("Failed to start settings transaction: {}", e))?;

    let mut bundle = settings_bundle_from_conn(&tx)?;
    bundle.qp_settings = normalize_settings_object(payload.qp_settings);
    bundle.qp_server_order = normalize_server_order(payload.qp_server_order);
    bundle.qp_host_view_mode = normalize_host_view_mode(payload.qp_host_view_mode);

    if let Some(hosts_changed) = payload.qp_hosts_changed {
        bundle.qp_hosts_changed = normalize_hosts_changed(hosts_changed);
    }

    persist_settings_bundle(&tx, &bundle)?;
    tx.commit()
        .map_err(|e| format!("Failed to commit settings transaction: {}", e))?;

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    logger::log_info(&format!("settings_set_all: SUCCESS {}ms", elapsed_ms));

    Ok(bundle)
}

fn dashboard_cache_path() -> Result<PathBuf, String> {
    let dir = get_app_data_dir()?;
    let cache_dir = dir.join("cache");
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create cache directory: {}", e))?;
    Ok(cache_dir.join("dashboard-cache.json"))
}

#[tauri::command]
fn cache_get_dashboard() -> Result<Option<serde_json::Value>, String> {
    let start = SystemTime::now();
    logger::log_debug("cache_get_dashboard: START");

    let path = dashboard_cache_path()?;
    if !path.exists() {
        logger::log_debug("cache_get_dashboard: no cache file");
        return Ok(None);
    }

    let contents =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read dashboard cache: {}", e))?;
    let parsed: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse dashboard cache: {}", e))?;

    // Extract cache metadata for logging
    let servers_count = parsed
        .get("serversData")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);
    let cached_at = parsed
        .get("cachedAt")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let age_ms = if let Ok(metadata) = fs::metadata(&path) {
        if let Ok(modified) = metadata.modified() {
            SystemTime::now()
                .duration_since(modified)
                .ok()
                .map(|d| d.as_millis())
        } else {
            None
        }
    } else {
        None
    };

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    logger::log_info(&format!(
        "cache_get_dashboard: SUCCESS {}ms age={} servers={} cachedAt={}",
        elapsed_ms,
        age_ms
            .map(|a| format!("{}ms", a))
            .unwrap_or_else(|| "unknown".to_string()),
        servers_count,
        cached_at
    ));

    Ok(Some(parsed))
}

#[tauri::command]
fn cache_set_dashboard(payload: serde_json::Value) -> Result<(), String> {
    let start = SystemTime::now();

    // Extract metadata for logging
    let servers_count = payload
        .get("serversData")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);

    // Reduced logging - cache writes happen frequently during heartbeat
    let path = dashboard_cache_path()?;
    let result = fs::write(
        &path,
        serde_json::to_string_pretty(&payload)
            .map_err(|e| format!("Failed to serialize dashboard cache: {}", e))?,
    )
    .map_err(|e| format!("Failed to write dashboard cache: {}", e));

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    // Only log if slow (>100ms) or error
    if let Err(e) = &result {
        logger::log_error(&format!(
            "cache_set_dashboard: FAILED {}ms: {}",
            elapsed_ms, e
        ));
    } else if elapsed_ms > 100 {
        logger::log_warn(&format!(
            "cache_set_dashboard: slow write {}ms servers={}",
            elapsed_ms, servers_count
        ));
    }

    result
}

#[tauri::command]
async fn persist_health_snapshot(
    server_name: String,
    health_data: serde_json::Value,
) -> Result<(), String> {
    let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize schema: {}", e))?;

    let json_str = serde_json::to_string(&health_data)
        .map_err(|e| format!("Failed to serialize health data: {}", e))?;

    db::save_health_snapshot(&conn, &server_name, &json_str)
        .map_err(|e| format!("Failed to save health snapshot: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn load_health_snapshots() -> Result<serde_json::Value, String> {
    let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize schema: {}", e))?;

    let snapshots = db::load_all_health_snapshots(&conn)
        .map_err(|e| format!("Failed to load health snapshots: {}", e))?;

    let result: Vec<serde_json::Value> = snapshots
        .iter()
        .filter_map(|(name, json, timestamp)| {
            serde_json::from_str::<serde_json::Value>(json)
                .ok()
                .map(|data| {
                    serde_json::json!({
                        "server_name": name,
                        "data": data,
                        "last_probed_at": timestamp
                    })
                })
        })
        .collect();

    Ok(serde_json::json!(result))
}

async fn run_bounded_credential_validation(
    credentials: &Credentials,
    op_label: &str,
) -> Result<(), String> {
    match timeout(
        Duration::from_secs(CREDENTIAL_VALIDATION_TIMEOUT_SECS),
        validate_credentials(credentials),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(ValidationError::InvalidCredentials)) => Err("Invalid credentials".to_string()),
        Ok(Err(e)) => Err(format!(
            "Credential validation failed ({}): {}",
            op_label, e
        )),
        Err(_) => Err("Credential validation timed out".to_string()),
    }
}

/// Login command - validates credentials and saves to Windows Credential Manager
#[tauri::command]
async fn login(username: String, password: String) -> Result<LoginResponse, String> {
    // Parse username
    let username = match Username::new(username) {
        Ok(u) => u,
        Err(e) => {
            return Ok(LoginResponse {
                success: false,
                error: Some(format!("Invalid username: {}", e)),
            });
        }
    };

    // Create credentials
    let credentials = Credentials::new(username.clone(), SecureString::new(password));

    // Validate credentials
    match run_bounded_credential_validation(&credentials, "login").await {
        Ok(_) => {
            // Save credentials
            let credential_store = WindowsCredentialManager::new();
            let profile = CredentialProfile::default();

            if let Err(e) = credential_store.store(&profile, &credentials).await {
                return Ok(LoginResponse {
                    success: false,
                    error: Some(format!("Failed to save credentials: {}", e)),
                });
            }

            Ok(LoginResponse {
                success: true,
                error: None,
            })
        }
        Err(e) => Ok(LoginResponse {
            success: false,
            error: Some(e.to_string()),
        }),
    }
}

/// Logout command - deletes credentials from Windows Credential Manager
#[tauri::command]
async fn logout(app: tauri::AppHandle) -> Result<(), String> {
    let credential_store = WindowsCredentialManager::new();
    let profile = CredentialProfile::default();

    credential_store
        .delete(&profile)
        .await
        .map_err(|e| format!("Failed to delete credentials: {}", e))?;

    // Note: In Tauri 2.x, tray menu item state management requires different approach
    // The options menu enable/disable is handled via the menu builder in setup
    // For now, this is a no-op as we rebuild tray on login state changes
    let _ = &app; // Suppress unused warning

    Ok(())
}

#[allow(dead_code)]
fn has_saved_credentials_sync() -> Result<bool, String> {
    async_runtime::block_on(async {
        let credential_store = WindowsCredentialManager::new();
        let profile = CredentialProfile::default();

        match credential_store.retrieve(&profile).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(format!("Failed to check credentials: {}", e)),
        }
    })
}

/// Check for saved credentials
#[tauri::command]
async fn check_saved_credentials() -> Result<CredentialsCheckResponse, String> {
    let credential_store = WindowsCredentialManager::new();
    let profile = CredentialProfile::default();

    match credential_store.retrieve(&profile).await {
        Ok(Some(credentials)) => Ok(CredentialsCheckResponse {
            has_credentials: true,
            username: Some(credentials.username().as_str().to_string()),
        }),
        Ok(None) => Ok(CredentialsCheckResponse {
            has_credentials: false,
            username: None,
        }),
        Err(e) => Err(format!("Failed to check credentials: {}", e)),
    }
}

/// Auto-login using saved credentials without exposing passwords to the UI
#[tauri::command]
async fn login_with_saved_credentials() -> Result<LoginResponse, String> {
    logger::log_info("login_with_saved_credentials: START");
    let credential_store = WindowsCredentialManager::new();
    let profile = CredentialProfile::default();

    let credentials = match credential_store.retrieve(&profile).await {
        Ok(Some(credentials)) => credentials,
        Ok(None) => {
            logger::log_warn("login_with_saved_credentials: No saved credentials found");
            return Ok(LoginResponse {
                success: false,
                error: Some("No saved credentials found".to_string()),
            });
        }
        Err(e) => {
            logger::log_error(&format!(
                "login_with_saved_credentials: Failed to retrieve credentials: {}",
                e
            ));
            return Err(format!("Failed to retrieve credentials: {}", e));
        }
    };

    let username = credentials.username().as_str();
    logger::log_info(&format!(
        "login_with_saved_credentials: Validating credentials for user: {}",
        username
    ));

    match run_bounded_credential_validation(&credentials, "login_with_saved_credentials").await {
        Ok(_) => {
            logger::log_info(&format!(
                "login_with_saved_credentials: SUCCESS for user: {}",
                username
            ));
            Ok(LoginResponse {
                success: true,
                error: None,
            })
        }
        Err(e) => {
            logger::log_error(&format!(
                "login_with_saved_credentials: FAILED for user: {} - {}",
                username, e
            ));
            Ok(LoginResponse {
                success: false,
                error: Some(e.to_string()),
            })
        }
    }
}

/// Get application info for About window
#[tauri::command]
async fn get_app_info() -> Result<AppInfoResponse, String> {
    Ok(AppInfoResponse {
        name: "QuickProbe".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

fn check_autostart_state() -> Result<bool, String> {
    let registry = WindowsRegistry::new();
    registry
        .value_exists(REGISTRY_RUN_KEY, APP_NAME)
        .map_err(|e| format!("Failed to read autostart setting: {}", e))
}

fn enable_autostart() -> Result<(), String> {
    let exe_path =
        std::env::current_exe().map_err(|e| format!("Failed to resolve executable path: {}", e))?;
    let exe_path_str = exe_path.to_string_lossy().to_string();

    let registry = WindowsRegistry::new();
    registry
        .write_string(REGISTRY_RUN_KEY, APP_NAME, &exe_path_str)
        .map_err(|e| format!("Failed to enable autostart: {}", e))
}

fn disable_autostart() -> Result<(), String> {
    let registry = WindowsRegistry::new();
    registry
        .delete_value(REGISTRY_RUN_KEY, APP_NAME)
        .map_err(|e| format!("Failed to disable autostart: {}", e))
}

/// Checks whether QuickProbe is configured to start automatically when the user signs in.
#[tauri::command]
fn check_autostart() -> Result<bool, String> {
    check_autostart_state()
}

/// Toggles the Windows autostart setting and returns the new state.
#[tauri::command]
fn toggle_autostart() -> Result<bool, String> {
    let currently_enabled = check_autostart_state()?;

    if currently_enabled {
        disable_autostart()?;
        Ok(false)
    } else {
        enable_autostart()?;
        Ok(true)
    }
}

/// Read the "start hidden" preference from settings.json (default: false).
#[tauri::command]
fn get_start_hidden_setting() -> Result<bool, String> {
    let settings = load_app_settings().unwrap_or_default();
    Ok(settings.start_hidden)
}

#[derive(Debug, Deserialize)]
struct StartHiddenArgs {
    #[serde(alias = "startHidden", alias = "start_hidden")]
    start_hidden: bool,
}

/// Persist the "start hidden" preference to settings.json.
#[tauri::command]
fn set_start_hidden_setting(args: StartHiddenArgs) -> Result<bool, String> {
    let mut settings = load_app_settings().unwrap_or_default();
    settings.start_hidden = args.start_hidden;
    save_app_settings(&settings)?;
    Ok(settings.start_hidden)
}

/// Enable the Options menu item in the system tray after successful login.
#[tauri::command]
fn enable_options_menu(app: tauri::AppHandle) -> Result<(), String> {
    // Note: In Tauri 2.x, tray menu item state management requires different approach
    // Menu items are managed via the Menu API and stored references
    // For now, this is a no-op - the options menu is always enabled
    let _ = &app; // Suppress unused warning
    Ok(())
}

#[tauri::command]
async fn export_backup_encrypted(destination: String, password: String) -> Result<String, String> {
    let dest_path = PathBuf::from(destination);
    let password = password.trim().to_string();

    // Validate password strength
    validate_backup_password(&password)?;

    tokio::task::spawn_blocking(move || {
        logger::log_info(&format!(
            "Starting backup export to: {}",
            dest_path.display()
        ));

        // Estimate backup size (rough estimate based on database size)
        let estimated_size = 1024 * 1024; // Default 1MB estimate

        // Check disk space before creating backup
        if let Err(e) = check_disk_space_for_backup(&dest_path, estimated_size) {
            logger::log_warn(&format!("Disk space check warning: {}", e));
            // Continue anyway - this is just a warning
        }

        let result = export_backup(&dest_path, &password);

        match &result {
            Ok(path) => logger::log_info(&format!("Backup export successful: {}", path)),
            Err(e) => logger::log_error(&format!("Backup export failed: {}", e)),
        }

        result
    })
    .await
    .map_err(|e| format!("Backup task failed: {}", e))?
}

#[tauri::command]
async fn import_backup_encrypted(
    source: String,
    password: String,
) -> Result<RestoreResponse, String> {
    let path = PathBuf::from(source);
    let password = password.trim().to_string();

    // Validate password strength
    validate_backup_password(&password)?;

    tokio::task::spawn_blocking(move || {
        logger::log_info(&format!(
            "Starting backup restore from: {}",
            path.display()
        ));

        // Validate backup file size before processing
        validate_backup_file_size(&path)?;

        // Read and validate backup payload
        let payload = read_backup_payload(&path, &password)?.ok_or_else(|| {
            "Backup file does not contain a valid quickprobe-backup.json file. The file may be corrupted or not a QuickProbe backup.".to_string()
        })?;

        // Validate schema version
        if payload.schema_version != BACKUP_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported backup schema version {}. This backup was created with a different version of QuickProbe and cannot be restored.",
                payload.schema_version
            ));
        }

        logger::log_info("Backup file validated successfully");

        // Create pre-restore backup before making any changes
        logger::log_info("Creating pre-restore backup...");
        let pre_restore_path = backup_destination_with_suffix("pre-restore")?;
        export_backup(&pre_restore_path, &password).map_err(|e| {
            format!(
                "Failed to create pre-restore backup. Restore aborted to prevent data loss: {}",
                e
            )
        })?;
        logger::log_info(&format!(
            "Pre-restore backup created: {}",
            pre_restore_path.display()
        ));

        // Clean up old pre-restore backups (keep 5 most recent)
        if let Err(e) = cleanup_old_pre_restore_backups(5) {
            logger::log_warn(&format!("Failed to cleanup old pre-restore backups: {}", e));
            // Don't fail the restore if cleanup fails
        }

        // Perform the restore
        logger::log_info("Restoring data to database...");
        let local_storage = restore_to_sqlite(&payload)?;
        logger::log_info("Backup restore completed successfully");

        Ok(RestoreResponse {
            local_storage,
            hosts_written: true,
        })
    })
    .await
    .map_err(|e| format!("Restore task failed: {}", e))?
}

#[tauri::command]
async fn export_hosts_csv(destination: String) -> Result<String, String> {
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
                .map_err(|e| format!("Failed to create CSV file: {}", e))?
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
            let fields = if let Some((health_json, timestamp)) = health_map.get(&host.name.to_uppercase()) {
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

        writer.flush()
            .map_err(|e| format!("Failed to flush CSV file: {}", e))?;

        Ok(dest_path.to_string_lossy().to_string())
    })
    .await
    .map_err(|e| format!("CSV export task failed: {}", e))?
}

/// Extracts structured health data fields from JSON for CSV export.
///
/// ## Purpose
///
/// Parses the health snapshot JSON (from `persist_health_snapshot`) and extracts
/// specific fields needed for CSV export via `export_hosts_csv`. This bridges the
/// JSON storage format with the tabular CSV format users request.
///
/// ## Extracted Fields (15 total)
///
/// 1. **timestamp**: When health check was performed
/// 2. **ipv4_addresses**: Comma-separated list (e.g., "10.0.0.1, 192.168.1.5")
/// 3. **ipv6_addresses**: Comma-separated list
/// 4. **os_version**: e.g., "Microsoft Windows Server 2019 Standard"
/// 5. **build_number**: e.g., "10.0.17763"
/// 6. **total_memory_mb**: Formatted to 2 decimal places
/// 7. **used_memory_mb**: Formatted to 2 decimal places
/// 8. **memory_used_percent**: Formatted to 2 decimal places
/// 9. **uptime_hours**: Formatted to 2 decimal places
/// 10. **ping_ok**: "true" or "false" string
/// 11. **tcp_ports_status**: Semicolon-separated (e.g., "3389:ok;5985:fail")
/// 12. **disk_count**: Total disks found
/// 13. **disk_alerts_count**: Number of low-space alerts
/// 14. **service_alerts_count**: Number of stopped critical services
/// 15. **process_count**: Total processes running
///
/// ## Error Handling
///
/// - **Invalid JSON**: Returns 15 empty strings (graceful degradation)
/// - **Missing fields**: Returns empty string for that field (no crash)
/// - **Type mismatches**: Uses `unwrap_or_default()` to provide safe fallback
///
/// ## Design Note
///
/// This function has a large 15-tuple return type because:
/// - It's only used by `export_hosts_csv` (single caller)
/// - Creating a struct would add complexity without benefit
/// - The tuple matches CSV column order directly
///
/// ## Future Improvement
///
/// Consider decomposing into smaller helper functions:
/// - `extract_network_info(json) -> (ipv4, ipv6)`
/// - `extract_os_info(json) -> (os_version, build_number)`
/// - `extract_memory_info(json) -> (total_mb, used_mb, percent)`
/// - etc.
///
/// This would improve testability and readability.
#[allow(dead_code)] // Kept for backward compatibility, superseded by extract_health_fields_comprehensive
#[allow(clippy::type_complexity)] // Complex tuple return type, but function is deprecated
fn extract_health_fields(
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

/// Comprehensive CSV health fields struct for clean export
#[derive(Default)]
struct CsvHealthFields {
    last_probed_at: String,
    hostname: String,
    os_version: String,
    build_number: String,
    product_type: String,
    install_date: String,
    location: String,
    ipv4_addresses: String,
    ipv6_addresses: String,
    subnet_masks: String,
    gateways: String,
    dns_servers: String,
    network_adapters: String,
    total_memory_gb: String,
    used_memory_gb: String,
    memory_used_percent: String,
    cpu_load_percent: String,
    uptime_hours: String,
    uptime_display: String,
    last_boot_time: String,
    process_count: String,
    ping_ok: String,
    tcp_ports_status: String,
    total_disks: String,
    disk_details: String,
    disk_alerts: String,
    service_status: String,
    stopped_services: String,
    service_alerts_count: String,
    high_cpu_processes: String,
    reboot_pending: String,
    reboot_signals: String,
    recent_errors_count: String,
    winrm_issue: String,
}

/// Extract comprehensive health data for CSV export - all fields shown on host cards
fn extract_health_fields_comprehensive(health_json: &str, timestamp: &str) -> CsvHealthFields {
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
                let drive = d
                    .get("drive_letter")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
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
                let drive = a
                    .get("drive_letter")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
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

    // WinRM issue (degraded probe indicator)
    if let Some(issue) = health.get("winrm_issue").and_then(|v| v.as_str()) {
        fields.winrm_issue = issue.to_string();
    }

    fields
}

fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Read hosts from SQLite (legacy CSV is migration-only)
#[allow(dead_code)] // Called from JavaScript via Tauri IPC
#[tauri::command]
async fn get_hosts() -> Result<Vec<ServerInfo>, String> {
    let start = SystemTime::now();
    // Removed START log - this is called many times per second during heartbeat

    let result = read_hosts_from_sqlite();

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    match &result {
        Ok(_hosts) => {
            // Only log if query is slow (>50ms) to reduce log spam
            if elapsed_ms > 50 {
                logger::log_warn(&format!("get_hosts: slow query {}ms", elapsed_ms));
            }
        }
        Err(e) => {
            logger::log_error(&format!("get_hosts: FAILED {}ms: {}", elapsed_ms, e));
        }
    }

    result
}

fn read_hosts_from_sqlite() -> Result<Vec<ServerInfo>, String> {
    let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;

    let mut stmt = conn
        .prepare(
            "SELECT server_name, notes, group_name, os_type, services FROM hosts ORDER BY rowid",
        )
        .map_err(|e| format!("Failed to prepare hosts query: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| format!("Failed to query hosts: {}", e))?;

    let mut servers = Vec::new();
    for row in rows {
        let (raw_name, raw_notes, raw_group, raw_os, raw_services) =
            row.map_err(|e| format!("Failed to read host row: {}", e))?;

        let name =
            normalize_host_name(&raw_name).map_err(|e| format!("Invalid host name: {}", e))?;

        let notes_trimmed = raw_notes.trim();
        let notes = if notes_trimmed.is_empty() {
            None
        } else {
            Some(notes_trimmed.to_string())
        };

        let group_trimmed = raw_group.trim();
        let group = if group_trimmed.is_empty() {
            None
        } else {
            Some(group_trimmed.to_string())
        };

        let os_type = normalize::normalize_os_type(Some(&raw_os));

        let services_list: Vec<String> = raw_services
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let services = if services_list.is_empty() {
            None
        } else {
            Some(services_list)
        };

        servers.push(ServerInfo {
            name,
            notes,
            group,
            services,
            os_type: Some(os_type),
        });
    }

    Ok(servers)
}

fn normalize_hosts_for_write(hosts: &[HostUpdate]) -> Result<Vec<NormalizedHost>, String> {
    let mut seen = std::collections::HashSet::new();
    let mut rows = Vec::with_capacity(hosts.len());

    for h in hosts {
        let normalized_name = normalize_host_name(&h.name)?;
        let name_key = normalized_name.to_lowercase();
        if !seen.insert(name_key) {
            return Err("Host names must be unique after normalization".to_string());
        }

        let services_joined = if let Some(raw_services) = h.services.as_ref() {
            normalize::normalize_services_list(raw_services)?
        } else {
            String::new()
        };

        let notes_clean = h.notes.clone().unwrap_or_default().trim().to_string();
        let box_clean = h.group.clone().unwrap_or_default().trim().to_string();
        let os_clean = normalize::normalize_os_type(h.os_type.as_deref());

        rows.push(NormalizedHost {
            name: normalized_name,
            notes: notes_clean,
            group: box_clean,
            os_type: os_clean,
            services: services_joined,
        });
    }

    Ok(rows)
}

fn write_hosts_sqlite(hosts: &[HostUpdate]) -> Result<(), String> {
    logger::log_debug(&format!(
        "write_hosts_sqlite: BEGIN transaction for {} host(s)",
        hosts.len()
    ));

    let rows = normalize_hosts_for_write(hosts)?;

    // Log any normalization changes
    for (original, normalized) in hosts.iter().zip(rows.iter()) {
        if original.name != normalized.name {
            logger::log_debug(&format!(
                "write_hosts_sqlite: normalized '{}' -> '{}'",
                original.name, normalized.name
            ));
        }
    }

    let mut conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| {
            logger::log_error(&format!("TX BEGIN failed: {}", e));
            format!("Failed to start transaction: {}", e)
        })?;

    logger::log_debug("write_hosts_sqlite: DELETE FROM hosts");
    tx.execute("DELETE FROM hosts", []).map_err(|e| {
        logger::log_error(&format!("DELETE failed: {}", e));
        format!("Failed to clear hosts: {}", e)
    })?;

    for row in &rows {
        tx.execute(
            "
            INSERT INTO hosts(server_name, notes, group_name, os_type, services)
            VALUES(?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(server_name) DO UPDATE SET
                notes = excluded.notes,
                group_name = excluded.group_name,
                os_type = excluded.os_type,
                services = excluded.services
            ",
            rusqlite::params![row.name, row.notes, row.group, row.os_type, row.services],
        )
        .map_err(|e| {
            logger::log_error(&format!("INSERT/UPDATE failed for '{}': {}", row.name, e));
            format!("Failed to persist host '{}': {}", row.name, e)
        })?;
    }

    logger::log_debug(&format!("write_hosts_sqlite: COMMIT ({} rows)", rows.len()));
    tx.commit().map_err(|e| {
        logger::log_error(&format!("TX COMMIT failed: {}", e));
        format!("Failed to commit hosts: {}", e)
    })?;

    // Clean up orphaned health snapshots for deleted hosts
    // This runs AFTER commit to ensure hosts table is consistent
    if rows.is_empty() {
        logger::log_debug("write_hosts_sqlite: Skipping health snapshot cleanup (no hosts)");
    } else {
        match db::cleanup_orphaned_health_snapshots(&conn) {
            Ok(deleted) if deleted > 0 => {
                logger::log_info(&format!(
                    "write_hosts_sqlite: Cleaned up {} orphaned health snapshot(s)",
                    deleted
                ));
            }
            Ok(_) => {
                logger::log_debug("write_hosts_sqlite: No orphaned health snapshots to clean up");
            }
            Err(e) => {
                logger::log_warn(&format!(
                    "write_hosts_sqlite: Failed to cleanup orphaned health snapshots: {}",
                    e
                ));
                // Don't fail the whole operation if cleanup fails
            }
        }
    }

    bump_hosts_changed_flag()?;
    logger::log_info(&format!(
        "write_hosts_sqlite: SUCCESS, {} host(s), qp_hosts_changed bumped",
        rows.len()
    ));
    Ok(())
}

fn persist_hosts(hosts: &[HostUpdate]) -> Result<(), String> {
    logger::log_debug(&format!("persist_hosts: {} host(s)", hosts.len()));
    write_hosts_sqlite(hosts)
}

fn split_domain_username(raw: &str) -> (String, String) {
    if let Some((domain, user)) = raw.split_once('\\') {
        if !domain.is_empty() && !user.is_empty() {
            return (domain.to_string(), user.to_string());
        }
    }

    if let Some((user, domain)) = raw.split_once('@') {
        if !user.is_empty() && !domain.is_empty() {
            return (domain.to_string(), user.to_string());
        }
    }

    (String::new(), raw.to_string())
}

/// Validate RDP parameters to prevent CRLF injection attacks
///
/// Checks for newlines, null bytes, path traversal, and invalid characters
/// that could be used to inject arbitrary RDP settings or execute malicious commands.
fn validate_rdp_parameter(value: &str, param_name: &str) -> Result<(), String> {
    // Check for CRLF injection attempts (CVE-class vulnerability)
    if value.contains('\r') || value.contains('\n') {
        return Err(format!(
            "Invalid {}: contains newline characters (potential injection attack)",
            param_name
        ));
    }

    // Check for null bytes
    if value.contains('\0') {
        return Err(format!("Invalid {}: contains null bytes", param_name));
    }

    // Check for excessive length (RDP fields have practical limits)
    if value.len() > 256 {
        return Err(format!(
            "Invalid {}: exceeds maximum length of 256 characters",
            param_name
        ));
    }

    // Hostname-specific validation
    if param_name == "hostname" {
        if value.is_empty() {
            return Err("Hostname cannot be empty".to_string());
        }

        // Check for path traversal attempts in hostname (could write to Startup folder)
        if value.contains("..") || value.contains('\\') || value.contains('/') {
            return Err("Invalid hostname: contains path separators or traversal sequences".to_string());
        }

        // Basic hostname validation: alphanumeric, dots, hyphens, colons (for ports)
        // This prevents injection of shell metacharacters
        if !value
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == ':')
        {
            return Err("Invalid hostname: contains invalid characters (only alphanumeric, dots, hyphens, and colons allowed)".to_string());
        }
    }

    Ok(())
}

/// Generates RDP file content (.rdp) with optimized settings for server management.
///
/// ## RDP Configuration
///
/// This generates a Windows Remote Desktop Protocol (.rdp) file with settings optimized for:
/// - **Server management**: Admin tasks, not general desktop use
/// - **Performance**: Compression enabled, visual effects minimized
/// - **Auto-reconnect**: Survives temporary network interruptions
/// - **Security**: Certificate warnings ignored (common for self-signed certs in labs)
///
/// ## Key Settings
///
/// - **Screen**: 1920x1080 windowed mode (screen mode id:i:2)
/// - **Authentication**: CredSSP enabled, prompts disabled (SSO when possible)
/// - **Redirection**: Printers, clipboard, smartcards (for convenience)
/// - **Performance**: Menu animations disabled, full window drag disabled, compression enabled
/// - **Reconnect**: Auto-reconnect enabled for transient network issues
///
/// ## Parameters
///
/// - `host`: Target hostname or IP (e.g., "server01.contoso.com" or "192.168.1.100")
/// - `username`: Username for login (without domain prefix)
/// - `domain`: Windows domain (can be empty for local accounts)
///
/// ## Security Notes
///
/// - **Password NOT embedded**: RDP file contains username only, password prompt on connect
/// - **Certificate validation disabled** (`cert ignore:i:1`): Accepts self-signed certs
///   - Rationale: Common in lab/dev environments, reduces friction
///   - Risk: Vulnerable to MITM if untrusted network
/// - **Credentials prompt disabled** (`prompt for credentials:i:0`): Uses SSO when available
///   - Falls back to Windows Credential Manager if available
///   - Prompts if no stored credentials found
///
/// ## Returns
///
/// RDP file content as string (ready to write to .rdp file with CRLF line endings).
fn build_rdp_content(host: &str, username: &str, domain: &str) -> String {
    let user_field = if domain.is_empty() {
        username.to_string()
    } else {
        format!("{}\\{}", domain, username)
    };

    format!(
        concat!(
            "screen mode id:i:2\r\n",
            "desktopwidth:i:1920\r\n",
            "desktopheight:i:1080\r\n",
            "session bpp:i:32\r\n",
            "full address:s:{host}\r\n",
            "compression:i:1\r\n",
            "keyboardhook:i:2\r\n",
            "audiocapturemode:i:1\r\n",
            "videoplaybackmode:i:1\r\n",
            "connection type:i:2\r\n",
            "networkautodetect:i:1\r\n",
            "bandwidthautodetect:i:1\r\n",
            "enableworkspacereconnect:i:1\r\n",
            "disable wallpaper:i:0\r\n",
            "allow desktop composition:i:0\r\n",
            "allow font smoothing:i:0\r\n",
            "disable full window drag:i:1\r\n",
            "disable menu anims:i:1\r\n",
            "disable themes:i:0\r\n",
            "disable cursor setting:i:0\r\n",
            "bitmapcachepersistenable:i:1\r\n",
            "audiomode:i:0\r\n",
            "redirectprinters:i:1\r\n",
            "redirectcomports:i:0\r\n",
            "redirectsmartcards:i:1\r\n",
            "redirectclipboard:i:1\r\n",
            "redirectposdevices:i:0\r\n",
            "autoreconnection enabled:i:1\r\n",
            "authentication level:i:0\r\n",
            "prompt for credentials:i:0\r\n",
            "negotiate security layer:i:1\r\n",
            "remoteapplicationmode:i:0\r\n",
            "alternate shell:s:\r\n",
            "shell working directory:s:\r\n",
            "gatewayhostname:s:\r\n",
            "gatewayusagemethod:i:4\r\n",
            "gatewaycredentialssource:i:4\r\n",
            "gatewayprofileusagemethod:i:0\r\n",
            "promptcredentialonce:i:1\r\n",
            "use redirection server name:i:0\r\n",
            "rdgiskdcproxy:i:0\r\n",
            "kdcproxyname:s:\r\n",
            "username:s:{user_field}\r\n",
            "domain:s:{domain}\r\n",
            "enablecredsspsupport:i:1\r\n",
            "public mode:i:0\r\n",
            "cert ignore:i:1\r\n",
            "prompt for credentials on client:i:0\r\n",
            "disableconnectionsharing:i:0\r\n",
        ),
        host = host,
        user_field = user_field,
        domain = domain,
    )
}

fn build_rdp_profile_candidates(server: &str) -> Vec<CredentialProfile> {
    let mut profiles = Vec::new();
    let trimmed = server.trim();
    if trimmed.is_empty() {
        return profiles;
    }

    let (host_no_port, port_opt) = trimmed
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map(|(host, port)| (host, Some(port)))
        .unwrap_or((trimmed, None));

    let short = host_no_port.split('.').next().unwrap_or(host_no_port);

    let mut seen = HashSet::new();
    let push_profile =
        |target: String, seen: &mut HashSet<String>, profiles: &mut Vec<CredentialProfile>| {
            if seen.insert(target.clone()) {
                profiles.push(CredentialProfile::new(target));
            }
        };

    push_profile(format!("TERMSRV/{}", trimmed), &mut seen, &mut profiles);

    if let Some(port) = port_opt {
        push_profile(
            format!("TERMSRV/{}:{}", host_no_port, port),
            &mut seen,
            &mut profiles,
        );
    }

    if host_no_port != trimmed {
        push_profile(
            format!("TERMSRV/{}", host_no_port),
            &mut seen,
            &mut profiles,
        );
    }

    push_profile(
        format!("TERMSRV/{}:3389", host_no_port),
        &mut seen,
        &mut profiles,
    );

    if short != host_no_port {
        push_profile(format!("TERMSRV/{}", short), &mut seen, &mut profiles);
        push_profile(format!("TERMSRV/{}:3389", short), &mut seen, &mut profiles);
    }

    profiles
}

async fn resolve_host_credentials_with_store(
    store: &impl CredentialStore,
    server_name: &str,
) -> Result<(Credentials, String), String> {
    let normalized = normalize_host_name(server_name)?;
    let host_profile = CredentialProfile::new(format!("QuickProbe:HOST/{}", normalized));

    // First try host-specific credentials
    if let Some(creds) = store
        .retrieve(&host_profile)
        .await
        .map_err(|e| format!("Failed to retrieve credentials: {}", e))?
    {
        logger::log_debug(&format!(
            "resolve_credentials: using host-specific creds for '{}' (profile: {})",
            server_name,
            host_profile.as_str()
        ));
        return Ok((creds, host_profile.as_str().to_string()));
    }

    // Fall back to RDP/TERMSRV profiles
    let mut picked: Option<(Credentials, String)> = None;
    for profile in build_rdp_profile_candidates(server_name) {
        if let Some(creds) = store
            .retrieve(&profile)
            .await
            .map_err(|e| format!("Failed to retrieve credentials: {}", e))?
        {
            picked = Some((creds, profile.as_str().to_string()));
            break;
        }
    }

    // Fall back to default profile
    if picked.is_none() {
        let default_profile = CredentialProfile::default();
        if let Some(creds) = store
            .retrieve(&default_profile)
            .await
            .map_err(|e| format!("Failed to retrieve credentials: {}", e))?
        {
            picked = Some((creds, default_profile.as_str().to_string()));
        }
    }

    let (creds, used_profile) = picked.ok_or_else(|| {
        format!(
            "No credentials found for '{}'. Tried: {}, TERMSRV/*, QuickProbe:DEFAULT. Please set host credentials or log in.",
            server_name,
            host_profile.as_str()
        )
    })?;

    logger::log_debug(&format!(
        "resolve_credentials: using fallback creds for '{}' (profile: {})",
        server_name, used_profile
    ));

    // Opportunistically store under the host profile for reuse
    if host_profile.as_str() != used_profile {
        let _ = store.store(&host_profile, &creds).await;
    }

    Ok((creds, used_profile))
}

async fn resolve_host_credentials(server_name: &str) -> Result<(Credentials, String), String> {
    let store = WindowsCredentialManager::new();
    resolve_host_credentials_with_store(&store, server_name).await
}

/// Wrapper to hold either Windows or Linux remote session
enum SessionKind {
    Windows(WindowsRemoteSession),
    Linux(LinuxRemoteSession),
}

impl SessionKind {
    fn as_remote(&self) -> &dyn RemoteSession {
        match self {
            SessionKind::Windows(s) => s,
            SessionKind::Linux(s) => s,
        }
    }

    fn is_windows(&self) -> bool {
        matches!(self, SessionKind::Windows(_))
    }
}

/// Determine the declared OS type for a host (defaults to Windows).
async fn resolve_host_os_type(server_name: &str) -> String {
    let normalized = match normalize_host_name(server_name) {
        Ok(n) => n,
        Err(_) => return "Windows".to_string(),
    };

    if let Ok(hosts) = get_hosts().await {
        for host in hosts {
            if host.name.eq_ignore_ascii_case(&normalized) {
                if let Some(os) = host.os_type {
                    if os.eq_ignore_ascii_case("linux") {
                        return "Linux".to_string();
                    } else if os.eq_ignore_ascii_case("windows") {
                        return "Windows".to_string();
                    }
                }
            }
        }
    }

    "Windows".to_string()
}

/// Connect to a remote session based on host OS.
async fn connect_remote_session(
    server_name: String,
    credentials: Credentials,
    os_hint: &str,
) -> Result<SessionKind, String> {
    use quickprobe::utils::{is_transient_error, retry_with_backoff, RetryConfig};

    logger::log_debug(&format!(
        "connect_remote_session: START '{}' os='{}'",
        server_name, os_hint
    ));

    // Clone values for retry closure
    let server_clone = server_name.clone();
    let creds_clone = credentials.clone();
    let os_clone = os_hint.to_string();

    let result = retry_with_backoff(
        RetryConfig::default(),
        || async {
            if os_clone.eq_ignore_ascii_case("linux") {
                LinuxRemoteSession::connect(server_clone.clone(), creds_clone.clone())
                    .await
                    .map(SessionKind::Linux)
            } else {
                WindowsRemoteSession::connect(server_clone.clone(), creds_clone.clone())
                    .await
                    .map(SessionKind::Windows)
            }
        },
        |err: &String| is_transient_error(err.as_str()),
    )
    .await;

    match &result {
        Ok(_) => {
            logger::log_debug_verbose(&format!("connect_remote_session: OK '{}'", server_name))
        }
        Err(e) => logger::log_error(&format!(
            "connect_remote_session: FAILED '{}': {}",
            server_name, e
        )),
    }

    result
}

fn write_rdp_file(host: &str, username: &str, domain: &str) -> Result<PathBuf, String> {
    // Validate all parameters to prevent CRLF injection and path traversal
    validate_rdp_parameter(host, "hostname")?;
    validate_rdp_parameter(username, "username")?;
    validate_rdp_parameter(domain, "domain")?;

    let app_dir = get_app_data_dir()?;
    let connections_dir = app_dir.join("Connections");
    fs::create_dir_all(&connections_dir)
        .map_err(|e| format!("Failed to create Connections directory: {}", e))?;

    let rdp_path = connections_dir.join(format!("{}.rdp", host));
    let content = build_rdp_content(host, username, domain);
    fs::write(&rdp_path, content.as_bytes())
        .map_err(|e| format!("Failed to write RDP file: {}", e))?;
    Ok(rdp_path)
}

fn launch_mstsc(rdp_path: &Path) -> Result<(), String> {
    Command::new("mstsc.exe")
        .arg(rdp_path)
        .spawn()
        .map_err(|e| format!("Failed to launch mstsc.exe: {}", e))?;
    Ok(())
}

#[tauri::command]
async fn save_rdp_credentials(
    server: String,
    username: String,
    password: String,
) -> Result<(), String> {
    let server = server.trim();
    let username = username.trim();

    if server.is_empty() {
        return Err("Server name is required".to_string());
    }
    if username.is_empty() {
        return Err("Username is required".to_string());
    }

    let store = WindowsCredentialManager::new();
    let normalized = normalize_host_name(server)?;
    let host_profile = CredentialProfile::new(format!("QuickProbe:HOST/{}", normalized));
    let rdp_profile = CredentialProfile::new(format!("TERMSRV/{}", server));
    let creds = Credentials::new(
        Username::new(username.to_string()).map_err(|e| e.to_string())?,
        SecureString::new(password),
    );

    store
        .store(&host_profile, &creds)
        .await
        .map_err(|e| e.to_string())?;

    logger::log_info(&format!(
        "save_rdp_credentials: stored creds for '{}' as profile '{}' (user: {})",
        server,
        host_profile.as_str(),
        username
    ));

    // Also persist to TERMSRV for mstsc compatibility
    let _ = store.store(&rdp_profile, &creds).await;
    Ok(())
}

#[tauri::command]
async fn launch_rdp(server: String) -> Result<(), String> {
    let server = server.trim();
    if server.is_empty() {
        return Err("Server name is required".to_string());
    }

    let store = WindowsCredentialManager::new();
    let (creds, _) = resolve_host_credentials(server).await?;

    let host_profile = CredentialProfile::new(format!("TERMSRV/{}", server));
    let _ = store.store(&host_profile, &creds).await;

    let (domain, user) = split_domain_username(creds.username().as_str());
    let rdp_path = write_rdp_file(server, &user, &domain)?;
    launch_mstsc(&rdp_path)
}

/// Launch SSH connection to a Linux host using Windows Terminal or fallback to cmd.exe
#[tauri::command]
async fn launch_ssh(server: String) -> Result<(), String> {
    let server = server.trim();
    if server.is_empty() {
        return Err("Server name is required".to_string());
    }

    logger::log_info(&format!("launch_ssh: Launching SSH to '{}'", server));

    // Get credentials for the host
    let (creds, _) = resolve_host_credentials(server).await?;
    let username = creds.username().as_str().to_string();

    // Parse host:port if specified
    let (host, port) = if let Some((h, p)) = server.rsplit_once(':') {
        if let Ok(port_num) = p.parse::<u16>() {
            (h.to_string(), Some(port_num))
        } else {
            (server.to_string(), None)
        }
    } else {
        (server.to_string(), None)
    };

    // Build SSH command
    let ssh_target = if username.is_empty() {
        host.clone()
    } else {
        format!("{}@{}", username, host)
    };

    let ssh_cmd = if let Some(p) = port {
        format!("ssh -p {} {}", p, ssh_target)
    } else {
        format!("ssh {}", ssh_target)
    };

    // Try Windows Terminal first (wt.exe), fall back to cmd.exe
    let result = tokio::task::spawn_blocking(move || {
        use std::process::Command;

        // Try Windows Terminal first
        let wt_result = Command::new("wt.exe")
            .arg("new-tab")
            .arg("--title")
            .arg(format!("SSH: {}", host))
            .arg("cmd")
            .arg("/k")
            .arg(&ssh_cmd)
            .spawn();

        match wt_result {
            Ok(_) => {
                logger::log_debug(&format!(
                    "launch_ssh: Opened Windows Terminal for '{}'",
                    host
                ));
                Ok(())
            }
            Err(_) => {
                // Fall back to cmd.exe with SSH
                logger::log_debug("launch_ssh: Windows Terminal not available, trying cmd.exe");
                Command::new("cmd.exe")
                    .arg("/c")
                    .arg("start")
                    .arg("cmd")
                    .arg("/k")
                    .arg(&ssh_cmd)
                    .spawn()
                    .map_err(|e| format!("Failed to launch SSH: {}", e))?;
                Ok(())
            }
        }
    })
    .await
    .map_err(|e| format!("SSH launch task failed: {}", e))?;

    result
}

/// Open Windows Explorer to the C$ administrative share on a remote host
///
/// Uses credentials (host-specific or global) to mount the share and open Explorer.
#[cfg(windows)]
#[tauri::command]
async fn open_explorer_share(server: String) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let server = server.trim();
    if server.is_empty() {
        return Err("Server name is required".to_string());
    }

    logger::log_info(&format!(
        "open_explorer_share: Opening Explorer to \\\\{}\\C$",
        server
    ));

    // Get credentials for the host
    let (creds, used_profile) = resolve_host_credentials(server).await?;
    let username = creds.username().as_str();
    let password = creds.password().as_str();

    logger::log_debug(&format!(
        "open_explorer_share: Using credentials from profile '{}' for '{}'",
        used_profile, server
    ));

    // Parse username into domain\user format if needed
    let (domain, user) = split_domain_username(username);
    let full_username = if !domain.is_empty() {
        format!("{}\\{}", domain, user)
    } else {
        user.to_string()
    };

    let unc_path = format!("\\\\{}\\C$", server);

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Use net use to mount the share with credentials
    // /delete first to clear any existing connection
    let _ = Command::new("net")
        .args(["use", &unc_path, "/delete", "/y"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    // Now mount with credentials
    let output = Command::new("net")
        .args([
            "use",
            &unc_path,
            password,
            &format!("/user:{}", full_username),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute net use: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        logger::log_error(&format!(
            "open_explorer_share: net use failed for '{}': {}",
            server, stderr
        ));
        return Err(format!(
            "Failed to connect to share: {}. Please verify credentials and network access.",
            stderr.trim()
        ));
    }

    // Open Explorer to the mounted share
    Command::new("explorer.exe")
        .arg(&unc_path)
        .spawn()
        .map_err(|e| format!("Failed to launch Explorer: {}", e))?;

    logger::log_info(&format!(
        "open_explorer_share: Successfully opened Explorer to '{}'",
        unc_path
    ));

    Ok(())
}

#[cfg(not(windows))]
#[tauri::command]
async fn open_explorer_share(_server: String) -> Result<(), String> {
    Err("Explorer share opening is only supported on Windows".to_string())
}

/// Launch an MMC snap-in targeting a remote server
///
/// This command launches various Microsoft Management Console (MMC) snap-ins
/// configured to manage a remote Windows server. Uses PowerShell to request
/// elevation via UAC prompt if needed.
#[cfg(windows)]
#[tauri::command]
async fn launch_mmc_snapin(server: String, snapin: String) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let server = server.trim();
    let snapin = snapin.trim().to_lowercase();

    if server.is_empty() {
        return Err("Server name is required".to_string());
    }
    if snapin.is_empty() {
        return Err("Snap-in name is required".to_string());
    }

    logger::log_info(&format!(
        "launch_mmc_snapin: Launching {} for server '{}'",
        snapin, server
    ));

    // Clear MMC cache to prevent showing previous console during load
    // MMC stores cached console state in %APPDATA%\Microsoft\MMC\
    if let Ok(appdata) = std::env::var("APPDATA") {
        let mmc_cache_path = PathBuf::from(appdata).join("Microsoft").join("MMC");
        if mmc_cache_path.exists() {
            logger::log_debug(&format!(
                "launch_mmc_snapin: Clearing MMC cache at {:?}",
                mmc_cache_path
            ));
            // Delete all files in the MMC cache directory (but not subdirectories)
            if let Ok(entries) = std::fs::read_dir(&mmc_cache_path) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.is_file() {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Build PowerShell command with proper ArgumentList array syntax
    // Different snap-ins require different parameter formats
    let ps_script = match snapin.as_str() {
        "eventvwr.msc" => {
            // Event Viewer requires /computer: with colon (not equals)
            format!(
                "Start-Process -FilePath 'mmc.exe' -ArgumentList @('{}','/computer:{}') -Verb RunAs",
                snapin, server
            )
        }
        "taskschd.msc" => {
            // Task Scheduler connects to remote using /computer parameter
            format!(
                "Start-Process -FilePath 'mmc.exe' -ArgumentList @('{}','/computer=\\\\{}') -Verb RunAs",
                snapin, server
            )
        }
        _ => {
            // Most snap-ins use /computer=\\server format
            format!(
                "Start-Process -FilePath 'mmc.exe' -ArgumentList @('{}','/computer=\\\\{}') -Verb RunAs",
                snapin, server
            )
        }
    };

    let result = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();

    match result {
        Ok(_) => {
            logger::log_info(&format!(
                "launch_mmc_snapin: Successfully launched {} for '{}'",
                snapin, server
            ));
            Ok(())
        }
        Err(e) => {
            let error_msg = format!("Failed to launch {}: {}", snapin, e);
            logger::log_error(&format!("launch_mmc_snapin: {}", error_msg));
            Err(error_msg)
        }
    }
}

#[cfg(not(windows))]
#[tauri::command]
async fn launch_mmc_snapin(_server: String, _snapin: String) -> Result<(), String> {
    Err("MMC snap-ins are only supported on Windows".to_string())
}

/// Launch regedit.exe for remote registry connection
///
/// Launches the Windows Registry Editor and automatically connects to the remote registry
/// using PowerShell automation to interact with the regedit UI.
#[cfg(windows)]
#[tauri::command]
async fn launch_remote_registry(server: String) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let server = server.trim();

    if server.is_empty() {
        return Err("Server name is required".to_string());
    }

    logger::log_info(&format!(
        "launch_remote_registry: Launching regedit for server '{}'",
        server
    ));

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Test connectivity to remote registry with retries
    // Service may take a moment to fully start after being enabled
    let mut last_error = String::new();
    let max_retries = 3;
    let mut connected = false;

    for attempt in 1..=max_retries {
        let test_result = Command::new("reg.exe")
            .args(["query", &format!("\\\\{}\\HKLM", server)])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        match test_result {
            Ok(output) if output.status.success() => {
                logger::log_debug(&format!(
                    "launch_remote_registry: Registry connectivity test successful for '{}' (attempt {})",
                    server, attempt
                ));
                connected = true;
                break;
            }
            Ok(output) => {
                last_error = String::from_utf8_lossy(&output.stderr).to_string();
                logger::log_warn(&format!(
                    "launch_remote_registry: Registry connectivity test failed for '{}' (attempt {}): {}",
                    server, attempt, last_error
                ));
            }
            Err(e) => {
                last_error = e.to_string();
                logger::log_warn(&format!(
                    "launch_remote_registry: Could not test registry connectivity (attempt {}): {}",
                    attempt, e
                ));
            }
        }

        // Wait before retrying (except on last attempt)
        if attempt < max_retries {
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    }

    if !connected {
        return Err(format!(
            "Cannot connect to remote registry on {}. Ensure RemoteRegistry service is running and you have permissions. Last error: {}",
            server, last_error.trim()
        ));
    }

    // Launch regedit and use PowerShell to automate the connection to remote registry
    // This PowerShell script:
    // 1. Launches regedit with elevation
    // 2. Waits for it to start
    // 3. Uses UI automation to select File -> Connect Network Registry
    // 4. Enters the server name and connects
    let ps_script = format!(
        r#"Start-Process -FilePath 'regedit.exe' -Verb RunAs -PassThru | Out-Null; Start-Sleep -Milliseconds 800; Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('%F'); Start-Sleep -Milliseconds 150; [System.Windows.Forms.SendKeys]::SendWait('C'); Start-Sleep -Milliseconds 300; [System.Windows.Forms.SendKeys]::SendWait('{}'); Start-Sleep -Milliseconds 150; [System.Windows.Forms.SendKeys]::SendWait('{{ENTER}}')"#,
        server.replace("\\", "\\\\").replace("'", "''")
    );

    let result = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();

    match result {
        Ok(_) => {
            logger::log_info(&format!(
                "launch_remote_registry: Successfully launched regedit for '{}'",
                server
            ));
            Ok(())
        }
        Err(e) => {
            let error_msg = format!("Failed to launch regedit: {}", e);
            logger::log_error(&format!("launch_remote_registry: {}", error_msg));
            Err(error_msg)
        }
    }
}

#[cfg(not(windows))]
#[tauri::command]
async fn launch_remote_registry(_server: String) -> Result<(), String> {
    Err("Remote Registry is only supported on Windows".to_string())
}

/// Restart a remote server (Windows or Linux)
///
/// For Windows: Uses PowerShell Restart-Computer cmdlet via WinRM
/// For Linux: Uses SSH to execute shutdown -r now
#[tauri::command]
async fn remote_restart(server_name: String) -> Result<(), String> {
    let server_name = server_name.trim();

    if server_name.is_empty() {
        return Err("Server name is required".to_string());
    }

    logger::log_info(&format!(
        "remote_restart: Initiating restart for '{}'",
        server_name
    ));

    let os_hint = resolve_host_os_type(server_name).await;
    let (credentials, _) = resolve_host_credentials(server_name).await?;

    if os_hint.eq_ignore_ascii_case("linux") {
        // Linux: Use SSH with shutdown command
        let session = LinuxRemoteSession::connect(server_name.to_string(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        // Use sudo shutdown -r now to restart immediately
        let restart_cmd = "sudo shutdown -r now";

        let result = session.execute_command(restart_cmd).await;

        match result {
            Ok(_) => {
                logger::log_info(&format!(
                    "remote_restart: Successfully initiated restart for '{}' (Linux)",
                    server_name
                ));
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to restart Linux server: {}", e);
                logger::log_error(&format!("remote_restart: {}", error_msg));
                Err(error_msg)
            }
        }
    } else {
        // Windows: Use WinRM/PowerShell
        let session = WindowsRemoteSession::connect(server_name.to_string(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        let restart_script = format!("Restart-Computer -ComputerName {} -Force", server_name);

        let result = session.execute_powershell(&restart_script).await;

        match result {
            Ok(_) => {
                logger::log_info(&format!(
                    "remote_restart: Successfully initiated restart for '{}' (Windows)",
                    server_name
                ));
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to restart Windows server: {}", e);
                logger::log_error(&format!("remote_restart: {}", error_msg));
                Err(error_msg)
            }
        }
    }
}

/// Shutdown a remote server (Windows or Linux)
///
/// For Windows: Uses PowerShell Stop-Computer cmdlet via WinRM
/// For Linux: Uses SSH to execute shutdown -h now
#[tauri::command]
async fn remote_shutdown(server_name: String) -> Result<(), String> {
    let server_name = server_name.trim();

    if server_name.is_empty() {
        return Err("Server name is required".to_string());
    }

    logger::log_info(&format!(
        "remote_shutdown: Initiating shutdown for '{}'",
        server_name
    ));

    let os_hint = resolve_host_os_type(server_name).await;
    let (credentials, _) = resolve_host_credentials(server_name).await?;

    if os_hint.eq_ignore_ascii_case("linux") {
        // Linux: Use SSH with shutdown command
        let session = LinuxRemoteSession::connect(server_name.to_string(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        // Use sudo shutdown -h now to halt immediately
        let shutdown_cmd = "sudo shutdown -h now";

        let result = session.execute_command(shutdown_cmd).await;

        match result {
            Ok(_) => {
                logger::log_info(&format!(
                    "remote_shutdown: Successfully initiated shutdown for '{}' (Linux)",
                    server_name
                ));
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to shutdown Linux server: {}", e);
                logger::log_error(&format!("remote_shutdown: {}", error_msg));
                Err(error_msg)
            }
        }
    } else {
        // Windows: Use WinRM/PowerShell
        let session = WindowsRemoteSession::connect(server_name.to_string(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        let shutdown_script = format!("Stop-Computer -ComputerName {} -Force", server_name);

        let result = session.execute_powershell(&shutdown_script).await;

        match result {
            Ok(_) => {
                logger::log_info(&format!(
                    "remote_shutdown: Successfully initiated shutdown for '{}' (Windows)",
                    server_name
                ));
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to shutdown Windows server: {}", e);
                logger::log_error(&format!("remote_shutdown: {}", error_msg));
                Err(error_msg)
            }
        }
    }
}

/// Save notes for a server in hosts.csv
///
/// Updates or creates the notes field for a specific server.
#[allow(dead_code)] // Called from JavaScript via Tauri IPC
#[tauri::command]
async fn save_server_notes(server_name: String, notes: String) -> Result<(), String> {
    let normalized_name = normalize_host_name(&server_name)?;
    let notes_clean = notes.trim().to_string();

    logger::log_debug(&format!(
        "save_server_notes: server='{}', notes_len={}",
        normalized_name,
        notes_clean.len()
    ));

    // Use granular UPDATE to avoid read-modify-write race
    // This prevents lost updates when multiple sessions save notes concurrently
    let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;

    let notes_value = if notes_clean.is_empty() {
        None
    } else {
        Some(notes_clean.clone())
    };

    let rows_affected = conn
        .execute(
            "UPDATE hosts SET notes = ?1 WHERE server_name = ?2",
            rusqlite::params![notes_value, normalized_name],
        )
        .map_err(|e| {
            logger::log_error(&format!(
                "save_server_notes: UPDATE failed for '{}': {}",
                normalized_name, e
            ));
            format!("Failed to update notes: {}", e)
        })?;

    if rows_affected == 0 {
        logger::log_warn(&format!(
            "save_server_notes: Server '{}' not found",
            normalized_name
        ));
        return Err(format!(
            "Server '{}' not found in hosts.csv",
            normalized_name
        ));
    }

    bump_hosts_changed_flag()?;
    logger::log_info(&format!(
        "save_server_notes: SUCCESS for '{}', qp_hosts_changed bumped",
        normalized_name
    ));
    Ok(())
}

/// Update a single host's properties (notes, group, os_type, services)
#[tauri::command]
async fn update_host(
    server_name: String,
    notes: Option<String>,
    group: Option<String>,
    os_type: Option<String>,
    services: Option<Vec<String>>,
) -> Result<(), String> {
    let normalized_name = normalize_host_name(&server_name)?;
    logger::log_info(&format!(
        "update_host: '{}' (normalized from '{}')",
        normalized_name, server_name
    ));

    if normalized_name.is_empty() {
        return Err("Invalid server name".to_string());
    }

    let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;

    // First verify the host exists
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM hosts WHERE server_name = ?1",
            rusqlite::params![normalized_name],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !exists {
        return Err(format!(
            "Server '{}' not found in hosts database",
            normalized_name
        ));
    }

    // Update all provided fields
    let notes_value = notes
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    let group_value = group
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty());
    let os_value = os_type
        .map(|o| o.trim().to_string())
        .filter(|o| !o.is_empty())
        .unwrap_or_else(|| "Windows".to_string());
    let services_value = services
        .map(|s| {
            s.iter()
                .map(|svc| svc.trim().to_string())
                .filter(|svc| !svc.is_empty())
                .collect::<Vec<_>>()
                .join(";")
        })
        .filter(|s| !s.is_empty());

    logger::log_debug(&format!(
        "update_host: '{}' notes={:?} group={:?} os={:?} services={:?}",
        normalized_name, notes_value, group_value, os_value, services_value
    ));

    conn.execute(
        "UPDATE hosts SET notes = ?1, group_name = ?2, os_type = ?3, services = ?4 WHERE server_name = ?5",
        rusqlite::params![notes_value, group_value, os_value, services_value, normalized_name],
    )
    .map_err(|e| {
        logger::log_error(&format!("update_host: SQL error for '{}': {}", normalized_name, e));
        format!("Database error: {}", e)
    })?;

    bump_hosts_changed_flag()?;
    logger::log_info(&format!(
        "update_host: SUCCESS for '{}', qp_hosts_changed bumped",
        normalized_name
    ));
    Ok(())
}

/// Replace hosts.csv with provided host entries
#[tauri::command]
async fn set_hosts(hosts: Vec<HostUpdate>) -> Result<(), String> {
    let start = SystemTime::now();
    logger::log_info(&format!("set_hosts: {} host(s)", hosts.len()));

    // Log changed fields per host (no secrets)
    for (i, host) in hosts.iter().enumerate() {
        let mut fields = Vec::new();
        if host.notes.is_some() {
            fields.push("notes");
        }
        if host.group.is_some() {
            fields.push("group");
        }
        if host.services.is_some() {
            fields.push("services");
        }
        if host.os_type.is_some() {
            fields.push("os_type");
        }

        logger::log_debug(&format!(
            "set_hosts[{}]: '{}' fields=[{}]",
            i,
            host.name,
            fields.join(",")
        ));
    }

    let result = persist_hosts(&hosts);

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    match &result {
        Ok(_) => logger::log_info(&format!("set_hosts: SUCCESS {}ms", elapsed_ms)),
        Err(e) => logger::log_error(&format!("set_hosts: FAILED {}ms: {}", elapsed_ms, e)),
    }

    result
}

/// Rename a group label across all hosts in hosts.csv
#[tauri::command]
async fn rename_group(old_group: String, new_group: String) -> Result<usize, String> {
    logger::log_info(&format!("rename_group: '{}' -> '{}'", old_group, new_group));

    let old_trim = old_group.trim().to_string();
    let new_trim = new_group.trim().to_string();
    if new_trim.is_empty() {
        return Err("New group name cannot be empty".to_string());
    }

    let mut hosts = get_hosts().await?;
    let mut updated_count = 0usize;
    for host in hosts.iter_mut() {
        let current = host.group.clone().unwrap_or_default();
        if current.eq_ignore_ascii_case(&old_trim) {
            host.group = Some(new_trim.clone());
            updated_count += 1;
        }
    }

    if updated_count == 0 {
        logger::log_info("rename_group: no hosts matched");
        return Ok(0);
    }

    let updates: Vec<HostUpdate> = hosts
        .into_iter()
        .map(|h| HostUpdate {
            name: h.name,
            notes: h.notes,
            group: h.group,
            services: h.services,
            os_type: h.os_type,
        })
        .collect();

    persist_hosts(&updates)?;
    logger::log_info(&format!(
        "rename_group: SUCCESS, {} host(s) updated",
        updated_count
    ));
    Ok(updated_count)
}

/// Get system health summary for a server
///
/// Returns comprehensive health information including OS details,
/// disk alerts, service status, and high CPU processes.
#[allow(dead_code)] // Called from JavaScript via Tauri IPC
#[tauri::command]
async fn get_system_health(
    server_name: String,
    disk_threshold: Option<f64>,
    critical_services: Option<Vec<String>>,
    tcp_ports: Option<Vec<u16>>,
) -> Result<SystemHealthSummary, String> {
    let start = SystemTime::now();
    logger::log_debug_verbose(&format!("get_system_health: START '{}'", server_name));

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

    logger::log_debug_verbose(&format!(
        "[HealthCheck] {} - Starting connectivity probes (ping + reachability)...",
        server_name
    ));
    let probe_start = SystemTime::now();
    let ping_ok = ping_host(&server_name).await.unwrap_or(false);
    let reachability =
        Some(probe_reachability(&server_name, &tcp_ports, TCP_PROBE_TIMEOUT_MS).await);
    let probe_ms = probe_start.elapsed().unwrap_or_default().as_millis();
    logger::log_debug_verbose(&format!(
        "[HealthCheck] {} - Connectivity probes completed in {}ms (ping: {}, reachability: {:?})",
        server_name, probe_ms, ping_ok, reachability
    ));
    let server_name_clone = server_name.clone();

    logger::log_debug_verbose(&format!(
        "[HealthCheck] {} - Connecting to remote session (OS: {})...",
        server_name, os_hint
    ));
    let session_start = SystemTime::now();
    let session = match connect_remote_session(server_name.clone(), credentials, &os_hint).await {
        Ok(s) => {
            let session_ms = session_start.elapsed().unwrap_or_default().as_millis();
            logger::log_debug_verbose(&format!(
                "[HealthCheck] {} - Remote session connected in {}ms",
                server_name, session_ms
            ));
            s
        }
        Err(e) => {
            let session_ms = session_start.elapsed().unwrap_or_default().as_millis();
            logger::log_error(&format!(
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
    logger::log_debug_verbose(&format!(
        "[HealthCheck] {} - Starting health data collection...",
        server_name
    ));
    let collect_start = SystemTime::now();
    let summary = match &session {
        SessionKind::Windows(win) => {
            match win.collect_system_health(services_slice, threshold).await {
                Ok(summary) => {
                    let collect_ms = collect_start.elapsed().unwrap_or_default().as_millis();
                    logger::log_debug_verbose(&format!(
                        "[HealthCheck] {} - Health data collection succeeded in {}ms",
                        server_name, collect_ms
                    ));
                    Ok(summary)
                }
                Err(fast_err) => {
                    let fast_ms = collect_start.elapsed().unwrap_or_default().as_millis();
                    logger::log_warn(&format!(
                        "[HealthCheck] {} - Fast path failed after {}ms, trying fallback... Error: {}",
                        server_name, fast_ms, fast_err
                    ));
                    let fallback_start = SystemTime::now();
                    match system_health_probe(win, services_slice, threshold).await {
                        Ok(fallback) => {
                            let fallback_ms =
                                fallback_start.elapsed().unwrap_or_default().as_millis();
                            logger::log_debug_verbose(&format!(
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
            logger::log_debug_verbose(&format!(
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
                    logger::log_debug_verbose(&format!(
                        "get_system_health: PARTIAL '{}' {}ms",
                        server_name, elapsed_ms
                    ));
                    return Ok(recovered);
                }

                let mut degraded =
                    degraded_summary_or_error(&server_name_clone, e, true, ping_ok).await?;
                degraded.reachability = reachability;
                let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
                logger::log_debug_verbose(&format!(
                    "get_system_health: DEGRADED '{}' {}ms",
                    server_name, elapsed_ms
                ));
                Ok(degraded)
            } else {
                let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
                logger::log_error(&format!(
                    "get_system_health: FAILED '{}' {}ms: {}",
                    server_name, elapsed_ms, e
                ));
                Err(e)
            }
        }
    }
}

/// Best-effort minimal health snapshot when the main probe fails.
async fn recover_minimal_health(session: &dyn RemoteSession) -> Option<SystemHealthSummary> {
    let os_info = session.get_os_info().await.ok()?;
    let memory_info = session.get_memory_info().await.ok();
    let processes = session.get_processes(None).await.ok();

    let (total_memory_mb, used_memory_mb, memory_used_percent) = if let Some(mem) = memory_info {
        let used = (mem.total_mb - mem.free_mb).max(0.0);
        let pct = if mem.total_mb > 0.0 {
            (used / mem.total_mb) * 100.0
        } else {
            0.0
        };
        (mem.total_mb, used, pct)
    } else {
        (0.0, 0.0, 0.0)
    };

    let process_count = processes.as_ref().map(|p| p.len()).unwrap_or(0);

    Some(SystemHealthSummary {
        server_name: os_info.hostname.clone(),
        winrm_issue: true,
        winrm_error: None,
        os_info,
        disk_alerts: Vec::new(),
        total_disks: 0,
        disks: Vec::new(),
        service_alerts: 0,
        service_status: Vec::new(),
        process_count,
        high_cpu_processes: Vec::new(),
        high_cpu_threshold: 50.0,
        total_memory_mb,
        used_memory_mb,
        memory_used_percent,
        uptime: None,
        pending_reboot: None,
        winrm_listeners: None,
        firewall_profiles: None,
        recent_errors: None,
        net_adapters: None,
        reachability: None,
    })
}

/// Fetch network adapter info only (debug helper)
#[tauri::command]
async fn fetch_net_adapters(server_name: String) -> Result<AdapterDebugResponse, String> {
    let start = SystemTime::now();
    logger::log_debug_verbose(&format!("fetch_net_adapters: START '{}'", server_name));

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
        logger::log_debug_verbose(&format!(
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
        logger::log_debug_verbose(&format!(
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
    logger::log_debug_verbose(&format!(
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
async fn fetch_os_info(server_name: String) -> Result<OsInfo, String> {
    let start = SystemTime::now();
    logger::log_debug_verbose(&format!("fetch_os_info: START '{}'", server_name));

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
        Ok(_) => logger::log_debug_verbose(&format!(
            "fetch_os_info: SUCCESS '{}' {}ms",
            server_name, elapsed_ms
        )),
        Err(e) => logger::log_error(&format!(
            "fetch_os_info: FAILED '{}' {}ms: {}",
            server_name, elapsed_ms, e
        )),
    }

    result
}

/// Fetch all services from a remote Windows host for service selection UI
#[tauri::command]
async fn get_remote_services(server_name: String) -> Result<Vec<ServiceInfo>, String> {
    let start = SystemTime::now();
    logger::log_debug_verbose(&format!("get_remote_services: START '{}'", server_name));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    let services = if os_hint.eq_ignore_ascii_case("linux") {
        // Linux: Use SSH to get systemd services
        let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        session
            .get_services(None)
            .await
            .map_err(|e| format!("Failed to retrieve services from {}: {}", server_name, e))?
    } else {
        // Windows: Use WinRM/PowerShell
        let session = WindowsRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        session
            .get_services(None)
            .await
            .map_err(|e| format!("Failed to retrieve services from {}: {}", server_name, e))?
    };

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    logger::log_debug(&format!(
        "get_remote_services: SUCCESS '{}' {}ms {} services",
        server_name,
        elapsed_ms,
        services.len()
    ));

    Ok(services)
}

/// Response from service control operation
#[derive(Debug, Serialize)]
struct ServiceControlResponse {
    success: bool,
    service_name: String,
    action: String,
    new_status: Option<String>,
    message: String,
}

/// Control a Windows service (start, stop, restart)
#[tauri::command]
async fn control_service(
    server_name: String,
    service_name: String,
    action: String,
) -> Result<ServiceControlResponse, String> {
    let start = SystemTime::now();
    logger::log_debug(&format!(
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
        // Linux: Use SSH with systemctl
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
            logger::log_info(&format!(
                "control_service: SUCCESS '{}' service='{}' action='{}' new_status='{:?}' {}ms",
                server_name, service_name, action_lower, new_status, elapsed_ms
            ));
        } else {
            logger::log_warn(&format!(
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

    // Build PowerShell command for service control
    // Use Get-Service and Start-Service/Stop-Service/Restart-Service
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

    // Parse the JSON response
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
        logger::log_info(&format!(
            "control_service: SUCCESS '{}' service='{}' action='{}' new_status='{}' {}ms",
            server_name,
            service_name,
            action_lower,
            ps_result.status.as_deref().unwrap_or("unknown"),
            elapsed_ms
        ));
    } else {
        logger::log_warn(&format!(
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

/// Process information for the process management UI (includes user field)
#[derive(Debug, Serialize, Deserialize)]
struct RemoteProcessInfo {
    pid: u32,
    name: String,
    cpu_percent: f64,
    memory_mb: f64,
    user: String,
}

/// Fetch all processes from a remote host for process management UI
#[tauri::command]
async fn get_remote_processes(server_name: String) -> Result<Vec<RemoteProcessInfo>, String> {
    let start = SystemTime::now();
    logger::log_debug_verbose(&format!("get_remote_processes: START '{}'", server_name));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    if os_hint.eq_ignore_ascii_case("linux") {
        // Linux: Use SSH with ps command
        let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        // Get processes with PID, name, CPU%, memory (RSS in KB), and user
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
        logger::log_debug_verbose(&format!(
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

    // PowerShell command to get process info with CPU percentage, memory, and user
    // Use Win32_PerfFormattedData_PerfProc_Process for actual real-time CPU %
    // and Get-Process -IncludeUserName for owner and memory info
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
    logger::log_debug_verbose(&format!(
        "get_remote_processes: SUCCESS '{}' {}ms {} processes",
        server_name,
        elapsed_ms,
        processes.len()
    ));

    Ok(processes)
}

/// Response from process kill operation
#[derive(Debug, Serialize)]
struct ProcessKillResponse {
    success: bool,
    pid: u32,
    process_name: String,
    message: String,
}

/// Kill a process on a remote host
#[tauri::command]
async fn kill_process(
    server_name: String,
    pid: u32,
    process_name: String,
) -> Result<ProcessKillResponse, String> {
    let start = SystemTime::now();
    logger::log_debug(&format!(
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
        // Linux: Use SSH with kill command
        let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

        // Try SIGTERM first, then check if process still exists
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
            logger::log_info(&format!(
                "kill_process: SUCCESS '{}' pid={} name='{}' {}ms",
                server_name, pid, process_name, elapsed_ms
            ));
        } else {
            logger::log_warn(&format!(
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

    // PowerShell command to kill process by PID
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
        logger::log_info(&format!(
            "kill_process: SUCCESS '{}' pid={} name='{}' {}ms",
            server_name, pid, process_name, elapsed_ms
        ));
    } else {
        logger::log_warn(&format!(
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

/// Response from remote PowerShell execution
#[derive(Debug, Serialize)]
struct RemotePowerShellResponse {
    success: bool,
    output: String,
    error: Option<String>,
}

/// Execute a PowerShell command on a remote Windows host
#[tauri::command]
async fn execute_remote_powershell(
    server_name: String,
    command: String,
) -> Result<RemotePowerShellResponse, String> {
    let start = SystemTime::now();
    logger::log_debug(&format!(
        "execute_remote_powershell: START '{}' command='{}'",
        server_name,
        command.chars().take(100).collect::<String>()
    ));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }
    if command.trim().is_empty() {
        return Err("Command cannot be empty".to_string());
    }

    // Check for potentially dangerous commands and warn in logs
    let command_lower = command.to_lowercase();
    let dangerous_patterns = [
        "remove-item",
        "del ",
        "rm ",
        "format-",
        "clear-disk",
        "stop-computer",
        "restart-computer",
    ];
    for pattern in dangerous_patterns {
        if command_lower.contains(pattern) {
            logger::log_warn(&format!(
                "execute_remote_powershell: Potentially destructive command detected on '{}': {}",
                server_name,
                command.chars().take(200).collect::<String>()
            ));
            break;
        }
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    if os_hint.eq_ignore_ascii_case("linux") {
        return Err("Remote PowerShell is only available for Windows hosts".to_string());
    }

    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    let session = WindowsRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

    // Execute the command and capture output
    // Wrap in try/catch to capture errors gracefully
    let ps_command = format!(
        r#"
$ErrorActionPreference = 'Continue'
try {{
    {}
}} catch {{
    Write-Error $_.Exception.Message
}}
"#,
        command
    );

    match session.execute_powershell(&ps_command).await {
        Ok(output) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            logger::log_debug(&format!(
                "execute_remote_powershell: SUCCESS '{}' {}ms output_len={}",
                server_name,
                elapsed_ms,
                output.len()
            ));

            Ok(RemotePowerShellResponse {
                success: true,
                output,
                error: None,
            })
        }
        Err(e) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            let error_msg = e.to_string();
            logger::log_warn(&format!(
                "execute_remote_powershell: ERROR '{}' {}ms error='{}'",
                server_name, elapsed_ms, error_msg
            ));

            Ok(RemotePowerShellResponse {
                success: false,
                output: String::new(),
                error: Some(error_msg),
            })
        }
    }
}

/// Response from remote SSH execution
#[derive(Debug, Serialize)]
struct RemoteSshResponse {
    success: bool,
    output: String,
    error: Option<String>,
}

/// Execute a shell command on a remote Linux host via SSH
#[tauri::command]
async fn execute_remote_ssh(
    server_name: String,
    command: String,
) -> Result<RemoteSshResponse, String> {
    let start = SystemTime::now();
    logger::log_debug(&format!(
        "execute_remote_ssh: START '{}' command='{}'",
        server_name,
        command.chars().take(100).collect::<String>()
    ));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }
    if command.trim().is_empty() {
        return Err("Command cannot be empty".to_string());
    }

    // Check for potentially dangerous commands and warn in logs
    let command_lower = command.to_lowercase();
    let dangerous_patterns = [
        "rm -rf",
        "rm -r",
        "dd if=",
        "mkfs",
        "shutdown",
        "reboot",
        "> /dev/",
        "chmod 777",
        ":(){ :|:& };:",
    ];
    for pattern in dangerous_patterns {
        if command_lower.contains(pattern) {
            logger::log_warn(&format!(
                "execute_remote_ssh: Potentially destructive command detected on '{}': {}",
                server_name,
                command.chars().take(200).collect::<String>()
            ));
            break;
        }
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    if !os_hint.eq_ignore_ascii_case("linux") {
        return Err("Remote SSH is only available for Linux hosts".to_string());
    }

    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

    // Execute the command
    match session.execute_command(&command).await {
        Ok(output) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            logger::log_debug(&format!(
                "execute_remote_ssh: SUCCESS '{}' {}ms output_len={}",
                server_name,
                elapsed_ms,
                output.len()
            ));

            Ok(RemoteSshResponse {
                success: true,
                output,
                error: None,
            })
        }
        Err(e) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            let error_msg = e.to_string();
            logger::log_warn(&format!(
                "execute_remote_ssh: ERROR '{}' {}ms error='{}'",
                server_name, elapsed_ms, error_msg
            ));

            Ok(RemoteSshResponse {
                success: false,
                output: String::new(),
                error: Some(error_msg),
            })
        }
    }
}

/// Execute a shell command on a remote Linux host via SSH with PTY (terminal) support.
/// This is for curses/ncurses applications like top, htop, vim, nano, etc.
#[tauri::command]
async fn execute_remote_ssh_pty(
    server_name: String,
    command: String,
    cols: Option<u32>,
    rows: Option<u32>,
) -> Result<RemoteSshResponse, String> {
    let start = SystemTime::now();
    let cols = cols.unwrap_or(120);
    let rows = rows.unwrap_or(40);

    logger::log_debug(&format!(
        "execute_remote_ssh_pty: START '{}' command='{}' cols={} rows={}",
        server_name,
        command.chars().take(100).collect::<String>(),
        cols,
        rows
    ));

    if server_name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }
    if command.trim().is_empty() {
        return Err("Command cannot be empty".to_string());
    }

    let os_hint = resolve_host_os_type(&server_name).await;
    if !os_hint.eq_ignore_ascii_case("linux") {
        return Err("Remote SSH is only available for Linux hosts".to_string());
    }

    let (credentials, _) = resolve_host_credentials(&server_name).await?;

    let session = LinuxRemoteSession::connect(server_name.clone(), credentials)
        .await
        .map_err(|e| format!("Failed to connect to {}: {}", server_name, e))?;

    // Execute the command with PTY support
    match session.execute_command_with_pty(&command, cols, rows).await {
        Ok(output) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            logger::log_debug(&format!(
                "execute_remote_ssh_pty: SUCCESS '{}' {}ms output_len={}",
                server_name,
                elapsed_ms,
                output.len()
            ));

            Ok(RemoteSshResponse {
                success: true,
                output,
                error: None,
            })
        }
        Err(e) => {
            let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
            let error_msg = e.to_string();
            logger::log_warn(&format!(
                "execute_remote_ssh_pty: ERROR '{}' {}ms error='{}'",
                server_name, elapsed_ms, error_msg
            ));

            Ok(RemoteSshResponse {
                success: false,
                output: String::new(),
                error: Some(error_msg),
            })
        }
    }
}

/// Quick heartbeat status for high-frequency refresh (no heavy process/disk sampling)
#[tauri::command]
async fn get_quick_status(
    server_name: String,
    services: Option<Vec<String>>,
    tcp_ports: Option<Vec<u16>>,
) -> Result<QuickStatus, String> {
    let start = SystemTime::now();
    logger::log_debug_verbose(&format!("get_quick_status: START '{}'", server_name));

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
        Ok(status) => logger::log_debug_verbose(&format!(
            "get_quick_status: COMPLETE '{}' {}ms ping={}",
            server_name, elapsed_ms, status.ping_ok
        )),
        Err(e) => logger::log_error(&format!(
            "get_quick_status: FAILED '{}' {}ms: {}",
            server_name, elapsed_ms, e
        )),
    }

    result
}

/// Probe basic reachability via ICMP ping and TCP connect attempts to selected ports.
async fn probe_reachability(
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use quickprobe::utils::CredentialError;
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::tempdir;
    use tokio::runtime::Runtime;

    fn lock_appdata() -> MutexGuard<'static, ()> {
        db::appdata_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn with_temp_appdata<F: FnOnce() -> Result<(), String>>(f: F) {
        let _guard = lock_appdata();

        let temp = tempdir().expect("tempdir");
        let appdata = temp.path().to_path_buf();
        let original = std::env::var("APPDATA").ok();
        let original_backend = std::env::var("QP_PERSIST_BACKEND").ok();
        std::env::set_var("APPDATA", &appdata);
        if original_backend.is_none() {
            std::env::set_var("QP_PERSIST_BACKEND", "sqlite");
        }
        // ensure clean state
        let _ = std::fs::remove_dir_all(appdata.join("QuickProbe"));
        let result = f();
        if let Err(e) = result {
            panic!("test failed: {}", e);
        }
        if let Some(val) = original {
            std::env::set_var("APPDATA", val);
        }
        match original_backend {
            Some(val) => std::env::set_var("QP_PERSIST_BACKEND", val),
            None => std::env::remove_var("QP_PERSIST_BACKEND"),
        }
    }

    fn with_backend<F: FnOnce() -> Result<(), String>>(backend: &str, f: F) -> Result<(), String> {
        let original = std::env::var("QP_PERSIST_BACKEND").ok();
        std::env::set_var("QP_PERSIST_BACKEND", backend);
        let result = f();
        match original {
            Some(val) => std::env::set_var("QP_PERSIST_BACKEND", val),
            None => std::env::remove_var("QP_PERSIST_BACKEND"),
        }
        result
    }

    #[derive(Default)]
    struct MemoryStore {
        inner: Mutex<HashMap<String, Credentials>>,
    }

    #[async_trait]
    impl CredentialStore for MemoryStore {
        async fn store(
            &self,
            profile: &CredentialProfile,
            creds: &Credentials,
        ) -> Result<(), CredentialError> {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.insert(profile.as_str().to_string(), creds.clone());
            Ok(())
        }

        async fn retrieve(
            &self,
            profile: &CredentialProfile,
        ) -> Result<Option<Credentials>, CredentialError> {
            let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            Ok(guard.get(profile.as_str()).cloned())
        }

        async fn exists(&self, profile: &CredentialProfile) -> Result<bool, CredentialError> {
            let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            Ok(guard.contains_key(profile.as_str()))
        }

        async fn delete(&self, profile: &CredentialProfile) -> Result<(), CredentialError> {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.remove(profile.as_str());
            Ok(())
        }
    }

    fn make_creds(user: &str) -> Credentials {
        Credentials::new(
            Username::new(user).expect("username"),
            SecureString::new("Secret123!"),
        )
    }

    #[test]
    fn resolve_host_credentials_prefers_host_profile() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let store = MemoryStore::default();
            let server = "web1.contoso.com";
            let host_profile = CredentialProfile::new("QuickProbe:HOST/WEB1");
            let rdp_profile = CredentialProfile::new(format!("TERMSRV/{}", server));
            let default_profile = CredentialProfile::default();

            store
                .store(&default_profile, &make_creds("global-user"))
                .await
                .expect("store default");
            store
                .store(&rdp_profile, &make_creds("rdp-user"))
                .await
                .expect("store rdp");
            let host_creds = make_creds("host-user");
            store
                .store(&host_profile, &host_creds)
                .await
                .expect("store host");

            let (creds, used_profile) = resolve_host_credentials_with_store(&store, server)
                .await
                .expect("resolve");

            assert_eq!(used_profile, host_profile.as_str());
            assert_eq!(creds.username().as_str(), host_creds.username().as_str());
        });
    }

    #[test]
    fn resolve_host_credentials_prefers_rdp_over_default() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let store = MemoryStore::default();
            let server = "app1.contoso.com";
            let rdp_profile = CredentialProfile::new(format!("TERMSRV/{}", server));
            let default_profile = CredentialProfile::default();
            let host_profile = CredentialProfile::new("QuickProbe:HOST/APP1");

            let rdp_creds = make_creds("rdp-user");
            store
                .store(&rdp_profile, &rdp_creds)
                .await
                .expect("store rdp");
            store
                .store(&default_profile, &make_creds("global-user"))
                .await
                .expect("store default");

            let (creds, used_profile) = resolve_host_credentials_with_store(&store, server)
                .await
                .expect("resolve");

            assert_eq!(used_profile, rdp_profile.as_str());
            assert_eq!(creds.username().as_str(), rdp_creds.username().as_str());

            // Should promote to host profile for future reuse
            let promoted = store.retrieve(&host_profile).await.expect("retrieve host");
            assert!(promoted.is_some());
            assert_eq!(
                promoted.unwrap().username().as_str(),
                rdp_creds.username().as_str()
            );
        });
    }

    #[test]
    fn resolve_host_credentials_falls_back_to_default() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let store = MemoryStore::default();
            let server = "db1.contoso.com";
            let default_profile = CredentialProfile::default();
            let host_profile = CredentialProfile::new("QuickProbe:HOST/DB1");

            let default_creds = make_creds("global-user");
            store
                .store(&default_profile, &default_creds)
                .await
                .expect("store default");

            let (creds, used_profile) = resolve_host_credentials_with_store(&store, server)
                .await
                .expect("resolve");

            assert_eq!(used_profile, default_profile.as_str());
            assert_eq!(creds.username().as_str(), default_creds.username().as_str());

            // Host profile should be backfilled for next lookup
            let promoted = store.retrieve(&host_profile).await.expect("retrieve host");
            assert!(promoted.is_some());
            assert_eq!(
                promoted.unwrap().username().as_str(),
                default_creds.username().as_str()
            );
        });
    }

    #[test]
    fn normalize_host_name_strips_domain_and_uppercases() {
        let out = normalize_host_name("server01.contoso.com").unwrap();
        assert_eq!(out, "SERVER01");
    }

    #[test]
    fn normalize_host_name_rejects_empty() {
        assert!(normalize_host_name("").is_err());
        assert!(normalize_host_name("   ").is_err());
    }

    #[test]
    fn merge_hosts_preserves_existing_and_uses_ad_description() {
        let existing = vec![
            ServerInfo {
                name: "app1.contoso.com".to_string(),
                notes: Some("keep me".to_string()),
                group: None,
                services: Some(vec!["WINRM".to_string(), "DFSR".to_string()]),
                os_type: Some("Windows".to_string()),
            },
            ServerInfo {
                name: "DB1".to_string(),
                notes: Some("db".to_string()),
                group: None,
                services: Some(vec!["SQL".to_string()]),
                os_type: Some("Windows".to_string()),
            },
        ];

        let discovered = vec![
            AdComputer {
                fqdn: "app1.contoso.local".to_string(),
                description: Some("AD desc that should not override".to_string()),
            },
            AdComputer {
                fqdn: "web1.contoso.local".to_string(),
                description: Some("Web role".to_string()),
            },
            AdComputer {
                fqdn: "db1.contoso.com".to_string(),
                description: Some("Duplicate".to_string()),
            },
        ];

        let merged = merge_hosts(existing, discovered, true).expect("merge should succeed");
        assert_eq!(merged.len(), 3);

        let app1 = merged.iter().find(|h| h.name == "APP1").expect("app1");
        assert_eq!(app1.notes.as_deref(), Some("keep me"));
        assert_eq!(
            app1.services.as_ref().unwrap(),
            &vec!["WINRM".to_string(), "DFSR".to_string()]
        );

        let web1 = merged.iter().find(|h| h.name == "WEB1").expect("web1");
        assert_eq!(web1.notes.as_deref(), Some("Web role"));
        assert!(web1.services.is_none());

        let db1 = merged.iter().find(|h| h.name == "DB1").expect("db1");
        assert_eq!(db1.notes.as_deref(), Some("db"));
        assert_eq!(db1.services.as_ref().unwrap(), &vec!["SQL".to_string()]);
    }

    #[test]
    fn merge_hosts_removes_missing_entries() {
        let existing = vec![
            ServerInfo {
                name: "app1.contoso.com".to_string(),
                notes: Some("keep me".to_string()),
                group: None,
                services: Some(vec!["WINRM".to_string()]),
                os_type: Some("Windows".to_string()),
            },
            ServerInfo {
                name: "DB1".to_string(),
                notes: Some("db".to_string()),
                group: Some("SQL".to_string()),
                services: Some(vec!["SQL".to_string()]),
                os_type: Some("Windows".to_string()),
            },
        ];

        let discovered = vec![AdComputer {
            fqdn: "db1.contoso.com".to_string(),
            description: Some("Database server".to_string()),
        }];

        let merged = merge_hosts(existing, discovered, true).expect("merge should succeed");
        assert_eq!(merged.len(), 1);
        let db1 = merged.first().expect("db1 present");
        assert_eq!(db1.name, "DB1");
        assert_eq!(db1.notes.as_deref(), Some("db"));
        assert_eq!(db1.group.as_deref(), Some("SQL"));
        assert_eq!(db1.services.as_ref().unwrap(), &vec!["SQL".to_string()]);
    }

    #[test]
    fn merge_hosts_can_keep_missing_windows_when_requested() {
        let existing = vec![
            ServerInfo {
                name: "app1.contoso.com".to_string(),
                notes: Some("keep me".to_string()),
                group: Some("App".to_string()),
                services: Some(vec!["WINRM".to_string()]),
                os_type: Some("Windows".to_string()),
            },
            ServerInfo {
                name: "db1.contoso.com".to_string(),
                notes: Some("db".to_string()),
                group: None,
                services: Some(vec!["SQL".to_string()]),
                os_type: Some("Windows".to_string()),
            },
        ];

        let discovered = vec![
            AdComputer {
                fqdn: "app1.contoso.local".to_string(),
                description: Some("AD desc that should not override".to_string()),
            },
            AdComputer {
                fqdn: "web1.contoso.com".to_string(),
                description: Some("Web role".to_string()),
            },
        ];

        let merged = merge_hosts(existing, discovered, false).expect("merge should succeed");
        assert_eq!(merged.len(), 3);

        let app1 = merged.iter().find(|h| h.name == "APP1").expect("app1");
        assert_eq!(app1.notes.as_deref(), Some("keep me"));
        let db1 = merged.iter().find(|h| h.name == "DB1").expect("db1 kept");
        assert_eq!(db1.notes.as_deref(), Some("db"));
        let web1 = merged
            .iter()
            .find(|h| h.name == "WEB1")
            .expect("web1 added");
        assert_eq!(web1.notes.as_deref(), Some("Web role"));
    }

    #[test]
    fn merge_hosts_keeps_linux_hosts_and_adds_discovered_windows() {
        let existing = vec![ServerInfo {
            name: "linux01.contoso.com".to_string(),
            notes: Some("linux host".to_string()),
            group: Some("Linux".to_string()),
            services: None,
            os_type: Some("Linux".to_string()),
        }];

        let discovered = vec![AdComputer {
            fqdn: "web1.contoso.com".to_string(),
            description: Some("Windows Web".to_string()),
        }];

        let merged = merge_hosts(existing, discovered, true).expect("merge should succeed");
        assert_eq!(merged.len(), 2);
        let linux = merged
            .iter()
            .find(|h| h.name == "LINUX01")
            .expect("linux kept");
        assert_eq!(linux.os_type.as_deref(), Some("Linux"));
        let web = merged
            .iter()
            .find(|h| h.name == "WEB1")
            .expect("web1 added");
        assert_eq!(web.notes.as_deref(), Some("Windows Web"));
    }

    #[test]
    fn save_server_notes_updates_normalized_row_and_preserves_services() {
        with_temp_appdata(|| {
            let initial = vec![
                HostUpdate {
                    name: "db1.contoso.com".to_string(),
                    notes: Some("old".to_string()),
                    group: None,
                    services: Some(vec!["SQL".to_string(), "WinRM".to_string()]),
                    os_type: Some("Windows".to_string()),
                },
                HostUpdate {
                    name: "WEB1".to_string(),
                    notes: Some("web".to_string()),
                    group: None,
                    services: None,
                    os_type: Some("Windows".to_string()),
                },
            ];
            write_hosts_sqlite(&initial)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            rt.block_on(save_server_notes(
                "db1".to_string(),
                "new-notes".to_string(),
            ))?;

            let hosts = rt.block_on(get_hosts())?;
            let db1 = hosts.iter().find(|h| h.name == "DB1").unwrap();
            assert_eq!(db1.notes.as_deref(), Some("new-notes"));
            assert_eq!(
                db1.services.as_ref().unwrap(),
                &vec!["SQL".to_string(), "WINRM".to_string()]
            );
            let web1 = hosts.iter().find(|h| h.name == "WEB1").unwrap();
            assert_eq!(web1.notes.as_deref(), Some("web"));
            Ok(())
        });
    }

    #[test]
    fn get_hosts_allows_empty_list() {
        with_temp_appdata(|| {
            // Empty dataset should still return an empty list
            write_hosts_sqlite(&[])?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let hosts = rt.block_on(get_hosts())?;
            assert!(hosts.is_empty());
            Ok(())
        });
    }

    #[test]
    fn get_hosts_preserves_notes_with_commas_and_services() {
        with_temp_appdata(|| {
            let initial = vec![HostUpdate {
                name: "app1".to_string(),
                notes: Some("Primary, Site, DC".to_string()),
                group: None,
                services: Some(vec!["WinRM".to_string(), "DFSR".to_string()]),
                os_type: Some("Windows".to_string()),
            }];

            write_hosts_sqlite(&initial)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let hosts = rt.block_on(get_hosts())?;

            assert_eq!(hosts.len(), 1);
            assert_eq!(hosts[0].notes.as_deref(), Some("Primary, Site, DC"));
            assert_eq!(
                hosts[0].services.as_ref().unwrap(),
                &vec!["WINRM".to_string(), "DFSR".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn get_hosts_splits_group_from_notes_column() {
        with_temp_appdata(|| {
            let initial = vec![HostUpdate {
                name: "app1.contoso.com".to_string(),
                notes: Some("Domain Controller".to_string()),
                group: Some("Azure".to_string()),
                services: Some(vec!["WinRM".to_string()]),
                os_type: Some("Windows".to_string()),
            }];

            write_hosts_sqlite(&initial)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let hosts = rt.block_on(get_hosts())?;

            assert_eq!(hosts.len(), 1);
            assert_eq!(hosts[0].name, "APP1");
            assert_eq!(hosts[0].notes.as_deref(), Some("Domain Controller"));
            assert_eq!(hosts[0].group.as_deref(), Some("Azure"));
            assert_eq!(
                hosts[0].services.as_ref().unwrap(),
                &vec!["WINRM".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn sqlite_write_persists_across_reopen() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                let hosts = vec![HostUpdate {
                    name: "app1.contoso.com".to_string(),
                    notes: Some("note".to_string()),
                    group: Some("Core".to_string()),
                    services: Some(vec!["winrm".to_string()]),
                    os_type: Some("Windows".to_string()),
                }];
                persist_hosts(&hosts)?;

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                let loaded = rt.block_on(get_hosts())?;
                assert_eq!(loaded.len(), 1);
                assert_eq!(loaded[0].name, "APP1");
                assert_eq!(loaded[0].notes.as_deref(), Some("note"));
                Ok(())
            })
        });
    }

    #[test]
    fn sqlite_edit_normalizes_and_updates() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                let initial = vec![HostUpdate {
                    name: "app1".to_string(),
                    notes: Some("old".to_string()),
                    group: Some("dev".to_string()),
                    services: Some(vec!["dns".to_string()]),
                    os_type: Some("linux".to_string()),
                }];
                persist_hosts(&initial)?;

                let updated = vec![HostUpdate {
                    name: "app1.domain.local".to_string(),
                    notes: Some("new note".to_string()),
                    group: Some(" core ".to_string()),
                    services: Some(vec!["winrm".to_string(), "dns".to_string()]),
                    os_type: Some("windows".to_string()),
                }];
                persist_hosts(&updated)?;

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                let loaded = rt.block_on(get_hosts())?;
                assert_eq!(loaded.len(), 1);
                assert_eq!(loaded[0].name, "APP1");
                assert_eq!(loaded[0].notes.as_deref(), Some("new note"));
                assert_eq!(loaded[0].group.as_deref(), Some("core"));
                assert_eq!(
                    loaded[0].services.as_ref().unwrap(),
                    &vec!["WINRM".to_string(), "DNS".to_string()]
                );
                assert_eq!(loaded[0].os_type.as_deref(), Some("Windows"));
                Ok(())
            })
        });
    }

    #[test]
    fn sqlite_delete_removes_host() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                let initial = vec![
                    HostUpdate {
                        name: "app1".to_string(),
                        notes: None,
                        group: None,
                        services: None,
                        os_type: None,
                    },
                    HostUpdate {
                        name: "app2".to_string(),
                        notes: None,
                        group: None,
                        services: None,
                        os_type: None,
                    },
                ];
                persist_hosts(&initial)?;

                let updated = vec![HostUpdate {
                    name: "app1".to_string(),
                    notes: Some("stay".to_string()),
                    group: None,
                    services: None,
                    os_type: None,
                }];
                persist_hosts(&updated)?;

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                let loaded = rt.block_on(get_hosts())?;
                assert_eq!(loaded.len(), 1);
                assert_eq!(loaded[0].name, "APP1");
                assert_eq!(loaded[0].notes.as_deref(), Some("stay"));
                Ok(())
            })
        });
    }

    #[test]
    fn sqlite_concurrent_upserts_do_not_busy() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                std::thread::scope(|s| {
                    for _ in 0..4 {
                        s.spawn(|| {
                            let hosts = vec![
                                HostUpdate {
                                    name: "app1".to_string(),
                                    notes: Some("note".to_string()),
                                    group: Some("core".to_string()),
                                    services: Some(vec!["winrm".to_string()]),
                                    os_type: Some("Windows".to_string()),
                                },
                                HostUpdate {
                                    name: "db1".to_string(),
                                    notes: Some("db".to_string()),
                                    group: Some("core".to_string()),
                                    services: Some(vec!["sql".to_string()]),
                                    os_type: Some("Windows".to_string()),
                                },
                            ];
                            persist_hosts(&hosts).expect("persist ok");
                        });
                    }
                });

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                let loaded = rt.block_on(get_hosts())?;
                assert_eq!(loaded.len(), 2);
                Ok(())
            })
        });
    }

    #[test]
    fn kv_defaults_match_ui_expectations() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                let settings = kv_get_value("qp_settings")?;
                assert_eq!(settings, Some(default_qp_settings_json()));
                let server_order = kv_get_value("qp_server_order")?;
                assert_eq!(server_order.as_deref(), Some("[]"));
                let host_view_mode = kv_get_value("qp_host_view_mode")?;
                assert_eq!(host_view_mode.as_deref(), Some("cards"));
                let hosts_changed = kv_get_value("qp_hosts_changed")?;
                assert!(hosts_changed.is_none());
                Ok(())
            })
        });
    }

    #[test]
    fn kv_round_trips_for_known_keys() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                kv_set_value("qp_settings", r#"{"theme":"dark"}"#)?;
                kv_set_value("qp_server_order", r#"["A","B"]"#)?;
                kv_set_value("qp_host_view_mode", "groups")?;
                kv_set_value("qp_hosts_changed", "12345")?;

                assert_eq!(
                    kv_get_value("qp_settings")?,
                    Some(r#"{"theme":"dark"}"#.to_string())
                );
                assert_eq!(
                    kv_get_value("qp_server_order")?,
                    Some(r#"["A","B"]"#.to_string())
                );
                assert_eq!(
                    kv_get_value("qp_host_view_mode")?,
                    Some("groups".to_string())
                );
                assert_eq!(kv_get_value("qp_hosts_changed")?, Some("12345".to_string()));
                Ok(())
            })
        });
    }

    #[test]
    fn settings_get_all_returns_defaults_when_empty() {
        with_temp_appdata(|| {
            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let bundle = rt.block_on(settings_get_all())?;
            let expected_settings: serde_json::Value =
                serde_json::from_str(&default_qp_settings_json()).unwrap();
            assert_eq!(bundle.qp_settings, expected_settings);
            assert_eq!(bundle.qp_server_order, serde_json::json!([]));
            assert_eq!(bundle.qp_host_view_mode, serde_json::json!("cards"));
            assert!(bundle.qp_hosts_changed.is_none());
            Ok(())
        });
    }

    #[test]
    fn settings_set_all_round_trips_values() {
        with_temp_appdata(|| {
            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let payload = SettingsSetPayload {
                qp_settings: serde_json::json!({
                    "probeTimeoutSeconds": 45,
                    "infoTimeoutMs": 3100,
                    "warningTimeoutMs": 4200,
                    "errorTimeoutMs": 1,
                    "locationMappings": [{"range":"10.0.0.0/8","label":"LAN"}],
                    "theme": "dark"
                }),
                qp_server_order: serde_json::json!(["B", "A"]),
                qp_host_view_mode: serde_json::json!("groups"),
                qp_hosts_changed: Some(serde_json::json!("12345")),
            };
            rt.block_on(settings_set_all(payload))?;

            let bundle = rt.block_on(settings_get_all())?;
            assert_eq!(
                bundle.qp_settings.get("theme"),
                Some(&serde_json::json!("dark"))
            );
            assert_eq!(
                bundle.qp_settings.get("probeTimeoutSeconds"),
                Some(&serde_json::json!(45))
            );
            assert_eq!(bundle.qp_server_order, serde_json::json!(["B", "A"]));
            assert_eq!(bundle.qp_host_view_mode, serde_json::json!("groups"));
            assert_eq!(bundle.qp_hosts_changed, Some(serde_json::json!("12345")));
            Ok(())
        });
    }

    #[test]
    fn settings_set_all_preserves_hosts_changed_when_missing() {
        with_temp_appdata(|| {
            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let initial = SettingsSetPayload {
                qp_settings: serde_json::json!({
                    "probeTimeoutSeconds": 60,
                    "infoTimeoutMs": 3500,
                    "warningTimeoutMs": 4500,
                    "errorTimeoutMs": 0,
                    "locationMappings": [],
                    "theme": "light"
                }),
                qp_server_order: serde_json::json!(["A"]),
                qp_host_view_mode: serde_json::json!("cards"),
                qp_hosts_changed: Some(serde_json::json!("original")),
            };
            rt.block_on(settings_set_all(initial))?;

            let update_without_hosts_changed = SettingsSetPayload {
                qp_settings: serde_json::json!({
                    "probeTimeoutSeconds": 30,
                    "infoTimeoutMs": 2000,
                    "warningTimeoutMs": 3000,
                    "errorTimeoutMs": 0,
                    "locationMappings": [],
                    "theme": "dark"
                }),
                qp_server_order: serde_json::json!(["A", "B"]),
                qp_host_view_mode: serde_json::json!("groups"),
                qp_hosts_changed: None,
            };
            rt.block_on(settings_set_all(update_without_hosts_changed))?;

            let bundle = rt.block_on(settings_get_all())?;
            assert_eq!(bundle.qp_hosts_changed, Some(serde_json::json!("original")));
            assert_eq!(bundle.qp_server_order, serde_json::json!(["A", "B"]));
            assert_eq!(bundle.qp_host_view_mode, serde_json::json!("groups"));
            Ok(())
        });
    }

    #[test]
    fn dashboard_cache_round_trips_to_local_file() {
        with_temp_appdata(|| {
            let payload = serde_json::json!({
                "cachedAt":"2024-02-01T00:00:00Z",
                "serversData":[
                    {
                        "name":"APP1",
                        "online":true,
                        "data":{"os_info":{"hostname":"APP1"}},
                        "error":null
                    },
                    {
                        "name":"APP2",
                        "online":false,
                        "data":{},
                        "error":"Timeout after 60000ms"
                    }
                ],
                "hostsSignature":"abc"
            });
            cache_set_dashboard(payload.clone())?;
            let loaded = cache_get_dashboard()?;
            assert_eq!(loaded, Some(payload));
            Ok(())
        });
    }

    #[test]
    fn export_backup_captures_sqlite_state() {
        with_temp_appdata(|| {
            persist_hosts(&[HostUpdate {
                name: "app1".to_string(),
                notes: Some("note".to_string()),
                group: Some("ops".to_string()),
                services: Some(vec!["winrm".to_string()]),
                os_type: Some("Windows".to_string()),
            }])?;
            kv_set_value("qp_settings", r#"{"theme":"light"}"#)?;
            let temp = tempdir().expect("tempdir");
            let dest = temp.path().join("backup.zip");

            export_backup(&dest, "pw")?;
            let payload = read_backup_payload(&dest, "pw")?.expect("payload exists");
            assert_eq!(payload.hosts.len(), 1);
            assert_eq!(payload.hosts[0].server_name, "APP1");
            assert_eq!(
                payload.kv.get("qp_settings").cloned().flatten(),
                Some(r#"{"theme":"light"}"#.to_string())
            );
            Ok(())
        });
    }

    #[test]
    fn restore_backup_normalizes_hosts_and_sets_flag() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                persist_hosts(&[HostUpdate {
                    name: "old".to_string(),
                    notes: None,
                    group: None,
                    services: None,
                    os_type: Some("Windows".to_string()),
                }])?;

                let mut kv_map = std::collections::BTreeMap::new();
                kv_map.insert(
                    "qp_settings".to_string(),
                    Some(r#"{"theme":"dark"}"#.to_string()),
                );

                let payload = BackupPayload {
                    schema_version: BACKUP_SCHEMA_VERSION,
                    exported_at: Utc::now().to_rfc3339(),
                    app_version: env!("CARGO_PKG_VERSION").to_string(),
                    mode: compute_runtime_mode_info()?,
                    hosts: vec![HostBackupRow {
                        server_name: "app1.contoso.com".to_string(),
                        notes: Some("note".to_string()),
                        group: Some("core".to_string()),
                        os_type: "windows".to_string(),
                        services: Some("winrm;sql".to_string()),
                    }],
                    kv: kv_map,
                };

                let temp = tempdir().expect("tempdir");
                let dest = temp.path().join("restore.zip");
                write_encrypted_backup(&dest, "pw", &payload)?;

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                rt.block_on(import_backup_encrypted(
                    dest.to_string_lossy().to_string(),
                    "pw".to_string(),
                ))?;

                let hosts = read_hosts_from_sqlite()?;
                assert_eq!(hosts.len(), 1);
                assert_eq!(hosts[0].name, "APP1");
                assert_eq!(
                    hosts[0].services.as_ref().unwrap(),
                    &vec!["WINRM".to_string(), "SQL".to_string()]
                );

                let hosts_changed = kv_get_value("qp_hosts_changed")?;
                assert!(hosts_changed.is_some());

                let app_dir = get_app_data_dir()?;
                let pre_backups: Vec<_> = std::fs::read_dir(app_dir)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        let lower = name.to_lowercase();
                        lower.starts_with("quickprobe-pre-restore-")
                    })
                    .collect();
                assert!(!pre_backups.is_empty());
                Ok(())
            })
        });
    }

    #[test]
    fn restore_backup_is_atomic_on_failure() {
        with_temp_appdata(|| {
            persist_hosts(&[HostUpdate {
                name: "good".to_string(),
                notes: None,
                group: None,
                services: None,
                os_type: Some("Windows".to_string()),
            }])?;

            let payload = BackupPayload {
                schema_version: BACKUP_SCHEMA_VERSION,
                exported_at: Utc::now().to_rfc3339(),
                app_version: env!("CARGO_PKG_VERSION").to_string(),
                mode: compute_runtime_mode_info()?,
                hosts: vec![HostBackupRow {
                    server_name: "".to_string(),
                    notes: None,
                    group: None,
                    os_type: "Windows".to_string(),
                    services: None,
                }],
                kv: std::collections::BTreeMap::new(),
            };

            let temp = tempdir().expect("tempdir");
            let dest = temp.path().join("invalid.zip");
            write_encrypted_backup(&dest, "pw", &payload)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let result = rt.block_on(import_backup_encrypted(
                dest.to_string_lossy().to_string(),
                "pw".to_string(),
            ));
            assert!(result.is_err());

            let hosts = read_hosts_from_sqlite()?;
            assert_eq!(hosts.len(), 1);
            assert_eq!(hosts[0].name, "GOOD");
            Ok(())
        });
    }
}

/// Format a domain like "contoso.com" into "DC=contoso,DC=com"
fn format_base_dn(domain: &str) -> Result<String, String> {
    let parts: Vec<&str> = domain.split('.').filter(|p| !p.trim().is_empty()).collect();
    if parts.is_empty() {
        return Err("Domain is required".to_string());
    }
    Ok(parts
        .into_iter()
        .map(|p| format!("DC={}", p))
        .collect::<Vec<String>>()
        .join(","))
}

fn build_bind_username(username: &str, domain: &str) -> String {
    if username.contains('@') || username.contains('\\') {
        username.to_string()
    } else {
        format!("{}@{}", username, domain)
    }
}

async fn ldap_search_windows_servers(
    domain: &str,
    server: &str,
    username: &str,
    password: &str,
) -> Result<Vec<AdComputer>, String> {
    let base_dn = format_base_dn(domain)?;
    let url = format!("ldap://{}:389", server);

    let (conn, mut ldap) = LdapConnAsync::new(&url)
        .await
        .map_err(|e| format!("Failed to connect LDAP: {}", e))?;
    ldap3::drive!(conn);

    let bind_user = build_bind_username(username, domain);
    ldap.simple_bind(&bind_user, password)
        .await
        .map_err(|e| format!("LDAP bind failed: {}", e))?
        .success()
        .map_err(|e| format!("LDAP bind rejected: {}", e))?;

    let filter = "(&(objectClass=computer)(operatingSystem=Windows Server*)(dNSHostName=*))";
    let attrs = vec!["dNSHostName", "description", "operatingSystem"];
    let (entries, _res) = ldap
        .search(&base_dn, Scope::Subtree, filter, attrs)
        .await
        .map_err(|e| format!("LDAP search failed: {}", e))?
        .success()
        .map_err(|e| format!("LDAP search error: {}", e))?;

    let mut computers = Vec::new();
    let mut seen = HashSet::new();

    for entry in entries {
        let se = SearchEntry::construct(entry);
        if let Some(values) = se.attrs.get("dNSHostName") {
            if let Some(host) = values.first() {
                let key = host.to_lowercase();
                if !seen.insert(key) {
                    continue;
                }

                let description = se
                    .attrs
                    .get("description")
                    .and_then(|vals| vals.first())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());

                computers.push(AdComputer {
                    fqdn: host.to_string(),
                    description,
                });
            }
        }
    }

    ldap.unbind().await.ok();

    computers.sort_by(|a, b| a.fqdn.to_lowercase().cmp(&b.fqdn.to_lowercase()));
    if computers.is_empty() {
        return Err("No Windows Server hosts found".to_string());
    }
    Ok(computers)
}

/// Merges Active Directory discovered computers with existing host inventory.
///
/// ## Merge Strategy
///
/// This function performs a three-way merge:
/// 1. **Linux hosts** from existing inventory are preserved (AD doesn't contain Linux)
/// 2. **Windows hosts found in AD** are updated:
///    - User-provided `notes` and `group` are preserved (not overwritten by AD description)
///    - AD description is used only if notes are empty
///    - Services list is preserved from existing inventory
/// 3. **New Windows hosts from AD** are added with AD description as initial notes
/// 4. **Windows hosts removed from AD**:
///    - If `remove_missing_windows = false`: Preserved (default, safer)
///    - If `remove_missing_windows = true`: Removed from inventory
///
/// ## Deduplication
///
/// - Hostnames are normalized (case-insensitive, trailing dots removed)
/// - Duplicate FQDNs after normalization: First occurrence wins
/// - Case-insensitive matching prevents "SERVER01" and "server01" duplicates
///
/// ## Edge Cases
///
/// - Empty AD descriptions → Replaced with "No Description Specified"
/// - Hosts with no OS type → Defaults to "Windows" (AD only contains Windows)
/// - Linux hosts are never removed, regardless of `remove_missing_windows` setting
///
/// ## Parameters
///
/// - `existing`: Current host inventory (may include Windows + Linux)
/// - `discovered`: Windows computers found in Active Directory via LDAP
/// - `remove_missing_windows`: If true, removes Windows hosts not found in AD
///
/// ## Returns
///
/// Merged list of hosts ready to write to database via `set_hosts()`.
fn merge_hosts(
    existing: Vec<ServerInfo>,
    discovered: Vec<AdComputer>,
    remove_missing_windows: bool,
) -> Result<Vec<HostUpdate>, String> {
    let mut existing_map = std::collections::HashMap::new();
    let mut merged: Vec<HostUpdate> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for host in existing {
        let normalized_name = normalize_host_name(&host.name)?;
        let key = normalized_name.to_lowercase();
        let os_label = host
            .os_type
            .clone()
            .unwrap_or_else(|| "Windows".to_string());
        let is_windows = !os_label.eq_ignore_ascii_case("linux");

        if is_windows {
            // keep the first occurrence after normalization
            existing_map.entry(key).or_insert(host);
        } else if seen.insert(key.clone()) {
            merged.push(HostUpdate {
                name: normalized_name,
                notes: host.notes,
                group: host.group,
                services: host.services,
                os_type: Some(os_label),
            });
        }
    }

    for entry in discovered {
        let normalized_name = normalize_host_name(&entry.fqdn)?;
        let key = normalized_name.to_lowercase();
        if !seen.insert(key.clone()) {
            continue;
        }

        if let Some(existing) = existing_map.get(&key) {
            merged.push(HostUpdate {
                name: normalized_name,
                notes: existing
                    .notes
                    .clone()
                    .or_else(|| entry.description.clone())
                    .or_else(|| Some("No Description Specified".to_string())),
                group: existing.group.clone(),
                services: existing.services.clone(),
                os_type: existing
                    .os_type
                    .clone()
                    .or_else(|| Some("Windows".to_string())),
            });
        } else {
            let notes = entry
                .description
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "No Description Specified".to_string());

            merged.push(HostUpdate {
                name: normalized_name,
                notes: Some(notes),
                group: None,
                services: None,
                os_type: Some("Windows".to_string()),
            });
        }
    }

    if !remove_missing_windows {
        for (key, host) in existing_map.into_iter() {
            if seen.contains(&key) {
                continue;
            }
            let normalized_name = normalize_host_name(&host.name)?;
            merged.push(HostUpdate {
                name: normalized_name,
                notes: host.notes.clone(),
                group: host.group.clone(),
                services: host.services.clone(),
                os_type: host.os_type.clone().or_else(|| Some("Windows".to_string())),
            });
        }
    }

    Ok(merged)
}

/// Scan Active Directory for Windows servers and merge into hosts.csv using LDAP (no PowerShell)
#[tauri::command]
async fn scan_domain(
    domain: Option<String>,
    server: Option<String>,
    skip_delete: Option<bool>,
) -> Result<ScanResult, String> {
    let start = SystemTime::now();
    let domain = domain.unwrap_or_default().trim().to_string();
    let server = server.unwrap_or_default().trim().to_string();
    let skip_delete = skip_delete.unwrap_or(false);

    logger::log_info(&format!(
        "scan_domain: domain='{}' dc='{}' skip_delete={}",
        domain, server, skip_delete
    ));

    if domain.is_empty() {
        return Err("Domain is required".to_string());
    }
    if server.is_empty() {
        return Err("Domain controller is required".to_string());
    }

    // Retrieve stored credentials
    let credential_store = WindowsCredentialManager::new();
    let profile = CredentialProfile::default();

    let credentials = credential_store
        .retrieve(&profile)
        .await
        .map_err(|e| format!("Failed to retrieve credentials: {}", e))?
        .ok_or_else(|| "No credentials stored. Please log in first.".to_string())?;

    let username = credentials.username().as_str();
    let password = credentials.password().as_str();

    let discovered = ldap_search_windows_servers(&domain, &server, username, password).await?;
    let discovered_count = discovered.len();
    logger::log_debug(&format!("scan_domain: LDAP found {}", discovered_count));

    let discovered_keys: std::collections::HashSet<String> = discovered
        .iter()
        .filter_map(|entry| normalize_host_name(&entry.fqdn).ok())
        .map(|n| n.to_lowercase())
        .collect();

    // Merge with existing hosts while preserving notes/services
    let existing = get_hosts().await?;
    let existing_windows: std::collections::HashSet<String> = existing
        .iter()
        .filter(|h| {
            h.os_type
                .as_ref()
                .map(|os| !os.eq_ignore_ascii_case("linux"))
                .unwrap_or(true)
        })
        .filter_map(|h| normalize_host_name(&h.name).ok())
        .map(|n| n.to_lowercase())
        .collect();

    let created = discovered_keys.difference(&existing_windows).count();

    let mut merged = merge_hosts(existing, discovered, !skip_delete)?;

    let mut removed = 0usize;
    if !skip_delete {
        let discovered_lower: std::collections::HashSet<String> =
            discovered_keys.iter().cloned().collect();

        let before = merged.len();
        merged.retain(|h| {
            let is_windows = h
                .os_type
                .as_ref()
                .map(|os| !os.eq_ignore_ascii_case("linux"))
                .unwrap_or(true);
            if !is_windows {
                return true;
            }
            match normalize_host_name(&h.name) {
                Ok(name) => discovered_lower.contains(&name.to_lowercase()),
                Err(_) => true,
            }
        });
        removed = existing_windows
            .difference(&discovered_keys)
            .count()
            .max(before.saturating_sub(merged.len()));
        logger::log_debug(&format!("scan_domain: {} hosts removed", removed));
    }

    persist_hosts(&merged)?;

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    logger::log_info(&format!(
        "scan_domain: SUCCESS {}ms found={} created={} removed={} total={}",
        elapsed_ms,
        discovered_count,
        created,
        removed,
        merged.len()
    ));

    Ok(ScanResult {
        found: discovered_count,
        total: merged.len(),
        created,
        removed,
    })
}
#[tauri::command]
fn log_debug(message: String) {
    logger::log_debug(&message);
}

#[tauri::command]
fn log_info(message: String) {
    logger::log_info(&message);
}

#[tauri::command]
fn log_warn(message: String) {
    logger::log_warn(&message);
}

#[tauri::command]
fn log_error(message: String) {
    logger::log_error(&message);
}

#[cfg(debug_assertions)]
#[tauri::command]
fn open_logs_folder() -> Result<(), String> {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let dir = PathBuf::from(base).join("QuickProbe").join("logs");

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&dir)
            .spawn()
            .map_err(|e| format!("Failed to open logs folder: {}", e))?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        return Err("Open logs folder is only supported on Windows".to_string());
    }

    Ok(())
}

#[cfg(not(debug_assertions))]
#[tauri::command]
fn open_logs_folder() -> Result<(), String> {
    Err("Logs folder is only available in debug builds".to_string())
}

// ============================================================================
// Auto-Update Commands
// ============================================================================

/// Check for available updates from GitHub releases.
/// Returns information about whether an update is available and release details.
#[tauri::command]
async fn check_for_update() -> Result<UpdateInfo, String> {
    updater::check_for_update_impl().await
}

/// Download and install an update.
/// Downloads the installer to temp directory and launches it.
#[tauri::command]
async fn download_and_install_update(update_info: UpdateInfo) -> Result<(), String> {
    updater::download_and_install_impl(update_info).await
}

fn main() {
    logger::init_dev_logger();
    logger::log_info("QuickProbe starting");
    if let Ok(mode) = compute_runtime_mode_info() {
        let detail = mode
            .details
            .db_path
            .clone()
            .unwrap_or_else(|| "<unset>".to_string());
        logger::log_info(&format!(
            "Runtime mode={} source={} detail={}",
            mode.mode, mode.config_source, detail
        ));
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // When a second instance is launched, focus the existing main window
            logger::log_info("Second instance detected, focusing existing window");
            let _ = show_and_focus_main(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            let app_handle = app.handle().clone();

            // Build system tray with menu
            let options_item = MenuItem::with_id(app, "options", "Options", true, None::<&str>)?;
            let about_item = MenuItem::with_id(app, "about", "About QuickProbe", true, None::<&str>)?;
            let separator = PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&options_item, &about_item, &separator, &quit_item])?;

            // Load icon from resources - Tauri 2.x requires explicit icon
            // Use the default window icon which is already loaded by Tauri
            let icon = app.default_window_icon().cloned().expect("Default window icon not found");

            let _tray = TrayIconBuilder::new()
                .icon(icon)
                .menu(&menu)
                .tooltip("QuickProbe")
                .on_menu_event(move |app, event| {
                    match event.id.as_ref() {
                        "options" => {
                            let _ = show_and_focus_options(app);
                        }
                        "about" => {
                            let _ = show_and_focus_about(app);
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let _ = show_and_focus_main(tray.app_handle());
                    }
                })
                .build(app)?;

            // Spawn async task to check for updates on startup
            let update_app_handle = app_handle.clone();
            async_runtime::spawn(async move {
                // Small delay to ensure windows are initialized
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                logger::log_info("Checking for updates on startup...");

                match updater::check_for_update_impl().await {
                    Ok(update_info) if update_info.available => {
                        logger::log_info(&format!(
                            "Update available: {} -> {}",
                            update_info.current_version, update_info.version
                        ));

                        // Hide main window
                        if let Some(main_window) = update_app_handle.get_webview_window("main") {
                            logger::log_info("Hiding main window for update...");
                            let _ = main_window.hide();
                        }

                        // Create and show the update-required window dynamically
                        // This is more reliable than using a pre-configured window
                        match WebviewWindowBuilder::new(
                            &update_app_handle,
                            "update-required-dynamic",
                            WebviewUrl::App("update-required.html".into()),
                        )
                        .title("QuickProbe - Update Required")
                        .inner_size(500.0, 600.0)
                        .min_inner_size(450.0, 500.0)
                        .resizable(false)
                        .decorations(true)
                        .center()
                        .visible(true)
                        .skip_taskbar(false)
                        .build()
                        {
                            Ok(window) => {
                                logger::log_info("Update-required window created successfully");
                                let _ = window.set_focus();
                            }
                            Err(e) => {
                                logger::log_error(&format!("Failed to create update-required window: {}. Falling back to pre-configured window.", e));
                                // Fallback: try the pre-configured window
                                if let Some(update_window) = update_app_handle.get_webview_window("update-required") {
                                    let _ = update_window.show();
                                    let _ = update_window.set_focus();
                                } else {
                                    // If all else fails, emit event to let UI know update check is done
                                    logger::log_warn("Could not show update window, letting UI handle window visibility");
                                    if let Some(main_window) = update_app_handle.get_webview_window("main") {
                                        let _ = main_window.emit("update-check-complete", serde_json::json!({"has_update": false}));
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        // No updates available - let the UI handle window visibility
                        // The login page already calls ensureWindowVisible() appropriately
                        logger::log_info("No updates available, update check complete");
                        if let Some(main_window) = update_app_handle.get_webview_window("main") {
                            let _ = main_window.emit("update-check-complete", serde_json::json!({"has_update": false}));
                        }
                    }
                    Err(e) => {
                        // Update check failed - let the UI handle window visibility
                        logger::log_warn(&format!("Update check failed: {}. Continuing normally.", e));
                        if let Some(main_window) = update_app_handle.get_webview_window("main") {
                            let _ = main_window.emit("update-check-complete", serde_json::json!({"has_update": false, "error": e}));
                        }
                    }
                }
            });

            // Register global shortcut
            let shortcut_app_handle = app_handle.clone();
            app.global_shortcut().on_shortcut("Ctrl+Shift+R", move |_app, _shortcut, event| {
                // Only toggle on key press, not release (Tauri 2.x fires both events)
                if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                    let _ = toggle_main_window(&shortcut_app_handle);
                }
            })?;

            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => match window.label() {
                "main" => {
                    let _ = window.hide();
                    let _ = window.set_skip_taskbar(true);
                    api.prevent_close();
                }
                "options" | "about" => {
                    let _ = window.hide();
                    api.prevent_close();
                }
                "update-required" | "update-required-dynamic" => {
                    // Closing the update window should exit the app
                    // (user must either update or quit)
                }
                _ => {}
            },
            WindowEvent::Resized(_size) => {
                if window.is_minimized().unwrap_or(false) {
                    let _ = window.hide();
                    let _ = window.set_skip_taskbar(true);
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            login,
            logout,
            check_saved_credentials,
            login_with_saved_credentials,
            get_hosts,
            save_server_notes,
            update_host,
            set_hosts,
            get_system_health,
            get_quick_status,
            scan_domain,
            save_rdp_credentials,
            launch_rdp,
            launch_ssh,
            open_explorer_share,
            launch_mmc_snapin,
            launch_remote_registry,
            remote_restart,
            remote_shutdown,
            check_autostart,
            toggle_autostart,
            get_start_hidden_setting,
            set_start_hidden_setting,
            enable_options_menu,
            export_backup_encrypted,
            import_backup_encrypted,
            export_hosts_csv,
            get_app_info,
            fetch_net_adapters,
            fetch_os_info,
            get_remote_services,
            control_service,
            get_remote_processes,
            kill_process,
            execute_remote_powershell,
            execute_remote_ssh,
            execute_remote_ssh_pty,
            rename_group,
            get_runtime_mode_info,
            debug_local_store_status,
            settings_get_all,
            settings_set_all,
            cache_get_dashboard,
            cache_set_dashboard,
            persist_health_snapshot,
            load_health_snapshots,
            log_debug,
            log_info,
            log_warn,
            log_error,
            open_logs_folder,
            check_for_update,
            download_and_install_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Show the main window with normal startup logic (respects start_hidden setting).
#[allow(dead_code)]
fn show_main_window_normal(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_fullscreen(false);
        let start_hidden = load_app_settings().unwrap_or_default().start_hidden;
        let has_creds = has_saved_credentials_sync().unwrap_or(false);

        if start_hidden && has_creds {
            let _ = hide_to_tray(&window);
        } else {
            let _ = window.set_skip_taskbar(false);
            let _ = window.maximize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

/// Bring the main window to the foreground and ensure it is visible.
fn show_and_focus_main(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.set_skip_taskbar(false).map_err(|e| e.to_string())?;
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        window.set_fullscreen(false).map_err(|e| e.to_string())?;
        window.maximize().map_err(|e| e.to_string())?;
        let _ = focus_dashboard_search(&window);
    }
    Ok(())
}

/// Show or create the About window from the tray.
fn show_and_focus_about(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("about") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }

    let window = WebviewWindowBuilder::new(app, "about", WebviewUrl::App("about.html".into()))
        .title("About QuickProbe")
        .inner_size(620.0, 850.0)
        .resizable(false)
        .visible(false)
        .build()
        .map_err(|e| e.to_string())?;

    window.center().map_err(|e| e.to_string())?;
    window.show().map_err(|e| e.to_string())?;
    window.set_focus().map_err(|e| e.to_string())?;

    Ok(())
}

/// Show or create the Options window from the tray.
fn show_and_focus_options(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("options") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }

    let window = WebviewWindowBuilder::new(app, "options", WebviewUrl::App("options.html".into()))
        .title("QuickProbe Options")
        .inner_size(900.0, 920.0)
        .min_inner_size(760.0, 820.0)
        .resizable(true)
        .visible(false)
        .build()
        .map_err(|e| e.to_string())?;

    window.center().map_err(|e| e.to_string())?;
    window.show().map_err(|e| e.to_string())?;
    window.set_focus().map_err(|e| e.to_string())?;

    Ok(())
}

/// Hide window to tray and remove from taskbar.
fn hide_to_tray<R: tauri::Runtime>(window: &WebviewWindow<R>) -> Result<(), String> {
    window.hide().map_err(|e| e.to_string())?;
    window.set_skip_taskbar(true).map_err(|e| e.to_string())?;
    Ok(())
}

fn focus_dashboard_search<R: tauri::Runtime>(window: &WebviewWindow<R>) -> Result<(), String> {
    // Try to focus the dashboard search box when the window is shown.
    window
        .eval(
            r#"
            (() => {
                const el = document.getElementById('server-search')
                    || document.querySelector('input[type="search"]');
                if (el) {
                    el.focus();
                    if (typeof el.select === 'function') {
                        el.select();
                    }
                }
            })();
            "#,
        )
        .map_err(|e| e.to_string())
}

fn toggle_main_window(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let visible = window.is_visible().unwrap_or(true);
        let focused = window.is_focused().unwrap_or(false);

        if visible && focused {
            // Only hide if window is both visible AND focused
            hide_to_tray(&window)?;
        } else {
            // Show and focus if hidden, OR if visible but not focused (behind other windows)
            show_and_focus_main(app)?;
            let _ = focus_dashboard_search(&window);
        }
    }
    Ok(())
}

/// Build a minimal health summary when WinRM is unavailable but the host responds to ping.
async fn degraded_summary_or_error(
    server_name: &str,
    winrm_error: String,
    ping_checked: bool,
    ping_ok: bool,
) -> Result<SystemHealthSummary, String> {
    let reachable = if ping_checked {
        ping_ok
    } else {
        ping_host(server_name).await.unwrap_or(false)
    };

    if reachable {
        Ok(SystemHealthSummary {
            server_name: server_name.to_string(),
            winrm_issue: true,
            winrm_error: Some(winrm_error.clone()),
            os_info: OsInfo {
                hostname: server_name.to_string(),
                os_version: "Unknown".to_string(),
                build_number: "-".to_string(),
                product_type: "WinRM unavailable".to_string(),
                install_date: "-".to_string(),
            },
            disk_alerts: Vec::new(),
            total_disks: 0,
            disks: Vec::new(),
            service_alerts: 0,
            service_status: Vec::new(),
            process_count: 0,
            high_cpu_processes: Vec::new(),
            high_cpu_threshold: 50.0,
            total_memory_mb: 0.0,
            used_memory_mb: 0.0,
            memory_used_percent: 0.0,
            uptime: None,
            pending_reboot: None,
            winrm_listeners: None,
            firewall_profiles: None,
            recent_errors: None,
            net_adapters: None,
            reachability: None,
        })
    } else {
        Err(winrm_error)
    }
}

/// Lightweight ping check to see if the host is reachable at the network level.
async fn ping_host(server_name: &str) -> Result<bool, String> {
    let host = server_name.to_string();
    let output = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new("ping");
        cmd.arg("-n").arg("1").arg("-w").arg("800").arg(host);

        #[cfg(windows)]
        {
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        cmd.output()
    })
    .await
    .map_err(|e| format!("Failed to spawn ping: {}", e))?
    .map_err(|e| format!("Ping execution failed: {}", e))?;

    Ok(output.status.success())
}
