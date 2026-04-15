//! Shared helper functions: KV store, app settings, normalisation, settings bundle.

use quickprobe::constants::*;
use quickprobe::db;
use rusqlite::TransactionBehavior;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::types::*;

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Normalize a host string to an uppercase shortname (strip domain suffix)
pub(crate) fn normalize_host_name(raw: &str) -> Result<String, String> {
    crate::normalize::normalize_server_name(raw)
}

pub(crate) fn current_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub(crate) fn server_info_to_updates(servers: Vec<ServerInfo>) -> Vec<HostUpdate> {
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

// ---------------------------------------------------------------------------
// App data directory and settings
// ---------------------------------------------------------------------------

/// Get the path to the QuickProbe data directory in AppData
///
/// Returns %APPDATA%\QuickProbe on Windows, creating it if it doesn't exist.
pub(crate) fn get_app_data_dir() -> Result<PathBuf, String> {
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "APPDATA environment variable not found".to_string())?;

    let quickprobe_dir = PathBuf::from(app_data).join("QuickProbe");

    if !quickprobe_dir.exists() {
        fs::create_dir_all(&quickprobe_dir)
            .map_err(|e| format!("Failed to create QuickProbe data directory: {}", e))?;
    }

    Ok(quickprobe_dir)
}

pub(crate) fn get_settings_path() -> Result<PathBuf, String> {
    let app_dir = get_app_data_dir()?;
    Ok(app_dir.join("settings.json"))
}

pub(crate) fn load_app_settings() -> Result<AppSettings, String> {
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

pub(crate) fn save_app_settings(settings: &AppSettings) -> Result<(), String> {
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

// ---------------------------------------------------------------------------
// KV store helpers
// ---------------------------------------------------------------------------

pub(crate) fn default_qp_settings_json() -> String {
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

pub(crate) fn kv_default_value(key: &str) -> Option<String> {
    match key {
        "qp_settings" => Some(default_qp_settings_json()),
        "qp_server_order" => Some("[]".to_string()),
        "qp_host_view_mode" => Some("cards".to_string()),
        "qp_hosts_changed" => None,
        _ => None,
    }
}

pub(crate) fn kv_get_value(key: &str) -> Result<Option<String>, String> {
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

pub(crate) fn kv_set_value(key: &str, value: &str) -> Result<(), String> {
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

pub(crate) fn bump_hosts_changed_flag() -> Result<(), String> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();
    kv_set_value("qp_hosts_changed", &now_ms)
}

// ---------------------------------------------------------------------------
// Settings bundle helpers
// ---------------------------------------------------------------------------

pub(crate) fn default_settings_bundle() -> SettingsBundle {
    let qp_settings = serde_json::from_str(&default_qp_settings_json()).unwrap_or_else(|_| {
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
        qp_server_order: serde_json::json!([]),
        qp_host_view_mode: serde_json::json!("cards"),
        qp_hosts_changed: None,
    }
}

pub(crate) fn kv_value_or_default(
    conn: &rusqlite::Connection,
    key: &str,
) -> Result<Option<String>, String> {
    let value = db::kv_get(conn, KV_SCOPE_TYPE, KV_SCOPE_ID, key)
        .map_err(|e| format!("Failed to read kv value: {}", e))?;
    if value.is_some() {
        Ok(value)
    } else {
        Ok(kv_default_value(key))
    }
}

pub(crate) fn parse_kv_json(raw: Option<String>) -> Option<serde_json::Value> {
    raw.map(|val| serde_json::from_str(&val).unwrap_or(serde_json::Value::String(val)))
}

pub(crate) fn merge_settings_with_defaults(value: serde_json::Value) -> serde_json::Value {
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

pub(crate) fn settings_bundle_from_conn(
    conn: &rusqlite::Connection,
) -> Result<SettingsBundle, String> {
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

pub(crate) fn normalize_settings_object(value: serde_json::Value) -> serde_json::Value {
    merge_settings_with_defaults(value)
}

pub(crate) fn normalize_server_order(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => serde_json::Value::Array(items),
        serde_json::Value::String(s) => serde_json::from_str(&s)
            .ok()
            .filter(|v: &serde_json::Value| v.is_array())
            .unwrap_or_else(|| serde_json::json!([])),
        _ => serde_json::json!([]),
    }
}

pub(crate) fn normalize_host_view_mode(value: serde_json::Value) -> serde_json::Value {
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

pub(crate) fn normalize_hosts_changed(value: serde_json::Value) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::Null => None,
        other => Some(other),
    }
}

pub(crate) fn persist_settings_bundle(
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
