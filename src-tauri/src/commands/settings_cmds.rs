//! Settings, autostart, dashboard cache, and health snapshot commands.

use quickprobe::backup::APP_NAME;
use quickprobe::constants::*;
use quickprobe::db;
use quickprobe::platform::WindowsRegistry;
use rusqlite::TransactionBehavior;
use std::fs;
use std::time::SystemTime;

use super::helpers::*;
use super::types::*;

// ---------------------------------------------------------------------------
// Autostart helpers
// ---------------------------------------------------------------------------

pub(crate) fn check_autostart_state() -> Result<bool, String> {
    let registry = WindowsRegistry::new();
    registry
        .value_exists(REGISTRY_RUN_KEY, APP_NAME)
        .map_err(|e| format!("Failed to read autostart setting: {}", e))
}

pub(crate) fn enable_autostart() -> Result<(), String> {
    let exe_path =
        std::env::current_exe().map_err(|e| format!("Failed to resolve executable path: {}", e))?;
    let exe_path_str = exe_path.to_string_lossy().to_string();

    let registry = WindowsRegistry::new();
    registry
        .write_string(REGISTRY_RUN_KEY, APP_NAME, &exe_path_str)
        .map_err(|e| format!("Failed to enable autostart: {}", e))
}

pub(crate) fn disable_autostart() -> Result<(), String> {
    let registry = WindowsRegistry::new();
    registry
        .delete_value(REGISTRY_RUN_KEY, APP_NAME)
        .map_err(|e| format!("Failed to disable autostart: {}", e))
}

pub(crate) fn dashboard_cache_path() -> Result<std::path::PathBuf, String> {
    let dir = get_app_data_dir()?;
    let cache_dir = dir.join("cache");
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create cache directory: {}", e))?;
    Ok(cache_dir.join("dashboard-cache.json"))
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub(crate) async fn settings_get_all() -> Result<SettingsBundle, String> {
    let start = SystemTime::now();
    crate::logger::log_debug("settings_get_all: START (local)");

    let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;
    let result = settings_bundle_from_conn(&conn);

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    match &result {
        Ok(_) => crate::logger::log_info(&format!("settings_get_all: SUCCESS {}ms", elapsed_ms)),
        Err(e) => {
            crate::logger::log_error(&format!("settings_get_all: FAILED {}ms: {}", elapsed_ms, e))
        }
    }

    result
}

#[tauri::command]
pub(crate) async fn settings_set_all(
    payload: SettingsSetPayload,
) -> Result<SettingsBundle, String> {
    let start = SystemTime::now();
    crate::logger::log_debug("settings_set_all: START (local)");

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
    crate::logger::log_info(&format!("settings_set_all: SUCCESS {}ms", elapsed_ms));

    Ok(bundle)
}

/// Checks whether QuickProbe is configured to start automatically when the user signs in.
#[tauri::command]
pub(crate) fn check_autostart() -> Result<bool, String> {
    check_autostart_state()
}

/// Toggles the Windows autostart setting and returns the new state.
#[tauri::command]
pub(crate) fn toggle_autostart() -> Result<bool, String> {
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
pub(crate) fn get_start_hidden_setting() -> Result<bool, String> {
    let settings = load_app_settings().unwrap_or_default();
    Ok(settings.start_hidden)
}

/// Persist the "start hidden" preference to settings.json.
#[tauri::command]
pub(crate) fn set_start_hidden_setting(args: StartHiddenArgs) -> Result<bool, String> {
    let mut settings = load_app_settings().unwrap_or_default();
    settings.start_hidden = args.start_hidden;
    save_app_settings(&settings)?;
    Ok(settings.start_hidden)
}

/// Enable the Options menu item in the system tray after successful login.
#[tauri::command]
pub(crate) fn enable_options_menu(app: tauri::AppHandle) -> Result<(), String> {
    // Note: In Tauri 2.x, tray menu item state management requires different approach
    // Menu items are managed via the Menu API and stored references
    // For now, this is a no-op - the options menu is always enabled
    let _ = &app; // Suppress unused warning
    Ok(())
}

#[tauri::command]
pub(crate) fn cache_get_dashboard() -> Result<Option<serde_json::Value>, String> {
    let start = SystemTime::now();
    crate::logger::log_debug("cache_get_dashboard: START");

    let path = dashboard_cache_path()?;
    if !path.exists() {
        crate::logger::log_debug("cache_get_dashboard: no cache file");
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
    crate::logger::log_info(&format!(
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
pub(crate) fn cache_set_dashboard(payload: serde_json::Value) -> Result<(), String> {
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
        crate::logger::log_error(&format!(
            "cache_set_dashboard: FAILED {}ms: {}",
            elapsed_ms, e
        ));
    } else if elapsed_ms > 100 {
        crate::logger::log_warn(&format!(
            "cache_set_dashboard: slow write {}ms servers={}",
            elapsed_ms, servers_count
        ));
    }

    result
}

#[tauri::command]
pub(crate) async fn persist_health_snapshot(
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
pub(crate) async fn load_health_snapshots() -> Result<serde_json::Value, String> {
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
