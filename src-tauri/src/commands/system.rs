//! System info, runtime mode, logging relay, and auto-update commands.

use quickprobe::backup::{ModeDetails, RuntimeModeInfo};
use quickprobe::updater::{self, UpdateInfo};
use quickprobe::{self, db};
use std::path::PathBuf;

use super::types::*;

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Get application info for About window
#[tauri::command]
pub(crate) async fn get_app_info() -> Result<AppInfoResponse, String> {
    Ok(AppInfoResponse {
        name: "QuickProbe".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[tauri::command]
pub(crate) fn get_runtime_mode_info() -> Result<RuntimeModeInfo, String> {
    compute_runtime_mode_info()
}

#[tauri::command]
pub(crate) fn debug_local_store_status() -> Result<LocalStoreStatus, String> {
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

// ---------------------------------------------------------------------------
// Logging relay commands (frontend → structured log file)
// ---------------------------------------------------------------------------

#[tauri::command]
pub(crate) fn log_debug(message: String) {
    crate::logger::log_debug(&message);
}

#[tauri::command]
pub(crate) fn log_info(message: String) {
    crate::logger::log_info(&message);
}

#[tauri::command]
pub(crate) fn log_warn(message: String) {
    crate::logger::log_warn(&message);
}

#[tauri::command]
pub(crate) fn log_error(message: String) {
    crate::logger::log_error(&message);
}

#[cfg(debug_assertions)]
#[tauri::command]
pub(crate) fn open_logs_folder() -> Result<(), String> {
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
pub(crate) fn open_logs_folder() -> Result<(), String> {
    Err("Logs folder is only available in debug builds".to_string())
}

// ---------------------------------------------------------------------------
// Auto-Update commands
// ---------------------------------------------------------------------------

/// Check for available updates from GitHub releases.
/// Returns information about whether an update is available and release details.
#[tauri::command]
pub(crate) async fn check_for_update() -> Result<UpdateInfo, String> {
    updater::check_for_update_impl().await
}

/// Download and install an update.
/// Downloads the installer to temp directory and launches it.
#[tauri::command]
pub(crate) async fn download_and_install_update(update_info: UpdateInfo) -> Result<(), String> {
    updater::download_and_install_impl(update_info).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn compute_runtime_mode_info() -> Result<RuntimeModeInfo, String> {
    Ok(runtime_mode_info_local())
}

pub(crate) fn runtime_mode_info_local() -> RuntimeModeInfo {
    let db_path = db::get_db_path()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    RuntimeModeInfo {
        mode: "local".to_string(),
        details: ModeDetails { db_path },
        config_source: "local".to_string(),
    }
}
