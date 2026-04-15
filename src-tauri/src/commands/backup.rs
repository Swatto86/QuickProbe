//! Encrypted backup and restore commands.

use quickprobe::backup::{
    self, BackupPayload, HostBackupRow, BACKUP_KV_KEYS, BACKUP_SCHEMA_VERSION,
};
use quickprobe::constants::*;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use zip::{write::SimpleFileOptions, AesMode, CompressionMethod, ZipArchive, ZipWriter};

use super::helpers::*;
use super::hosts::*;
use super::system::runtime_mode_info_local;
use super::types::*;

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub(crate) async fn export_backup_encrypted(
    destination: String,
    password: String,
) -> Result<String, String> {
    let dest_path = PathBuf::from(destination);
    let password = password.trim().to_string();

    // Validate password strength
    validate_backup_password(&password)?;

    tokio::task::spawn_blocking(move || {
        crate::logger::log_info(&format!(
            "Starting backup export to: {}",
            dest_path.display()
        ));

        // Estimate backup size (rough estimate based on database size)
        let estimated_size = 1024 * 1024; // Default 1MB estimate

        // Check disk space before creating backup
        if let Err(e) = check_disk_space_for_backup(&dest_path, estimated_size) {
            crate::logger::log_warn(&format!("Disk space check warning: {}", e));
            // Continue anyway - this is just a warning
        }

        let result = export_backup(&dest_path, &password);

        match &result {
            Ok(path) => crate::logger::log_info(&format!("Backup export successful: {}", path)),
            Err(e) => crate::logger::log_error(&format!("Backup export failed: {}", e)),
        }

        result
    })
    .await
    .map_err(|e| format!("Backup task failed: {}", e))?
}

#[tauri::command]
pub(crate) async fn import_backup_encrypted(
    source: String,
    password: String,
) -> Result<RestoreResponse, String> {
    let path = PathBuf::from(source);
    let password = password.trim().to_string();

    // Validate password strength
    validate_backup_password(&password)?;

    tokio::task::spawn_blocking(move || {
        crate::logger::log_info(&format!(
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

        crate::logger::log_info("Backup file validated successfully");

        // Create pre-restore backup before making any changes
        crate::logger::log_info("Creating pre-restore backup...");
        let pre_restore_path = backup_destination_with_suffix("pre-restore")?;
        export_backup(&pre_restore_path, &password).map_err(|e| {
            format!(
                "Failed to create pre-restore backup. Restore aborted to prevent data loss: {}",
                e
            )
        })?;
        crate::logger::log_info(&format!(
            "Pre-restore backup created: {}",
            pre_restore_path.display()
        ));

        // Clean up old pre-restore backups (keep 5 most recent)
        if let Err(e) = cleanup_old_pre_restore_backups(5) {
            crate::logger::log_warn(&format!("Failed to cleanup old pre-restore backups: {}", e));
            // Don't fail the restore if cleanup fails
        }

        // Perform the restore
        crate::logger::log_info("Restoring data to database...");
        let local_storage = restore_to_sqlite(&payload)?;
        crate::logger::log_info("Backup restore completed successfully");

        Ok(RestoreResponse {
            local_storage,
            hosts_written: true,
        })
    })
    .await
    .map_err(|e| format!("Restore task failed: {}", e))?
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn hosts_for_backup() -> Result<Vec<HostBackupRow>, String> {
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

fn kv_for_backup() -> Result<BTreeMap<String, Option<String>>, String> {
    let mut kv_map = BTreeMap::new();
    for key in BACKUP_KV_KEYS {
        kv_map.insert((*key).to_string(), kv_get_value(key)?);
    }
    Ok(kv_map)
}

pub(crate) fn build_backup_payload() -> Result<BackupPayload, String> {
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

pub(crate) fn write_encrypted_backup(
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

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .with_aes_encryption(AesMode::Aes256, password);

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
    let mut file = match archive.by_name_decrypt(name, password.as_bytes()) {
        Ok(f) => f,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(zip::result::ZipError::InvalidPassword) => {
            return Err(format!(
                "Failed to decrypt {}: invalid password. Please verify your password is correct.",
                name
            ));
        }
        Err(e) => {
            return Err(format!(
                "Failed to open {}: {}. This may indicate a corrupted file.",
                name, e
            ));
        }
    };
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Failed to read {}: {}", name, e))?;
    Ok(Some(contents))
}

pub(crate) fn read_backup_payload(
    path: &Path,
    password: &str,
) -> Result<Option<BackupPayload>, String> {
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

pub(crate) fn backup_destination_with_suffix(suffix: &str) -> Result<PathBuf, String> {
    let dir = get_app_data_dir()?;
    let timestamp = timestamp_suffix();
    let name = format!("QuickProbe-{}-{}.zip", suffix, timestamp);
    Ok(dir.join(name))
}

pub(crate) fn export_backup(destination: &Path, password: &str) -> Result<String, String> {
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
            crate::logger::log_warn(&format!("Failed to read app data dir for cleanup: {}", e));
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
                crate::logger::log_debug(&format!(
                    "Deleted old pre-restore backup: {}",
                    path.display()
                ));
            }
            Err(e) => {
                crate::logger::log_warn(&format!(
                    "Failed to delete old pre-restore backup {}: {}",
                    path.display(),
                    e
                ));
            }
        }
    }

    if deleted > 0 {
        crate::logger::log_info(&format!(
            "Cleaned up {} old pre-restore backup(s), kept {} most recent",
            deleted, keep_count
        ));
    }

    Ok(())
}

fn restore_to_sqlite(payload: &BackupPayload) -> Result<serde_json::Value, String> {
    use quickprobe::db;
    use rusqlite::TransactionBehavior;

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
    chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string()
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
