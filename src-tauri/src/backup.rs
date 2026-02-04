use chrono::Utc;
use rusqlite::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub const APP_NAME: &str = "QuickProbe";
pub const BACKUP_SCHEMA_VERSION: u32 = 1;
pub const BACKUP_KV_KEYS: &[&str] = &[
    "qp_settings",
    "qp_server_order",
    "qp_host_view_mode",
    "qp_hosts_changed",
];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupManifest {
    pub app: String,
    pub version: String,
    pub created_epoch_ms: u128,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostBackupRow {
    #[serde(rename = "serverName")]
    pub server_name: String,
    #[serde(rename = "notes", default)]
    pub notes: Option<String>,
    #[serde(rename = "group", default)]
    pub group: Option<String>,
    #[serde(rename = "osType")]
    pub os_type: String,
    #[serde(rename = "services", default)]
    pub services: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ModeDetails {
    #[serde(rename = "dbPath")]
    pub db_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuntimeModeInfo {
    pub mode: String,
    pub details: ModeDetails,
    #[serde(rename = "configSource")]
    pub config_source: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupPayload {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "exportedAt")]
    pub exported_at: String,
    #[serde(rename = "appVersion")]
    pub app_version: String,
    pub mode: RuntimeModeInfo,
    pub hosts: Vec<HostBackupRow>,
    pub kv: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone)]
pub struct NormalizedBackupHost {
    pub server_name: String,
    pub notes: String,
    pub group: String,
    pub os_type: String,
    pub services: String,
}

pub fn build_backup_manifest(app_version: &str, created_epoch_ms: u128) -> BackupManifest {
    BackupManifest {
        app: APP_NAME.to_string(),
        version: app_version.to_string(),
        created_epoch_ms,
    }
}

pub fn build_backup_payload(
    hosts: Vec<HostBackupRow>,
    kv: BTreeMap<String, Option<String>>,
    mode: RuntimeModeInfo,
    app_version: &str,
) -> BackupPayload {
    BackupPayload {
        schema_version: BACKUP_SCHEMA_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        app_version: app_version.to_string(),
        mode,
        hosts,
        kv,
    }
}

/// Normalizes and validates backup host data.
/// This function:
/// 1. Normalizes server names (converts to uppercase, strips FQDN domain)
/// 2. Validates that all server names are unique after normalization
/// 3. Normalizes services (trims, deduplicates, uppercases)
/// 4. Normalizes OS type (defaults to Windows if not specified)
/// 5. Trims notes and group names
///
/// Returns an error if any host name is invalid or if duplicate host names
/// are detected after normalization.
pub fn normalize_backup_hosts(
    hosts: &[HostBackupRow],
) -> Result<Vec<NormalizedBackupHost>, String> {
    let mut seen = HashSet::new();
    let mut rows = Vec::with_capacity(hosts.len());

    for h in hosts {
        let normalized_name = crate::normalize::normalize_server_name(&h.server_name)
            .map_err(|e| format!("Invalid server name '{}': {}", h.server_name, e))?;
        let key = normalized_name.to_lowercase();
        if !seen.insert(key) {
            return Err(format!(
                "Duplicate host name '{}' found in backup after normalization",
                normalized_name
            ));
        }

        let services_joined = if let Some(raw) = h.services.as_ref() {
            crate::normalize::normalize_services(raw)?
        } else {
            String::new()
        };

        let notes = h.notes.as_deref().unwrap_or("").trim().to_string();
        let group = h.group.as_deref().unwrap_or("").trim().to_string();
        let os_type = crate::normalize::normalize_os_type(Some(&h.os_type));

        rows.push(NormalizedBackupHost {
            server_name: normalized_name,
            notes,
            group,
            os_type,
            services: services_joined,
        });
    }

    Ok(rows)
}

/// Applies a backup payload to the database within a transaction.
/// This function performs the following operations atomically:
/// 1. Validates the backup schema version
/// 2. Normalizes and validates all host data
/// 3. Clears existing hosts table
/// 4. Inserts/updates all hosts from backup
/// 5. Clears and restores KV settings
/// 6. Updates the qp_hosts_changed timestamp
///
/// All operations are performed within the provided transaction, ensuring
/// atomicity. If any operation fails, the transaction can be rolled back.
pub fn apply_backup_payload(
    tx: &Transaction,
    payload: &BackupPayload,
    kv_scope_type: &str,
    kv_scope_id: &str,
    kv_keys: &[&str],
    now_epoch_ms: u128,
) -> Result<(), String> {
    // Validate schema version first
    if payload.schema_version != BACKUP_SCHEMA_VERSION {
        return Err(format!(
            "Unsupported backup schema version {}. Expected version {}.",
            payload.schema_version, BACKUP_SCHEMA_VERSION
        ));
    }

    // Validate and normalize all hosts before making any database changes
    let normalized_hosts = normalize_backup_hosts(&payload.hosts).map_err(|e| {
        format!(
            "Backup data validation failed: {}. The backup may be corrupted or invalid.",
            e
        )
    })?;

    // Clear existing hosts table
    tx.execute("DELETE FROM hosts", []).map_err(|e| {
        format!(
            "Failed to clear hosts table: {}. Database may be locked or corrupted.",
            e
        )
    })?;

    for host in normalized_hosts {
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
            rusqlite::params![
                host.server_name,
                host.notes,
                host.group,
                host.os_type,
                host.services
            ],
        )
        .map_err(|e| format!("Failed to persist host: {}", e))?;
    }

    for key in kv_keys {
        tx.execute(
            "DELETE FROM kv WHERE scope_type = ?1 AND scope_id = ?2 AND key = ?3",
            (kv_scope_type, kv_scope_id, *key),
        )
        .map_err(|e| format!("Failed to clear kv key '{}': {}", key, e))?;
    }

    for (key, value) in payload.kv.iter() {
        if let Some(val) = value {
            tx.execute(
                "
                INSERT INTO kv(scope_type, scope_id, key, value)
                VALUES(?1, ?2, ?3, ?4)
                ON CONFLICT(scope_type, scope_id, key)
                DO UPDATE SET value = excluded.value, updated_at = datetime('now')
                ",
                rusqlite::params![kv_scope_type, kv_scope_id, key, val],
            )
            .map_err(|e| format!("Failed to persist kv '{}': {}", key, e))?;
        }
    }

    tx.execute(
        "
        INSERT INTO kv(scope_type, scope_id, key, value)
        VALUES(?1, ?2, 'qp_hosts_changed', ?3)
        ON CONFLICT(scope_type, scope_id, key)
        DO UPDATE SET value = excluded.value, updated_at = datetime('now')
        ",
        rusqlite::params![kv_scope_type, kv_scope_id, now_epoch_ms.to_string()],
    )
    .map_err(|e| format!("Failed to set qp_hosts_changed: {}", e))?;

    Ok(())
}
