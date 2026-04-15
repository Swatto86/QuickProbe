//! Host CRUD commands and SQLite host persistence.

use quickprobe::db;
use rusqlite::TransactionBehavior;
use std::time::SystemTime;

use super::helpers::*;
use super::state::{clear_session_cache, invalidate_session_cache};
use super::types::*;

// ---------------------------------------------------------------------------
// SQLite host read / write
// ---------------------------------------------------------------------------

pub(crate) fn read_hosts_from_sqlite() -> Result<Vec<ServerInfo>, String> {
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

        let os_type = crate::normalize::normalize_os_type(Some(&raw_os));

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

pub(crate) fn normalize_hosts_for_write(
    hosts: &[HostUpdate],
) -> Result<Vec<NormalizedHost>, String> {
    let mut seen = std::collections::HashSet::new();
    let mut rows = Vec::with_capacity(hosts.len());

    for h in hosts {
        let normalized_name = normalize_host_name(&h.name)?;
        let name_key = normalized_name.to_lowercase();
        if !seen.insert(name_key) {
            return Err("Host names must be unique after normalization".to_string());
        }

        let services_joined = if let Some(raw_services) = h.services.as_ref() {
            crate::normalize::normalize_services_list(raw_services)?
        } else {
            String::new()
        };

        let notes_clean = h.notes.clone().unwrap_or_default().trim().to_string();
        let box_clean = h.group.clone().unwrap_or_default().trim().to_string();
        let os_clean = crate::normalize::normalize_os_type(h.os_type.as_deref());

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

pub(crate) fn write_hosts_sqlite(hosts: &[HostUpdate]) -> Result<(), String> {
    crate::logger::log_debug(&format!(
        "write_hosts_sqlite: BEGIN transaction for {} host(s)",
        hosts.len()
    ));

    let rows = normalize_hosts_for_write(hosts)?;

    for (original, normalized) in hosts.iter().zip(rows.iter()) {
        if original.name != normalized.name {
            crate::logger::log_debug(&format!(
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
            crate::logger::log_error(&format!("TX BEGIN failed: {}", e));
            format!("Failed to start transaction: {}", e)
        })?;

    crate::logger::log_debug("write_hosts_sqlite: DELETE FROM hosts");
    tx.execute("DELETE FROM hosts", []).map_err(|e| {
        crate::logger::log_error(&format!("DELETE failed: {}", e));
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
            crate::logger::log_error(&format!("INSERT/UPDATE failed for '{}': {}", row.name, e));
            format!("Failed to persist host '{}': {}", row.name, e)
        })?;
    }

    crate::logger::log_debug(&format!("write_hosts_sqlite: COMMIT ({} rows)", rows.len()));
    tx.commit().map_err(|e| {
        crate::logger::log_error(&format!("TX COMMIT failed: {}", e));
        format!("Failed to commit hosts: {}", e)
    })?;

    if rows.is_empty() {
        crate::logger::log_debug("write_hosts_sqlite: Skipping health snapshot cleanup (no hosts)");
    } else {
        match db::cleanup_orphaned_health_snapshots(&conn) {
            Ok(deleted) if deleted > 0 => {
                crate::logger::log_info(&format!(
                    "write_hosts_sqlite: Cleaned up {} orphaned health snapshot(s)",
                    deleted
                ));
            }
            Ok(_) => {
                crate::logger::log_debug(
                    "write_hosts_sqlite: No orphaned health snapshots to clean up",
                );
            }
            Err(e) => {
                crate::logger::log_warn(&format!(
                    "write_hosts_sqlite: Failed to cleanup orphaned health snapshots: {}",
                    e
                ));
            }
        }
    }

    bump_hosts_changed_flag()?;
    crate::logger::log_info(&format!(
        "write_hosts_sqlite: SUCCESS, {} host(s), qp_hosts_changed bumped",
        rows.len()
    ));
    Ok(())
}

pub(crate) fn persist_hosts(hosts: &[HostUpdate]) -> Result<(), String> {
    crate::logger::log_debug(&format!("persist_hosts: {} host(s)", hosts.len()));
    write_hosts_sqlite(hosts)
}

// ---------------------------------------------------------------------------
// Tauri IPC commands
// ---------------------------------------------------------------------------

/// Read hosts from SQLite
#[allow(dead_code)]
#[tauri::command]
pub(crate) async fn get_hosts() -> Result<Vec<ServerInfo>, String> {
    let start = SystemTime::now();

    let result = read_hosts_from_sqlite();

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    match &result {
        Ok(_hosts) => {
            if elapsed_ms > 50 {
                crate::logger::log_warn(&format!("get_hosts: slow query {}ms", elapsed_ms));
            }
        }
        Err(e) => {
            crate::logger::log_error(&format!("get_hosts: FAILED {}ms: {}", elapsed_ms, e));
        }
    }

    result
}

/// Replace all hosts in the database with provided host entries
#[tauri::command]
pub(crate) async fn set_hosts(hosts: Vec<HostUpdate>) -> Result<(), String> {
    let start = SystemTime::now();
    crate::logger::log_info(&format!("set_hosts: {} host(s)", hosts.len()));

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

        crate::logger::log_debug(&format!(
            "set_hosts[{}]: '{}' fields=[{}]",
            i,
            host.name,
            fields.join(",")
        ));
    }

    let result = persist_hosts(&hosts);

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    match &result {
        Ok(_) => {
            clear_session_cache().await;
            crate::logger::log_info(&format!("set_hosts: SUCCESS {}ms", elapsed_ms));
        }
        Err(e) => crate::logger::log_error(&format!("set_hosts: FAILED {}ms: {}", elapsed_ms, e)),
    }

    result
}

/// Save notes for a server in the hosts database.
#[allow(dead_code)]
#[tauri::command]
pub(crate) async fn save_server_notes(server_name: String, notes: String) -> Result<(), String> {
    let normalized_name = normalize_host_name(&server_name)?;
    let notes_clean = notes.trim().to_string();

    crate::logger::log_debug(&format!(
        "save_server_notes: server='{}', notes_len={}",
        normalized_name,
        notes_clean.len()
    ));

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
            crate::logger::log_error(&format!(
                "save_server_notes: UPDATE failed for '{}': {}",
                normalized_name, e
            ));
            format!("Failed to update notes: {}", e)
        })?;

    if rows_affected == 0 {
        crate::logger::log_warn(&format!(
            "save_server_notes: Server '{}' not found",
            normalized_name
        ));
        return Err(format!(
            "Server '{}' not found in hosts database",
            normalized_name
        ));
    }

    bump_hosts_changed_flag()?;
    crate::logger::log_info(&format!(
        "save_server_notes: SUCCESS for '{}', qp_hosts_changed bumped",
        normalized_name
    ));
    Ok(())
}

/// Update a single host's properties (notes, group, os_type, services)
#[tauri::command]
pub(crate) async fn update_host(
    server_name: String,
    notes: Option<String>,
    group: Option<String>,
    os_type: Option<String>,
    services: Option<Vec<String>>,
) -> Result<(), String> {
    let normalized_name = normalize_host_name(&server_name)?;
    crate::logger::log_info(&format!(
        "update_host: '{}' (normalized from '{}')",
        normalized_name, server_name
    ));

    if normalized_name.is_empty() {
        return Err("Invalid server name".to_string());
    }

    let conn = db::open_db().map_err(|e| format!("Failed to open database: {}", e))?;
    db::init_schema(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;

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

    let notes_value = notes
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    let group_value = group
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty());
    let os_value = crate::normalize::normalize_os_type(os_type.as_deref());
    let services_value = if let Some(raw_services) = services {
        let cleaned: Vec<String> = raw_services
            .into_iter()
            .map(|svc| svc.trim().to_string())
            .filter(|svc| !svc.is_empty())
            .collect();
        if cleaned.is_empty() {
            None
        } else {
            Some(
                crate::normalize::normalize_services_list(&cleaned)
                    .map_err(|e| format!("Invalid services list: {}", e))?,
            )
        }
    } else {
        None
    };

    crate::logger::log_debug(&format!(
        "update_host: '{}' notes={:?} group={:?} os={:?} services={:?}",
        normalized_name, notes_value, group_value, os_value, services_value
    ));

    conn.execute(
        "UPDATE hosts SET notes = ?1, group_name = ?2, os_type = ?3, services = ?4 WHERE server_name = ?5",
        rusqlite::params![notes_value, group_value, os_value, services_value, normalized_name],
    )
    .map_err(|e| {
        crate::logger::log_error(&format!("update_host: SQL error for '{}': {}", normalized_name, e));
        format!("Database error: {}", e)
    })?;

    bump_hosts_changed_flag()?;
    crate::logger::log_info(&format!(
        "update_host: SUCCESS for '{}', qp_hosts_changed bumped",
        normalized_name
    ));

    invalidate_session_cache(&normalized_name).await;

    Ok(())
}

/// Rename a group label across all hosts in the database
#[tauri::command]
pub(crate) async fn rename_group(old_group: String, new_group: String) -> Result<usize, String> {
    crate::logger::log_info(&format!("rename_group: '{}' -> '{}'", old_group, new_group));

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
        crate::logger::log_info("rename_group: no hosts matched");
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
    crate::logger::log_info(&format!(
        "rename_group: SUCCESS, {} host(s) updated",
        updated_count
    ));
    Ok(updated_count)
}
