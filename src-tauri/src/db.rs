//! # Database Layer
//!
//! SQLite-based persistence for hosts, health snapshots, and application settings.
//!
//! ## Database Location
//!
//! Database file: `%APPDATA%\QuickProbe\quickprobe.db` (Windows)
//!
//! This ensures per-Windows-user isolation when running on a shared host or via
//! RemoteApp. Each user maintains their own independent host inventory.
//!
//! ## Concurrency and Durability
//!
//! - **WAL Mode**: Write-Ahead Logging for improved concurrency (readers don't block writers)
//! - **FULL Sync**: `synchronous=FULL` ensures durability even on power loss
//! - **Immediate Transactions**: Prevents dirty reads during concurrent operations
//! - **Static Mutexes**: Two coordination locks serialize:
//!   - `OPEN_LOCK`: Database connection initialization
//!   - `SCHEMA_LOCK`: Schema migration execution
//!
//! Both mutexes have poison recovery with logging to handle panics gracefully.
//!
//! ## Schema
//!
//! ### Tables
//!
//! - **`hosts`**: Server inventory with notes, groups, and service lists
//!   - Primary key: `server_name` (case-normalized, trailing dots removed)
//!   - Columns: `server_name`, `notes`, `group`, `services` (JSON array), `os_type`
//!
//! - **`health_snapshots`**: Latest probe results per host (one row per server)
//!   - Primary key: `server_name` (foreign key to `hosts`)
//!   - Column: `health_json` (full JSON payload from last successful probe)
//!   - Orphaned rows are cleaned up when host is deleted or on restore
//!
//! - **`kv_store`**: Key-value settings storage
//!   - Composite key: `(scope_type, scope_id, key)`
//!   - Used for: dashboard cache, runtime mode, backup pre-restore snapshots
//!
//! ## Race Condition Fixes
//!
//! Historical note: Earlier versions used read-modify-write patterns that caused
//! race conditions (e.g., two concurrent updates could clobber each other's changes).
//! Current version uses granular UPDATE/INSERT statements to avoid this.
//!
//! See: `tests/note_save_race_test.rs`, `tests/db_sync_test.rs`

use rusqlite::{Connection, OptionalExtension};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const APP_NAME: &str = "QuickProbe";
const DB_FILE_NAME: &str = "quickprobe.db";
const SCHEMA_VERSION: &str = "3";

#[derive(Debug, thiserror::Error)]
pub enum QpError {
    #[error("APPDATA environment variable not found")]
    MissingAppData,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Returns %APPDATA%\QuickProbe, creating it if needed.
pub fn get_appdata_dir() -> Result<PathBuf, QpError> {
    let app_data = std::env::var("APPDATA").map_err(|_| QpError::MissingAppData)?;
    let target = PathBuf::from(app_data).join(APP_NAME);
    fs::create_dir_all(&target)?;
    Ok(target)
}

/// Returns %APPDATA%\QuickProbe\quickprobe.db.
pub fn get_db_path() -> Result<PathBuf, QpError> {
    Ok(get_appdata_dir()?.join(DB_FILE_NAME))
}

/// Opens the QuickProbe SQLite database and applies baseline PRAGMAs.
pub fn open_db() -> Result<Connection, QpError> {
    let _guard = open_lock().lock().unwrap_or_else(|p| {
        crate::logger::log_warn(
            "Recovered from poisoned mutex 'open_lock' - previous thread panicked",
        );
        p.into_inner()
    });

    let db_path = get_db_path()?;
    open_connection(&db_path)
}

fn schema_lock() -> &'static Mutex<()> {
    static SCHEMA_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    SCHEMA_LOCK.get_or_init(|| Mutex::new(()))
}

fn open_lock() -> &'static Mutex<()> {
    static OPEN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    OPEN_LOCK.get_or_init(|| Mutex::new(()))
}

/// Creates tables if missing and records the schema version in `meta`.
pub fn init_schema(conn: &Connection) -> Result<(), QpError> {
    let _guard = schema_lock().lock().unwrap_or_else(|p| {
        crate::logger::log_warn(
            "Recovered from poisoned mutex 'schema_lock' - previous thread panicked",
        );
        p.into_inner()
    });

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hosts (
            server_name TEXT PRIMARY KEY,
            notes TEXT,
            group_name TEXT,
            os_type TEXT NOT NULL DEFAULT 'Windows',
            services TEXT
        );

        CREATE TABLE IF NOT EXISTS kv (
            scope_type TEXT NOT NULL,
            scope_id   TEXT NOT NULL,
            key        TEXT NOT NULL,
            value      TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (scope_type, scope_id, key)
        );
        ",
    )?;

    // Check current version for migrations
    let current_version: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "0".to_string());

    // Apply migrations
    if current_version.as_str() < "2" {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS host_health (
                server_name TEXT PRIMARY KEY,
                snapshot_json TEXT NOT NULL,
                last_probed_at TEXT NOT NULL
            )",
            [],
        )?;
    }

    // Migration v3: Remove CASCADE constraint from host_health to preserve snapshots when hosts are updated
    if current_version.as_str() < "3" {
        // SQLite doesn't support ALTER TABLE to drop foreign key, so we need to recreate the table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS host_health_new (
                server_name TEXT PRIMARY KEY,
                snapshot_json TEXT NOT NULL,
                last_probed_at TEXT NOT NULL
            )",
            [],
        )?;

        // Copy existing data
        conn.execute(
            "INSERT INTO host_health_new (server_name, snapshot_json, last_probed_at)
             SELECT server_name, snapshot_json, last_probed_at FROM host_health",
            [],
        )?;

        // Drop old table and rename new one
        conn.execute("DROP TABLE IF EXISTS host_health", [])?;
        conn.execute("ALTER TABLE host_health_new RENAME TO host_health", [])?;
    }

    conn.execute(
        "INSERT INTO meta(key, value) VALUES('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [SCHEMA_VERSION],
    )?;

    Ok(())
}

/// Fetches a value from the kv table for a given scope and key.
pub fn kv_get(
    conn: &Connection,
    scope_type: &str,
    scope_id: &str,
    key: &str,
) -> Result<Option<String>, QpError> {
    conn.query_row(
        "SELECT value FROM kv WHERE scope_type = ?1 AND scope_id = ?2 AND key = ?3",
        (scope_type, scope_id, key),
        |row| row.get(0),
    )
    .optional()
    .map_err(QpError::from)
}

/// Inserts or updates a value in the kv table and bumps updated_at.
pub fn kv_set(
    conn: &Connection,
    scope_type: &str,
    scope_id: &str,
    key: &str,
    value: &str,
) -> Result<(), QpError> {
    conn.execute(
        "
        INSERT INTO kv(scope_type, scope_id, key, value)
        VALUES(?1, ?2, ?3, ?4)
        ON CONFLICT(scope_type, scope_id, key)
        DO UPDATE SET value = excluded.value, updated_at = datetime('now')
        ",
        (scope_type, scope_id, key, value),
    )?;
    Ok(())
}

/// Saves health snapshot for a host
pub fn save_health_snapshot(
    conn: &Connection,
    server_name: &str,
    snapshot_json: &str,
) -> Result<(), QpError> {
    conn.execute(
        "INSERT INTO host_health(server_name, snapshot_json, last_probed_at)
         VALUES(?1, ?2, datetime('now'))
         ON CONFLICT(server_name) DO UPDATE SET
             snapshot_json = excluded.snapshot_json,
             last_probed_at = excluded.last_probed_at",
        (server_name, snapshot_json),
    )?;
    Ok(())
}

/// Loads all health snapshots
pub fn load_all_health_snapshots(
    conn: &Connection,
) -> Result<Vec<(String, String, String)>, QpError> {
    let mut stmt = conn.prepare(
        "SELECT server_name, snapshot_json, last_probed_at
         FROM host_health
         ORDER BY last_probed_at DESC",
    )?;

    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;

    rows.collect::<Result<Vec<_>, _>>().map_err(QpError::from)
}

/// Deletes health snapshots for servers that are not in the current host list
/// This prevents orphaned health data from being merged when hosts are re-added
/// Uses case-insensitive comparison via UPPER() to handle name normalization
pub fn cleanup_orphaned_health_snapshots(conn: &Connection) -> Result<usize, QpError> {
    // First check if hosts table has any entries to avoid deleting all snapshots
    let host_count: i64 = conn.query_row("SELECT COUNT(*) FROM hosts", [], |row| row.get(0))?;

    if host_count == 0 {
        // Don't delete any snapshots if hosts table is empty (safety check)
        return Ok(0);
    }

    // Delete snapshots where uppercase name doesn't match any uppercase host name
    // This handles case sensitivity issues between JavaScript and Rust normalization
    let deleted = conn.execute(
        "DELETE FROM host_health
         WHERE UPPER(server_name) NOT IN (SELECT UPPER(server_name) FROM hosts)",
        [],
    )?;
    Ok(deleted)
}

fn open_connection(path: &Path) -> Result<Connection, QpError> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

fn apply_pragmas(conn: &Connection) -> Result<(), QpError> {
    conn.busy_timeout(Duration::from_millis(5_000))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

pub fn appdata_test_lock() -> &'static Mutex<()> {
    static APPDATA_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    APPDATA_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_schema_creates_tables_and_meta() {
        let temp_dir = tempdir().expect("temp dir created");
        let db_path = temp_dir.path().join(DB_FILE_NAME);

        let mut conn = open_connection(&db_path).expect("opened temp db");
        init_schema(&mut conn).expect("initialized schema");

        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('meta', 'hosts', 'kv')",
            )
            .unwrap();

        let mut tables = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        tables.sort();
        assert_eq!(
            tables,
            vec!["hosts".to_string(), "kv".to_string(), "meta".to_string()]
        );

        let schema_version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn pragmas_applied_on_open() {
        let temp_dir = tempdir().expect("temp dir created");
        let db_path = temp_dir.path().join(DB_FILE_NAME);

        let conn = open_connection(&db_path).expect("opened temp db");

        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_lowercase(), "wal");
    }
}
