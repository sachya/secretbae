//! Schema definition and migration.

use rusqlite::Connection;

use crate::{Result, StoreError};

/// Bumped whenever `MIGRATIONS` gains an entry.
pub const SCHEMA_VERSION: u32 = 1;

/// Applied in order; index + 1 is the schema version each one produces.
///
/// Migrations are append-only. Editing an existing entry would silently diverge the schema of
/// a store that has already been migrated from one that has not.
const MIGRATIONS: &[&str] = &[include_str!("migrations/001_initial.sql")];

pub fn migrate(conn: &Connection) -> Result<()> {
    let applied: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    if applied > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew { found: applied, supported: SCHEMA_VERSION });
    }

    for (index, migration) in MIGRATIONS.iter().enumerate().skip(applied as usize) {
        let version = u32::try_from(index).map_err(|_| StoreError::Corrupt { what: "migration index" })? + 1;
        conn.execute_batch(migration)?;
        // Not a bound parameter: SQLite does not accept one in a PRAGMA, and `version` is
        // derived from a compile-time constant array index rather than any input.
        conn.execute_batch(&format!("PRAGMA user_version = {version}"))?;
    }

    Ok(())
}

/// Connection settings applied to every connection, not just at migration time.
pub fn apply_pragmas(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA synchronous = FULL;
         PRAGMA busy_timeout = 5000;",
    )?;
    Ok(())
}
