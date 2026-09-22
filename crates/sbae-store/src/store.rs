//! Connection lifecycle and the `meta` table.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use sbae_core::SealedMasterKey;
use time::OffsetDateTime;

use crate::{schema, Result, StoreError};

const META_SEALED_MASTER_KEY: &str = "sealed_master_key";

/// A secretbae database.
///
/// Holds ciphertext only. The store never sees a master key and cannot decrypt anything it
/// contains, which keeps every cryptographic decision in `sbae-core`.
pub struct Store {
    pub(crate) conn: Connection,
}

impl Store {
    /// Open (creating if absent) and migrate the store at `path`.
    ///
    /// Restricting the file to the owner is the caller's job: the daemon sets the mode before
    /// this runs, since only it knows which user it is about to drop to.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// An ephemeral store, for tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        schema::apply_pragmas(&conn)?;
        schema::migrate(&conn)?;
        Ok(Self { conn })
    }

    /// The sealed master key, or `None` if `init` has not run.
    pub fn sealed_master_key(&self) -> Result<Option<SealedMasterKey>> {
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [META_SEALED_MASTER_KEY], |row| {
                row.get(0)
            })
            .optional()?;

        stored
            .map(|bytes| {
                SealedMasterKey::from_bytes(&bytes)
                    .map_err(|_| StoreError::Corrupt { what: "sealed master key" })
            })
            .transpose()
    }

    /// Record the sealed master key. Used by `init` and by `rekey`.
    pub fn set_sealed_master_key(&self, sealed: &SealedMasterKey) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![META_SEALED_MASTER_KEY, sealed.to_bytes()],
        )?;
        Ok(())
    }

    /// Refuses to overwrite an existing master key, so a second `init` cannot orphan every
    /// secret already in the store.
    pub fn initialise_master_key(&self, sealed: &SealedMasterKey) -> Result<()> {
        if self.sealed_master_key()?.is_some() {
            return Err(StoreError::AlreadyInitialised);
        }
        self.set_sealed_master_key(sealed)
    }

    /// Direct connection access for `sbae-audit`, which appends to this same database.
    ///
    /// Exposed rather than wrapped because the audit chain must own its own transaction
    /// boundaries: its append has to take the write lock before reading the chain tail.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    #[must_use]
    pub fn schema_version(&self) -> u32 {
        schema::SCHEMA_VERSION
    }
}

/// Seconds since the Unix epoch, the form every timestamp column uses.
pub(crate) fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub(crate) fn timestamp(seconds: i64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| StoreError::Corrupt { what: "timestamp" })
}

#[cfg(test)]
mod tests {
    use sbae_core::{seal, KeyfileSeal, MasterKey};

    use super::*;

    fn sealed() -> SealedMasterKey {
        let backend = KeyfileSeal::from_hex(&"ab".repeat(32)).unwrap();
        seal::seal_master(&backend, &MasterKey::generate().unwrap(), 1).unwrap()
    }

    #[test]
    fn a_new_store_has_no_master_key() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.sealed_master_key().unwrap().is_none());
    }

    #[test]
    fn master_key_round_trips() {
        let store = Store::open_in_memory().unwrap();
        let key = sealed();
        store.initialise_master_key(&key).unwrap();
        assert_eq!(store.sealed_master_key().unwrap().unwrap(), key);
    }

    /// Re-running `init` against a populated store would make every secret in it undecryptable.
    #[test]
    fn refuses_a_second_initialisation() {
        let store = Store::open_in_memory().unwrap();
        store.initialise_master_key(&sealed()).unwrap();
        assert!(matches!(
            store.initialise_master_key(&sealed()),
            Err(StoreError::AlreadyInitialised)
        ));
    }

    /// `rekey` must still be able to replace it deliberately.
    #[test]
    fn rekey_may_replace_the_master_key() {
        let store = Store::open_in_memory().unwrap();
        store.initialise_master_key(&sealed()).unwrap();
        let replacement = sealed();
        store.set_sealed_master_key(&replacement).unwrap();
        assert_eq!(store.sealed_master_key().unwrap().unwrap(), replacement);
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        schema::apply_pragmas(&conn).unwrap();
        schema::migrate(&conn).unwrap();
        schema::migrate(&conn).unwrap();

        let version: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, schema::SCHEMA_VERSION);
    }

    #[test]
    fn refuses_a_store_from_a_newer_build() {
        let conn = Connection::open_in_memory().unwrap();
        schema::apply_pragmas(&conn).unwrap();
        conn.execute_batch("PRAGMA user_version = 99").unwrap();
        assert!(matches!(schema::migrate(&conn), Err(StoreError::SchemaTooNew { .. })));
    }
}
