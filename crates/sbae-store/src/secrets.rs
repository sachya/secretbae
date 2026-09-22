//! Secret and version operations.

use core::fmt::Write as _;
use std::collections::HashMap;

use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use sbae_core::{Nonce, SealedVersion, VersionBinding};
use sbae_proto::{SecretPath, Tag, Version, VersionState};
use uuid::Uuid;

use crate::{
    store::{now, timestamp},
    DeleteMode, ListFilter, Result, SecretSummary, StoredVersion, Store, StoreError,
    VersionInfo, VersionSelector, WriteMeta,
};

/// Versions retained per secret before the oldest are destroyed on write.
const DEFAULT_MAX_VERSIONS: u32 = 10;

/// A version number reserved inside an open transaction.
///
/// Sealing requires the `(secret_id, version)` binding, but only the store can allocate it.
/// Handing out a reserved slot lets the caller seal against real coordinates while the
/// transaction still holds them, so two concurrent writers cannot be given the same version.
pub struct WriteSlot<'store> {
    tx: Transaction<'store>,
    secret_id: Uuid,
    version: Version,
    max_versions: u32,
}

impl WriteSlot<'_> {
    /// The coordinates the caller must seal against.
    #[must_use]
    pub fn binding(&self) -> VersionBinding {
        VersionBinding::new(self.secret_id, self.version.get())
    }

    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// Store the sealed payload and publish it as the current version.
    pub fn commit(self, sealed: &SealedVersion, meta: &WriteMeta) -> Result<Version> {
        let timestamp = now();

        self.tx.execute(
            "INSERT INTO secret_versions
                 (secret_id, version, state, nonce, ciphertext, dek_nonce, wrapped_dek,
                  mk_generation, created_at, created_by, comment)
             VALUES (?1, ?2, 'active', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                self.secret_id.as_bytes().as_slice(),
                self.version.get(),
                sealed.nonce.as_bytes().as_slice(),
                sealed.ciphertext,
                sealed.key.dek_nonce.as_bytes().as_slice(),
                sealed.key.wrapped_dek,
                sealed.key.mk_generation,
                timestamp,
                meta.created_by,
                meta.comment,
            ],
        )?;

        self.tx.execute(
            "UPDATE secrets SET current_version = ?2, updated_at = ?3 WHERE id = ?1",
            params![self.secret_id.as_bytes().as_slice(), self.version.get(), timestamp],
        )?;

        prune(&self.tx, self.secret_id, self.version, self.max_versions)?;
        self.tx.commit()?;
        Ok(self.version)
    }
}

/// Destroy versions that have fallen outside the retention window.
///
/// Never touches `keep`, which is the version just written and therefore the current one.
fn prune(tx: &Transaction<'_>, secret_id: Uuid, keep: Version, max_versions: u32) -> Result<()> {
    let Some(oldest_to_keep) = keep.get().checked_sub(max_versions) else {
        return Ok(());
    };

    tx.execute(
        "UPDATE secret_versions
            SET state = 'destroyed', nonce = NULL, ciphertext = NULL,
                dek_nonce = NULL, wrapped_dek = NULL
          WHERE secret_id = ?1 AND state <> 'destroyed'
            AND version <> ?2 AND version <= ?3",
        params![secret_id.as_bytes().as_slice(), keep.get(), oldest_to_keep],
    )?;
    Ok(())
}

impl Store {
    /// Reserve the next version of `path`, creating the secret if it does not yet exist.
    pub fn begin_write(&mut self, path: &SecretPath) -> Result<WriteSlot<'_>> {
        // IMMEDIATE takes the write lock up front, so the version number this reserves cannot
        // be taken by a racing writer between the read and the insert.
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<(Vec<u8>, u32)> = tx
            .query_row(
                "SELECT id, max_versions FROM secrets WHERE path = ?1",
                [path.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let (secret_id, max_versions) = if let Some((raw, max_versions)) = existing {
            (decode_uuid(&raw)?, max_versions)
        } else {
            let id = Uuid::new_v4();
            let timestamp = now();
            tx.execute(
                "INSERT INTO secrets (id, path, current_version, max_versions,
                                      created_at, updated_at)
                 VALUES (?1, ?2, NULL, ?3, ?4, ?4)",
                params![id.as_bytes().as_slice(), path.as_str(), DEFAULT_MAX_VERSIONS, timestamp],
            )?;
            (id, DEFAULT_MAX_VERSIONS)
        };

        let highest: u32 = tx.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE secret_id = ?1",
            [secret_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;

        Ok(WriteSlot {
            tx,
            secret_id,
            version: Version::new(highest + 1)?,
            max_versions,
        })
    }

    /// Fetch a version's ciphertext. Only `active` versions are returned.
    pub fn read_version(
        &self,
        path: &SecretPath,
        selector: VersionSelector,
    ) -> Result<StoredVersion> {
        let (secret_id, version) = self.resolve(path, selector)?;

        self.conn
            .query_row(
                "SELECT state, nonce, ciphertext, dek_nonce, wrapped_dek, mk_generation,
                        created_at, created_by, comment
                   FROM secret_versions WHERE secret_id = ?1 AND version = ?2",
                params![secret_id.as_bytes().as_slice(), version.get()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, u32>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)
            .and_then(|row| build_stored_version(secret_id, version, row))
    }

    /// Version metadata, newest first. Carries no ciphertext.
    pub fn versions(&self, path: &SecretPath) -> Result<Vec<VersionInfo>> {
        let secret_id = self.secret_id(path)?;

        let mut statement = self.conn.prepare(
            "SELECT version, state, created_at, created_by, comment
               FROM secret_versions WHERE secret_id = ?1 ORDER BY version DESC",
        )?;

        let rows = statement.query_map([secret_id.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;

        rows.map(|row| {
            let (version, state, created_at, created_by, comment) = row?;
            Ok(VersionInfo {
                version: Version::new(version)?,
                state: VersionState::parse(&state)?,
                created_at: timestamp(created_at)?,
                created_by,
                comment,
            })
        })
        .collect()
    }

    /// Move `current_version` to an earlier version without discarding anything.
    pub fn rollback(&self, path: &SecretPath, to: Version) -> Result<()> {
        let secret_id = self.secret_id(path)?;

        let state: String = self
            .conn
            .query_row(
                "SELECT state FROM secret_versions WHERE secret_id = ?1 AND version = ?2",
                params![secret_id.as_bytes().as_slice(), to.get()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;

        if !VersionState::parse(&state)?.is_readable() {
            return Err(StoreError::NotFound);
        }

        self.conn.execute(
            "UPDATE secrets SET current_version = ?2, updated_at = ?3 WHERE id = ?1",
            params![secret_id.as_bytes().as_slice(), to.get(), now()],
        )?;
        Ok(())
    }

    /// Soft-delete or destroy a version.
    pub fn delete_version(
        &self,
        path: &SecretPath,
        selector: VersionSelector,
        mode: DeleteMode,
    ) -> Result<Version> {
        let (secret_id, version) = self.resolve(path, selector)?;

        let statement = match mode {
            DeleteMode::Soft => {
                "UPDATE secret_versions SET state = 'deleted'
                  WHERE secret_id = ?1 AND version = ?2 AND state = 'active'"
            }
            DeleteMode::Destroy => {
                "UPDATE secret_versions
                    SET state = 'destroyed', nonce = NULL, ciphertext = NULL,
                        dek_nonce = NULL, wrapped_dek = NULL
                  WHERE secret_id = ?1 AND version = ?2 AND state <> 'destroyed'"
            }
        };

        let changed = self
            .conn
            .execute(statement, params![secret_id.as_bytes().as_slice(), version.get()])?;

        if changed == 0 {
            return Err(StoreError::NotFound);
        }

        // `current_version` must never name a version that can no longer be read. Left stale,
        // it makes `ls` keep advertising a secret whose every version has been destroyed --
        // metadata that reads as "this is still retrievable" when nothing is.
        self.conn.execute(
            "UPDATE secrets
                SET updated_at = ?2,
                    current_version = (
                        SELECT MAX(version) FROM secret_versions
                         WHERE secret_id = ?1 AND state = 'active'
                    )
              WHERE id = ?1",
            params![secret_id.as_bytes().as_slice(), now()],
        )?;
        Ok(version)
    }

    /// Secrets matching `filter`, ordered by path.
    pub fn list(&self, filter: &ListFilter) -> Result<Vec<SecretSummary>> {
        let mut sql = String::from(
            "SELECT id, path, current_version, created_at, updated_at,
                    (SELECT COUNT(*) FROM secret_versions v
                      WHERE v.secret_id = secrets.id AND v.state <> 'destroyed')
               FROM secrets WHERE 1 = 1",
        );
        let mut bound: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(prefix) = filter.prefix.as_deref().filter(|p| !p.is_empty()) {
            // Compared by substring rather than LIKE: `_` is a LIKE wildcard and is also a
            // legal path character, so LIKE would silently over-match. Appending `/` is what
            // keeps `prod/billing` from matching `prod/billing-admin`.
            let n = bound.len() + 1;
            let _ = write!(sql, " AND (path = ?{n} OR substr(path, 1, length(?{n}) + 1) = ?{n} || '/')");
            bound.push(Box::new(prefix.trim_end_matches('/').to_owned()));
        }

        if !filter.include_empty {
            sql.push_str(" AND current_version IS NOT NULL");
        }

        for tag in &filter.tags {
            let (key_param, value_param) = (bound.len() + 1, bound.len() + 2);
            let _ = write!(
                sql,
                " AND EXISTS (SELECT 1 FROM secret_tags st JOIN tags t ON t.id = st.tag_id
                               WHERE st.secret_id = secrets.id AND t.key = ?{key_param} AND t.value = ?{value_param})"
            );
            bound.push(Box::new(tag.key().to_owned()));
            bound.push(Box::new(tag.value().to_owned()));
        }

        sql.push_str(" ORDER BY path");

        let mut statement = self.conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::ToSql> = bound.iter().map(AsRef::as_ref).collect();
        let rows = statement.query_map(params.as_slice(), |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<u32>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, u64>(5)?,
            ))
        })?;

        let mut tags_by_secret = self.all_tags()?;
        rows.map(|row| {
            let (id, path, current_version, created_at, updated_at, version_count) = row?;
            let id = decode_uuid(&id)?;
            Ok(SecretSummary {
                path: SecretPath::new(&path)?,
                current_version: current_version.map(Version::new).transpose()?,
                version_count,
                tags: tags_by_secret.remove(&id).unwrap_or_default(),
                created_at: timestamp(created_at)?,
                updated_at: timestamp(updated_at)?,
            })
        })
        .collect()
    }

    /// Resolve a selector to a concrete version, without checking readability.
    fn resolve(&self, path: &SecretPath, selector: VersionSelector) -> Result<(Uuid, Version)> {
        let (id, current): (Vec<u8>, Option<u32>) = self
            .conn
            .query_row(
                "SELECT id, current_version FROM secrets WHERE path = ?1",
                [path.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;

        let version = match selector {
            VersionSelector::Exact(version) => version,
            VersionSelector::Current => Version::new(current.ok_or(StoreError::NotFound)?)?,
        };

        Ok((decode_uuid(&id)?, version))
    }

    /// The immutable id a secret's ciphertext is bound to.
    pub fn secret_id(&self, path: &SecretPath) -> Result<Uuid> {
        let raw: Vec<u8> = self
            .conn
            .query_row("SELECT id FROM secrets WHERE path = ?1", [path.as_str()], |row| row.get(0))
            .optional()?
            .ok_or(StoreError::NotFound)?;
        decode_uuid(&raw)
    }

    fn all_tags(&self) -> Result<HashMap<Uuid, Vec<Tag>>> {
        let mut statement = self.conn.prepare(
            "SELECT st.secret_id, t.key, t.value
               FROM secret_tags st JOIN tags t ON t.id = st.tag_id
              ORDER BY t.key, t.value",
        )?;

        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })?;

        let mut grouped: HashMap<Uuid, Vec<Tag>> = HashMap::new();
        for row in rows {
            let (id, key, value) = row?;
            grouped.entry(decode_uuid(&id)?).or_default().push(Tag::new(&key, &value)?);
        }
        Ok(grouped)
    }
}

type VersionRow = (
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    u32,
    i64,
    Option<String>,
    Option<String>,
);

fn build_stored_version(
    secret_id: Uuid,
    version: Version,
    row: VersionRow,
) -> Result<StoredVersion> {
    let (state, nonce, ciphertext, dek_nonce, wrapped_dek, mk_generation, created, by, comment) =
        row;

    let state = VersionState::parse(&state)?;
    if !state.is_readable() {
        // Same error as a missing path: whether a version was deleted is not something an
        // unauthorised caller should be able to learn.
        return Err(StoreError::NotFound);
    }

    let missing = || StoreError::Corrupt { what: "secret version" };
    Ok(StoredVersion {
        binding: VersionBinding::new(secret_id, version.get()),
        sealed: SealedVersion {
            nonce: Nonce::from_slice(&nonce.ok_or_else(missing)?)?,
            ciphertext: ciphertext.ok_or_else(missing)?,
            key: sbae_core::WrappedKey {
                dek_nonce: Nonce::from_slice(&dek_nonce.ok_or_else(missing)?)?,
                wrapped_dek: wrapped_dek.ok_or_else(missing)?,
                mk_generation,
            },
        },
        info: VersionInfo {
            version,
            state,
            created_at: timestamp(created)?,
            created_by: by,
            comment,
        },
    })
}

fn decode_uuid(raw: &[u8]) -> Result<Uuid> {
    let bytes: [u8; 16] =
        raw.try_into().map_err(|_| StoreError::Corrupt { what: "secret id" })?;
    Ok(Uuid::from_bytes(bytes))
}
