//! Whole-store operations: master-key rotation, export and import.
//!
//! Each runs in a single transaction, so a crash part-way leaves the store exactly as it was
//! rather than half-rotated or half-restored.
//!
//! No cryptography happens here. `rekey_with` hands each sealed version back to the caller to
//! rewrap and `export_secrets` returns sealed payloads unopened, keeping every key operation
//! in `sbae-core` where it can be reviewed in one place.

use rusqlite::{params, TransactionBehavior};
use sbae_core::{Nonce, SealedMasterKey, SealedVersion, VersionBinding, WrappedKey};
use sbae_proto::{SecretPath, Tag, Version, VersionState};
use uuid::Uuid;

use crate::{
    store::timestamp, ExportedSecret, ExportedVersion, Result, Store, StoreError,
};

/// One `secret_versions` row as read for rotation, before its nonce is parsed.
///
/// Deliberately carries no payload. Rotation rewrites a 32-byte wrapped key and never reads
/// the ciphertext, so selecting it would make a rotation cost memory proportional to the size
/// of the whole store rather than to the number of versions in it.
struct RewrapRow {
    secret_id: Vec<u8>,
    version: u32,
    dek_nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
    mk_generation: u32,
}

/// Outcome of a rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RekeyReport {
    pub versions_rewrapped: usize,
    pub new_generation: u32,
}

impl Store {
    /// Rotate the master key, rewrapping every version's data key.
    ///
    /// `rewrap` receives each sealed version and must re-encrypt its wrapped data key under
    /// the new master key. The payload itself is never touched -- that is the entire point of
    /// the envelope, and why rotation costs a few hundred 32-byte writes rather than a full
    /// re-encryption of the store.
    ///
    /// The new sealed master key is written in the same transaction, so the store can never
    /// be left holding versions wrapped under a key it no longer records.
    pub fn rekey_with<F>(
        &mut self,
        new_sealed_master: &SealedMasterKey,
        mut rewrap: F,
    ) -> Result<RekeyReport>
    where
        F: FnMut(VersionBinding, &mut WrappedKey) -> Result<()>,
    {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let pending: Vec<RewrapRow> = {
            let mut statement = tx.prepare(
                "SELECT secret_id, version, dek_nonce, wrapped_dek, mk_generation
                   FROM secret_versions WHERE state <> 'destroyed'",
            )?;
            let rows = statement.query_map([], |row| {
                Ok(RewrapRow {
                    secret_id: row.get(0)?,
                    version: row.get(1)?,
                    dek_nonce: row.get(2)?,
                    wrapped_dek: row.get(3)?,
                    mk_generation: row.get(4)?,
                })
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };

        let mut rewrapped = 0;
        for row in pending {
            let mut key = WrappedKey {
                dek_nonce: Nonce::from_slice(&row.dek_nonce)?,
                wrapped_dek: row.wrapped_dek,
                mk_generation: row.mk_generation,
            };

            let binding = VersionBinding::new(decode_uuid(&row.secret_id)?, row.version);
            rewrap(binding, &mut key)?;

            tx.execute(
                "UPDATE secret_versions
                    SET dek_nonce = ?3, wrapped_dek = ?4, mk_generation = ?5
                  WHERE secret_id = ?1 AND version = ?2",
                params![
                    row.secret_id,
                    row.version,
                    key.dek_nonce.as_bytes().as_slice(),
                    key.wrapped_dek,
                    key.mk_generation,
                ],
            )?;
            rewrapped += 1;
        }

        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('sealed_master_key', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![new_sealed_master.to_bytes()],
        )?;

        tx.commit()?;
        Ok(RekeyReport {
            versions_rewrapped: rewrapped,
            new_generation: new_sealed_master.generation,
        })
    }

    /// Every secret with its retained versions, sealed exactly as stored.
    pub fn export_secrets(&self) -> Result<Vec<ExportedSecret>> {
        let mut statement = self
            .conn
            .prepare("SELECT id, path, max_versions, current_version FROM secrets ORDER BY path")?;

        let secrets: Vec<(Vec<u8>, String, u32, Option<u32>)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;

        secrets
            .into_iter()
            .map(|(id, path, max_versions, current_version)| {
                let path = SecretPath::new(&path)?;
                Ok(ExportedSecret {
                    tags: self.tags(&path)?,
                    versions: self.exported_versions(&decode_uuid(&id)?)?,
                    path,
                    max_versions,
                    current_version: current_version.map(Version::new).transpose()?,
                })
            })
            .collect()
    }

    fn exported_versions(&self, secret_id: &Uuid) -> Result<Vec<ExportedVersion>> {
        let mut statement = self.conn.prepare(
            "SELECT version, state, nonce, ciphertext, dek_nonce, wrapped_dek, mk_generation,
                    created_at, created_by, comment
               FROM secret_versions WHERE secret_id = ?1 ORDER BY version",
        )?;

        let rows = statement.query_map([secret_id.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, u32>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        })?;

        rows.map(|row| {
            let (version, state, nonce, ciphertext, dek_nonce, wrapped, generation, at, by, note) =
                row?;

            let sealed = match (nonce, ciphertext, dek_nonce, wrapped) {
                (Some(nonce), Some(ciphertext), Some(dek_nonce), Some(wrapped_dek)) => {
                    Some(SealedVersion {
                        nonce: Nonce::from_slice(&nonce)?,
                        ciphertext,
                        key: WrappedKey {
                            dek_nonce: Nonce::from_slice(&dek_nonce)?,
                            wrapped_dek,
                            mk_generation: generation,
                        },
                    })
                }
                _ => None,
            };

            Ok(ExportedVersion {
                version: Version::new(version)?,
                state: VersionState::parse(&state)?,
                created_at: timestamp(at)?,
                created_by: by,
                comment: note,
                sealed,
            })
        })
        .collect()
    }

    /// Write a secret and its versions verbatim, preserving version numbers and provenance.
    ///
    /// Refuses a path that already exists rather than merging, because silently interleaving
    /// two histories would produce a version list no operator could reason about.
    pub fn import_secret(&mut self, secret: &ExportedSecret) -> Result<()> {
        self.import_secret_with_id(Uuid::new_v4(), secret)
    }

    /// Import under a caller-chosen id.
    ///
    /// A version's associated data binds the secret id, so a caller that sealed payloads
    /// before the import must be able to name the same id here -- otherwise nothing it wrote
    /// would ever decrypt again.
    pub fn import_secret_with_id(&mut self, id: Uuid, secret: &ExportedSecret) -> Result<()> {
        if self.exists(&secret.path)? {
            return Err(StoreError::AlreadyExists);
        }

        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let created = secret
            .versions
            .first()
            .map_or_else(crate::store::now, |first| first.created_at.unix_timestamp());

        tx.execute(
            "INSERT INTO secrets (id, path, current_version, max_versions, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![
                id.as_bytes().as_slice(),
                secret.path.as_str(),
                secret.current_version.map(Version::get),
                secret.max_versions,
                created,
            ],
        )?;

        for version in &secret.versions {
            let sealed = version.sealed.as_ref();
            tx.execute(
                "INSERT INTO secret_versions
                     (secret_id, version, state, nonce, ciphertext, dek_nonce, wrapped_dek,
                      mk_generation, created_at, created_by, comment)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    id.as_bytes().as_slice(),
                    version.version.get(),
                    version.state.as_str(),
                    sealed.map(|s| s.nonce.as_bytes().as_slice()),
                    sealed.map(|s| s.ciphertext.as_slice()),
                    sealed.map(|s| s.key.dek_nonce.as_bytes().as_slice()),
                    sealed.map(|s| s.key.wrapped_dek.as_slice()),
                    sealed.map_or(0, |s| s.key.mk_generation),
                    version.created_at.unix_timestamp(),
                    version.created_by,
                    version.comment,
                ],
            )?;
        }

        tx.commit()?;

        let tags: Vec<Tag> = secret.tags.clone();
        self.add_tags(&secret.path, &tags)
    }
}

fn decode_uuid(raw: &[u8]) -> Result<Uuid> {
    let bytes: [u8; 16] = raw.try_into().map_err(|_| StoreError::Corrupt { what: "secret id" })?;
    Ok(Uuid::from_bytes(bytes))
}
