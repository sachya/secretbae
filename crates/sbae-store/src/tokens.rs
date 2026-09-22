//! Token and policy persistence.

use rusqlite::{params, OptionalExtension};
use sbae_policy::{LookupPrefix, Policy, TokenHash, TokenId, TokenRecord};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    store::{now, timestamp},
    Result, Store, StoreError,
};

/// A token plus the policies attached to it, as shown by `token list`.
#[derive(Clone, Debug)]
pub struct TokenSummary {
    pub record: TokenRecord,
    pub policies: Vec<String>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

/// Everything needed to persist a newly issued token.
///
/// A struct rather than a long parameter list because `bound_uid` and `expires_at` are both
/// optional and adjacent -- as positional arguments they would be trivial to transpose, and
/// transposing them silently produces a token with no uid binding.
pub struct NewToken<'a> {
    pub id: TokenId,
    pub prefix: &'a LookupPrefix,
    pub hash: &'a TokenHash,
    pub name: &'a str,
    pub bound_uid: Option<u32>,
    pub expires_at: Option<OffsetDateTime>,
    pub policies: &'a [String],
}

impl Store {
    /// Persist a newly issued token and attach it to named policies.
    ///
    /// Fails if any named policy is absent, rather than creating a token with fewer grants
    /// than the operator asked for -- a token that silently grants less is a debugging trap.
    pub fn create_token(&mut self, token: &NewToken<'_>) -> Result<()> {
        let NewToken { id, prefix, hash, name, bound_uid, expires_at, policies } = *token;
        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO tokens (id, lookup_prefix, hash, name, bound_uid, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id.as_uuid().as_bytes().as_slice(),
                prefix.as_str(),
                hash.as_bytes().as_slice(),
                name,
                bound_uid,
                now(),
                expires_at.map(OffsetDateTime::unix_timestamp),
            ],
        )?;

        for policy in policies {
            let attached = tx.execute(
                "INSERT INTO token_policies (token_id, policy_id)
                 SELECT ?1, id FROM policies WHERE name = ?2",
                params![id.as_uuid().as_bytes().as_slice(), policy],
            )?;

            if attached == 0 {
                return Err(StoreError::NotFound);
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// Find a token by the public half of its value.
    pub fn token_by_prefix(&self, prefix: &LookupPrefix) -> Result<Option<TokenRecord>> {
        self.conn
            .query_row(
                "SELECT id, hash, name, bound_uid, expires_at, revoked_at
                   FROM tokens WHERE lookup_prefix = ?1",
                [prefix.as_str()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<u32>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()?
            .map(|(id, hash, name, bound_uid, expires_at, revoked_at)| {
                Ok(TokenRecord {
                    id: TokenId::from_uuid(decode_uuid(&id)?),
                    prefix: prefix.clone(),
                    hash: TokenHash::from_slice(&hash)
                        .map_err(|_| StoreError::Corrupt { what: "token hash" })?,
                    name,
                    bound_uid,
                    expires_at: expires_at.map(timestamp).transpose()?,
                    revoked_at: revoked_at.map(timestamp).transpose()?,
                })
            })
            .transpose()
    }

    /// The policies attached to a token, parsed and ready to evaluate.
    pub fn policies_for_token(&self, id: TokenId) -> Result<Vec<Policy>> {
        let mut statement = self.conn.prepare(
            "SELECT p.document
               FROM token_policies tp JOIN policies p ON p.id = tp.policy_id
              WHERE tp.token_id = ?1
              ORDER BY p.name",
        )?;

        let rows =
            statement.query_map([id.as_uuid().as_bytes().as_slice()], |row| row.get::<_, String>(0))?;

        rows.map(|document| Ok(Policy::from_json(&document?)?)).collect()
    }

    /// Record that a token was used. Best-effort: a failure here must not fail the request
    /// the caller actually made, so the caller is expected to ignore the error.
    pub fn touch_token(&self, id: TokenId) -> Result<()> {
        self.conn.execute(
            "UPDATE tokens SET last_used_at = ?2 WHERE id = ?1",
            params![id.as_uuid().as_bytes().as_slice(), now()],
        )?;
        Ok(())
    }

    /// Revoke a token. Idempotent, so repeated revocation during incident response is safe.
    pub fn revoke_token(&self, prefix: &LookupPrefix) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE tokens SET revoked_at = ?2 WHERE lookup_prefix = ?1 AND revoked_at IS NULL",
            params![prefix.as_str(), now()],
        )?;

        if changed == 0 && self.token_by_prefix(prefix)?.is_none() {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn list_tokens(&self) -> Result<Vec<TokenSummary>> {
        let mut statement = self.conn.prepare(
            "SELECT lookup_prefix, created_at, last_used_at FROM tokens ORDER BY created_at",
        )?;

        let prefixes: Vec<(String, i64, Option<i64>)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;

        prefixes
            .into_iter()
            .map(|(prefix, created_at, last_used_at)| {
                let prefix = LookupPrefix::parse(&prefix)
                    .map_err(|_| StoreError::Corrupt { what: "token prefix" })?;
                let record = self.token_by_prefix(&prefix)?.ok_or(StoreError::NotFound)?;
                Ok(TokenSummary {
                    policies: self.policy_names_for_token(record.id)?,
                    record,
                    created_at: timestamp(created_at)?,
                    last_used_at: last_used_at.map(timestamp).transpose()?,
                })
            })
            .collect()
    }

    fn policy_names_for_token(&self, id: TokenId) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            "SELECT p.name FROM token_policies tp JOIN policies p ON p.id = tp.policy_id
              WHERE tp.token_id = ?1 ORDER BY p.name",
        )?;

        let rows =
            statement.query_map([id.as_uuid().as_bytes().as_slice()], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Create or replace a policy. Storing the parsed form's re-serialisation rather than the
    /// operator's text means anything unparseable is rejected at write time, not at the first
    /// request that depends on it.
    pub fn put_policy(&self, policy: &Policy) -> Result<()> {
        self.conn.execute(
            "INSERT INTO policies (name, document, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET document = excluded.document",
            params![policy.name, policy.to_json()?, now()],
        )?;
        Ok(())
    }

    /// Create `policy` only if no policy of that name exists yet. Returns whether it was
    /// newly created.
    ///
    /// Used to seed built-in policies (`root`, `unrestricted`) on every startup so an
    /// existing store upgraded from an older version gains them too. Unlike [`put_policy`],
    /// this never overwrites: an operator who has customised a built-in name is not silently
    /// reverted to the shipped default on the next restart.
    pub fn ensure_policy_exists(&self, policy: &Policy) -> Result<bool> {
        let inserted = self.conn.execute(
            "INSERT INTO policies (name, document, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO NOTHING",
            params![policy.name, policy.to_json()?, now()],
        )?;
        Ok(inserted > 0)
    }

    /// Every policy document, for inclusion in a backup bundle.
    pub fn all_policy_documents(&self) -> Result<Vec<String>> {
        let mut statement =
            self.conn.prepare("SELECT document FROM policies ORDER BY name")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn list_policy_names(&self) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare("SELECT name FROM policies ORDER BY name")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn delete_policy(&self, name: &str) -> Result<()> {
        if self.conn.execute("DELETE FROM policies WHERE name = ?1", [name])? == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn secret_count(&self) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM secrets WHERE current_version IS NOT NULL",
            [],
            |row| row.get(0),
        )?)
    }
}

fn decode_uuid(raw: &[u8]) -> Result<Uuid> {
    let bytes: [u8; 16] = raw.try_into().map_err(|_| StoreError::Corrupt { what: "token id" })?;
    Ok(Uuid::from_bytes(bytes))
}
