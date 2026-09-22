//! Tag operations.

use rusqlite::{params, OptionalExtension};
use sbae_proto::{SecretPath, Tag, TagSelector};

use crate::{store::now, Result, Store};

impl Store {
    /// Attach tags to a secret. Re-adding an existing tag is a no-op rather than an error,
    /// so `tag add` is safe to run from configuration management.
    pub fn add_tags(&self, path: &SecretPath, tags: &[Tag]) -> Result<()> {
        let secret_id = self.secret_id(path)?;

        for tag in tags {
            self.conn.execute(
                "INSERT INTO tags (key, value) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                params![tag.key(), tag.value()],
            )?;

            self.conn.execute(
                "INSERT INTO secret_tags (secret_id, tag_id)
                 SELECT ?1, id FROM tags WHERE key = ?2 AND value = ?3
                 ON CONFLICT DO NOTHING",
                params![secret_id.as_bytes().as_slice(), tag.key(), tag.value()],
            )?;
        }

        self.touch(path)
    }

    /// Detach tags from a secret. Tags no longer used by any secret are removed entirely so
    /// the `tags` table does not accumulate labels that exist only in history.
    pub fn remove_tags(&self, path: &SecretPath, selectors: &[TagSelector]) -> Result<()> {
        let secret_id = self.secret_id(path)?;

        for selector in selectors {
            match selector {
                TagSelector::Exact(tag) => self.conn.execute(
                    "DELETE FROM secret_tags
                      WHERE secret_id = ?1
                        AND tag_id IN (SELECT id FROM tags WHERE key = ?2 AND value = ?3)",
                    params![secret_id.as_bytes().as_slice(), tag.key(), tag.value()],
                )?,
                TagSelector::Key(key) => self.conn.execute(
                    "DELETE FROM secret_tags
                      WHERE secret_id = ?1
                        AND tag_id IN (SELECT id FROM tags WHERE key = ?2)",
                    params![secret_id.as_bytes().as_slice(), key],
                )?,
            };
        }

        self.conn.execute(
            "DELETE FROM tags WHERE id NOT IN (SELECT tag_id FROM secret_tags)",
            [],
        )?;

        self.touch(path)
    }

    /// Tags on a secret, ordered so output is stable between runs.
    pub fn tags(&self, path: &SecretPath) -> Result<Vec<Tag>> {
        let secret_id = self.secret_id(path)?;

        let mut statement = self.conn.prepare(
            "SELECT t.key, t.value
               FROM secret_tags st JOIN tags t ON t.id = st.tag_id
              WHERE st.secret_id = ?1
              ORDER BY t.key, t.value",
        )?;

        let rows = statement.query_map([secret_id.as_bytes().as_slice()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.map(|row| {
            let (key, value) = row?;
            Ok(Tag::new(&key, &value)?)
        })
        .collect()
    }

    /// Every distinct tag in the store, for shell completion and `tag ls` with no path.
    pub fn all_distinct_tags(&self) -> Result<Vec<Tag>> {
        let mut statement =
            self.conn.prepare("SELECT key, value FROM tags ORDER BY key, value")?;

        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.map(|row| {
            let (key, value) = row?;
            Ok(Tag::new(&key, &value)?)
        })
        .collect()
    }

    fn touch(&self, path: &SecretPath) -> Result<()> {
        self.conn.execute(
            "UPDATE secrets SET updated_at = ?2 WHERE path = ?1",
            params![path.as_str(), now()],
        )?;
        Ok(())
    }

    /// Whether a secret exists, regardless of whether it has any readable version.
    pub fn exists(&self, path: &SecretPath) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM secrets WHERE path = ?1", [path.as_str()], |_| Ok(()))
            .optional()?
            .is_some())
    }
}
