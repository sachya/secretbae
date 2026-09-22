//! The chain anchor: what makes truncation detectable.
//!
//! A hash chain on its own proves that no entry was altered or removed from the *middle*, but
//! says nothing about entries removed from the *end* -- delete the last ten rows and the
//! remainder still verifies perfectly. That is the difference between an attacker being
//! unable to hide their tracks and merely having to delete a few more rows.
//!
//! So every append also rewrites an anchor recording how long the chain is and where it ends,
//! authenticated with the same audit key. The key lives only in the daemon's locked memory,
//! so an attacker with write access to the database can shorten the chain but cannot produce
//! an anchor that agrees with the shortened version.

use rusqlite::{Connection, OptionalExtension};

use sbae_core::Key32;

use crate::{AuditError, EntryHash, Result};

const META_KEY: &str = "audit_anchor";
const DOMAIN: &[u8] = b"secretbae/audit/anchor/v1";
const ENCODED_LEN: usize = 8 + 32 + 32;

/// How long the chain is and what it ends with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub entries: u64,
    pub tail_hash: EntryHash,
}

impl Anchor {
    fn mac(&self, audit_key: &Key32) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(audit_key.expose());
        hasher.update(DOMAIN);
        hasher.update(&self.entries.to_le_bytes());
        hasher.update(self.tail_hash.as_bytes());
        *hasher.finalize().as_bytes()
    }

    fn encode(&self, audit_key: &Key32) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(ENCODED_LEN);
        encoded.extend_from_slice(&self.entries.to_le_bytes());
        encoded.extend_from_slice(self.tail_hash.as_bytes());
        encoded.extend_from_slice(&self.mac(audit_key));
        encoded
    }

    /// Decode and authenticate. Returns `None` when the MAC does not verify, which means the
    /// anchor was written by something that did not hold the audit key.
    fn decode(encoded: &[u8], audit_key: &Key32) -> Option<Self> {
        if encoded.len() != ENCODED_LEN {
            return None;
        }

        let anchor = Self {
            entries: u64::from_le_bytes(encoded[..8].try_into().ok()?),
            tail_hash: EntryHash::from_bytes(encoded[8..40].try_into().ok()?),
        };

        // Constant time is not required: the comparand is a hash of data the caller can
        // already read, and a mismatch aborts verification outright.
        (anchor.mac(audit_key) == encoded[40..]).then_some(anchor)
    }
}

/// Rewrite the anchor. Must be called inside the same transaction as the append it describes,
/// so the chain and its anchor can never disagree because of a crash between the two.
pub fn store(tx: &rusqlite::Transaction<'_>, audit_key: &Key32, anchor: Anchor) -> Result<()> {
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![META_KEY, anchor.encode(audit_key)],
    )?;
    Ok(())
}

/// The stored anchor, or `None` if the log has never been written to.
pub fn load(conn: &Connection, audit_key: &Key32) -> Result<Option<Anchor>> {
    let stored: Option<Vec<u8>> = conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [META_KEY], |row| row.get(0))
        .optional()?;

    match stored {
        None => Ok(None),
        Some(encoded) => Anchor::decode(&encoded, audit_key)
            .map(Some)
            .ok_or(AuditError::Corrupt { what: "audit anchor failed authentication" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Key32 {
        Key32::from_bytes([byte; 32])
    }

    fn anchor() -> Anchor {
        Anchor { entries: 7, tail_hash: EntryHash::from_bytes([9u8; 32]) }
    }

    #[test]
    fn an_anchor_round_trips() {
        let encoded = anchor().encode(&key(1));
        assert_eq!(Anchor::decode(&encoded, &key(1)), Some(anchor()));
    }

    /// Without the audit key an attacker cannot mint an anchor for a chain they shortened.
    #[test]
    fn an_anchor_forged_under_another_key_is_rejected() {
        let encoded = anchor().encode(&key(2));
        assert_eq!(Anchor::decode(&encoded, &key(1)), None);
    }

    #[test]
    fn editing_the_recorded_length_invalidates_the_anchor() {
        let mut encoded = anchor().encode(&key(1));
        encoded[0] ^= 0x01;
        assert_eq!(Anchor::decode(&encoded, &key(1)), None);
    }

    #[test]
    fn editing_the_recorded_tail_invalidates_the_anchor() {
        let mut encoded = anchor().encode(&key(1));
        encoded[8] ^= 0x01;
        assert_eq!(Anchor::decode(&encoded, &key(1)), None);
    }

    #[test]
    fn a_truncated_or_padded_anchor_is_rejected() {
        let encoded = anchor().encode(&key(1));
        assert_eq!(Anchor::decode(&encoded[..ENCODED_LEN - 1], &key(1)), None);
        assert_eq!(Anchor::decode(&[encoded, vec![0]].concat(), &key(1)), None);
        assert_eq!(Anchor::decode(&[], &key(1)), None);
    }
}
