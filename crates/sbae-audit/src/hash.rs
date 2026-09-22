//! Cryptographic hash operations for the audit chain.

use core::fmt;

use sbae_core::Key32;

use crate::{AuditEntry, AuditError, Result};

/// A 32-byte BLAKE3 hash linking entries into the tamper-evident chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryHash([u8; 32]);

impl EntryHash {
    /// Genesis previous-hash value linking the very first entry.
    pub const GENESIS: Self = Self([0u8; 32]);

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl TryFrom<&[u8]> for EntryHash {
    type Error = AuditError;

    fn try_from(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = slice.try_into().map_err(|_| AuditError::InvalidHashLength {
            expected: 32,
            found: slice.len(),
        })?;
        Ok(Self(bytes))
    }
}

impl From<[u8; 32]> for EntryHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<EntryHash> for [u8; 32] {
    fn from(hash: EntryHash) -> Self {
        hash.0
    }
}

impl fmt::Display for EntryHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for EntryHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntryHash({self})")
    }
}

/// Computes `entry_hash = blake3::keyed_hash(audit_key, prev_hash || canonical(entry))`.
///
/// A keyed MAC ensures an attacker with raw database write access cannot recompute valid hashes.
#[must_use]
pub fn compute_entry_hash(
    audit_key: &Key32,
    prev_hash: &EntryHash,
    entry: &AuditEntry,
) -> EntryHash {
    let mut hasher = blake3::Hasher::new_keyed(audit_key.expose());
    hasher.update(prev_hash.as_bytes());
    hasher.update(&entry.canonical());
    let hash: [u8; 32] = *hasher.finalize().as_bytes();
    EntryHash::from_bytes(hash)
}
