//! Persisted audit log entries.

use crate::{AuditEntry, EntryHash, Seq};

/// An audit entry committed to SQLite, bound to its sequence number and chain hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: Seq,
    pub entry: AuditEntry,
    pub prev_hash: EntryHash,
    pub entry_hash: EntryHash,
}
