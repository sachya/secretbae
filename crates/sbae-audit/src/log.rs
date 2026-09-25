//! Appending new entries to the tamper-evident audit log.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use sbae_core::Key32;

use crate::{
    anchor, compute_entry_hash, Anchor, AuditEntry, AuditError, AuditPath, AuditRecord, Detail,
    EntryHash, PeerPid, PeerUid, Result, Seq, TokenPrefix,
};

/// Writes one [`AuditEntry`] to the audit table in `conn`, extending the hash chain.
///
/// An `IMMEDIATE` transaction takes SQLite's write lock before reading the tail, preventing
/// concurrent writers from seeing the same tail and branching the hash chain. The anchor is
/// rewritten in that same transaction so a crash can never leave the two disagreeing.
pub fn append(conn: &mut Connection, audit_key: &Key32, entry: &AuditEntry) -> Result<AuditRecord> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let tail: Option<Vec<u8>> = tx
        .query_row(
            "SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;

    let prev_hash = match tail {
        Some(bytes) => EntryHash::try_from(bytes.as_slice())?,
        None => EntryHash::GENESIS,
    };

    let entries: u64 = tx.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))?;

    let entry_hash = compute_entry_hash(audit_key, &prev_hash, entry);

    tx.execute(
        "INSERT INTO audit (
            ts, token_prefix, peer_uid, peer_pid, action, path, version, result, detail, prev_hash, entry_hash
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            entry.ts.as_i64(),
            entry.token_prefix.as_ref().map(TokenPrefix::as_str),
            entry.peer_uid.map(PeerUid::as_u32),
            entry.peer_pid.map(PeerPid::as_u32),
            entry.action.as_str(),
            entry.path.as_ref().map(AuditPath::as_str),
            entry.version.map(sbae_proto::Version::get),
            entry.result.as_str(),
            entry.detail.as_ref().map(Detail::as_str),
            prev_hash.as_bytes().as_slice(),
            entry_hash.as_bytes().as_slice(),
        ],
    )?;

    let inserted_id = tx.last_insert_rowid();
    let seq_num = u64::try_from(inserted_id).map_err(|_| AuditError::Corrupt {
        what: "sqlite rowid was negative",
    })?;
    let seq = Seq::new(seq_num);

    anchor::store(
        &tx,
        audit_key,
        Anchor {
            entries: entries + 1,
            tail_hash: entry_hash,
        },
    )?;
    tx.commit()?;

    Ok(AuditRecord {
        seq,
        entry: entry.clone(),
        prev_hash,
        entry_hash,
    })
}
