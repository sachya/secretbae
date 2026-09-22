//! Tamper-evident append-only audit log for secretbae.
//!
//! Every state change and authorization event is committed to the SQLite `audit` table
//! as an entry in a cryptographically keyed hash chain. The MAC key is derived from the
//! master key via HKDF, so that write access to the SQLite file alone is insufficient to
//! recompute valid chain hashes after altering or deleting rows.
//!
//! ```text
//! entry_0 (genesis) ──► entry_1 ──► entry_2 ──► ... ──► tail
//!   prev_hash: [0;32]     prev: H_0     prev: H_1
//!   hash: H_0             hash: H_1     hash: H_2
//! ```

#![forbid(unsafe_code)]
#![allow(clippy::similar_names)]

mod anchor;
mod canonical;
mod entry;
mod error;
mod hash;
mod log;
mod record;
mod rekey;
mod verify;

pub use entry::{
    Action, AuditEntry, AuditPath, AuditResult, Detail, PeerPid, PeerUid, Seq, Timestamp,
    TokenPrefix,
};
pub use error::{AuditError, Result};
pub use hash::{compute_entry_hash, EntryHash};
pub use anchor::Anchor;
pub use log::append;
pub use rekey::{rekey_chain, ChainRekeyReport};
pub use record::AuditRecord;
pub use verify::{verify, VerificationResult};
