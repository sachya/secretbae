//! Verification of the audit log hash chain.

use core::fmt;

use rusqlite::Connection;
use sbae_core::Key32;

use crate::{
    compute_entry_hash, Action, AuditEntry, AuditError, AuditPath, AuditResult, Detail, EntryHash,
    PeerPid, PeerUid, Result, Seq, Timestamp, TokenPrefix,
};

/// The outcome of walking the audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    /// The audit chain is unbroken and all entry hashes match their recorded contents.
    Valid {
        entries_verified: u64,
        tail_hash: Option<EntryHash>,
    },
    /// A row's content or `entry_hash` was modified after append.
    Modified {
        seq: Seq,
        stored_hash: EntryHash,
        computed_hash: EntryHash,
    },
    /// Sequence numbers have a gap, indicating row deletion or table truncation.
    Gap {
        expected: Seq,
        found: Seq,
    },
    /// Entries were removed from the end of the chain. Undetectable by the links alone --
    /// a shortened chain still verifies -- so this is caught by the authenticated anchor.
    Truncated {
        expected_entries: u64,
        found_entries: u64,
    },
    /// The anchor is absent, or was written by something without the audit key.
    AnchorInvalid,
    /// A row's `prev_hash` does not point to the previous row's `entry_hash`.
    BrokenLink {
        seq: Seq,
        expected_prev: EntryHash,
        found_prev: EntryHash,
    },
    /// A row's data contains corrupt or unparseable columns.
    Corrupt {
        seq: Seq,
        what: &'static str,
    },
}

impl VerificationResult {
    /// Returns `true` if the entire log verified without any discrepancies.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    /// The sequence number where verification first failed, or `None` if the chain is clean.
    #[must_use]
    pub const fn broken_seq(&self) -> Option<Seq> {
        match self {
            Self::Modified { seq, .. }
            | Self::BrokenLink { seq, .. }
            | Self::Corrupt { seq, .. } => Some(*seq),
            Self::Gap { expected, .. } => Some(*expected),
            // A clean chain has no broken entry; truncation and a bad anchor are properties
            // of the chain as a whole, so neither has a single entry to point at.
            Self::Valid { .. } | Self::Truncated { .. } | Self::AnchorInvalid => None,
        }
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid { entries_verified, .. } => {
                write!(f, "audit chain verified clean ({entries_verified} entries)")
            }
            Self::Modified { seq, stored_hash, computed_hash } => {
                write!(
                    f,
                    "entry modified at seq {seq}: stored hash {stored_hash}, computed {computed_hash}"
                )
            }
            Self::Gap { expected, found } => {
                write!(f, "sequence gap detected: expected seq {expected}, found {found}")
            }
            Self::Truncated { expected_entries, found_entries } => write!(
                f,
                "audit chain truncated: anchor records {expected_entries} entries, found {found_entries}"
            ),
            Self::AnchorInvalid => {
                f.write_str("audit anchor is missing or was not written by this store")
            }
            Self::BrokenLink { seq, expected_prev, found_prev } => {
                write!(
                    f,
                    "chain link broken at seq {seq}: expected prev_hash {expected_prev}, found {found_prev}"
                )
            }
            Self::Corrupt { seq, what } => {
                write!(f, "corrupt entry at seq {seq}: {what}")
            }
        }
    }
}

enum RowValidation {
    Valid {
        seq: Seq,
        prev_hash: EntryHash,
        entry_hash: EntryHash,
        entry: AuditEntry,
    },
    Corrupt {
        seq: Seq,
        what: &'static str,
    },
}

fn parse_and_validate_row(
    row: &rusqlite::Row<'_>,
    fallback_seq: Seq,
) -> rusqlite::Result<RowValidation> {
    let raw_seq: i64 = row.get(0)?;
    let Ok(seq_u64) = u64::try_from(raw_seq) else {
        return Ok(RowValidation::Corrupt {
            seq: fallback_seq,
            what: "negative sequence number in row",
        });
    };
    let current_seq = Seq::new(seq_u64);

    let raw_prev: Vec<u8> = row.get(10)?;
    let Ok(prev_hash) = EntryHash::try_from(raw_prev.as_slice()) else {
        return Ok(RowValidation::Corrupt {
            seq: current_seq,
            what: "invalid prev_hash length",
        });
    };

    let raw_entry_hash: Vec<u8> = row.get(11)?;
    let Ok(entry_hash) = EntryHash::try_from(raw_entry_hash.as_slice()) else {
        return Ok(RowValidation::Corrupt {
            seq: current_seq,
            what: "invalid entry_hash length",
        });
    };

    let raw_ts: i64 = row.get(1)?;
    let ts = Timestamp::from_unix(raw_ts);
    let token_prefix: Option<String> = row.get(2)?;
    let uid: Option<u32> = row.get(3)?;
    let pid: Option<u32> = row.get(4)?;

    let action_str: String = row.get(5)?;
    let Ok(action) = Action::parse(&action_str) else {
        return Ok(RowValidation::Corrupt {
            seq: current_seq,
            what: "unknown action variant",
        });
    };

    let path: Option<String> = row.get(6)?;
    let raw_version: Option<u32> = row.get(7)?;
    let version = match raw_version {
        Some(v) => {
            let Ok(ver) = sbae_proto::Version::new(v) else {
                return Ok(RowValidation::Corrupt {
                    seq: current_seq,
                    what: "invalid version number",
                });
            };
            Some(ver)
        }
        None => None,
    };

    let result_str: String = row.get(8)?;
    let Ok(result) = AuditResult::parse(&result_str) else {
        return Ok(RowValidation::Corrupt {
            seq: current_seq,
            what: "unknown result variant",
        });
    };

    let detail: Option<String> = row.get(9)?;

    let entry = AuditEntry {
        ts,
        token_prefix: token_prefix.map(TokenPrefix::new),
        peer_uid: uid.map(PeerUid::new),
        peer_pid: pid.map(PeerPid::new),
        action,
        path: path.map(AuditPath::new),
        version,
        result,
        detail: detail.map(Detail::new),
    };

    Ok(RowValidation::Valid {
        seq: current_seq,
        prev_hash,
        entry_hash,
        entry,
    })
}

/// Read one entry's content, reusing the same parser the chain walk uses so the two can
/// never disagree about how a row decodes.
pub(crate) fn read_entry(tx: &Connection, seq: i64) -> Result<AuditEntry> {
    let stored_seq = Seq::new(u64::try_from(seq).map_err(|_| AuditError::Corrupt {
        what: "negative audit sequence",
    })?);

    tx.query_row(
        "SELECT seq, ts, token_prefix, peer_uid, peer_pid, action, path, version, result, detail,
                prev_hash, entry_hash
           FROM audit WHERE seq = ?1",
        [seq],
        |row| parse_and_validate_row(row, stored_seq),
    )
    .map_err(AuditError::from)
    .and_then(|validation| match validation {
        RowValidation::Valid { entry, .. } => Ok(entry),
        RowValidation::Corrupt { what, .. } => Err(AuditError::Corrupt { what }),
    })
}

/// Walks the audit chain from genesis to tail, checking every link and MAC.
///
/// Stops at and reports the first sequence number where an inconsistency occurs, distinguishing
/// content tampering from row deletion or link corruption.
pub fn verify(conn: &Connection, audit_key: &Key32) -> Result<VerificationResult> {
    let mut stmt = conn.prepare(
        "SELECT seq, ts, token_prefix, peer_uid, peer_pid, action, path, version, result, detail, prev_hash, entry_hash
         FROM audit ORDER BY seq ASC",
    )?;

    let mut rows = stmt.query([])?;

    let mut count = 0u64;
    let mut expected_seq = Seq::FIRST;
    let mut expected_prev_hash = EntryHash::GENESIS;

    while let Some(row) = rows.next()? {
        let validation = parse_and_validate_row(row, expected_seq)?;
        let RowValidation::Valid { seq, prev_hash, entry_hash, entry } = validation else {
            let RowValidation::Corrupt { seq, what } = validation else { unreachable!() };
            return Ok(VerificationResult::Corrupt { seq, what });
        };

        if seq != expected_seq {
            return Ok(VerificationResult::Gap {
                expected: expected_seq,
                found: seq,
            });
        }

        if prev_hash != expected_prev_hash {
            return Ok(VerificationResult::BrokenLink {
                seq,
                expected_prev: expected_prev_hash,
                found_prev: prev_hash,
            });
        }

        let computed_hash = compute_entry_hash(audit_key, &prev_hash, &entry);
        if entry_hash != computed_hash {
            return Ok(VerificationResult::Modified {
                seq,
                stored_hash: entry_hash,
                computed_hash,
            });
        }

        count += 1;
        expected_seq = seq.next();
        expected_prev_hash = entry_hash;
    }

    let tail_hash = (count > 0).then_some(expected_prev_hash);

    match crate::anchor::load(conn, audit_key)? {
        None if count == 0 => Ok(VerificationResult::Valid { entries_verified: 0, tail_hash }),
        // A chain with entries but no anchor means the anchor row was deleted.
        None => Ok(VerificationResult::AnchorInvalid),
        Some(anchor) if anchor.entries > count => Ok(VerificationResult::Truncated {
            expected_entries: anchor.entries,
            found_entries: count,
        }),
        Some(anchor) if anchor.entries != count || Some(anchor.tail_hash) != tail_hash => {
            Ok(VerificationResult::AnchorInvalid)
        }
        Some(_) => Ok(VerificationResult::Valid { entries_verified: count, tail_hash }),
    }
}
