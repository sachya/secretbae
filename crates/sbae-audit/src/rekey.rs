//! Re-keying the audit chain when the master key rotates.
//!
//! The chain's MAC key is derived from the master key, so a rotation would otherwise leave
//! every existing entry unverifiable. Rather than discarding the history, the chain is
//! recomputed under the new key with its contents and order untouched.
//!
//! The chain is verified under the old key *first* and the rotation refuses to proceed if it
//! does not hold. Skipping that check would make rekey a laundering step: an attacker who
//! tampered with an entry could rotate the key and have the daemon re-MAC their forgery into
//! a chain that verifies perfectly.

use rusqlite::{params, TransactionBehavior};
use sbae_core::Key32;

use crate::{
    anchor, compute_entry_hash, verify, AuditError, EntryHash, Result, VerificationResult,
};

/// Outcome of re-keying the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainRekeyReport {
    pub entries_rekeyed: u64,
}

/// Recompute every entry hash under `new_key`.
pub fn rekey_chain(
    conn: &mut rusqlite::Connection,
    old_key: &Key32,
    new_key: &Key32,
) -> Result<ChainRekeyReport> {
    match verify(conn, old_key)? {
        VerificationResult::Valid { .. } => {}
        broken => return Err(AuditError::RefusingToRekeyBrokenChain(broken.to_string())),
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let entries: Vec<i64> = {
        let mut statement = tx.prepare("SELECT seq FROM audit ORDER BY seq ASC")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };

    let mut previous = EntryHash::GENESIS;
    for seq in &entries {
        let entry = crate::verify::read_entry(&tx, *seq)?;
        let entry_hash = compute_entry_hash(new_key, &previous, &entry);

        tx.execute(
            "UPDATE audit SET prev_hash = ?2, entry_hash = ?3 WHERE seq = ?1",
            params![seq, previous.as_bytes().as_slice(), entry_hash.as_bytes().as_slice()],
        )?;

        previous = entry_hash;
    }

    let rekeyed = u64::try_from(entries.len()).map_err(|_| AuditError::Corrupt {
        what: "implausible audit entry count",
    })?;

    // An empty chain carries no anchor, matching a store that has never been written to.
    // Writing one for zero entries would leave a tail hash that no entry accounts for.
    if rekeyed > 0 {
        anchor::store(&tx, new_key, anchor::Anchor { entries: rekeyed, tail_hash: previous })?;
    }

    tx.commit()?;
    Ok(ChainRekeyReport { entries_rekeyed: rekeyed })
}

#[cfg(test)]
mod tests {
    use sbae_core::MasterKey;
    use sbae_store::Store;

    use super::*;
    use crate::{append, Action, AuditEntry, AuditResult};

    fn keys() -> (Key32, Key32) {
        (
            MasterKey::generate().unwrap().audit_key().unwrap(),
            MasterKey::generate().unwrap().audit_key().unwrap(),
        )
    }

    fn populate(store: &mut Store, key: &Key32, count: usize) {
        for _ in 0..count {
            append(
                store.connection_mut(),
                key,
                &AuditEntry::new(Action::Read, AuditResult::Success),
            )
            .unwrap();
        }
    }

    #[test]
    fn a_rekeyed_chain_verifies_under_the_new_key_and_not_the_old_one() {
        let mut store = Store::open_in_memory().unwrap();
        let (old, new) = keys();
        populate(&mut store, &old, 4);

        let report = rekey_chain(store.connection_mut(), &old, &new).unwrap();
        assert_eq!(report.entries_rekeyed, 4);

        assert!(verify(store.connection(), &new).unwrap().is_valid());
        assert!(!verify(store.connection(), &old).unwrap().is_valid());
    }

    #[test]
    fn history_survives_the_rotation() {
        let mut store = Store::open_in_memory().unwrap();
        let (old, new) = keys();
        populate(&mut store, &old, 3);

        rekey_chain(store.connection_mut(), &old, &new).unwrap();

        let count: u64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 3, "rotation must not discard entries");
    }

    /// Otherwise rotation would re-MAC a forged entry into a chain that verifies perfectly.
    #[test]
    fn a_tampered_chain_is_refused_rather_than_relaundered() {
        let mut store = Store::open_in_memory().unwrap();
        let (old, new) = keys();
        populate(&mut store, &old, 3);

        store
            .connection()
            .execute("UPDATE audit SET action = 'delete' WHERE seq = 2", [])
            .unwrap();

        assert!(matches!(
            rekey_chain(store.connection_mut(), &old, &new),
            Err(AuditError::RefusingToRekeyBrokenChain(_))
        ));
        assert!(!verify(store.connection(), &new).unwrap().is_valid(), "still broken");
    }

    #[test]
    fn a_truncated_chain_is_refused() {
        let mut store = Store::open_in_memory().unwrap();
        let (old, new) = keys();
        populate(&mut store, &old, 4);

        store
            .connection()
            .execute("DELETE FROM audit WHERE seq = (SELECT MAX(seq) FROM audit)", [])
            .unwrap();

        assert!(rekey_chain(store.connection_mut(), &old, &new).is_err());
    }

    #[test]
    fn an_empty_chain_rekeys_cleanly() {
        let mut store = Store::open_in_memory().unwrap();
        let (old, new) = keys();

        assert_eq!(rekey_chain(store.connection_mut(), &old, &new).unwrap().entries_rekeyed, 0);
        assert!(verify(store.connection(), &new).unwrap().is_valid());
    }

    #[test]
    fn appends_continue_cleanly_after_a_rotation() {
        let mut store = Store::open_in_memory().unwrap();
        let (old, new) = keys();
        populate(&mut store, &old, 2);

        rekey_chain(store.connection_mut(), &old, &new).unwrap();
        populate(&mut store, &new, 2);

        assert!(verify(store.connection(), &new).unwrap().is_valid());
    }
}
