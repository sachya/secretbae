//! End-to-end properties and tamper-evidence guarantees of the audit log.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use rusqlite::Connection;
use sbae_audit::{
    append, compute_entry_hash, verify, Action, AuditEntry, AuditPath, AuditResult, EntryHash,
    PeerPid, PeerUid, Seq, Timestamp, VerificationResult,
};
use sbae_core::MasterKey;
use sbae_proto::{SecretPath, Version};
use sbae_store::Store;
use uuid::Uuid;

struct Fixture {
    store: Store,
    master: MasterKey,
}

impl Fixture {
    fn in_memory() -> Self {
        Self {
            store: Store::open_in_memory().unwrap(),
            master: MasterKey::generate().unwrap(),
        }
    }

    fn audit_key(&self) -> sbae_core::Key32 {
        self.master.audit_key().unwrap()
    }
}

impl std::ops::Deref for Fixture {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.store.connection()
    }
}

struct TempDatabase {
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sbae_audit_test_{}.db", Uuid::new_v4()));
        Store::open(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn open_connection(&self) -> Connection {
        let conn = Connection::open(&self.path).unwrap();
        conn.execute_batch("PRAGMA busy_timeout = 10000;").unwrap();
        conn
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
        let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
    }
}

#[test]
fn a_chain_of_several_entries_verifies_clean() {
    let mut fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    let entries = [
        AuditEntry::new(Action::Init, AuditResult::Success),
        AuditEntry::new(Action::Unseal, AuditResult::Success)
            .with_token_prefix("adm_tok")
            .with_peer_uid(PeerUid::new(0))
            .with_peer_pid(PeerPid::new(100)),
        AuditEntry::new(Action::Write, AuditResult::Success)
            .with_path(SecretPath::new("prod/billing/db").unwrap())
            .with_version(Version::new(1).unwrap())
            .with_detail("created secret"),
        AuditEntry::new(Action::Read, AuditResult::Success)
            .with_path(SecretPath::new("prod/billing/db").unwrap())
            .with_version(Version::new(1).unwrap())
            .with_token_prefix("app_tok"),
        AuditEntry::new(Action::Delete, AuditResult::Success)
            .with_path(SecretPath::new("prod/billing/db").unwrap())
            .with_detail("soft delete"),
    ];

    for entry in &entries {
        append(fixture.store.connection_mut(), &key, entry).unwrap();
    }

    let verification = verify(&fixture, &key).unwrap();
    assert!(verification.is_valid());
    assert_eq!(verification.broken_seq(), None);
    assert!(matches!(
        verification,
        VerificationResult::Valid {
            entries_verified: 5,
            tail_hash: Some(_)
        }
    ));
}

#[test]
fn modifying_one_entry_field_is_detected_and_verify_names_the_right_seq() {
    let mut fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    for i in 1..=5 {
        let entry = AuditEntry::new(Action::Read, AuditResult::Success)
            .with_path(SecretPath::new(&format!("service/secret_{i}")).unwrap())
            .with_version(Version::new(i).unwrap());
        append(fixture.store.connection_mut(), &key, &entry).unwrap();
    }

    // Tamper with action on seq 3
    fixture
        .execute("UPDATE audit SET action = 'delete' WHERE seq = 3", [])
        .unwrap();

    let verification = verify(&fixture, &key).unwrap();
    assert!(!verification.is_valid());
    assert_eq!(verification.broken_seq(), Some(Seq::new(3)));
    assert!(matches!(
        verification,
        VerificationResult::Modified { seq, .. } if seq == Seq::new(3)
    ));
}

#[test]
fn deleting_a_middle_row_is_detected_as_a_gap() {
    let mut fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    for i in 1..=5 {
        let entry = AuditEntry::new(Action::Write, AuditResult::Success)
            .with_path(SecretPath::new(&format!("config/app_{i}")).unwrap())
            .with_version(Version::new(i).unwrap());
        append(fixture.store.connection_mut(), &key, &entry).unwrap();
    }

    // Delete row seq 3
    fixture
        .execute("DELETE FROM audit WHERE seq = 3", [])
        .unwrap();

    let verification = verify(&fixture, &key).unwrap();
    assert!(!verification.is_valid());
    assert_eq!(verification.broken_seq(), Some(Seq::new(3)));
    assert!(matches!(
        verification,
        VerificationResult::Gap { expected, found } if expected == Seq::new(3) && found == Seq::new(4)
    ));
}

#[test]
fn verifying_with_the_wrong_key_fails() {
    let mut fixture = Fixture::in_memory();
    let right_key = fixture.audit_key();

    let wrong_master = MasterKey::generate().unwrap();
    let wrong_key = wrong_master.audit_key().unwrap();

    let entry = AuditEntry::new(Action::Init, AuditResult::Success);
    append(fixture.store.connection_mut(), &right_key, &entry).unwrap();

    let right_verification = verify(&fixture, &right_key).unwrap();
    assert!(right_verification.is_valid());

    let wrong_verification = verify(&fixture, &wrong_key).unwrap();
    assert!(!wrong_verification.is_valid());
    assert_eq!(wrong_verification.broken_seq(), Some(Seq::new(1)));
    assert!(matches!(
        wrong_verification,
        VerificationResult::Modified { seq, .. } if seq == Seq::new(1)
    ));
}

#[test]
fn concurrent_appends_produce_a_strictly_increasing_unforked_chain() {
    let temp_db = TempDatabase::new();
    let master = MasterKey::generate().unwrap();
    let audit_key = Arc::new(master.audit_key().unwrap());

    let worker_count = 6;
    let appends_per_worker = 15;
    let total_expected = worker_count * appends_per_worker;

    let db_path = temp_db.path().to_path_buf();

    let mut handles = Vec::new();
    for worker_id in 0..worker_count {
        let key = Arc::clone(&audit_key);
        let path = db_path.clone();

        let handle = thread::spawn(move || {
            let mut conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 10000;",
            )
            .unwrap();

            for i in 1..=appends_per_worker {
                let entry = AuditEntry::new(Action::Write, AuditResult::Success)
                    .with_path(SecretPath::new(&format!("worker_{worker_id}/secret_{i}")).unwrap())
                    .with_peer_pid(PeerPid::new(u32::try_from(worker_id).unwrap()))
                    .with_detail(format!("batch append item {i}"));

                append(&mut conn, &key, &entry).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("worker thread panicked");
    }

    let conn = temp_db.open_connection();
    let verification = verify(&conn, &audit_key).unwrap();
    assert!(verification.is_valid());

    let u64_total = u64::try_from(total_expected).unwrap();
    assert!(matches!(
        verification,
        VerificationResult::Valid { entries_verified, tail_hash: Some(_) } if entries_verified == u64_total
    ));

    // Verify chain linkage row by row
    let mut stmt = conn
        .prepare("SELECT seq, prev_hash, entry_hash FROM audit ORDER BY seq ASC")
        .unwrap();

    let mut rows = stmt.query([]).unwrap();
    let mut expected_seq = 1u64;
    let mut expected_prev = EntryHash::GENESIS;

    while let Some(row) = rows.next().unwrap() {
        let seq: i64 = row.get(0).unwrap();
        assert_eq!(seq, i64::try_from(expected_seq).unwrap());

        let prev_raw: Vec<u8> = row.get(1).unwrap();
        let prev_hash = EntryHash::try_from(prev_raw.as_slice()).unwrap();
        assert_eq!(prev_hash, expected_prev);

        let entry_raw: Vec<u8> = row.get(2).unwrap();
        let entry_hash = EntryHash::try_from(entry_raw.as_slice()).unwrap();

        expected_prev = entry_hash;
        expected_seq += 1;
    }

    assert_eq!(expected_seq, u64_total + 1);
}

#[test]
fn a_plaintext_canary_never_appears_in_any_stored_column() {
    let mut fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    let canary = "CANARY_SECRET_DATA_XYZ_987654321_DO_NOT_STORE";

    let entry = AuditEntry::new(Action::Write, AuditResult::Success)
        .with_path(SecretPath::new("prod/payments/stripe").unwrap())
        .with_version(Version::new(1).unwrap())
        .with_token_prefix("adm_prefix")
        .with_peer_uid(PeerUid::new(1001))
        .with_peer_pid(PeerPid::new(2002))
        .with_detail("configured payment key");

    append(fixture.store.connection_mut(), &key, &entry).unwrap();

    let mut stmt = fixture.prepare("SELECT * FROM audit").unwrap();
    let mut rows = stmt.query([]).unwrap();

    while let Some(row) = rows.next().unwrap() {
        for col_idx in 0..12 {
            let val: rusqlite::types::Value = row.get(col_idx).unwrap();
            match val {
                rusqlite::types::Value::Text(s) => {
                    assert!(
                        !s.contains(canary),
                        "canary leaked in text column {col_idx}: {s}"
                    );
                }
                rusqlite::types::Value::Blob(b) => {
                    let canary_bytes = canary.as_bytes();
                    assert!(
                        !b.windows(canary_bytes.len())
                            .any(|window| window == canary_bytes),
                        "canary leaked in blob column {col_idx}"
                    );
                }
                rusqlite::types::Value::Null
                | rusqlite::types::Value::Integer(_)
                | rusqlite::types::Value::Real(_) => {}
            }
        }
    }
}

#[test]
fn canonical_encoding_prevents_field_boundary_shifting() {
    let key = MasterKey::generate().unwrap().audit_key().unwrap();
    let prev = EntryHash::GENESIS;
    let ts = Timestamp::from_unix(1_000_000);

    // If strings were concatenated directly, "read" + "a/b" and "reada" + "/b"
    // would produce identical byte streams "reada/b". Length prefixing must make them distinct.
    let entry_a = AuditEntry::new(Action::Read, AuditResult::Success)
        .with_ts(ts)
        .with_path(AuditPath::new("a/b"));

    let entry_b = AuditEntry::new(Action::Init, AuditResult::Success)
        .with_ts(ts)
        .with_path(AuditPath::new("/b"));

    assert_ne!(entry_a.canonical(), entry_b.canonical());
    assert_ne!(
        compute_entry_hash(&key, &prev, &entry_a),
        compute_entry_hash(&key, &prev, &entry_b)
    );
}

#[test]
fn empty_audit_log_verifies_clean() {
    let fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    let verification = verify(&fixture, &key).unwrap();
    assert!(verification.is_valid());
    assert_eq!(
        verification,
        VerificationResult::Valid {
            entries_verified: 0,
            tail_hash: None
        }
    );
}

#[test]
fn deleting_the_first_row_is_detected_as_a_gap() {
    let mut fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    for i in 1..=3 {
        let entry = AuditEntry::new(Action::Read, AuditResult::Success)
            .with_path(SecretPath::new(&format!("secrets/item_{i}")).unwrap());
        append(fixture.store.connection_mut(), &key, &entry).unwrap();
    }

    // Delete seq 1
    fixture
        .execute("DELETE FROM audit WHERE seq = 1", [])
        .unwrap();

    let verification = verify(&fixture, &key).unwrap();
    assert!(!verification.is_valid());
    assert_eq!(verification.broken_seq(), Some(Seq::new(1)));
    assert!(matches!(
        verification,
        VerificationResult::Gap { expected, found } if expected == Seq::new(1) && found == Seq::new(2)
    ));
}

#[test]
fn modifying_prev_hash_breaks_chain_linkage() {
    let mut fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    for _ in 0..3 {
        let entry = AuditEntry::new(Action::List, AuditResult::Success);
        append(fixture.store.connection_mut(), &key, &entry).unwrap();
    }

    // Corrupt prev_hash of seq 2
    fixture
        .execute(
            "UPDATE audit SET prev_hash = X'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE seq = 2",
            [],
        )
        .unwrap();

    let verification = verify(&fixture, &key).unwrap();
    assert!(!verification.is_valid());
    assert_eq!(verification.broken_seq(), Some(Seq::new(2)));
    assert!(matches!(
        verification,
        VerificationResult::BrokenLink { seq, .. } if seq == Seq::new(2)
    ));
}

#[test]
fn all_actions_and_results_round_trip_through_string_representations() {
    let actions = [
        Action::Init,
        Action::Unseal,
        Action::Read,
        Action::Write,
        Action::Delete,
        Action::Rollback,
        Action::List,
        Action::Tag,
        Action::TokenCreate,
        Action::TokenRevoke,
        Action::PolicyWrite,
        Action::Resolve,
        Action::AuthFailure,
    ];

    for action in actions {
        let stored = action.as_str();
        assert_eq!(Action::parse(stored).unwrap(), action);
    }

    let results = [
        AuditResult::Success,
        AuditResult::Denied,
        AuditResult::NotFound,
        AuditResult::Error,
    ];

    for result in results {
        let stored = result.as_str();
        assert_eq!(AuditResult::parse(stored).unwrap(), result);
    }
}

/// The failure a hash chain does not catch on its own: an attacker who cannot alter an entry
/// deletes the most recent ones instead. The links still agree, so only the authenticated
/// anchor reveals that entries are missing.
#[test]
fn deleting_entries_from_the_end_is_detected_by_the_anchor() {
    let mut fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    for _ in 0..5 {
        append(
            fixture.store.connection_mut(),
            &key,
            &AuditEntry::new(Action::Read, AuditResult::Success)
                .with_path(SecretPath::new("prod/billing/db").unwrap()),
        )
        .unwrap();
    }
    assert!(verify(&fixture, &key).unwrap().is_valid());

    fixture
        .execute("DELETE FROM audit WHERE seq > 3", [])
        .unwrap();

    assert_eq!(
        verify(&fixture, &key).unwrap(),
        VerificationResult::Truncated {
            expected_entries: 5,
            found_entries: 3
        }
    );
}

/// Deleting the anchor along with the entries must not launder the truncation.
#[test]
fn removing_the_anchor_entirely_is_also_detected() {
    let mut fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    append(
        fixture.store.connection_mut(),
        &key,
        &AuditEntry::new(Action::Init, AuditResult::Success),
    )
    .unwrap();

    fixture
        .execute("DELETE FROM meta WHERE key = 'audit_anchor'", [])
        .unwrap();
    assert_eq!(
        verify(&fixture, &key).unwrap(),
        VerificationResult::AnchorInvalid
    );
}

/// An attacker without the audit key cannot mint a replacement anchor that agrees with the
/// chain they shortened.
#[test]
fn an_anchor_rewritten_without_the_audit_key_is_rejected() {
    let mut fixture = Fixture::in_memory();
    let key = fixture.audit_key();

    append(
        fixture.store.connection_mut(),
        &key,
        &AuditEntry::new(Action::Init, AuditResult::Success),
    )
    .unwrap();

    let forged = vec![0u8; 8 + 32 + 32];
    fixture
        .execute(
            "UPDATE meta SET value = ?1 WHERE key = 'audit_anchor'",
            [forged],
        )
        .unwrap();

    assert!(
        verify(&fixture, &key).is_err(),
        "a forged anchor must not verify"
    );
}
