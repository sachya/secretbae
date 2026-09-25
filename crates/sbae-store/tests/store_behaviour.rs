//! End-to-end behaviour of the store, exercised through the same calls the daemon makes.

use sbae_core::{MasterKey, SealedVersion};
use sbae_proto::{SecretPath, Tag, TagSelector, Version, VersionState};
use sbae_store::{DeleteMode, ListFilter, Store, StoreError, VersionSelector, WriteMeta};

const GENERATION: u32 = 1;

struct Fixture {
    store: Store,
    master: MasterKey,
}

impl Fixture {
    fn new() -> Self {
        Self {
            store: Store::open_in_memory().unwrap(),
            master: MasterKey::generate().unwrap(),
        }
    }

    /// Mirrors the daemon's write path: reserve a slot, seal against its binding, commit.
    fn put(&mut self, path: &str, value: &[u8]) -> Version {
        let path = SecretPath::new(path).unwrap();
        let slot = self.store.begin_write(&path).unwrap();
        let sealed = SealedVersion::seal(&self.master, GENERATION, slot.binding(), value).unwrap();
        slot.commit(&sealed, &WriteMeta::default()).unwrap()
    }

    fn get(&self, path: &str, selector: VersionSelector) -> Result<Vec<u8>, StoreError> {
        let path = SecretPath::new(path).unwrap();
        let stored = self.store.read_version(&path, selector)?;
        Ok(stored
            .sealed
            .open(&self.master, stored.binding)
            .unwrap()
            .expose()
            .to_vec())
    }

    fn current(&self, path: &str) -> Result<Vec<u8>, StoreError> {
        self.get(path, VersionSelector::Current)
    }
}

fn path(raw: &str) -> SecretPath {
    SecretPath::new(raw).unwrap()
}

fn tag(raw: &str) -> Tag {
    raw.parse().unwrap()
}

fn selector(raw: &str) -> TagSelector {
    raw.parse().unwrap()
}

#[test]
fn writes_append_immutable_versions() {
    let mut fixture = Fixture::new();

    assert_eq!(fixture.put("prod/billing/db", b"first").get(), 1);
    assert_eq!(fixture.put("prod/billing/db", b"second").get(), 2);
    assert_eq!(fixture.put("prod/billing/db", b"third").get(), 3);

    assert_eq!(fixture.current("prod/billing/db").unwrap(), b"third");
    assert_eq!(
        fixture
            .get(
                "prod/billing/db",
                VersionSelector::Exact(Version::new(1).unwrap())
            )
            .unwrap(),
        b"first",
        "earlier versions must remain readable"
    );
}

#[test]
fn rollback_moves_the_pointer_without_discarding_anything() {
    let mut fixture = Fixture::new();
    fixture.put("prod/db", b"good");
    fixture.put("prod/db", b"bad");

    fixture
        .store
        .rollback(&path("prod/db"), Version::new(1).unwrap())
        .unwrap();
    assert_eq!(fixture.current("prod/db").unwrap(), b"good");

    // The rolled-past version is still there, which is what makes a rollback reversible.
    assert_eq!(
        fixture
            .get("prod/db", VersionSelector::Exact(Version::new(2).unwrap()))
            .unwrap(),
        b"bad"
    );

    fixture
        .store
        .rollback(&path("prod/db"), Version::new(2).unwrap())
        .unwrap();
    assert_eq!(fixture.current("prod/db").unwrap(), b"bad");
}

#[test]
fn a_write_after_a_rollback_still_takes_the_next_unused_number() {
    let mut fixture = Fixture::new();
    fixture.put("prod/db", b"v1");
    fixture.put("prod/db", b"v2");
    fixture
        .store
        .rollback(&path("prod/db"), Version::new(1).unwrap())
        .unwrap();

    // Version 2 is already taken, so the new write must be 3 even though current is 1.
    assert_eq!(fixture.put("prod/db", b"v3").get(), 3);
    assert_eq!(fixture.current("prod/db").unwrap(), b"v3");
}

#[test]
fn soft_delete_hides_a_version_but_destroy_discards_the_ciphertext() {
    let mut fixture = Fixture::new();
    fixture.put("prod/db", b"v1");
    fixture.put("prod/db", b"v2");

    let v1 = VersionSelector::Exact(Version::new(1).unwrap());
    fixture
        .store
        .delete_version(&path("prod/db"), v1, DeleteMode::Soft)
        .unwrap();
    assert!(matches!(
        fixture.get("prod/db", v1),
        Err(StoreError::NotFound)
    ));

    let states = fixture.store.versions(&path("prod/db")).unwrap();
    assert_eq!(
        states[1].state,
        VersionState::Deleted,
        "the row survives a soft delete"
    );

    fixture
        .store
        .delete_version(&path("prod/db"), v1, DeleteMode::Destroy)
        .unwrap();
    let states = fixture.store.versions(&path("prod/db")).unwrap();
    assert_eq!(states[1].state, VersionState::Destroyed);

    assert_eq!(
        fixture.current("prod/db").unwrap(),
        b"v2",
        "other versions are unaffected"
    );
}

#[test]
fn retention_destroys_versions_beyond_the_window() {
    let mut fixture = Fixture::new();
    for n in 1..=13 {
        fixture.put("prod/db", format!("v{n}").as_bytes());
    }

    let versions = fixture.store.versions(&path("prod/db")).unwrap();
    assert_eq!(versions.len(), 13, "version numbers are never reused");

    let destroyed: Vec<u32> = versions
        .iter()
        .filter(|v| v.state == VersionState::Destroyed)
        .map(|v| v.version.get())
        .collect();
    assert_eq!(
        destroyed,
        vec![3, 2, 1],
        "the default window keeps the newest 10"
    );

    assert_eq!(fixture.current("prod/db").unwrap(), b"v13");
    assert!(fixture
        .get("prod/db", VersionSelector::Exact(Version::new(4).unwrap()))
        .is_ok());
}

#[test]
fn missing_paths_and_missing_versions_are_indistinguishable() {
    let mut fixture = Fixture::new();
    fixture.put("prod/db", b"v1");

    assert!(matches!(
        fixture.current("prod/absent"),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        fixture.get("prod/db", VersionSelector::Exact(Version::new(99).unwrap())),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn tags_attach_detach_and_deduplicate() {
    let mut fixture = Fixture::new();
    fixture.put("prod/db", b"v1");
    let db = path("prod/db");

    fixture
        .store
        .add_tags(&db, &[tag("env=prod"), tag("app=billing")])
        .unwrap();
    fixture.store.add_tags(&db, &[tag("env=prod")]).unwrap();

    let tags = fixture.store.tags(&db).unwrap();
    assert_eq!(tags.len(), 2, "re-adding a tag must not duplicate it");
    assert_eq!(tags[0].to_string(), "app=billing");

    fixture
        .store
        .remove_tags(&db, &[selector("app=billing")])
        .unwrap();
    assert_eq!(fixture.store.tags(&db).unwrap(), vec![tag("env=prod")]);
    assert_eq!(
        fixture.store.all_distinct_tags().unwrap(),
        vec![tag("env=prod")],
        "an orphaned tag is cleaned up"
    );
}

#[test]
fn list_filters_by_every_requested_tag() {
    let mut fixture = Fixture::new();
    fixture.put("prod/billing/db", b"x");
    fixture.put("prod/search/db", b"x");
    fixture.put("dev/billing/db", b"x");

    fixture
        .store
        .add_tags(
            &path("prod/billing/db"),
            &[tag("env=prod"), tag("app=billing")],
        )
        .unwrap();
    fixture
        .store
        .add_tags(&path("prod/search/db"), &[tag("env=prod")])
        .unwrap();
    fixture
        .store
        .add_tags(&path("dev/billing/db"), &[tag("app=billing")])
        .unwrap();

    let matched = |tags: Vec<Tag>| -> Vec<String> {
        fixture
            .store
            .list(&ListFilter {
                tags,
                ..ListFilter::default()
            })
            .unwrap()
            .into_iter()
            .map(|s| s.path.to_string())
            .collect()
    };

    assert_eq!(
        matched(vec![tag("env=prod")]),
        ["prod/billing/db", "prod/search/db"]
    );
    assert_eq!(
        matched(vec![tag("env=prod"), tag("app=billing")]),
        ["prod/billing/db"],
        "tags must combine as AND, not OR"
    );
    assert!(matched(vec![tag("env=staging")]).is_empty());
}

/// The bug a naive `starts_with` or a `LIKE` would introduce.
#[test]
fn list_prefix_respects_segment_boundaries_and_underscores() {
    let mut fixture = Fixture::new();
    fixture.put("prod/billing/db", b"x");
    fixture.put("prod/billing-admin/db", b"x");
    fixture.put("prod/billing_ops/db", b"x");

    let listed = |prefix: &str| -> Vec<String> {
        fixture
            .store
            .list(&ListFilter {
                prefix: Some(prefix.to_owned()),
                ..ListFilter::default()
            })
            .unwrap()
            .into_iter()
            .map(|s| s.path.to_string())
            .collect()
    };

    assert_eq!(listed("prod/billing"), ["prod/billing/db"]);
    assert_eq!(
        listed("prod/billing/"),
        ["prod/billing/db"],
        "a trailing slash is equivalent"
    );
    assert_eq!(listed("prod/billing-admin"), ["prod/billing-admin/db"]);
    assert_eq!(listed("prod").len(), 3);
    assert_eq!(listed("").len(), 3);
}

#[test]
fn list_hides_secrets_with_no_readable_version_unless_asked() {
    let mut fixture = Fixture::new();
    fixture.put("prod/db", b"v1");

    let store = &fixture.store;
    assert_eq!(store.list(&ListFilter::default()).unwrap().len(), 1);

    let summary = &store.list(&ListFilter::default()).unwrap()[0];
    assert_eq!(summary.current_version, Some(Version::new(1).unwrap()));
    assert_eq!(summary.path.as_str(), "prod/db");
}

/// Proves the AAD binding survives a full storage round-trip: a row moved between secrets
/// in the database cannot be decrypted in its new home.
#[test]
fn ciphertext_relocated_between_secrets_fails_to_open() {
    let mut fixture = Fixture::new();
    fixture.put("prod/db", b"production-password");
    fixture.put("dev/db", b"development-password");

    let production = fixture
        .store
        .read_version(&path("prod/db"), VersionSelector::Current)
        .unwrap();
    let development = fixture
        .store
        .read_version(&path("dev/db"), VersionSelector::Current)
        .unwrap();

    let smuggled = production.sealed.open(&fixture.master, development.binding);
    assert!(
        smuggled.is_err(),
        "prod ciphertext must not open in the dev slot"
    );
}

#[test]
fn version_metadata_is_recorded_and_ordered_newest_first() {
    let mut fixture = Fixture::new();
    let path = path("prod/db");

    let slot = fixture.store.begin_write(&path).unwrap();
    let sealed = SealedVersion::seal(&fixture.master, GENERATION, slot.binding(), b"v1").unwrap();
    slot.commit(
        &sealed,
        &WriteMeta {
            created_by: Some("sbae_root".to_owned()),
            comment: Some("initial import".to_owned()),
        },
    )
    .unwrap();

    fixture.put("prod/db", b"v2");

    let versions = fixture.store.versions(&path).unwrap();
    assert_eq!(versions[0].version.get(), 2);
    assert_eq!(versions[1].version.get(), 1);
    assert_eq!(versions[1].created_by.as_deref(), Some("sbae_root"));
    assert_eq!(versions[1].comment.as_deref(), Some("initial import"));
}

/// Removing by bare key is the common case: an operator retiring a label knows its key, not
/// necessarily which value is currently attached.
#[test]
fn a_bare_key_removes_every_value_under_it() {
    let mut fixture = Fixture::new();
    fixture.put("prod/db", b"v1");
    let db = path("prod/db");

    fixture
        .store
        .add_tags(&db, &[tag("env=prod"), tag("app=billing")])
        .unwrap();
    fixture.store.remove_tags(&db, &[selector("env")]).unwrap();

    assert_eq!(fixture.store.tags(&db).unwrap(), vec![tag("app=billing")]);
}

/// `ls` must not keep advertising a secret whose every version has been destroyed: the stale
/// metadata reads as "still retrievable" when nothing is.
#[test]
fn a_secret_drops_out_of_listings_once_nothing_readable_remains() {
    let mut fixture = Fixture::new();
    fixture.put("prod/db", b"v1");
    fixture.put("prod/db", b"v2");
    let db = path("prod/db");

    let listed = || fixture.store.list(&ListFilter::default()).unwrap().len();
    assert_eq!(listed(), 1);

    let v2 = VersionSelector::Exact(Version::new(2).unwrap());
    fixture
        .store
        .delete_version(&db, v2, DeleteMode::Destroy)
        .unwrap();
    assert_eq!(
        listed(),
        1,
        "one version is gone but another still decrypts"
    );
    assert_eq!(
        fixture.store.list(&ListFilter::default()).unwrap()[0].current_version,
        Some(Version::new(1).unwrap()),
        "current must fall back to the newest version that still reads"
    );

    let v1 = VersionSelector::Exact(Version::new(1).unwrap());
    fixture
        .store
        .delete_version(&db, v1, DeleteMode::Destroy)
        .unwrap();
    assert_eq!(
        listed(),
        0,
        "nothing readable remains, so nothing should be listed"
    );
}

/// Rotation must rewrite 32-byte wrapped keys and nothing else.
///
/// This is the whole economic claim of envelope encryption, and it is easy to lose: an earlier
/// implementation selected every payload into memory to rewrite the key beside it, which made
/// a rotation cost memory proportional to the size of the store and aborted the daemon under
/// its memlock limit. `rekey_with` now hands out a `WrappedKey`, which has no payload to load.
#[test]
fn rotation_leaves_every_payload_byte_identical() {
    let mut fixture = Fixture::new();

    let large = vec![b'x'; 64 * 1024];
    fixture.put("prod/big/cert", &large);
    fixture.put("prod/small/pw", b"short");
    fixture.put("prod/big/cert", &large);

    let before: Vec<Vec<u8>> = ["prod/big/cert", "prod/small/pw"]
        .iter()
        .map(|p| {
            fixture
                .store
                .read_version(&path(p), VersionSelector::Current)
                .unwrap()
                .sealed
                .ciphertext
        })
        .collect();

    let successor = MasterKey::generate().unwrap();
    let backend = sbae_core::KeyfileSeal::from_hex(&"ab".repeat(32)).unwrap();
    let sealed = sbae_core::seal::seal_master(&backend, &successor, 2).unwrap();

    let report = fixture
        .store
        .rekey_with(&sealed, |binding, key| {
            key.rewrap(&fixture.master, &successor, 2, binding)
                .map_err(StoreError::from)
        })
        .unwrap();
    assert_eq!(report.versions_rewrapped, 3);

    for (index, p) in ["prod/big/cert", "prod/small/pw"].iter().enumerate() {
        let stored = fixture
            .store
            .read_version(&path(p), VersionSelector::Current)
            .unwrap();
        assert_eq!(
            stored.sealed.ciphertext, before[index],
            "{p} was re-encrypted"
        );

        let opened = stored.sealed.open(&successor, stored.binding).unwrap();
        assert!(
            !opened.expose().is_empty(),
            "{p} no longer opens under the new key"
        );
        assert!(
            stored.sealed.open(&fixture.master, stored.binding).is_err(),
            "{p} still opens under the retired key"
        );
    }
}
