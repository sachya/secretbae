//! Token and policy persistence, exercised the way the daemon uses it.

use sbae_policy::{issue, IssuedToken, LookupPrefix, PathPattern, Policy, Rule};
use sbae_proto::Capability;
use sbae_store::{NewToken, Store, StoreError};
use time::{Duration, OffsetDateTime};

fn policy(name: &str, pattern: &str) -> Policy {
    Policy {
        name: name.to_owned(),
        rules: vec![Rule {
            path: PathPattern::new(pattern).unwrap(),
            capabilities: [Capability::Read].into_iter().collect(),
            require_tags: Vec::new(),
        }],
        deny: Vec::new(),
    }
}

fn persist(store: &mut Store, issued: &IssuedToken, policies: &[String]) -> Result<(), StoreError> {
    store.create_token(&NewToken {
        id: issued.id,
        prefix: &issued.prefix,
        hash: &issued.hash,
        name: "billing-app",
        bound_uid: Some(33),
        expires_at: None,
        policies,
    })
}

#[test]
fn a_stored_token_is_found_by_its_prefix_with_its_binding_intact() {
    let mut store = Store::open_in_memory().unwrap();
    store.put_policy(&policy("billing", "prod/billing/**")).unwrap();

    let issued = issue().unwrap();
    persist(&mut store, &issued, &["billing".to_owned()]).unwrap();

    let found = store.token_by_prefix(&issued.prefix).unwrap().unwrap();
    assert_eq!(found.id, issued.id);
    assert_eq!(found.bound_uid, Some(33), "the uid binding must survive a round trip");
    assert_eq!(found.name, "billing-app");
    assert!(found.revoked_at.is_none());
}

#[test]
fn an_unknown_prefix_yields_nothing() {
    let store = Store::open_in_memory().unwrap();
    let absent = LookupPrefix::parse("AAAAAAAA").unwrap();
    assert!(store.token_by_prefix(&absent).unwrap().is_none());
}

#[test]
fn attached_policies_come_back_parsed_and_ordered() {
    let mut store = Store::open_in_memory().unwrap();
    store.put_policy(&policy("billing", "prod/billing/**")).unwrap();
    store.put_policy(&policy("audit", "prod/audit/**")).unwrap();

    let issued = issue().unwrap();
    persist(&mut store, &issued, &["billing".to_owned(), "audit".to_owned()]).unwrap();

    let attached = store.policies_for_token(issued.id).unwrap();
    assert_eq!(attached.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["audit", "billing"]);
}

/// A token that silently ends up with fewer grants than asked for is a debugging trap, so the
/// whole creation must roll back rather than leave a usable token behind.
#[test]
fn naming_a_policy_that_does_not_exist_creates_no_token_at_all() {
    let mut store = Store::open_in_memory().unwrap();
    store.put_policy(&policy("billing", "prod/billing/**")).unwrap();

    let issued = issue().unwrap();
    let outcome = persist(&mut store, &issued, &["billing".to_owned(), "absent".to_owned()]);

    assert!(matches!(outcome, Err(StoreError::NotFound)));
    assert!(
        store.token_by_prefix(&issued.prefix).unwrap().is_none(),
        "the partially created token must have been rolled back"
    );
}

#[test]
fn revocation_is_recorded_and_repeating_it_is_harmless() {
    let mut store = Store::open_in_memory().unwrap();
    store.put_policy(&policy("billing", "prod/**")).unwrap();

    let issued = issue().unwrap();
    persist(&mut store, &issued, &["billing".to_owned()]).unwrap();

    store.revoke_token(&issued.prefix).unwrap();
    let revoked_at = store.token_by_prefix(&issued.prefix).unwrap().unwrap().revoked_at;
    assert!(revoked_at.is_some());

    store.revoke_token(&issued.prefix).unwrap();
    assert_eq!(
        store.token_by_prefix(&issued.prefix).unwrap().unwrap().revoked_at,
        revoked_at,
        "re-revoking must not move the original revocation time"
    );
}

#[test]
fn revoking_an_unknown_token_is_reported() {
    let store = Store::open_in_memory().unwrap();
    let absent = LookupPrefix::parse("AAAAAAAA").unwrap();
    assert!(matches!(store.revoke_token(&absent), Err(StoreError::NotFound)));
}

#[test]
fn an_expiry_survives_a_round_trip() {
    let mut store = Store::open_in_memory().unwrap();
    store.put_policy(&policy("billing", "prod/**")).unwrap();

    let issued = issue().unwrap();
    let expires_at = OffsetDateTime::now_utc() + Duration::days(90);
    store
        .create_token(&NewToken {
            id: issued.id,
            prefix: &issued.prefix,
            hash: &issued.hash,
            name: "temporary",
            bound_uid: None,
            expires_at: Some(expires_at),
            policies: &["billing".to_owned()],
        })
        .unwrap();

    let found = store.token_by_prefix(&issued.prefix).unwrap().unwrap();
    assert_eq!(found.expires_at.unwrap().unix_timestamp(), expires_at.unix_timestamp());
}

#[test]
fn policies_can_be_replaced_listed_and_deleted() {
    let store = Store::open_in_memory().unwrap();
    store.put_policy(&policy("billing", "prod/billing/**")).unwrap();
    store.put_policy(&policy("audit", "prod/audit/**")).unwrap();
    assert_eq!(store.list_policy_names().unwrap(), ["audit", "billing"]);

    store.put_policy(&policy("billing", "prod/billing/readonly/**")).unwrap();
    assert_eq!(store.list_policy_names().unwrap().len(), 2, "replacing must not duplicate");

    store.delete_policy("audit").unwrap();
    assert_eq!(store.list_policy_names().unwrap(), ["billing"]);
    assert!(matches!(store.delete_policy("audit"), Err(StoreError::NotFound)));
}

/// Deleting a policy must not leave a token pointing at a grant that no longer exists.
#[test]
fn deleting_a_policy_detaches_it_from_every_token() {
    let mut store = Store::open_in_memory().unwrap();
    store.put_policy(&policy("billing", "prod/**")).unwrap();

    let issued = issue().unwrap();
    persist(&mut store, &issued, &["billing".to_owned()]).unwrap();
    assert_eq!(store.policies_for_token(issued.id).unwrap().len(), 1);

    store.delete_policy("billing").unwrap();
    assert!(
        store.policies_for_token(issued.id).unwrap().is_empty(),
        "the token must be left with no grants rather than a dangling reference"
    );
}

#[test]
fn ensure_policy_exists_creates_but_never_overwrites() {
    let store = Store::open_in_memory().unwrap();

    assert!(store.ensure_policy_exists(&policy("unrestricted", "**")).unwrap(), "first call creates it");
    assert!(
        !store.ensure_policy_exists(&policy("unrestricted", "prod/**")).unwrap(),
        "second call must report no change"
    );

    let attached = store.all_policy_documents().unwrap();
    assert_eq!(attached.len(), 1);
    assert!(
        attached[0].contains("\"**\""),
        "an operator's own edit to a built-in policy name must survive a reseed: {}",
        attached[0]
    );
}
