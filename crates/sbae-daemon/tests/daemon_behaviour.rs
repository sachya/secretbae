//! End-to-end daemon behaviour over a real Unix socket.
//!
//! These drive the actual router across an actual `UnixListener`, so peer credentials come
//! from the kernel rather than from a mock. The privilege drop itself is not exercised here:
//! it is irreversible, and performing it would break every later test in the process.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use data_encoding::BASE64;
use sbae_core::{seal, KeyfileSeal, MasterKey};
use sbae_daemon::{server::PeerInfo, DaemonState};
use sbae_policy::{issue, IssuedToken, PathPattern, Policy, Rule};
use sbae_proto::{api, Capability};
use sbae_store::{NewToken, Store};

struct Harness {
    socket: PathBuf,
    directory: PathBuf,
}

impl Harness {
    /// Stand up a daemon on a private socket, returning it with an admin-capable token.
    fn start(bound_uid: Option<u32>) -> (Self, IssuedToken) {
        let directory = std::env::temp_dir().join(format!("sbae-daemon-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let socket = directory.join("sock");

        let mut store = Store::open(&directory.join("store.db")).unwrap();
        let keyfile = KeyfileSeal::generate_hex().unwrap();
        let backend = KeyfileSeal::from_hex(&keyfile).unwrap();
        let master = MasterKey::generate().unwrap();
        store
            .initialise_master_key(&seal::seal_master(&backend, &master, 1).unwrap())
            .unwrap();

        store
            .put_policy(&Policy {
                name: "everything".to_owned(),
                rules: vec![Rule {
                    path: PathPattern::new("**").unwrap(),
                    capabilities: Capability::ALL.into_iter().collect(),
                    require_tags: Vec::new(),
                }],
                deny: Vec::new(),
            })
            .unwrap();

        let issued = issue().unwrap();
        store
            .create_token(&NewToken {
                id: issued.id,
                prefix: &issued.prefix,
                hash: &issued.hash,
                name: "test",
                bound_uid,
                expires_at: None,
                policies: &["everything".to_owned()],
            })
            .unwrap();

        let state = Arc::new(DaemonState::new(store, Box::new(backend), master, 1).unwrap());
        let listener_path = socket.clone();

        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::UnixListener::bind(&listener_path).unwrap();
                    let router = sbae_daemon::routes::router(state)
                        .into_make_service_with_connect_info::<PeerInfo>();
                    axum::serve(listener, router).await.unwrap();
                });
        });

        wait_for(&socket);
        (Self { socket, directory }, issued)
    }

    fn store_path(&self) -> PathBuf {
        self.directory.join("store.db")
    }

    /// Minimal HTTP/1.1 over the socket, so the test depends on no client library.
    fn post(&self, route: &str, token: Option<&str>, body: &str) -> (u16, String) {
        let mut stream = UnixStream::connect(&self.socket).unwrap();

        let authorization = token
            .map(|token| format!("authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "POST {route} HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n\
             {authorization}content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );

        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        let status = response
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let payload = response
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        (status, payload)
    }
}

fn wait_for(socket: &Path) {
    for _ in 0..200 {
        if UnixStream::connect(socket).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    panic!("daemon did not start listening on {}", socket.display());
}

fn write_secret(harness: &Harness, token: &str, path: &str, value: &str) -> (u16, String) {
    harness.post(
        api::route::WRITE,
        Some(token),
        &format!(
            r#"{{"path":"{path}","value":"{}","tags":["env=prod"]}}"#,
            BASE64.encode(value.as_bytes())
        ),
    )
}

#[test]
fn a_secret_written_over_the_socket_reads_back_identically() {
    let (harness, issued) = Harness::start(None);
    let token = issued.secret.expose();

    let (status, _) = write_secret(&harness, token, "prod/billing/db", "postgres://user:pw@/db");
    assert_eq!(status, 200);

    let (status, body) = harness.post(
        api::route::READ,
        Some(token),
        r#"{"path":"prod/billing/db"}"#,
    );
    assert_eq!(status, 200);

    let parsed: api::ReadResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed.version.get(), 1);
    assert_eq!(
        String::from_utf8(BASE64.decode(parsed.value.as_bytes()).unwrap()).unwrap(),
        "postgres://user:pw@/db"
    );
}

#[test]
fn a_request_with_no_token_is_refused() {
    let (harness, _) = Harness::start(None);
    let (status, body) = harness.post(api::route::READ, None, r#"{"path":"prod/db"}"#);

    assert_eq!(status, 403);
    assert!(body.contains("not found or not permitted"));
}

#[test]
fn a_forged_token_is_refused() {
    let (harness, _) = Harness::start(None);
    let forged = issue().unwrap();

    let (status, _) = harness.post(
        api::route::READ,
        Some(forged.secret.expose()),
        r#"{"path":"prod/db"}"#,
    );
    assert_eq!(status, 403);
}

/// A missing path and a forbidden one must be indistinguishable, or the error itself becomes
/// a way to enumerate the store.
#[test]
fn a_missing_path_answers_exactly_like_a_forbidden_one() {
    let (harness, issued) = Harness::start(None);
    let token = issued.secret.expose();

    let missing = harness.post(api::route::READ, Some(token), r#"{"path":"prod/absent"}"#);
    let forbidden = harness.post(api::route::READ, None, r#"{"path":"prod/absent"}"#);

    assert_eq!(missing.0, forbidden.0);
    assert_eq!(missing.1, forbidden.1);
}

/// The headline local-hardening property, proven against real kernel-supplied credentials:
/// a token bound to another uid is inert even when presented correctly.
#[test]
fn a_token_bound_to_another_uid_is_refused_over_a_real_socket() {
    let impossible_uid = 4_294_967_294;
    let (harness, issued) = Harness::start(Some(impossible_uid));

    let (status, _) = write_secret(&harness, issued.secret.expose(), "prod/db", "value");
    assert_eq!(
        status, 403,
        "the connecting process does not have the bound uid"
    );

    let (harness, issued) = Harness::start(Some(unsafe { libc::getuid() }));
    let (status, _) = write_secret(&harness, issued.secret.expose(), "prod/db", "value");
    assert_eq!(
        status, 200,
        "the same token bound to the real uid is accepted"
    );
}

#[test]
fn versions_accumulate_and_roll_back_over_the_socket() {
    let (harness, issued) = Harness::start(None);
    let token = issued.secret.expose();

    write_secret(&harness, token, "prod/db", "first");
    write_secret(&harness, token, "prod/db", "second");

    let (_, body) = harness.post(api::route::VERSIONS, Some(token), r#"{"path":"prod/db"}"#);
    let listed: api::VersionsResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(listed.versions.len(), 2);

    let (status, _) = harness.post(
        api::route::ROLLBACK,
        Some(token),
        r#"{"path":"prod/db","to":1}"#,
    );
    assert_eq!(status, 200);

    let (_, body) = harness.post(api::route::READ, Some(token), r#"{"path":"prod/db"}"#);
    let parsed: api::ReadResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(BASE64.decode(parsed.value.as_bytes()).unwrap(), b"first");
}

#[test]
fn tags_filter_a_listing() {
    let (harness, issued) = Harness::start(None);
    let token = issued.secret.expose();

    write_secret(&harness, token, "prod/db", "x");

    let (_, body) = harness.post(api::route::LIST, Some(token), r#"{"tags":["env=prod"]}"#);
    let listed: api::ListResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(listed.secrets.len(), 1);
    assert_eq!(listed.secrets[0].path.as_str(), "prod/db");

    let (_, body) = harness.post(api::route::LIST, Some(token), r#"{"tags":["env=dev"]}"#);
    let listed: api::ListResponse = serde_json::from_str(&body).unwrap();
    assert!(listed.secrets.is_empty());
}

/// `exec` fetches a whole profile in one request; the batch must be all-or-nothing rather
/// than silently returning a short environment the application then fails on.
#[test]
fn resolve_returns_every_requested_path_in_one_request() {
    let (harness, issued) = Harness::start(None);
    let token = issued.secret.expose();

    write_secret(&harness, token, "prod/billing/db", "db-value");
    write_secret(&harness, token, "prod/billing/stripe", "stripe-value");

    let (status, body) = harness.post(
        api::route::RESOLVE,
        Some(token),
        r#"{"paths":["prod/billing/db","prod/billing/stripe"]}"#,
    );
    assert_eq!(status, 200);

    let resolved: api::ResolveResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(resolved.secrets.len(), 2);
    assert_eq!(
        BASE64.decode(resolved.secrets[0].value.as_bytes()).unwrap(),
        b"db-value"
    );

    let (status, _) = harness.post(
        api::route::RESOLVE,
        Some(token),
        r#"{"paths":["prod/billing/db","prod/billing/absent"]}"#,
    );
    assert_eq!(status, 403, "one unreadable path must fail the whole batch");
}

#[test]
fn an_unknown_route_is_refused_rather_than_falling_through() {
    let (harness, issued) = Harness::start(None);
    let (status, _) = harness.post("/v1/not-a-route", Some(issued.secret.expose()), "{}");
    assert_eq!(status, 403);
}

/// Every request the daemon serves must leave a verifiable trace.
#[test]
fn operations_extend_a_chain_that_still_verifies() {
    let (harness, issued) = Harness::start(None);
    let token = issued.secret.expose();

    write_secret(&harness, token, "prod/db", "value");
    harness.post(api::route::READ, Some(token), r#"{"path":"prod/db"}"#);
    harness.post(api::route::READ, None, r#"{"path":"prod/db"}"#);

    let (status, body) = harness.post(api::route::AUDIT_VERIFY, Some(token), "{}");
    assert_eq!(status, 200);

    let outcome: api::AuditVerifyResponse = serde_json::from_str(&body).unwrap();
    assert!(
        outcome.broken_at.is_none(),
        "chain broken: {:?}",
        outcome.detail
    );
    assert!(
        outcome.entries >= 3,
        "the write, the read and the denial must all be recorded"
    );
}

/// A secret's value must appear in exactly one place: the response to an explicit read.
///
/// Everything else the daemon produces -- listings, version metadata, status, and above all the
/// audit log, which is the most persistent of them -- is searched for a sentinel that was
/// stored as a secret. A leak into the audit log would be the worst kind: durable, replicated
/// into every backup, and readable by anyone who can read the database.
#[test]
fn a_secret_value_reaches_no_response_or_record_except_its_own_read() {
    const CANARY: &str = "sentinel-9f3a1c7e-value-must-not-escape";

    let (harness, issued) = Harness::start(None);
    let token = issued.secret.expose();

    harness.post(
        api::route::WRITE,
        Some(token),
        &format!(
            r#"{{"path":"prod/canary/key","value":"{}","tags":["env=prod"],"comment":"canary"}}"#,
            BASE64.encode(CANARY.as_bytes())
        ),
    );

    // Drive the surface that could plausibly echo a value back.
    let surface = [
        (api::route::LIST, "{}"),
        (api::route::VERSIONS, r#"{"path":"prod/canary/key"}"#),
        (api::route::STATUS, "{}"),
        (
            api::route::TAG_ADD,
            r#"{"path":"prod/canary/key","tags":["app=canary"]}"#,
        ),
        (
            api::route::TAG_REMOVE,
            r#"{"path":"prod/canary/key","tags":["app"]}"#,
        ),
        (api::route::TOKEN_LIST, "{}"),
        (api::route::POLICY_LIST, "{}"),
        (api::route::AUDIT_VERIFY, "{}"),
    ];

    for (route, body) in surface {
        let (status, response) = harness.post(route, Some(token), body);
        assert!(
            !response.contains(CANARY),
            "{route} returned the secret value (status {status})"
        );
    }

    // The value is base64 on the wire, so check for that form too: a leak could be encoded.
    let encoded = BASE64.encode(CANARY.as_bytes());
    for (route, body) in surface {
        let (_, response) = harness.post(route, Some(token), body);
        assert!(
            !response.contains(&encoded),
            "{route} returned the encoded value"
        );
    }

    // Every audit column, in both forms. This is the durable record.
    let store = Store::open(&harness.store_path()).unwrap();
    let mut statement = store
        .connection()
        .prepare("SELECT ts, token_prefix, action, path, version, result, detail FROM audit")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((0..7)
                .map(|column| {
                    row.get::<_, Option<String>>(column)
                        .ok()
                        .flatten()
                        .unwrap_or_default()
                })
                .collect::<Vec<String>>()
                .join("\u{1}"))
        })
        .unwrap();

    for row in rows {
        let row = row.unwrap();
        assert!(
            !row.contains(CANARY),
            "the audit log recorded a secret value: {row}"
        );
        assert!(
            !row.contains(&encoded),
            "the audit log recorded an encoded secret value"
        );
    }

    // The control: an explicit read does return it, so the assertions above are not vacuous.
    let (_, read) = harness.post(
        api::route::READ,
        Some(token),
        r#"{"path":"prod/canary/key"}"#,
    );
    let parsed: api::ReadResponse = serde_json::from_str(&read).unwrap();
    assert_eq!(
        BASE64.decode(parsed.value.as_bytes()).unwrap(),
        CANARY.as_bytes()
    );
}
