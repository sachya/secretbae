//! Verification of CLI behavior, security invariants, argument parsing, and protocol flows.

use std::path::Path;

use clap::CommandFactory;
use clap::Parser;
use sbae_cli::cli::Cli;
use sbae_cli::env::build_child_env;
use sbae_cli::profile::{check_no_duplicate_env_names, screaming_snake, validate_profile_mode, EnvEntry, Profile};
use sbae_cli::token::{resolve_token_with_sources, validate_file_mode};
use sbae_proto::{SecretPath, Version};

#[test]
fn clap_debug_assert_validates_cli_command_graph() {
    Cli::command().debug_assert();
}

#[test]
fn every_command_and_subcommand_parses_successfully() {
    // 1. status
    let cli = Cli::try_parse_from(["secretbae", "status"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Status));

    // 2. put
    let cli = Cli::try_parse_from(["secretbae", "put", "prod/db", "--stdin"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Put { stdin: true, .. }));

    let cli = Cli::try_parse_from([
        "secretbae", "put", "prod/db", "--value", "secret123", "--tag", "env=prod", "--tag", "team=billing", "--comment", "init",
    ])
    .unwrap();
    if let sbae_cli::cli::Command::Put { value, tags, comment, .. } = cli.command {
        assert_eq!(value, Some("secret123".to_owned()));
        assert_eq!(tags.len(), 2);
        assert_eq!(comment, Some("init".to_owned()));
    } else {
        panic!("unexpected command variant");
    }

    // 3. get
    let cli = Cli::try_parse_from(["secretbae", "get", "prod/db"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Get { raw: false, version: None, .. }));

    let cli = Cli::try_parse_from(["secretbae", "get", "prod/db", "--version", "3", "--raw"]).unwrap();
    if let sbae_cli::cli::Command::Get { raw, version, .. } = cli.command {
        assert!(raw);
        assert_eq!(version, Some(Version::new(3).unwrap()));
    } else {
        panic!("unexpected command variant");
    }

    // 4. ls
    let cli = Cli::try_parse_from(["secretbae", "ls"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Ls { prefix: None, .. }));

    let cli = Cli::try_parse_from(["secretbae", "ls", "prod/billing", "--tag", "env=prod"]).unwrap();
    if let sbae_cli::cli::Command::Ls { prefix, tags } = cli.command {
        assert_eq!(prefix, Some("prod/billing".to_owned()));
        assert_eq!(tags.len(), 1);
    } else {
        panic!("unexpected command variant");
    }

    // 5. versions
    let cli = Cli::try_parse_from(["secretbae", "versions", "prod/db"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Versions { .. }));

    // 6. rollback
    let cli = Cli::try_parse_from(["secretbae", "rollback", "prod/db", "--to", "2"]).unwrap();
    if let sbae_cli::cli::Command::Rollback { to, .. } = cli.command {
        assert_eq!(to, Version::new(2).unwrap());
    } else {
        panic!("unexpected command variant");
    }

    // 7. rm
    let cli = Cli::try_parse_from(["secretbae", "rm", "prod/db", "--version", "1", "--destroy"]).unwrap();
    if let sbae_cli::cli::Command::Rm { version, destroy, .. } = cli.command {
        assert_eq!(version, Some(Version::new(1).unwrap()));
        assert!(destroy);
    } else {
        panic!("unexpected command variant");
    }

    // 8. tag add / rm / ls
    let cli = Cli::try_parse_from(["secretbae", "tag", "add", "prod/db", "env=prod", "tier=backend"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Tag { action: sbae_cli::cli::TagAction::Add { .. } }));

    let cli = Cli::try_parse_from(["secretbae", "tag", "rm", "prod/db", "env=prod"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Tag { action: sbae_cli::cli::TagAction::Rm { .. } }));

    let cli = Cli::try_parse_from(["secretbae", "tag", "ls", "prod/db"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Tag { action: sbae_cli::cli::TagAction::Ls { .. } }));

    // 9. token create / list / revoke
    let cli = Cli::try_parse_from([
        "secretbae", "token", "create", "--name", "worker", "--policy", "read-prod", "--policy", "read-dev", "--ttl", "90d", "--bind-uid", "1000",
    ])
    .unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Token { action: sbae_cli::cli::TokenAction::Create { .. } }));

    let cli = Cli::try_parse_from(["secretbae", "token", "list", "sbae_pref"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Token { action: sbae_cli::cli::TokenAction::List { .. } }));

    let cli = Cli::try_parse_from(["secretbae", "token", "revoke", "sbae_pref"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Token { action: sbae_cli::cli::TokenAction::Revoke { .. } }));

    // 10. policy put / list / rm
    let cli = Cli::try_parse_from(["secretbae", "policy", "put", "--file", "/etc/pol.json"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Policy { action: sbae_cli::cli::PolicyAction::Put { .. } }));

    let cli = Cli::try_parse_from(["secretbae", "policy", "list"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Policy { action: sbae_cli::cli::PolicyAction::List }));

    let cli = Cli::try_parse_from(["secretbae", "policy", "rm", "pol-name"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Policy { action: sbae_cli::cli::PolicyAction::Rm { .. } }));

    // 11. audit verify
    let cli = Cli::try_parse_from(["secretbae", "audit", "verify"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Audit { action: sbae_cli::cli::AuditAction::Verify }));

    // 12. exec
    let cli = Cli::try_parse_from(["secretbae", "exec", "--profile", "billing", "--", "/bin/app", "--foo", "bar"]).unwrap();
    if let sbae_cli::cli::Command::Exec { profile, command } = cli.command {
        assert_eq!(profile, "billing");
        assert_eq!(command, vec!["/bin/app", "--foo", "bar"]);
    } else {
        panic!("unexpected command variant");
    }

    // 13. completions
    let cli = Cli::try_parse_from(["secretbae", "completions", "bash"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Completions { .. }));

    // 14. top
    let cli = Cli::try_parse_from(["secretbae", "top"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Top { interval: 2, once: false }));

    let cli = Cli::try_parse_from(["secretbae", "top", "--interval", "5", "--once"]).unwrap();
    assert!(matches!(cli.command, sbae_cli::cli::Command::Top { interval: 5, once: true }));

    // Global flags
    let cli = Cli::try_parse_from(["secretbae", "--json", "--socket", "/tmp/sock", "status"]).unwrap();
    assert!(cli.json);
    assert_eq!(cli.socket, Path::new("/tmp/sock"));
}

#[test]
fn cli_rejects_plain_token_argument_to_prevent_process_listing_leaks() {
    let result = Cli::try_parse_from(["secretbae", "--token", "secret_value", "status"]);
    assert!(result.is_err(), "Must refuse --token flag taking value directly");
}

#[test]
fn token_resolution_strictly_follows_precedence_order() {
    let reader = |p: &Path| match p.to_str().unwrap() {
        "/flag/token" => Ok("token_from_flag".to_owned()),
        "/profile/token" => Ok("token_from_profile".to_owned()),
        "/env/token" => Ok("token_from_env_file".to_owned()),
        "/home/.config/secretbae/token" => Ok("token_from_home".to_owned()),
        _ => Err(anyhow::anyhow!("file not found")),
    };

    let home_path = Path::new("/home/.config/secretbae/token");

    // Precedence: CLI flag wins over everything
    let res = resolve_token_with_sources(
        Some(Path::new("/flag/token")),
        Some(Path::new("/profile/token")),
        Some("/env/token"),
        Some("direct_env_token"),
        Some((home_path, true)),
        reader,
    )
    .unwrap();
    assert_eq!(res.as_str(), "token_from_flag");

    // Profile token wins over environment
    let res = resolve_token_with_sources(
        None,
        Some(Path::new("/profile/token")),
        Some("/env/token"),
        Some("direct_env_token"),
        Some((home_path, true)),
        reader,
    )
    .unwrap();
    assert_eq!(res.as_str(), "token_from_profile");

    // SECRETBAE_TOKEN_FILE wins over SECRETBAE_TOKEN
    let res = resolve_token_with_sources(
        None,
        None,
        Some("/env/token"),
        Some("direct_env_token"),
        Some((home_path, true)),
        reader,
    )
    .unwrap();
    assert_eq!(res.as_str(), "token_from_env_file");

    // SECRETBAE_TOKEN wins over ~/.config/secretbae/token
    let res = resolve_token_with_sources(
        None,
        None,
        None,
        Some("direct_env_token"),
        Some((home_path, true)),
        reader,
    )
    .unwrap();
    assert_eq!(res.as_str(), "direct_env_token");

    // Fallback to home config
    let res = resolve_token_with_sources(
        None,
        None,
        None,
        None,
        Some((home_path, true)),
        reader,
    )
    .unwrap();
    assert_eq!(res.as_str(), "token_from_home");

    // Refusal when nothing exists
    let res = resolve_token_with_sources(
        None,
        None,
        None,
        None,
        Some((home_path, false)),
        reader,
    );
    assert!(res.is_err());
}

#[test]
fn token_resolution_refuses_files_reachable_beyond_owner_and_group() {
    assert!(validate_file_mode(0o600).is_ok());
    assert!(validate_file_mode(0o400).is_ok());

    // The shipped deployment: root owns the token, the service group reads it. Forbidding
    // this would make the documented setup impossible.
    assert!(validate_file_mode(0o440).is_ok());
    assert!(validate_file_mode(0o640).is_ok());

    assert!(validate_file_mode(0o644).is_err(), "world-readable");
    assert!(validate_file_mode(0o460).is_err(), "group could swap the token");
    assert!(validate_file_mode(0o666).is_err());
    assert!(validate_file_mode(0o777).is_err());
}

#[test]
fn profile_parsing_and_screaming_snake_mapping() {
    let toml = r#"
token_file = "/etc/tokens/billing.token"

[[env]]
name = "DB_URL"
path = "prod/billing/db_url"

[[env_from]]
prefix = "prod/billing/runtime/"
transform = "screaming_snake"
"#;

    let profile: Profile = toml::from_str(toml).unwrap();
    assert_eq!(profile.env.len(), 1);
    let entry: &EnvEntry = &profile.env[0];
    assert_eq!(entry.name, "DB_URL");
    assert_eq!(screaming_snake("db_url"), "DB_URL");
    assert_eq!(screaming_snake("stripe-key"), "STRIPE_KEY");
    assert_eq!(screaming_snake("app.port"), "APP_PORT");
}

#[test]
fn duplicate_env_var_names_in_profile_are_refused() {
    let duplicates = vec![
        ("API_KEY".to_owned(), SecretPath::new("prod/api1").unwrap()),
        ("API_KEY".to_owned(), SecretPath::new("prod/api2").unwrap()),
    ];
    assert!(check_no_duplicate_env_names(&duplicates).is_err());
}

#[test]
fn profile_mode_validation_refuses_group_and_world_writable_files() {
    assert!(validate_profile_mode(0o644).is_ok());
    assert!(validate_profile_mode(0o600).is_ok());

    assert!(validate_profile_mode(0o664).is_err());
    assert!(validate_profile_mode(0o666).is_err());
    assert!(validate_profile_mode(0o777).is_err());
}

#[test]
fn child_environment_builder_strips_inherited_token_variables_and_values() {
    let parent = vec![
        ("PATH".to_owned(), "/bin".to_owned()),
        ("SECRETBAE_TOKEN".to_owned(), "my_secret_token".to_owned()),
        ("SECRETBAE_TOKEN_FILE".to_owned(), "/tmp/tok".to_owned()),
        ("LEAKED_SECRET_VAR".to_owned(), "my_secret_token".to_owned()),
        ("APP_ENV".to_owned(), "production".to_owned()),
    ];

    let secrets = vec![("DATABASE_URL".to_owned(), "postgres://...".to_owned())];
    let child = build_child_env(parent, &secrets, Some("my_secret_token"));

    let map: std::collections::HashMap<_, _> = child.into_iter().collect();
    assert!(!map.contains_key("SECRETBAE_TOKEN"));
    assert!(!map.contains_key("SECRETBAE_TOKEN_FILE"));
    assert!(!map.contains_key("LEAKED_SECRET_VAR"));
    assert_eq!(map.get("PATH").unwrap(), "/bin");
    assert_eq!(map.get("APP_ENV").unwrap(), "production");
    assert_eq!(map.get("DATABASE_URL").unwrap(), "postgres://...");
}

#[cfg(unix)]
#[test]
fn fake_unix_socket_server_verifies_exec_issues_exactly_one_batched_resolve_request() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let temp_dir = std::env::temp_dir().join(format!("sbae_sock_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let sock_path = temp_dir.join("test.sock");
    let _ = std::fs::remove_file(&sock_path);

    let listener = UnixListener::bind(&sock_path).unwrap();
    let resolve_count = Arc::new(AtomicUsize::new(0));
    let read_count = Arc::new(AtomicUsize::new(0));

    let count_clone = Arc::clone(&resolve_count);
    let read_clone = Arc::clone(&read_count);

    let server_handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let Ok(n) = stream.read(&mut buf) else { break };
            let req_str = String::from_utf8_lossy(&buf[..n]);

            if req_str.contains("POST /v1/resolve HTTP/1.1") {
                count_clone.fetch_add(1, Ordering::SeqCst);
                let resp_body = serde_json::json!({
                    "secrets": [
                        {
                            "path": "prod/billing/db_url",
                            "version": 1,
                            "value": data_encoding::BASE64.encode(b"postgres://db:5432")
                        },
                        {
                            "path": "prod/billing/stripe",
                            "version": 3,
                            "value": data_encoding::BASE64.encode(b"sk_test_secret_key")
                        }
                    ]
                });
                let resp_bytes = serde_json::to_vec(&resp_body).unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_bytes.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(&resp_bytes);
                let _ = stream.flush();
                break;
            } else if req_str.contains("POST /v1/secrets/read HTTP/1.1") {
                read_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    let client = sbae_cli::client::Client::new(&sock_path, Some("token123".to_owned()));
    let profile = Profile {
        token_file: None,
        env: vec![
            EnvEntry {
                name: "DATABASE_URL".to_owned(),
                path: SecretPath::new("prod/billing/db_url").unwrap(),
                version: None,
            },
            EnvEntry {
                name: "STRIPE_KEY".to_owned(),
                path: SecretPath::new("prod/billing/stripe").unwrap(),
                version: Some(Version::new(3).unwrap()),
            },
        ],
        env_from: vec![],
    };

    let resolved = sbae_cli::exec::resolve_profile(&client, &profile).unwrap();
    assert_eq!(resolved.len(), 2);
    assert_eq!(resolved[0].0, "DATABASE_URL");
    assert_eq!(resolved[0].1, "postgres://db:5432");
    assert_eq!(resolved[1].0, "STRIPE_KEY");
    assert_eq!(resolved[1].1, "sk_test_secret_key");

    server_handle.join().unwrap();

    assert_eq!(resolve_count.load(Ordering::SeqCst), 1, "must issue exactly one batched resolve request");
    assert_eq!(read_count.load(Ordering::SeqCst), 0, "must never issue per-secret read requests");

    let _ = std::fs::remove_dir_all(&temp_dir);
}