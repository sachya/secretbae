//! Command-line client for the secretbae secret management daemon.

#![forbid(unsafe_code)]

pub mod admin;
pub mod cli;
pub mod client;
pub mod duration;
pub mod env;
pub mod exec;
pub mod format;
pub mod profile;
pub mod token;
pub mod top;

use std::io::Read;

use clap::{CommandFactory, Parser};
use sbae_proto::api::{
    route, Ack, DeleteRequest, ListRequest, ListResponse, NameRequest, PathRequest, PolicyListResponse,
    PolicyPutRequest, ReadRequest, ReadResponse, RollbackRequest, StatusResponse, TagRemoveRequest, TagRequest,
    TokenCreateRequest, TokenCreateResponse, TokenListResponse, TokenRevokeRequest, VersionsResponse,
    WriteRequest, WriteResponse,
};

use crate::cli::{AuditAction, Cli, Command, PolicyAction, TagAction, TokenAction};
use crate::client::Client;

/// Parses CLI arguments and executes the requested command.
pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run_with(cli)
}

/// Executes the given parsed CLI invocation.
pub fn run_with(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "secretbae",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        Command::Exec { profile, command } => {
            exec::run_exec(&cli.socket, cli.token_file.as_deref(), &profile, &command)
        }
        Command::Top { interval, once } => {
            let token_opt = match token::resolve_token(cli.token_file.as_deref(), None) {
                Ok(t) => Some(t.as_str().to_owned()),
                Err(e) => {
                    if cli.token_file.is_some() {
                        return Err(e);
                    }
                    None
                }
            };
            let client = Client::new(&cli.socket, token_opt);
            top::run_top(&client, top::RefreshInterval::from_secs(interval), once)
        }
        command => {
            let token_opt = match token::resolve_token(cli.token_file.as_deref(), None) {
                Ok(t) => Some(t.as_str().to_owned()),
                Err(e) => {
                    // Commands that can run without authentication (such as probing status)
                    if matches!(command, Command::Status) {
                        None
                    } else {
                        return Err(e);
                    }
                }
            };

            let client = Client::new(&cli.socket, token_opt);
            dispatch_client_command(&client, command, cli.json)
        }
    }
}

fn dispatch_client_command(client: &Client, command: Command, json: bool) -> anyhow::Result<()> {
    match command {
        Command::Status
        | Command::Put { .. }
        | Command::Get { .. }
        | Command::Ls { .. }
        | Command::Versions { .. }
        | Command::Rollback { .. }
        | Command::Rm { .. } => dispatch_secret_command(client, command, json),
        Command::Tag { action } => dispatch_tag_command(client, action, json),
        Command::Token { action } => dispatch_token_command(client, action, json),
        Command::Policy { action } => dispatch_policy_command(client, action, json),
        Command::Audit { action } => dispatch_audit_command(client, action, json),
        Command::Rekey { yes } => admin::rekey(client, yes, json),
        Command::Backup { output, passphrase } => {
            admin::backup(client, &output, passphrase, json)
        }
        Command::Restore { input, passphrase } => {
            admin::restore(client, &input, passphrase, json)
        }
        Command::Exec { .. } | Command::Completions { .. } | Command::Top { .. } => unreachable!(),
    }
}

fn dispatch_secret_command(client: &Client, command: Command, json: bool) -> anyhow::Result<()> {
    match command {
        Command::Status => {
            let req = serde_json::json!({});
            let resp: StatusResponse = client.post(route::STATUS, &req)?;
            format::print_status(&resp, json)
        }
        Command::Put {
            path,
            stdin,
            file,
            value,
            tags,
            comment,
        } => {
            let raw_bytes = if stdin {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .map_err(|e| anyhow::anyhow!("failed to read secret payload from stdin: {e}"))?;
                buf
            } else if let Some(path) = file {
                std::fs::read(&path).map_err(|e| {
                    anyhow::anyhow!("failed to read secret payload from '{}': {e}", path.display())
                })?
            } else if let Some(val) = value {
                val.into_bytes()
            } else {
                anyhow::bail!("one of --stdin, --file, or --value must be provided");
            };

            let base64_payload = data_encoding::BASE64.encode(&raw_bytes);
            let req = WriteRequest {
                path,
                value: base64_payload,
                tags,
                comment,
            };
            let resp: WriteResponse = client.post(route::WRITE, &req)?;
            format::print_write(&resp, json)
        }
        Command::Get { path, version, raw } => {
            let req = ReadRequest { path, version };
            let resp: ReadResponse = client.post(route::READ, &req)?;
            format::print_read(&resp, raw, json)
        }
        Command::Ls { prefix, tags } => {
            let req = ListRequest { prefix, tags };
            let resp: ListResponse = client.post(route::LIST, &req)?;
            format::print_list(&resp, json)
        }
        Command::Versions { path } => {
            let req = PathRequest { path };
            let resp: VersionsResponse = client.post(route::VERSIONS, &req)?;
            format::print_versions(&resp, json)
        }
        Command::Rollback { path, to } => {
            let req = RollbackRequest { path, to };
            let ack: Ack = client.post(route::ROLLBACK, &req)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ack)?);
            } else {
                println!("Rolled back {} to version {}", req.path, to);
            }
            Ok(())
        }
        Command::Rm {
            path,
            version,
            destroy,
        } => {
            let req = DeleteRequest {
                path,
                version,
                destroy,
            };
            let ack: Ack = client.post(route::DELETE, &req)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ack)?);
            } else {
                let action = if destroy { "Destroyed" } else { "Deleted" };
                let ver_str = version
                    .map_or_else(|| "all versions".to_owned(), |v| format!("version {v}"));
                println!("{action} {} ({ver_str})", req.path);
            }
            Ok(())
        }
        _ => unreachable!(),
    }
}

fn dispatch_tag_command(client: &Client, action: TagAction, json: bool) -> anyhow::Result<()> {
    match action {
        TagAction::Add { path, tags } => {
            let req = TagRequest { path, tags };
            let ack: Ack = client.post(route::TAG_ADD, &req)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ack)?);
            } else {
                println!("Attached {} tag(s) to {}", req.tags.len(), req.path);
            }
            Ok(())
        }
        TagAction::Rm { path, tags } => {
            let req = TagRemoveRequest { path, tags };
            let ack: Ack = client.post(route::TAG_REMOVE, &req)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ack)?);
            } else {
                println!("Removed {} tag(s) from {}", req.tags.len(), req.path);
            }
            Ok(())
        }
        TagAction::Ls { path } => {
            let req = ListRequest {
                prefix: Some(path.as_str().to_owned()),
                tags: vec![],
            };
            let resp: ListResponse = client.post(route::LIST, &req)?;
            let secret = resp
                .secrets
                .into_iter()
                .find(|s| s.path == path)
                .ok_or_else(|| anyhow::anyhow!("secret '{path}' not found"))?;

            if json {
                println!("{}", serde_json::to_string_pretty(&secret.tags)?);
            } else if secret.tags.is_empty() {
                println!("No tags found on {path}.");
            } else {
                for tag in &secret.tags {
                    println!("{tag}");
                }
            }
            Ok(())
        }
    }
}

fn dispatch_token_command(client: &Client, action: TokenAction, json: bool) -> anyhow::Result<()> {
    match action {
        TokenAction::Create {
            name,
            policies,
            ttl,
            bind_uid,
        } => {
            let ttl_seconds = ttl
                .as_deref()
                .map(|s| s.parse::<duration::TtlSeconds>().map(duration::TtlSeconds::get))
                .transpose()?;
            let bound = bind_uid.as_deref().map(token::parse_bind_uid).transpose()?;
            let req = TokenCreateRequest {
                name,
                policies,
                bind_uid: bound,
                ttl_seconds,
            };
            let resp: TokenCreateResponse = client.post(route::TOKEN_CREATE, &req)?;
            format::print_token_create(&resp, json)
        }
        TokenAction::List { prefix } => {
            let req = serde_json::json!({});
            let mut resp: TokenListResponse = client.post(route::TOKEN_LIST, &req)?;
            if let Some(p) = prefix {
                resp.tokens.retain(|t| t.prefix.starts_with(&p));
            }
            format::print_token_list(&resp, json)
        }
        TokenAction::Revoke { prefix } => {
            let req = TokenRevokeRequest {
                prefix: prefix.clone(),
            };
            let ack: Ack = client.post(route::TOKEN_REVOKE, &req)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ack)?);
            } else {
                println!("Revoked token {prefix}");
            }
            Ok(())
        }
    }
}

fn dispatch_policy_command(client: &Client, action: PolicyAction, json: bool) -> anyhow::Result<()> {
    match action {
        PolicyAction::Put { file } => {
            let document = std::fs::read_to_string(&file).map_err(|e| {
                anyhow::anyhow!("failed to read policy file '{}': {e}", file.display())
            })?;
            let req = PolicyPutRequest { document };
            let ack: Ack = client.post(route::POLICY_PUT, &req)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ack)?);
            } else {
                println!("Policy stored successfully.");
            }
            Ok(())
        }
        PolicyAction::List => {
            let req = serde_json::json!({});
            let resp: PolicyListResponse = client.post(route::POLICY_LIST, &req)?;
            format::print_policy_list(&resp.policies, json)
        }
        PolicyAction::Rm { name } => {
            let req = NameRequest { name };
            let ack: Ack = client.post(route::POLICY_DELETE, &req)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ack)?);
            } else {
                println!("Deleted policy {}", req.name);
            }
            Ok(())
        }
    }
}

fn dispatch_audit_command(client: &Client, action: AuditAction, json: bool) -> anyhow::Result<()> {
    match action {
        AuditAction::Verify => {
            let req = serde_json::json!({});
            let resp = client.post(route::AUDIT_VERIFY, &req)?;
            format::print_audit_verify(&resp, json)
        }
    }
}