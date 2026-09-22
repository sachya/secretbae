//! Profile resolution and process replacement.
//!
//! Resolves secret profiles in a single batched network round-trip and replaces the current
//! process directly via execve(2) without writing secrets to disk or spawning intermediate shells.

use std::collections::HashMap;
use std::path::Path;

use sbae_proto::api::{route, ListRequest, ListResponse, ResolveRequest, ResolveResponse};
use sbae_proto::{SecretPath, Version};

use crate::client::Client;
use crate::{env, profile, token};

/// Resolves all secrets required by a profile, issuing exactly one batched resolve request.
pub fn resolve_profile(
    client: &Client,
    prof: &profile::Profile,
) -> anyhow::Result<Vec<(String, String)>> {
    let mut mapped_vars: Vec<(String, SecretPath, Option<Version>)> = Vec::new();

    // 1. Collect direct env entries
    for env_entry in &prof.env {
        mapped_vars.push((
            env_entry.name.clone(),
            env_entry.path.clone(),
            env_entry.version,
        ));
    }

    // 2. Expand wildcard env_from entries
    for env_from in &prof.env_from {
        if env_from.transform != "screaming_snake" {
            anyhow::bail!(
                "unsupported transform '{}' (expected 'screaming_snake')",
                env_from.transform
            );
        }

        let list_req = ListRequest {
            prefix: Some(env_from.prefix.clone()),
            tags: vec![],
        };
        let list_resp: ListResponse = client.post(route::LIST, &list_req)?;

        for secret in list_resp.secrets {
            let derived_name = profile::screaming_snake(secret.path.leaf());
            mapped_vars.push((derived_name, secret.path, None));
        }
    }

    // 3. Ensure no duplicate environment variable names
    let check_pairs: Vec<(String, SecretPath)> = mapped_vars
        .iter()
        .map(|(name, path, _)| (name.clone(), path.clone()))
        .collect();
    profile::check_no_duplicate_env_names(&check_pairs)?;

    if mapped_vars.is_empty() {
        return Ok(Vec::new());
    }

    // 4. Deduplicate paths for the batched resolve request
    let mut unique_paths: Vec<SecretPath> = Vec::new();
    for (_, path, _) in &mapped_vars {
        if !unique_paths.contains(path) {
            unique_paths.push(path.clone());
        }
    }

    // Single batched POST to RESOLVE
    let resolve_req = ResolveRequest { paths: unique_paths };
    let resolve_resp: ResolveResponse = client.post(route::RESOLVE, &resolve_req)?;

    let mut resolved_map: HashMap<SecretPath, (Version, String)> = HashMap::new();
    for secret in resolve_resp.secrets {
        resolved_map.insert(secret.path, (secret.version, secret.value));
    }

    // 5. Decode secret values and verify pinned versions
    let mut result = Vec::new();
    for (name, path, pinned_version) in mapped_vars {
        let (version, b64_val) = resolved_map
            .get(&path)
            .ok_or_else(|| anyhow::anyhow!("daemon did not return secret for path '{path}'"))?;

        if let Some(expected) = pinned_version {
            if *version != expected {
                anyhow::bail!(
                    "secret '{path}' resolved to version {version}, but profile pinned version {expected}"
                );
            }
        }

        let raw_bytes = data_encoding::BASE64
            .decode(b64_val.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to decode base64 payload for '{path}': {e}"))?;
        let str_val = String::from_utf8(raw_bytes).map_err(|_| {
            anyhow::anyhow!(
                "secret '{path}' contains non-UTF-8 binary data; cannot inject as environment variable"
            )
        })?;

        result.push((name, str_val));
    }

    Ok(result)
}

/// Executes a target process after populating its environment with profile secrets.
pub fn run_exec(
    socket_path: &Path,
    cli_token_file: Option<&Path>,
    profile_arg: &str,
    cmd_args: &[String],
) -> anyhow::Result<()> {
    if cmd_args.is_empty() {
        anyhow::bail!("missing target command to execute");
    }

    let profile_path = profile::resolve_profile_path(profile_arg);
    profile::check_profile_permissions(&profile_path)?;

    let profile_str = std::fs::read_to_string(&profile_path).map_err(|e| {
        anyhow::anyhow!("failed to read profile '{}': {e}", profile_path.display())
    })?;
    let prof: profile::Profile = toml::from_str(&profile_str).map_err(|e| {
        anyhow::anyhow!("failed to parse profile TOML '{}': {e}", profile_path.display())
    })?;

    let token = token::resolve_token(cli_token_file, prof.token_file.as_deref())?;
    let client = Client::new(socket_path, Some(token.as_str().to_owned()));

    let resolved_vars = resolve_profile(&client, &prof)?;
    let child_env = env::build_child_env(std::env::vars(), &resolved_vars, Some(token.as_str()));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(&cmd_args[0]);
        if cmd_args.len() > 1 {
            command.args(&cmd_args[1..]);
        }
        command.env_clear();
        command.envs(child_env);
        let err = command.exec();
        anyhow::bail!("failed to execute '{}': {err}", cmd_args[0]);
    }

    #[cfg(not(unix))]
    {
        let _ = child_env;
        anyhow::bail!("execve is only supported on Unix platforms");
    }
}