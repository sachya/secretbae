//! Output formatting for CLI commands.
//!
//! Enforces that secret values are never printed to stdout or logs except on an explicit get.

use std::io::Write;

use sbae_proto::api::{
    AuditVerifyResponse, ListResponse, ReadResponse, StatusResponse, TokenCreateResponse,
    TokenListResponse, VersionsResponse, WriteResponse,
};

pub fn print_status(resp: &StatusResponse, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(resp)?);
    } else {
        println!("Version:        {} (schema {})", resp.version, resp.schema_version);
        println!(
            "Status:         {} ({})",
            if resp.sealed { "sealed" } else { "unsealed" },
            resp.seal_kind
        );
        println!("MK Generation:  {}", resp.mk_generation);
        println!("Secrets:        {}", resp.secret_count);
    }
    Ok(())
}

pub fn print_write(resp: &WriteResponse, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(resp)?);
    } else {
        println!("Created version {} of {}", resp.version, resp.path);
    }
    Ok(())
}

pub fn print_read(resp: &ReadResponse, raw: bool, json: bool) -> anyhow::Result<()> {
    let bytes = data_encoding::BASE64
        .decode(resp.value.as_bytes())
        .map_err(|e| anyhow::anyhow!("malformed base64 secret payload from daemon: {e}"))?;

    if raw {
        let mut stdout = std::io::stdout();
        stdout.write_all(&bytes)?;
        stdout.flush()?;
    } else if json {
        println!("{}", serde_json::to_string_pretty(resp)?);
    } else {
        match String::from_utf8(bytes) {
            Ok(text) => println!("{text}"),
            Err(_) => println!("{}", resp.value),
        }
    }
    Ok(())
}

pub fn print_list(resp: &ListResponse, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(resp)?);
    } else if resp.secrets.is_empty() {
        println!("No secrets found.");
    } else {
        println!("{:<32} {:<10} {:<24} TAGS", "PATH", "VERSION", "UPDATED");
        for secret in &resp.secrets {
            let ver = secret
                .current_version
                .map_or_else(|| "-".to_owned(), |v| format!("v{v}"));
            let tags: Vec<String> = secret.tags.iter().map(ToString::to_string).collect();
            let tags_str = if tags.is_empty() { "-".to_owned() } else { tags.join(",") };
            println!("{:<32} {:<10} {:<24} {}", secret.path, ver, secret.updated_at, tags_str);
        }
    }
    Ok(())
}

pub fn print_versions(resp: &VersionsResponse, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(resp)?);
    } else if resp.versions.is_empty() {
        println!("No versions found for {}.", resp.path);
    } else {
        println!("{:<10} {:<12} {:<24} {:<16} COMMENT", "VERSION", "STATE", "CREATED", "BY");
        for v in &resp.versions {
            println!(
                "{:<10} {:<12} {:<24} {:<16} {}",
                format!("v{}", v.version),
                v.state.as_str(),
                v.created_at,
                v.created_by.as_deref().unwrap_or("-"),
                v.comment.as_deref().unwrap_or("-"),
            );
        }
    }
    Ok(())
}

pub fn print_token_create(resp: &TokenCreateResponse, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(resp)?);
    } else {
        println!("Token created successfully.");
        println!("Token:      {}", resp.token);
        println!("Prefix:     {}", resp.prefix);
        println!("Expires:    {}", resp.expires_at.as_deref().unwrap_or("never"));
        println!();
        println!("Record this token now. It will not be shown again.");
    }
    Ok(())
}

pub fn print_token_list(resp: &TokenListResponse, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(resp)?);
    } else if resp.tokens.is_empty() {
        println!("No tokens found.");
    } else {
        println!(
            "{:<12} {:<20} {:<20} {:<10} {:<24} STATUS",
            "PREFIX", "NAME", "POLICIES", "BOUND UID", "EXPIRES"
        );
        for t in &resp.tokens {
            let status = if t.revoked { "revoked" } else { "active" };
            let bound = t.bound_uid.map_or_else(|| "-".to_owned(), |u| u.to_string());
            let expires = t.expires_at.as_deref().unwrap_or("never");
            let policies = t.policies.join(",");
            println!(
                "{:<12} {:<20} {:<20} {:<10} {:<24} {}",
                t.prefix, t.name, policies, bound, expires, status
            );
        }
    }
    Ok(())
}

pub fn print_policy_list(policies: &[String], json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(policies)?);
    } else if policies.is_empty() {
        println!("No policies found.");
    } else {
        for p in policies {
            println!("{p}");
        }
    }
    Ok(())
}

pub fn print_audit_verify(resp: &AuditVerifyResponse, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(resp)?);
    } else if let Some(seq) = resp.broken_at {
        let detail = resp.detail.as_deref().unwrap_or("unknown mismatch");
        println!("Audit verification FAILED at entry {seq}: {detail}");
    } else {
        println!("Audit chain verified: {} entries intact.", resp.entries);
    }
    if resp.broken_at.is_some() {
        anyhow::bail!("audit log verification failed");
    }
    Ok(())
}