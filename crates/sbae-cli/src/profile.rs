//! Profile definition and environment mappings.
//!
//! A profile selects which secrets are resolved and bound into environment variables when
//! launching a service. We refuse group- or world-writable profile files so an unprivileged
//! local user cannot edit a profile to exfiltrate secrets intended for another service.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sbae_proto::{SecretPath, Version};
use serde::Deserialize;

/// Profile name wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileName(String);

impl ProfileName {
    #[must_use]
    pub fn new(name: String) -> Self {
        Self(name)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A parsed execution profile.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub env: Vec<EnvEntry>,
    #[serde(default)]
    pub env_from: Vec<EnvFromEntry>,
}

/// A single explicit environment mapping.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvEntry {
    pub name: String,
    pub path: SecretPath,
    #[serde(default)]
    pub version: Option<Version>,
}

/// A prefix-based wildcard mapping.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFromEntry {
    pub prefix: String,
    pub transform: String,
}

/// Converts a path's final segment into `SCREAMING_SNAKE_CASE`.
///
/// Hyphens and periods become underscores, and characters are uppercased.
#[must_use]
pub fn screaming_snake(leaf: &str) -> String {
    leaf.chars()
        .map(|c| match c {
            '-' | '.' => '_',
            _ => c.to_ascii_uppercase(),
        })
        .collect()
}

/// Validates that a file's mode bits contain neither group-write nor world-write access.
pub fn validate_profile_mode(mode: u32) -> anyhow::Result<()> {
    // 0o020 is S_IWGRP, 0o002 is S_IWOTH
    if (mode & 0o022) != 0 {
        anyhow::bail!(
            "permissions {:04o} are insecure; profile file must not be group- or world-writable",
            mode & 0o777
        );
    }
    Ok(())
}

/// Checks that a profile file is not group- or world-writable.
pub fn check_profile_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| anyhow::anyhow!("failed to inspect profile file '{}': {e}", path.display()))?;
        let mode = meta.permissions().mode();
        validate_profile_mode(mode).map_err(|_| {
            anyhow::anyhow!(
                "profile file '{}' has permissions {:04o}; must not be group- or world-writable",
                path.display(),
                mode & 0o777
            )
        })?;
    }

    #[cfg(not(unix))]
    {
        if !path.exists() {
            anyhow::bail!("profile file '{}' does not exist", path.display());
        }
    }

    Ok(())
}

/// Resolves a profile argument into a filesystem path.
#[must_use]
pub fn resolve_profile_path(profile_arg: &str) -> PathBuf {
    let is_toml_ext = Path::new(profile_arg)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"));
    if profile_arg.contains('/') || profile_arg.contains('\\') || is_toml_ext {
        PathBuf::from(profile_arg)
    } else {
        Path::new("/etc/secretbae/profiles").join(format!("{profile_arg}.toml"))
    }
}

/// Validates that no two entries map to the same environment variable name.
pub fn check_no_duplicate_env_names(entries: &[(String, SecretPath)]) -> anyhow::Result<()> {
    let mut seen: HashMap<&str, &SecretPath> = HashMap::new();
    for (name, path) in entries {
        if let Some(existing) = seen.get(name.as_str()) {
            anyhow::bail!(
                "duplicate environment variable name '{name}' in profile (conflicts between '{existing}' and '{path}')"
            );
        }
        seen.insert(name.as_str(), path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_parsing_deserializes_all_fields() {
        let toml_content = r#"
token_file = "/etc/secretbae/tokens/billing.token"

[[env]]
name = "DATABASE_URL"
path = "prod/billing/db_url"

[[env]]
name = "STRIPE_KEY"
path = "prod/billing/stripe"
version = 3

[[env_from]]
prefix = "prod/billing/runtime/"
transform = "screaming_snake"
"#;

        let profile: Profile = toml::from_str(toml_content).unwrap();
        assert_eq!(
            profile.token_file,
            Some(PathBuf::from("/etc/secretbae/tokens/billing.token"))
        );
        assert_eq!(profile.env.len(), 2);
        assert_eq!(profile.env[0].name, "DATABASE_URL");
        assert_eq!(profile.env[0].path.as_str(), "prod/billing/db_url");
        assert_eq!(profile.env[0].version, None);

        assert_eq!(profile.env[1].name, "STRIPE_KEY");
        assert_eq!(profile.env[1].path.as_str(), "prod/billing/stripe");
        assert_eq!(profile.env[1].version, Some(Version::new(3).unwrap()));

        assert_eq!(profile.env_from.len(), 1);
        assert_eq!(profile.env_from[0].prefix, "prod/billing/runtime/");
        assert_eq!(profile.env_from[0].transform, "screaming_snake");
    }

    #[test]
    fn screaming_snake_maps_leaf_segments_correctly() {
        assert_eq!(screaming_snake("api_key"), "API_KEY");
        assert_eq!(screaming_snake("db_url"), "DB_URL");
        assert_eq!(screaming_snake("stripe-key"), "STRIPE_KEY");
        assert_eq!(screaming_snake("service.token"), "SERVICE_TOKEN");
        assert_eq!(screaming_snake("plain"), "PLAIN");
    }

    #[test]
    fn duplicate_env_var_names_are_refused() {
        let entries = vec![
            ("DATABASE_URL".to_owned(), SecretPath::new("prod/db1").unwrap()),
            ("DATABASE_URL".to_owned(), SecretPath::new("prod/db2").unwrap()),
        ];
        assert!(check_no_duplicate_env_names(&entries).is_err());

        let distinct = vec![
            ("DATABASE_URL".to_owned(), SecretPath::new("prod/db1").unwrap()),
            ("REDIS_URL".to_owned(), SecretPath::new("prod/cache").unwrap()),
        ];
        assert!(check_no_duplicate_env_names(&distinct).is_ok());
    }

    #[test]
    fn profile_mode_validation_refuses_group_and_world_writable_files() {
        assert!(validate_profile_mode(0o644).is_ok());
        assert!(validate_profile_mode(0o600).is_ok());
        assert!(validate_profile_mode(0o444).is_ok());

        assert!(validate_profile_mode(0o664).is_err());
        assert!(validate_profile_mode(0o666).is_err());
        assert!(validate_profile_mode(0o777).is_err());
    }
}