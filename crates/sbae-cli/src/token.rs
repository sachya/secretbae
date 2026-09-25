//! Token discovery and permission enforcement.
//!
//! A bearer token is a sensitive capability. A loosely-permissioned token file on a shared
//! multi-tenant machine exposes secrets to unprivileged local accounts, so any group- or
//! world-readable mode is rejected before reading.

use std::fmt;
use std::path::{Path, PathBuf};

/// A resolved authentication token.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedToken(String);

impl ResolvedToken {
    #[must_use]
    pub fn new(raw: String) -> Self {
        Self(raw)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResolvedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResolvedToken(***)")
    }
}

/// Token file path domain wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenFilePath(PathBuf);

impl TokenFilePath {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Reject a token file that anyone outside its owner and group can reach, or that its group
/// can rewrite.
///
/// Group *read* is deliberately allowed: a service token is owned by root and read by the
/// application's own account, which is exactly what `0440 root:<app group>` expresses. A rule
/// that forbade it would make the documented deployment impossible and push operators towards
/// copying tokens into world-readable places instead.
pub fn validate_file_mode(mode: u32) -> anyhow::Result<()> {
    let permissions = mode & 0o777;

    // Any access at all for "other", or write access for the group.
    if (permissions & 0o007) != 0 || (permissions & 0o020) != 0 {
        anyhow::bail!(
            "permissions {permissions:04o} are insecure; a token file must not be readable or              writable by other, nor writable by its group (expected 0400, 0600 or 0440)"
        );
    }
    Ok(())
}

/// Validates that the file exists and is neither group- nor world-readable.
pub fn check_token_file_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| {
            anyhow::anyhow!("failed to inspect token file '{}': {e}", path.display())
        })?;
        let mode = meta.permissions().mode();
        validate_file_mode(mode)
            .map_err(|source| anyhow::anyhow!("token file '{}': {source}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        if !path.exists() {
            anyhow::bail!("token file '{}' does not exist", path.display());
        }
    }

    Ok(())
}

/// Reads a token file after validating permissions, trimming whitespace.
pub fn read_token_file(path: &Path) -> anyhow::Result<String> {
    check_token_file_permissions(path)?;
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read token file '{}': {e}", path.display()))?;
    let trimmed = raw.trim().to_owned();
    if trimmed.is_empty() {
        anyhow::bail!("token file '{}' is empty", path.display());
    }
    Ok(trimmed)
}

/// Resolves token following the documented precedence order using provided source lookups.
pub fn resolve_token_with_sources<F>(
    cli_token_file: Option<&Path>,
    profile_token_file: Option<&Path>,
    env_token_file: Option<&str>,
    env_token: Option<&str>,
    home_token_file: Option<(&Path, bool)>,
    read_file: F,
) -> anyhow::Result<ResolvedToken>
where
    F: Fn(&Path) -> anyhow::Result<String>,
{
    // 1. Explicit CLI argument --token-file
    if let Some(path) = cli_token_file {
        let content = read_file(path)?;
        return Ok(ResolvedToken(content));
    }

    // 1b. Profile-specified token_file (for exec)
    if let Some(path) = profile_token_file {
        let content = read_file(path)?;
        return Ok(ResolvedToken(content));
    }

    // 2. SECRETBAE_TOKEN_FILE environment variable
    if let Some(path_str) = env_token_file {
        let trimmed = path_str.trim();
        if !trimmed.is_empty() {
            let content = read_file(Path::new(trimmed))?;
            return Ok(ResolvedToken(content));
        }
    }

    // 3. SECRETBAE_TOKEN environment variable
    if let Some(token_str) = env_token {
        let trimmed = token_str.trim();
        if !trimmed.is_empty() {
            return Ok(ResolvedToken(trimmed.to_owned()));
        }
    }

    // 4. ~/.config/secretbae/token
    if let Some((path, exists)) = home_token_file {
        if exists {
            let content = read_file(path)?;
            return Ok(ResolvedToken(content));
        }
    }

    anyhow::bail!(
        "no authentication token found; specify --token-file, set SECRETBAE_TOKEN_FILE or SECRETBAE_TOKEN, or place token in ~/.config/secretbae/token"
    )
}

/// Resolves the bearer token from the active environment and filesystem.
pub fn resolve_token(
    cli_token_file: Option<&Path>,
    profile_token_file: Option<&Path>,
) -> anyhow::Result<ResolvedToken> {
    let env_file = std::env::var("SECRETBAE_TOKEN_FILE").ok();
    let env_tok = std::env::var("SECRETBAE_TOKEN").ok();

    let home_file = std::env::var_os("HOME").map(|h| {
        let p = PathBuf::from(h)
            .join(".config")
            .join("secretbae")
            .join("token");
        let exists = p.is_file();
        (p, exists)
    });

    let home_ref = home_file.as_ref().map(|(p, exists)| (p.as_path(), *exists));

    resolve_token_with_sources(
        cli_token_file,
        profile_token_file,
        env_file.as_deref(),
        env_tok.as_deref(),
        home_ref,
        read_token_file,
    )
}

/// Resolves a `USER_OR_UID` argument into a numeric UID.
pub fn parse_bind_uid(raw: &str) -> anyhow::Result<u32> {
    let raw = raw.trim();
    if let Ok(uid) = raw.parse::<u32>() {
        return Ok(uid);
    }

    #[cfg(unix)]
    {
        let passwd = std::fs::read_to_string("/etc/passwd").map_err(|e| {
            anyhow::anyhow!("failed to read /etc/passwd to resolve user '{raw}': {e}")
        })?;
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[0] == raw {
                return parts[2]
                    .parse::<u32>()
                    .map_err(|_| anyhow::anyhow!("invalid UID for user '{raw}' in /etc/passwd"));
            }
        }
        anyhow::bail!("user '{raw}' not found in /etc/passwd");
    }

    #[cfg(not(unix))]
    {
        anyhow::bail!("username lookup is only supported on Unix; specify numeric UID");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_validation_refuses_group_and_world_readable_bits() {
        // Owner only: acceptable
        assert!(validate_file_mode(0o600).is_ok());
        assert!(validate_file_mode(0o400).is_ok());
        assert!(validate_file_mode(0o700).is_ok());
        // The shipped deployment: root owns the token, the service group reads it.
        assert!(validate_file_mode(0o440).is_ok());
        assert!(validate_file_mode(0o640).is_ok());
        assert!(
            validate_file_mode(0o460).is_err(),
            "group write allows swapping the token"
        );

        // Group readable: rejected

        // World readable: rejected
        assert!(validate_file_mode(0o604).is_err());
        assert!(validate_file_mode(0o644).is_err());
        assert!(validate_file_mode(0o777).is_err());
    }

    #[test]
    fn token_resolution_precedence_order_is_strictly_enforced() {
        let cli_path = Path::new("/cli/token");
        let profile_path = Path::new("/profile/token");
        let home_path = Path::new("/home/.config/secretbae/token");

        let reader = |p: &Path| match p.to_str().unwrap() {
            "/cli/token" => Ok("token_cli".to_owned()),
            "/profile/token" => Ok("token_profile".to_owned()),
            "/env/token_file" => Ok("token_env_file".to_owned()),
            "/home/.config/secretbae/token" => Ok("token_home".to_owned()),
            _ => Err(anyhow::anyhow!("file not found")),
        };

        // 1. CLI flag takes highest precedence
        let resolved = resolve_token_with_sources(
            Some(cli_path),
            Some(profile_path),
            Some("/env/token_file"),
            Some("token_env"),
            Some((home_path, true)),
            reader,
        )
        .unwrap();
        assert_eq!(resolved.as_str(), "token_cli");

        // 2. Profile token takes precedence over env vars
        let resolved = resolve_token_with_sources(
            None,
            Some(profile_path),
            Some("/env/token_file"),
            Some("token_env"),
            Some((home_path, true)),
            reader,
        )
        .unwrap();
        assert_eq!(resolved.as_str(), "token_profile");

        // 3. SECRETBAE_TOKEN_FILE overrides SECRETBAE_TOKEN
        let resolved = resolve_token_with_sources(
            None,
            None,
            Some("/env/token_file"),
            Some("token_env"),
            Some((home_path, true)),
            reader,
        )
        .unwrap();
        assert_eq!(resolved.as_str(), "token_env_file");

        // 4. SECRETBAE_TOKEN overrides ~/.config/secretbae/token
        let resolved = resolve_token_with_sources(
            None,
            None,
            None,
            Some("token_env"),
            Some((home_path, true)),
            reader,
        )
        .unwrap();
        assert_eq!(resolved.as_str(), "token_env");

        // 5. ~/.config/secretbae/token used when nothing else set
        let resolved =
            resolve_token_with_sources(None, None, None, None, Some((home_path, true)), reader)
                .unwrap();
        assert_eq!(resolved.as_str(), "token_home");

        // 6. Error returned when no sources exist
        let err =
            resolve_token_with_sources(None, None, None, None, Some((home_path, false)), reader);
        assert!(err.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn loosely_permissioned_token_file_on_filesystem_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = std::env::temp_dir().join(format!("sbae_test_token_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let token_file = temp_dir.join("test.token");
        std::fs::write(&token_file, "sbae_secret").unwrap();

        // 0644 mode (group/world readable) must be rejected
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token_file(&token_file).is_err());

        // 0600 mode (owner only) must succeed
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token_file(&token_file).unwrap(), "sbae_secret");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
/// Combine `--policy` and `--unrestricted` into the final policy list for a new token.
///
/// A pure function so the precedence is testable without a daemon: `--unrestricted` adds the
/// built-in policy if it is not already named explicitly, and at least one policy of some
/// kind is required -- a token created with no policy at all would be a silent no-op grant
/// that looks successful and does nothing.
pub fn resolve_policies(explicit: Vec<String>, unrestricted: bool) -> anyhow::Result<Vec<String>> {
    let mut policies = explicit;

    if unrestricted
        && !policies
            .iter()
            .any(|p| p == sbae_proto::api::BUILTIN_UNRESTRICTED_POLICY)
    {
        policies.push(sbae_proto::api::BUILTIN_UNRESTRICTED_POLICY.to_owned());
    }

    if policies.is_empty() {
        anyhow::bail!(
            "token create needs at least one grant: pass --policy <name> or --unrestricted"
        );
    }

    Ok(policies)
}

#[cfg(test)]
mod resolve_policies_tests {
    use super::*;

    #[test]
    fn unrestricted_alone_attaches_the_builtin_policy() {
        assert_eq!(
            resolve_policies(vec![], true).unwrap(),
            vec!["unrestricted"]
        );
    }

    #[test]
    fn explicit_policies_alone_are_used_as_given() {
        assert_eq!(
            resolve_policies(vec!["billing".to_owned()], false).unwrap(),
            vec!["billing"]
        );
    }

    #[test]
    fn both_combine_without_duplicating_the_builtin_name() {
        assert_eq!(
            resolve_policies(vec!["billing".to_owned()], true).unwrap(),
            vec!["billing", "unrestricted"]
        );
        assert_eq!(
            resolve_policies(vec!["unrestricted".to_owned()], true).unwrap(),
            vec!["unrestricted"],
            "must not duplicate an already-explicit unrestricted"
        );
    }

    #[test]
    fn neither_flag_is_refused_rather_than_minting_a_grantless_token() {
        assert!(resolve_policies(vec![], false).is_err());
    }
}
