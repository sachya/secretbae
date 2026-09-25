//! Daemon configuration.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{DaemonError, Result};

/// Paths and identities the daemon needs before it can drop privileges.
///
/// Every field has a default matching the shipped packaging, so a minimal deployment needs no
/// configuration file at all.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Seal keyfile. Read as root, then never touched again.
    pub keyfile: PathBuf,
    pub store: PathBuf,
    pub socket: PathBuf,
    /// A second, minimal, plain-text protocol for reading secrets -- see `docs/API.md`. Reuses
    /// `socket_mode` and the same three gates as `socket`; the only new surface is its parser.
    pub resolve_socket: PathBuf,
    /// Account the daemon runs as once the master key is in memory.
    pub user: String,
    /// Socket mode. Group-accessible so an application's user can connect; the token and its
    /// uid binding are what actually authorise the caller.
    pub socket_mode: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            keyfile: PathBuf::from("/etc/secretbae/master.key"),
            store: PathBuf::from("/var/lib/secretbae/store.db"),
            socket: PathBuf::from(sbae_proto::api::DEFAULT_SOCKET_PATH),
            resolve_socket: PathBuf::from(sbae_proto::api::DEFAULT_RESOLVE_SOCKET_PATH),
            user: "secretbae".to_owned(),
            socket_mode: 0o660,
        }
    }
}

impl Config {
    /// Load from `path`, or fall back to defaults when the file is absent.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                toml::from_str(&contents).map_err(|source| DaemonError::Config(source.to_string()))
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(DaemonError::Io(source)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_shipped_packaging() {
        let config = Config::default();
        assert_eq!(config.keyfile, Path::new("/etc/secretbae/master.key"));
        assert_eq!(config.socket, Path::new("/run/secretbae/sock"));
        assert_eq!(
            config.resolve_socket,
            Path::new("/run/secretbae/resolve.sock")
        );
        assert_eq!(config.user, "secretbae");
        assert_eq!(config.socket_mode, 0o660);
    }

    #[test]
    fn a_partial_file_keeps_the_remaining_defaults() {
        let config: Config = toml::from_str(r#"user = "vault""#).unwrap();
        assert_eq!(config.user, "vault");
        assert_eq!(config.socket, Path::new("/run/secretbae/sock"));
    }

    /// A typo must not silently leave the daemon on a default the operator did not intend.
    #[test]
    fn an_unknown_key_is_refused() {
        assert!(toml::from_str::<Config>(r#"usr = "vault""#).is_err());
    }

    #[test]
    fn a_missing_file_yields_defaults() {
        let config = Config::load(Path::new("/nonexistent/secretbae.toml")).unwrap();
        assert_eq!(config.user, Config::default().user);
    }
}
