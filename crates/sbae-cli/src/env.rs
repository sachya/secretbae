//! Environment preparation for executed child processes.
//!
//! When launching a child service, we strip any token variables and inherited token values
//! so that child processes cannot perform unauthorized management actions or leak credentials.

use std::collections::BTreeMap;

/// Prepares the child process environment by merging secrets and stripping all token traces.
#[must_use]
pub fn build_child_env(
    parent_env: impl IntoIterator<Item = (String, String)>,
    resolved_secrets: &[(String, String)],
    token_to_strip: Option<&str>,
) -> Vec<(String, String)> {
    let mut env_map: BTreeMap<String, String> = BTreeMap::new();

    for (key, val) in parent_env {
        // Strip the standard secretbae token variables
        if key == "SECRETBAE_TOKEN" || key == "SECRETBAE_TOKEN_FILE" {
            continue;
        }

        // Strip any environment variable whose value matches the bearer token
        if let Some(token) = token_to_strip {
            if !token.is_empty() && val == token {
                continue;
            }
        }

        env_map.insert(key, val);
    }

    // Inject resolved secrets
    for (name, val) in resolved_secrets {
        env_map.insert(name.clone(), val.clone());
    }

    env_map.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_builder_strips_inherited_token_variables_and_values() {
        let parent_env = vec![
            ("PATH".to_owned(), "/usr/bin".to_owned()),
            ("USER".to_owned(), "app".to_owned()),
            ("SECRETBAE_TOKEN".to_owned(), "sbae_token_val".to_owned()),
            (
                "SECRETBAE_TOKEN_FILE".to_owned(),
                "/etc/tokens/app.token".to_owned(),
            ),
            ("LEGACY_APP_TOKEN".to_owned(), "sbae_token_val".to_owned()),
            ("OTHER_KEY".to_owned(), "safe_value".to_owned()),
        ];

        let resolved_secrets = vec![
            (
                "DATABASE_URL".to_owned(),
                "postgres://user:pw@host/db".to_owned(),
            ),
            ("API_KEY".to_owned(), "secret_api_key".to_owned()),
        ];

        let child_env = build_child_env(parent_env, &resolved_secrets, Some("sbae_token_val"));
        let env_map: BTreeMap<String, String> = child_env.into_iter().collect();

        // Standard token vars must be stripped
        assert!(!env_map.contains_key("SECRETBAE_TOKEN"));
        assert!(!env_map.contains_key("SECRETBAE_TOKEN_FILE"));

        // Any var holding the token value must be stripped
        assert!(!env_map.contains_key("LEGACY_APP_TOKEN"));

        // Unrelated parent vars must remain intact
        assert_eq!(env_map.get("PATH").unwrap(), "/usr/bin");
        assert_eq!(env_map.get("USER").unwrap(), "app");
        assert_eq!(env_map.get("OTHER_KEY").unwrap(), "safe_value");

        // Resolved secrets must be injected
        assert_eq!(
            env_map.get("DATABASE_URL").unwrap(),
            "postgres://user:pw@host/db"
        );
        assert_eq!(env_map.get("API_KEY").unwrap(), "secret_api_key");
    }
}
