use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ProtoError;

/// The maximum number of `/`-separated segments in a path.
pub const MAX_SEGMENTS: usize = 16;
/// The maximum length of a single segment.
pub const MAX_SEGMENT_LEN: usize = 64;
/// The maximum length of a whole path.
pub const MAX_PATH_LEN: usize = 512;

/// A validated secret path, such as `prod/billing/db_url`.
///
/// Validation is enforced at construction so that no other layer -- storage, policy matching,
/// audit -- ever has to defend against a malformed path.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretPath(String);

impl SecretPath {
    pub fn new(raw: &str) -> Result<Self, ProtoError> {
        if raw.is_empty() || raw.len() > MAX_PATH_LEN {
            return Err(ProtoError::InvalidPath {
                path: truncate_for_error(raw),
                reason: "must be between 1 and 512 characters",
            });
        }

        let segments: Vec<&str> = raw.split('/').collect();
        if segments.len() > MAX_SEGMENTS {
            return Err(ProtoError::InvalidPath {
                path: truncate_for_error(raw),
                reason: "has more than 16 segments",
            });
        }

        for segment in &segments {
            validate_segment(segment).map_err(|reason| ProtoError::InvalidPath {
                path: truncate_for_error(raw),
                reason,
            })?;
        }

        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// The final segment, used to derive an environment variable name in `exec` profiles.
    #[must_use]
    pub fn leaf(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    /// Whether this path sits underneath `prefix`, respecting segment boundaries.
    ///
    /// Segment-aware so that `prod/billing-admin` is not treated as living under
    /// `prod/billing`, which a naive `starts_with` would get wrong.
    #[must_use]
    pub fn starts_with_prefix(&self, prefix: &str) -> bool {
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        if prefix.is_empty() {
            return true;
        }
        self.0
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }
}

fn validate_segment(segment: &str) -> Result<(), &'static str> {
    if segment.is_empty() {
        return Err("contains an empty segment (leading, trailing or doubled '/')");
    }
    if segment.len() > MAX_SEGMENT_LEN {
        return Err("contains a segment longer than 64 characters");
    }
    if segment == "." || segment == ".." {
        return Err("contains a '.' or '..' segment");
    }

    for byte in segment.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => {}
            // Rejected rather than silently lowercased: if `prod/DB` and `prod/db` could both
            // exist, a policy granting one would read to a human as granting the other.
            b'A'..=b'Z' => return Err("contains uppercase; paths are lowercase only"),
            _ => return Err("contains characters outside [a-z0-9._-] and '/'"),
        }
    }

    Ok(())
}

fn truncate_for_error(raw: &str) -> String {
    raw.chars().take(64).collect()
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretPath({})", self.0)
    }
}

impl FromStr for SecretPath {
    type Err = ProtoError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw)
    }
}

impl TryFrom<String> for SecretPath {
    type Error = ProtoError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::new(&raw)
    }
}

impl From<SecretPath> for String {
    fn from(path: SecretPath) -> Self {
        path.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_paths() {
        for raw in ["a", "prod/billing/db_url", "dev/app-1/key.pem", "x/y/z"] {
            assert!(SecretPath::new(raw).is_ok(), "should accept {raw}");
        }
    }

    #[test]
    fn rejects_traversal_and_empty_segments() {
        for raw in [
            "../etc/passwd",
            "prod/../dev/db",
            "prod//db",
            "/prod/db",
            "prod/db/",
            ".",
        ] {
            assert!(SecretPath::new(raw).is_err(), "should reject {raw}");
        }
    }

    #[test]
    fn rejects_uppercase_to_keep_paths_unambiguous() {
        assert!(SecretPath::new("prod/DB").is_err());
        assert!(SecretPath::new("Prod/db").is_err());
    }

    #[test]
    fn rejects_control_characters_and_separators() {
        for raw in [
            "prod/db\0",
            "prod/db\n",
            "prod/db url",
            "prod/db:x",
            "prod/../*",
        ] {
            assert!(SecretPath::new(raw).is_err(), "should reject {raw:?}");
        }
    }

    #[test]
    fn enforces_length_limits() {
        assert!(SecretPath::new(&"a".repeat(MAX_SEGMENT_LEN)).is_ok());
        assert!(SecretPath::new(&"a".repeat(MAX_SEGMENT_LEN + 1)).is_err());
        assert!(SecretPath::new(&vec!["a"; MAX_SEGMENTS].join("/")).is_ok());
        assert!(SecretPath::new(&vec!["a"; MAX_SEGMENTS + 1].join("/")).is_err());
    }

    /// The bug a naive `starts_with` would introduce: a token scoped to `prod/billing`
    /// silently reaching `prod/billing-admin`.
    #[test]
    fn prefix_matching_respects_segment_boundaries() {
        let path = SecretPath::new("prod/billing-admin/key").unwrap();
        assert!(!path.starts_with_prefix("prod/billing"));
        assert!(path.starts_with_prefix("prod/billing-admin"));
        assert!(path.starts_with_prefix("prod/billing-admin/"));
        assert!(path.starts_with_prefix("prod"));
        assert!(path.starts_with_prefix(""));
    }

    #[test]
    fn leaf_returns_the_final_segment() {
        assert_eq!(
            SecretPath::new("prod/billing/db_url").unwrap().leaf(),
            "db_url"
        );
        assert_eq!(SecretPath::new("solo").unwrap().leaf(), "solo");
    }

    #[test]
    fn serde_round_trip_revalidates() {
        let path = SecretPath::new("prod/billing/db_url").unwrap();
        let json = serde_json::to_string(&path).unwrap();
        assert_eq!(serde_json::from_str::<SecretPath>(&json).unwrap(), path);

        assert!(serde_json::from_str::<SecretPath>("\"../escape\"").is_err());
    }
}
