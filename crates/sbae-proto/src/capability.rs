use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ProtoError;

/// An action a policy rule can grant on a path.
///
/// Kept deliberately coarse. A finer-grained set invites policies nobody can read, and an
/// unreadable policy is an insecure one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    /// Read a secret's plaintext.
    Read,
    /// Create a secret or append a new version.
    Write,
    /// Soft-delete, destroy, or roll back.
    Delete,
    /// Enumerate paths and metadata, without reading any plaintext.
    List,
    /// Manage tokens and policies. Never granted to an application token.
    Admin,
}

impl Capability {
    pub const ALL: [Self; 5] = [
        Self::Read,
        Self::Write,
        Self::Delete,
        Self::List,
        Self::Admin,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Admin => "admin",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = ProtoError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == raw)
            .ok_or(ProtoError::InvalidCapability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_round_trips_through_its_name() {
        for capability in Capability::ALL {
            assert_eq!(
                capability.as_str().parse::<Capability>().unwrap(),
                capability
            );
        }
    }

    #[test]
    fn unknown_capabilities_are_rejected() {
        // A typo in a policy document must fail loudly, never silently grant nothing.
        assert!("reed".parse::<Capability>().is_err());
        assert!("*".parse::<Capability>().is_err());
    }

    #[test]
    fn serde_uses_the_same_lowercase_names() {
        assert_eq!(
            serde_json::to_string(&Capability::Read).unwrap(),
            "\"read\""
        );
    }
}
