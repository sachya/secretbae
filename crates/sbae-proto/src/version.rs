use core::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ProtoError;

/// A secret version number. Versions start at 1 and only ever increase.
///
/// `NonZeroU32` rather than `u32` so that "version 0" -- which would otherwise be an easy
/// off-by-one for a caller iterating from zero -- cannot be constructed at all.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Version(NonZeroU32);

impl Version {
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    pub fn new(value: u32) -> Result<Self, ProtoError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(ProtoError::InvalidVersion)
    }

    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }

    /// The version a write should create, given the highest that currently exists.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

impl FromStr for Version {
    type Err = ProtoError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw.parse().map_err(|_| ProtoError::InvalidVersion)?)
    }
}

impl TryFrom<u32> for Version {
    type Error = ProtoError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Version> for u32 {
    fn from(version: Version) -> Self {
        version.get()
    }
}

/// Lifecycle of a single version.
///
/// Deletion is two-stage on purpose: `Deleted` hides a version but keeps its ciphertext, so a
/// mistake is recoverable, while `Destroyed` discards the ciphertext irreversibly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VersionState {
    Active,
    Deleted,
    Destroyed,
}

impl VersionState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deleted => "deleted",
            Self::Destroyed => "destroyed",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, ProtoError> {
        match raw {
            "active" => Ok(Self::Active),
            "deleted" => Ok(Self::Deleted),
            "destroyed" => Ok(Self::Destroyed),
            _ => Err(ProtoError::InvalidVersionState),
        }
    }

    /// Whether the plaintext can still be returned to a caller.
    #[must_use]
    pub fn is_readable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_zero_is_unrepresentable() {
        assert!(Version::new(0).is_err());
        assert!(serde_json::from_str::<Version>("0").is_err());
        assert!("0".parse::<Version>().is_err());
    }

    #[test]
    fn versions_start_at_one_and_increment() {
        assert_eq!(Version::FIRST.get(), 1);
        assert_eq!(Version::FIRST.next().get(), 2);
    }

    #[test]
    fn serde_round_trip() {
        let version = Version::new(7).unwrap();
        assert_eq!(serde_json::to_string(&version).unwrap(), "7");
        assert_eq!(serde_json::from_str::<Version>("7").unwrap(), version);
    }

    #[test]
    fn only_active_versions_are_readable() {
        assert!(VersionState::Active.is_readable());
        assert!(!VersionState::Deleted.is_readable());
        assert!(!VersionState::Destroyed.is_readable());
    }

    #[test]
    fn state_parses_from_its_stored_form() {
        for state in [
            VersionState::Active,
            VersionState::Deleted,
            VersionState::Destroyed,
        ] {
            assert_eq!(VersionState::parse(state.as_str()).unwrap(), state);
        }
        assert!(VersionState::parse("purged").is_err());
    }
}
