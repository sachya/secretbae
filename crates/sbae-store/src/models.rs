//! Values returned by, and passed to, the store.

use sbae_core::{SealedVersion, VersionBinding};
use sbae_proto::{SecretPath, Tag, Version, VersionState};
use time::OffsetDateTime;

/// A secret and its tags, without any version payload.
#[derive(Clone, Debug)]
pub struct SecretSummary {
    pub path: SecretPath,
    pub current_version: Option<Version>,
    /// Versions that still hold ciphertext. Destroyed versions are tombstones kept only so
    /// their numbers are never reused, so counting them would overstate what is recoverable.
    pub version_count: u64,
    pub tags: Vec<Tag>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Metadata for one version. Deliberately carries no ciphertext, so it is safe to return
/// to a caller holding only the `list` capability.
#[derive(Clone, Debug)]
pub struct VersionInfo {
    pub version: Version,
    pub state: VersionState,
    pub created_at: OffsetDateTime,
    pub created_by: Option<String>,
    pub comment: Option<String>,
}

/// A version's ciphertext together with the binding needed to open it.
pub struct StoredVersion {
    pub binding: VersionBinding,
    pub sealed: SealedVersion,
    pub info: VersionInfo,
}

/// Provenance recorded against a new version.
#[derive(Clone, Debug, Default)]
pub struct WriteMeta {
    pub created_by: Option<String>,
    pub comment: Option<String>,
}

/// Which version of a secret an operation refers to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VersionSelector {
    /// Whatever `current_version` points at, which a rollback may have moved backwards.
    #[default]
    Current,
    Exact(Version),
}

/// How thoroughly to remove a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteMode {
    /// Hide the version but keep its ciphertext, so the deletion is reversible.
    Soft,
    /// Discard the ciphertext irreversibly.
    Destroy,
}

/// Criteria for `list`. An empty filter matches every secret.
#[derive(Clone, Debug, Default)]
pub struct ListFilter {
    /// Matched on segment boundaries, so `prod/billing` never matches `prod/billing-admin`.
    pub prefix: Option<String>,
    /// A secret must carry *every* listed tag to match.
    pub tags: Vec<Tag>,
    /// Include secrets whose versions have all been deleted.
    pub include_empty: bool,
}

/// One secret and its retained versions, as carried in a backup bundle.
///
/// Version numbers, states and provenance are preserved rather than renumbered, so a restore
/// reproduces the history an operator would see in `versions`, not a flattened copy of it.
pub struct ExportedSecret {
    pub path: SecretPath,
    pub tags: Vec<Tag>,
    pub max_versions: u32,
    pub current_version: Option<Version>,
    pub versions: Vec<ExportedVersion>,
}

pub struct ExportedVersion {
    pub version: Version,
    pub state: VersionState,
    pub created_at: OffsetDateTime,
    pub created_by: Option<String>,
    pub comment: Option<String>,
    /// Absent for destroyed versions, whose ciphertext is gone by definition.
    pub sealed: Option<SealedVersion>,
}
