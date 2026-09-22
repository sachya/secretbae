//! Domain types and entry representation for the audit log.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::AuditError;

/// Position in the audit log. Starts at 1 and increases strictly by 1 per committed entry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Seq(u64);

impl Seq {
    pub const FIRST: Self = Self(1);

    #[must_use]
    pub const fn new(seq: u64) -> Self {
        Self(seq)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Next expected sequence number in an unbroken chain.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seq({})", self.0)
    }
}

/// Seconds since Unix epoch recorded against an audit event.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    #[must_use]
    pub fn now() -> Self {
        Self(time::OffsetDateTime::now_utc().unix_timestamp())
    }

    #[must_use]
    pub const fn from_unix(seconds: i64) -> Self {
        Self(seconds)
    }

    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({})", self.0)
    }
}

/// Leading characters of the token presented by the client.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenPrefix(String);

impl TokenPrefix {
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self(prefix.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TokenPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for TokenPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenPrefix({:?})", self.0)
    }
}

impl From<&str> for TokenPrefix {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for TokenPrefix {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Operating system user ID of the client process from peer credentials.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerUid(u32);

impl PeerUid {
    #[must_use]
    pub const fn new(uid: u32) -> Self {
        Self(uid)
    }

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for PeerUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for PeerUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerUid({})", self.0)
    }
}

/// Operating system process ID of the client process from peer credentials.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerPid(u32);

impl PeerPid {
    #[must_use]
    pub const fn new(pid: u32) -> Self {
        Self(pid)
    }

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for PeerPid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for PeerPid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerPid({})", self.0)
    }
}

/// Contextual path referenced by the operation, accepting canonical or attempted paths.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditPath(String);

impl AuditPath {
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<sbae_proto::SecretPath> for AuditPath {
    fn from(path: sbae_proto::SecretPath) -> Self {
        Self(path.as_str().to_string())
    }
}

impl From<&sbae_proto::SecretPath> for AuditPath {
    fn from(path: &sbae_proto::SecretPath) -> Self {
        Self(path.as_str().to_string())
    }
}

impl From<&str> for AuditPath {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for AuditPath {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for AuditPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Contextual diagnostic detail recorded with the entry.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Detail(String);

impl Detail {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Detail({:?})", self.0)
    }
}

impl From<&str> for Detail {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for Detail {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Action performed by a caller or system component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Init,
    Unseal,
    Read,
    Write,
    Delete,
    Rollback,
    List,
    Tag,
    TokenCreate,
    TokenRevoke,
    PolicyWrite,
    Resolve,
    AuthFailure,
    Rekey,
    Backup,
    Restore,
}

impl Action {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Unseal => "unseal",
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Rollback => "rollback",
            Self::List => "list",
            Self::Tag => "tag",
            Self::TokenCreate => "token_create",
            Self::TokenRevoke => "token_revoke",
            Self::PolicyWrite => "policy_write",
            Self::Resolve => "resolve",
            Self::AuthFailure => "auth_failure",
            Self::Rekey => "rekey",
            Self::Backup => "backup",
            Self::Restore => "restore",
        }
    }

    /// Parses the stored representation into an [`Action`].
    pub fn parse(raw: &str) -> Result<Self, AuditError> {
        match raw {
            "init" => Ok(Self::Init),
            "unseal" => Ok(Self::Unseal),
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "delete" => Ok(Self::Delete),
            "rollback" => Ok(Self::Rollback),
            "list" => Ok(Self::List),
            "tag" => Ok(Self::Tag),
            "token_create" => Ok(Self::TokenCreate),
            "token_revoke" => Ok(Self::TokenRevoke),
            "policy_write" => Ok(Self::PolicyWrite),
            "resolve" => Ok(Self::Resolve),
            "auth_failure" => Ok(Self::AuthFailure),
            "rekey" => Ok(Self::Rekey),
            "backup" => Ok(Self::Backup),
            "restore" => Ok(Self::Restore),
            _ => Err(AuditError::UnknownAction(raw.to_string())),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of an audited operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Denied,
    NotFound,
    Error,
}

impl AuditResult {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::NotFound => "not_found",
            Self::Error => "error",
        }
    }

    /// Parses the stored representation into an [`AuditResult`].
    pub fn parse(raw: &str) -> Result<Self, AuditError> {
        match raw {
            "success" => Ok(Self::Success),
            "denied" => Ok(Self::Denied),
            "not_found" => Ok(Self::NotFound),
            "error" => Ok(Self::Error),
            _ => Err(AuditError::UnknownResult(raw.to_string())),
        }
    }
}

impl fmt::Display for AuditResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An uncommitted event to be appended to the audit log.
///
/// Plaintext secrets must never be passed to or stored in audit records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub ts: Timestamp,
    pub token_prefix: Option<TokenPrefix>,
    pub peer_uid: Option<PeerUid>,
    pub peer_pid: Option<PeerPid>,
    pub action: Action,
    pub path: Option<AuditPath>,
    pub version: Option<sbae_proto::Version>,
    pub result: AuditResult,
    pub detail: Option<Detail>,
}

impl AuditEntry {
    #[must_use]
    pub fn new(action: Action, result: AuditResult) -> Self {
        Self {
            ts: Timestamp::now(),
            token_prefix: None,
            peer_uid: None,
            peer_pid: None,
            action,
            path: None,
            version: None,
            result,
            detail: None,
        }
    }

    #[must_use]
    pub const fn with_ts(mut self, ts: Timestamp) -> Self {
        self.ts = ts;
        self
    }

    #[must_use]
    pub fn with_token_prefix(mut self, prefix: impl Into<TokenPrefix>) -> Self {
        self.token_prefix = Some(prefix.into());
        self
    }

    #[must_use]
    pub const fn with_peer_uid(mut self, uid: PeerUid) -> Self {
        self.peer_uid = Some(uid);
        self
    }

    #[must_use]
    pub const fn with_peer_pid(mut self, pid: PeerPid) -> Self {
        self.peer_pid = Some(pid);
        self
    }

    #[must_use]
    pub fn with_path(mut self, path: impl Into<AuditPath>) -> Self {
        self.path = Some(path.into());
        self
    }

    #[must_use]
    pub const fn with_version(mut self, version: sbae_proto::Version) -> Self {
        self.version = Some(version);
        self
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<Detail>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}
