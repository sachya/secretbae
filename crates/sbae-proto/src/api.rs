//! The daemon's wire contract.
//!
//! JSON over HTTP/1.1 on a Unix socket. HTTP because every language already has a client
//! that speaks it over a socket path, which removes any need to ship SDKs.
//!
//! Every operation is a `POST` carrying a JSON body, including reads. Secret paths therefore
//! never appear in a request line, where they would end up in access logs and process
//! listings; the body is the only place they travel.

use serde::{Deserialize, Serialize};

use crate::{Capability, SecretPath, Tag, TagSelector, Version, VersionState};

/// Header carrying the caller's token, as `Bearer <token>`.
pub const AUTH_HEADER: &str = "authorization";
pub const BEARER_PREFIX: &str = "Bearer ";

/// Default socket path. Overridable in the daemon's configuration.
pub const DEFAULT_SOCKET_PATH: &str = "/run/secretbae/sock";

/// Default path for the plain-text resolve socket. Overridable in the daemon's configuration.
pub const DEFAULT_RESOLVE_SOCKET_PATH: &str = "/run/secretbae/resolve.sock";

/// The one verb the resolve socket understands.
pub const RESOLVE_SOCKET_VERB: &str = "RESOLVE";

/// Bumped if the framing ever needs to change; a client and daemon that disagree fail closed
/// with the same "not found or not permitted" message as any other denial.
pub const RESOLVE_SOCKET_VERSION: u32 = 1;

/// A request line, or a single path line, longer than this is refused before it is read in
/// full. Bounds how much a single connection can make the daemon buffer.
pub const RESOLVE_SOCKET_MAX_LINE_BYTES: usize = 4096;

/// A batch larger than this is refused outright. `secretbae exec` profiles are a handful of
/// entries; this is generous headroom without being unbounded.
pub const RESOLVE_SOCKET_MAX_PATHS: usize = 256;

/// The bootstrap policy `init` binds to a uid-0 token: every capability, including admin.
pub const BUILTIN_ROOT_POLICY: &str = "root";

/// A policy seeded on every startup, not just `init`, so a store upgraded from an older
/// version gains it too. Grants read, write, delete and list on every path -- deliberately
/// excluding `admin`, so a token attached to it can never create or revoke other tokens or
/// change policy, however much of the secret data it can see.
///
/// Exists so a first token can be minted without writing a policy document: `secretbae token
/// create --unrestricted` attaches this by name. It still goes through the same token
/// issuance, uid binding and revocation as any other token -- there is no way to read a
/// secret that does not require holding one.
pub const BUILTIN_UNRESTRICTED_POLICY: &str = "unrestricted";

pub mod route {
    pub const STATUS: &str = "/v1/status";
    pub const READ: &str = "/v1/secrets/read";
    pub const WRITE: &str = "/v1/secrets/write";
    pub const LIST: &str = "/v1/secrets/list";
    pub const VERSIONS: &str = "/v1/secrets/versions";
    pub const ROLLBACK: &str = "/v1/secrets/rollback";
    pub const DELETE: &str = "/v1/secrets/delete";
    pub const TAG_ADD: &str = "/v1/tags/add";
    pub const TAG_REMOVE: &str = "/v1/tags/remove";
    /// The batched fetch `secretbae exec` makes once at service start.
    pub const RESOLVE: &str = "/v1/resolve";
    pub const TOKEN_CREATE: &str = "/v1/tokens/create";
    pub const TOKEN_LIST: &str = "/v1/tokens/list";
    pub const TOKEN_REVOKE: &str = "/v1/tokens/revoke";
    pub const POLICY_PUT: &str = "/v1/policies/put";
    pub const POLICY_LIST: &str = "/v1/policies/list";
    pub const POLICY_DELETE: &str = "/v1/policies/delete";
    pub const AUDIT_VERIFY: &str = "/v1/audit/verify";
    pub const REKEY: &str = "/v1/rekey";
    pub const BACKUP: &str = "/v1/backup";
    pub const RESTORE: &str = "/v1/restore";
}

/// Secret values are base64 so that binary payloads (keys, certificates) survive JSON intact.
pub type Base64 = String;

/// The single error shape the daemon returns.
///
/// Messages are deliberately coarse. "not found or not permitted" covers a missing path, a
/// deleted version and a denied request alike, so a caller cannot map out what exists.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    pub version: String,
    pub schema_version: u32,
    pub sealed: bool,
    pub seal_kind: String,
    pub mk_generation: u32,
    pub secret_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub path: SecretPath,
    /// Absent means the current version, which a rollback may have moved backwards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadResponse {
    pub path: SecretPath,
    pub version: Version,
    pub value: Base64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteRequest {
    pub path: SecretPath,
    pub value: Base64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteResponse {
    pub path: SecretPath,
    pub version: Version,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// A secret must carry every listed tag to match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSummaryDto {
    pub path: SecretPath,
    pub current_version: Option<Version>,
    /// Versions still holding ciphertext; destroyed tombstones are not counted.
    pub version_count: u64,
    pub tags: Vec<Tag>,
    /// RFC 3339.
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListResponse {
    pub secrets: Vec<SecretSummaryDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRequest {
    pub path: SecretPath,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionInfoDto {
    pub version: Version,
    pub state: VersionState,
    pub created_at: String,
    pub created_by: Option<String>,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionsResponse {
    pub path: SecretPath,
    pub versions: Vec<VersionInfoDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    pub path: SecretPath,
    pub to: Version,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteRequest {
    pub path: SecretPath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
    /// Discard the ciphertext irreversibly rather than soft-deleting.
    #[serde(default)]
    pub destroy: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagRequest {
    pub path: SecretPath,
    pub tags: Vec<Tag>,
}

/// Removal takes selectors rather than tags, so a bare key can name every value under it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagRemoveRequest {
    pub path: SecretPath,
    pub tags: Vec<TagSelector>,
}

/// The batched fetch performed once per service start.
///
/// One request for the whole profile rather than one per secret, so a restart costs a single
/// round trip and produces a single coherent audit event.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub paths: Vec<SecretPath>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSecret {
    pub path: SecretPath,
    pub version: Version,
    pub value: Base64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveResponse {
    pub secrets: Vec<ResolvedSecret>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenCreateRequest {
    pub name: String,
    pub policies: Vec<String>,
    /// Bind the token to a local user, so it is inert for any other uid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_uid: Option<u32>,
    /// Lifetime in seconds. Absent means it never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// The only time the token itself is ever transmitted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenCreateResponse {
    pub token: String,
    pub prefix: String,
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSummaryDto {
    pub prefix: String,
    pub name: String,
    pub policies: Vec<String>,
    pub bound_uid: Option<u32>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked: bool,
    pub last_used_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenListResponse {
    pub tokens: Vec<TokenSummaryDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRevokeRequest {
    pub prefix: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPutRequest {
    /// A policy document as defined by `sbae-policy`.
    pub document: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyListResponse {
    pub policies: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameRequest {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditVerifyResponse {
    pub entries: u64,
    /// `None` when the chain is intact.
    pub broken_at: Option<i64>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RekeyResponse {
    pub versions_rewrapped: u64,
    pub audit_entries_rekeyed: u64,
    pub generation: u32,
}

/// The passphrase travels over the local socket, the same channel that already carries
/// tokens. The resulting bundle crosses back already encrypted, so plaintext never leaves the
/// daemon in either direction.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRequest {
    pub passphrase: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupResponse {
    pub bundle: Base64,
    pub secrets: u64,
    pub versions: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub passphrase: String,
    pub bundle: Base64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreResponse {
    pub secrets: u64,
    pub versions: u64,
    pub policies: u64,
}

/// The decrypted contents of a backup bundle.
///
/// Tokens are deliberately excluded. They are bound to the uids of the machine that issued
/// them and only their hashes are stored, so restoring them elsewhere would produce
/// credentials nobody holds; a restore is expected to mint fresh ones. The audit chain is
/// likewise excluded -- it is keyed to the master key of the machine that wrote it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupBundle {
    pub created_at: String,
    pub secrets: Vec<BackupSecret>,
    pub policies: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSecret {
    pub path: SecretPath,
    pub tags: Vec<Tag>,
    pub max_versions: u32,
    pub current_version: Option<Version>,
    pub versions: Vec<BackupVersion>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVersion {
    pub version: Version,
    pub state: VersionState,
    pub created_at: String,
    pub created_by: Option<String>,
    pub comment: Option<String>,
    /// Absent for destroyed versions, whose ciphertext is gone by definition.
    pub value: Option<Base64>,
}

/// Acknowledgement for operations with nothing to return.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub ok: bool,
}

impl Ack {
    #[must_use]
    pub fn ok() -> Self {
        Self { ok: true }
    }
}

/// The capability each route requires. Kept beside the route constants so that adding an
/// endpoint without deciding its capability is a compile error rather than an open door.
#[must_use]
pub fn required_capability(route: &str) -> Option<Capability> {
    Some(match route {
        route::READ | route::RESOLVE => Capability::Read,
        route::WRITE | route::TAG_ADD | route::TAG_REMOVE => Capability::Write,
        route::DELETE | route::ROLLBACK => Capability::Delete,
        route::LIST | route::VERSIONS | route::STATUS => Capability::List,
        route::TOKEN_CREATE
        | route::TOKEN_LIST
        | route::TOKEN_REVOKE
        | route::POLICY_PUT
        | route::POLICY_LIST
        | route::POLICY_DELETE
        | route::AUDIT_VERIFY
        | route::REKEY
        | route::BACKUP
        | route::RESTORE => Capability::Admin,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_declares_a_required_capability() {
        for route in [
            route::STATUS,
            route::READ,
            route::WRITE,
            route::LIST,
            route::VERSIONS,
            route::ROLLBACK,
            route::DELETE,
            route::TAG_ADD,
            route::TAG_REMOVE,
            route::RESOLVE,
            route::TOKEN_CREATE,
            route::TOKEN_LIST,
            route::TOKEN_REVOKE,
            route::POLICY_PUT,
            route::POLICY_LIST,
            route::POLICY_DELETE,
            route::AUDIT_VERIFY,
            route::REKEY,
            route::BACKUP,
            route::RESTORE,
        ] {
            assert!(
                required_capability(route).is_some(),
                "{route} has no capability"
            );
        }
    }

    #[test]
    fn an_unknown_route_grants_nothing() {
        assert_eq!(required_capability("/v1/anything-else"), None);
        assert_eq!(required_capability("/"), None);
    }

    /// Token and policy management must never be reachable with an application capability.
    #[test]
    fn management_routes_require_admin() {
        for route in [
            route::TOKEN_CREATE,
            route::TOKEN_REVOKE,
            route::POLICY_PUT,
            route::POLICY_DELETE,
            route::AUDIT_VERIFY,
            route::REKEY,
            route::BACKUP,
            route::RESTORE,
        ] {
            assert_eq!(
                required_capability(route),
                Some(Capability::Admin),
                "{route}"
            );
        }
    }

    #[test]
    fn requests_reject_unknown_fields() {
        assert!(serde_json::from_str::<ReadRequest>(r#"{"path":"prod/db"}"#).is_ok());
        assert!(serde_json::from_str::<ReadRequest>(r#"{"path":"prod/db","verison":2}"#).is_err());
        assert!(serde_json::from_str::<ReadRequest>(r#"{"path":"../escape"}"#).is_err());
    }
}
