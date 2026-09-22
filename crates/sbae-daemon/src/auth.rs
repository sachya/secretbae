//! The three gates every request passes.
//!
//! 1. A syntactically valid, unexpired, unrevoked token.
//! 2. `SO_PEERCRED`: if the token is bound to a uid, the connecting process must present it.
//! 3. A policy attached to that token granting the route's capability on the target path.
//!
//! Failures are recorded in the audit log with the specific reason, but the caller is only
//! ever told "not found or not permitted" -- distinguishing "no such token" from "wrong uid"
//! from "no such path" would turn every rejection into an oracle.

use sbae_audit::{Action, AuditEntry, AuditResult};
use sbae_policy::{
    authenticate, evaluate, AccessRequest, AuthFailure, LookupPrefix, PeerCredentials,
    PresentedToken, TokenId,
};
use sbae_proto::{api, Capability, SecretPath, Tag};
use time::OffsetDateTime;

use crate::{DaemonError, Result, SharedState};

/// A caller that cleared all three gates.
pub struct Authenticated {
    pub token_id: TokenId,
    pub prefix: LookupPrefix,
    pub peer: PeerCredentials,
}

/// Every way a request can be turned away. Kept internal to the daemon.
#[derive(Debug)]
pub enum Denied {
    MissingToken,
    MalformedToken,
    Authentication(AuthFailure),
    NoGrant,
    UnknownRoute,
}

impl Denied {
    /// The detail written to the audit log. Never sent to the caller.
    fn audit_detail(&self) -> &'static str {
        match self {
            Self::MissingToken => "no token presented",
            Self::MalformedToken => "malformed token",
            Self::Authentication(AuthFailure::UnknownToken) => "unknown token or wrong secret",
            Self::Authentication(AuthFailure::Expired) => "token expired",
            Self::Authentication(AuthFailure::Revoked) => "token revoked",
            Self::Authentication(AuthFailure::PeerMismatch { .. }) => {
                "token is bound to a different uid"
            }
            Self::NoGrant => "no policy grants this capability on this path",
            Self::UnknownRoute => "unknown route",
        }
    }
}

/// Pull the bearer token out of the request headers.
pub fn extract_token(headers: &http::HeaderMap) -> core::result::Result<PresentedToken, Denied> {
    let raw = headers
        .get(api::AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(Denied::MissingToken)?;

    let token = raw.strip_prefix(api::BEARER_PREFIX).ok_or(Denied::MalformedToken)?;
    PresentedToken::parse(token).map_err(|_| Denied::MalformedToken)
}

/// What the caller is asking to do, resolved before authorization so that the policy engine
/// sees the same path and tags the store would act on.
pub struct Requested<'a> {
    pub route: &'a str,
    pub path: Option<&'a SecretPath>,
}

/// Run all three gates, writing an audit entry either way.
pub fn authorize(
    state: &SharedState,
    headers: &http::HeaderMap,
    peer: PeerCredentials,
    requested: &Requested<'_>,
) -> core::result::Result<Authenticated, Denied> {
    let outcome = check(state, headers, peer, requested);

    match &outcome {
        Ok(authenticated) => {
            // Best effort: failing to record last-used must not fail the caller's request.
            let _ = state.store().touch_token(authenticated.token_id);
        }
        Err(denied) => record_denial(state, peer, requested, denied),
    }

    outcome
}

fn check(
    state: &SharedState,
    headers: &http::HeaderMap,
    peer: PeerCredentials,
    requested: &Requested<'_>,
) -> core::result::Result<Authenticated, Denied> {
    let capability = api::required_capability(requested.route).ok_or(Denied::UnknownRoute)?;
    let presented = extract_token(headers)?;

    let store = state.store();
    let record = store
        .token_by_prefix(presented.prefix())
        .map_err(|_| Denied::Authentication(AuthFailure::UnknownToken))?
        .ok_or(Denied::Authentication(AuthFailure::UnknownToken))?;

    let token_id = authenticate(&record, &presented, peer, OffsetDateTime::now_utc())
        .map_err(Denied::Authentication)?;

    let policies = store.policies_for_token(token_id).map_err(|_| Denied::NoGrant)?;

    // Tags are read from the store rather than taken from the request, so a caller cannot
    // satisfy a `require_tags` rule by claiming a tag the secret does not carry.
    let tags: Vec<Tag> = requested
        .path
        .map(|path| store.tags(path).unwrap_or_default())
        .unwrap_or_default();

    let granted = requested.path.map_or_else(
        || grants_without_path(&policies, capability),
        |path| evaluate(&policies, &AccessRequest { path, capability, tags: &tags }).is_allowed(),
    );

    drop(store);

    if granted {
        Ok(Authenticated { token_id, prefix: record.prefix, peer })
    } else {
        Err(Denied::NoGrant)
    }
}

/// Routes with no single target path -- `list`, `status`, token and policy management.
///
/// A grant counts if any rule carries the capability at all. `list` still filters its results
/// per path afterwards, so this decides only whether the caller may ask the question.
fn grants_without_path(policies: &[sbae_policy::Policy], capability: Capability) -> bool {
    policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .any(|rule| rule.capabilities.contains(&capability))
}

fn record_denial(
    state: &SharedState,
    peer: PeerCredentials,
    requested: &Requested<'_>,
    denied: &Denied,
) {
    let mut entry = AuditEntry::new(Action::AuthFailure, AuditResult::Denied)
        .with_peer_uid(sbae_audit::PeerUid::new(peer.uid))
        .with_peer_pid(sbae_audit::PeerPid::new(peer.pid.unsigned_abs()))
        .with_detail(denied.audit_detail());

    if let Some(path) = requested.path {
        entry = entry.with_path(path.clone());
    }

    let keys = state.keys();
    let mut store = state.store();
    let _ = sbae_audit::append(store.connection_mut(), &keys.audit_key, &entry);
}

/// The single error a rejected caller ever sees.
pub const DENIED_MESSAGE: &str = "not found or not permitted";

impl From<Denied> for DaemonError {
    fn from(_: Denied) -> Self {
        Self::Config(DENIED_MESSAGE.to_owned())
    }
}

/// Record a successful, audited operation.
pub fn record(
    state: &SharedState,
    authenticated: &Authenticated,
    action: Action,
    result: AuditResult,
    path: Option<&SecretPath>,
    version: Option<sbae_proto::Version>,
) -> Result<()> {
    let mut entry = AuditEntry::new(action, result)
        .with_token_prefix(authenticated.prefix.as_str())
        .with_peer_uid(sbae_audit::PeerUid::new(authenticated.peer.uid))
        .with_peer_pid(sbae_audit::PeerPid::new(authenticated.peer.pid.unsigned_abs()));

    if let Some(path) = path {
        entry = entry.with_path(path.clone());
    }
    if let Some(version) = version {
        entry = entry.with_version(version);
    }

    let keys = state.keys();
    let mut store = state.store();
    sbae_audit::append(store.connection_mut(), &keys.audit_key, &entry)?;
    Ok(())
}
