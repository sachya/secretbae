//! Request handlers.
//!
//! Every handler follows the same shape: authorize, act, audit. Failures collapse to one
//! opaque message so that a caller cannot learn which paths exist by probing.

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use data_encoding::BASE64;
use sbae_audit::{Action, AuditResult};
use sbae_core::SealedVersion;
use sbae_policy::{issue, PeerCredentials, PresentedToken};
use sbae_proto::api::{self, route};
use sbae_proto::SecretPath;
use sbae_store::{DeleteMode, ListFilter, NewToken, VersionSelector, WriteMeta};
use time::{Duration, OffsetDateTime};

use crate::auth::{
    authorize, extract_token, record, Authenticated, Denied, Requested, DENIED_MESSAGE,
};
use crate::server::PeerInfo;
use crate::SharedState;

/// The only failure a caller ever sees.
pub struct ApiError(pub(crate) StatusCode, pub(crate) String);

impl ApiError {
    pub(crate) fn denied() -> Self {
        Self(StatusCode::FORBIDDEN, DENIED_MESSAGE.to_owned())
    }

    pub(crate) fn bad_request(message: &str) -> Self {
        Self(StatusCode::BAD_REQUEST, message.to_owned())
    }

    pub(crate) fn internal() -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error".to_owned(),
        )
    }
}

impl From<Denied> for ApiError {
    fn from(_: Denied) -> Self {
        Self::denied()
    }
}

/// Store failures collapse to the same message as an authorization failure, so a caller
/// cannot tell "this path does not exist" from "you may not read it".
impl From<sbae_store::StoreError> for ApiError {
    fn from(source: sbae_store::StoreError) -> Self {
        if source.is_client_error() {
            Self::denied()
        } else {
            Self::internal()
        }
    }
}

impl From<crate::DaemonError> for ApiError {
    fn from(_: crate::DaemonError) -> Self {
        Self::internal()
    }
}

impl From<sbae_core::Error> for ApiError {
    fn from(_: sbae_core::Error) -> Self {
        Self::internal()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(api::ErrorResponse { error: self.1 })).into_response()
    }
}

pub(crate) type ApiResult<T> = core::result::Result<Json<T>, ApiError>;

/// One secret to fetch: current version, or a specific one pinned by the caller.
pub(crate) struct ResolveTarget {
    pub path: SecretPath,
    pub version: Option<sbae_proto::Version>,
}

/// A resolved secret with its plaintext still in the zeroizing wrapper it was decrypted into,
/// so each transport can encode it however it needs (base64 for JSON, raw bytes on the wire)
/// without an extra unzeroized copy in between.
pub(crate) struct ResolvedSecret {
    pub path: SecretPath,
    pub version: sbae_proto::Version,
    pub plaintext: sbae_core::SecretBytes,
}

/// Every way [`resolve_secrets`] can fail, kept distinct from [`ApiError`] so each transport
/// maps denial-shaped failures and internal ones the same way `ApiError`'s own `From` impls
/// already do, rather than collapsing through `DaemonError` and losing that distinction.
pub(crate) enum ResolveFailure {
    Denied(Denied),
    Store(sbae_store::StoreError),
    Crypto,
    Audit(crate::DaemonError),
}

impl From<Denied> for ResolveFailure {
    fn from(source: Denied) -> Self {
        Self::Denied(source)
    }
}

impl From<sbae_store::StoreError> for ResolveFailure {
    fn from(source: sbae_store::StoreError) -> Self {
        Self::Store(source)
    }
}

impl From<sbae_core::Error> for ResolveFailure {
    fn from(_: sbae_core::Error) -> Self {
        Self::Crypto
    }
}

impl From<crate::DaemonError> for ResolveFailure {
    fn from(source: crate::DaemonError) -> Self {
        Self::Audit(source)
    }
}

impl From<ResolveFailure> for ApiError {
    fn from(source: ResolveFailure) -> Self {
        match source {
            ResolveFailure::Denied(denied) => denied.into(),
            ResolveFailure::Store(source) => source.into(),
            ResolveFailure::Crypto => Self::internal(),
            ResolveFailure::Audit(source) => source.into(),
        }
    }
}

impl ResolveFailure {
    /// The message a non-HTTP transport can send verbatim, kept in step with [`ApiError`]'s own
    /// denied-vs-internal split above rather than duplicating it.
    #[must_use]
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::Denied(_) => DENIED_MESSAGE,
            Self::Store(source) if source.is_client_error() => DENIED_MESSAGE,
            Self::Store(_) | Self::Crypto | Self::Audit(_) => "internal error",
        }
    }
}

/// Shared by the HTTP `/v1/resolve` route and the plain resolve socket.
///
/// All-or-nothing: a path the caller may not read fails the whole batch rather than returning a
/// short result the caller then fails on later (see the HTTP handler below). Gates once,
/// unconditionally, before looking at any path -- an empty batch must still require and audit a
/// valid token exactly like a non-empty one, which an earlier version of the HTTP handler did
/// not do (a request with no paths skipped its own gate entirely).
pub(crate) fn resolve_secrets<F>(
    state: &SharedState,
    peer: PeerCredentials,
    targets: &[ResolveTarget],
    mut present: F,
) -> core::result::Result<Vec<ResolvedSecret>, ResolveFailure>
where
    F: FnMut() -> core::result::Result<PresentedToken, Denied>,
{
    let caller = authorize(
        state,
        present(),
        peer,
        &Requested {
            route: route::RESOLVE,
            path: None,
        },
    )?;

    let mut resolved = Vec::with_capacity(targets.len());
    for target in targets {
        // Re-authorized per path: the token is unchanged, but `require_tags` grants are
        // evaluated against each path's own tags, exactly like every other path-scoped route.
        authorize(
            state,
            present(),
            peer,
            &Requested {
                route: route::RESOLVE,
                path: Some(&target.path),
            },
        )?;

        let selector = target
            .version
            .map_or(VersionSelector::Current, VersionSelector::Exact);

        let keys = state.keys();
        let store = state.store();
        let stored = store.read_version(&target.path, selector)?;
        let plaintext = stored.sealed.open(&keys.master, stored.binding)?;
        drop(store);

        resolved.push(ResolvedSecret {
            path: target.path.clone(),
            version: stored.info.version,
            plaintext,
        });
    }

    // One audit entry for the whole batch: this is a service start, not N unrelated reads.
    record(
        state,
        &caller,
        Action::Resolve,
        AuditResult::Success,
        None,
        None,
    )?;

    Ok(resolved)
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route(route::STATUS, post(status))
        .route(route::READ, post(read))
        .route(route::WRITE, post(write))
        .route(route::LIST, post(list))
        .route(route::VERSIONS, post(versions))
        .route(route::ROLLBACK, post(rollback))
        .route(route::DELETE, post(delete))
        .route(route::TAG_ADD, post(tag_add))
        .route(route::TAG_REMOVE, post(tag_remove))
        .route(route::RESOLVE, post(resolve))
        .route(route::TOKEN_CREATE, post(token_create))
        .route(route::TOKEN_LIST, post(token_list))
        .route(route::TOKEN_REVOKE, post(token_revoke))
        .route(route::POLICY_PUT, post(policy_put))
        .route(route::POLICY_LIST, post(policy_list))
        .route(route::POLICY_DELETE, post(policy_delete))
        .route(route::AUDIT_VERIFY, post(audit_verify))
        .route(route::REKEY, post(crate::maintenance::rekey))
        .route(route::BACKUP, post(crate::maintenance::backup))
        .route(route::RESTORE, post(crate::maintenance::restore))
        .fallback(not_found)
        .with_state(state)
}

pub(crate) fn gate(
    state: &SharedState,
    headers: &HeaderMap,
    peer: PeerCredentials,
    route: &str,
    path: Option<&SecretPath>,
) -> core::result::Result<Authenticated, ApiError> {
    Ok(authorize(
        state,
        extract_token(headers),
        peer,
        &Requested { route, path },
    )?)
}

pub(crate) fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

async fn status(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
) -> ApiResult<api::StatusResponse> {
    gate(&state, &headers, peer.credentials(), route::STATUS, None)?;

    let store = state.store();
    Ok(Json(api::StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        schema_version: store.schema_version(),
        sealed: false,
        seal_kind: "keyfile".to_owned(),
        mk_generation: state.keys().generation,
        secret_count: store.secret_count()?,
    }))
}

async fn read(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::ReadRequest>,
) -> ApiResult<api::ReadResponse> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::READ,
        Some(&request.path),
    )?;
    let selector = request
        .version
        .map_or(VersionSelector::Current, VersionSelector::Exact);

    let value = {
        let keys = state.keys();
        let store = state.store();
        let stored = store.read_version(&request.path, selector)?;
        let plaintext = stored.sealed.open(&keys.master, stored.binding)?;
        (BASE64.encode(plaintext.expose()), stored.info.version)
    };

    record(
        &state,
        &caller,
        Action::Read,
        AuditResult::Success,
        Some(&request.path),
        Some(value.1),
    )?;

    Ok(Json(api::ReadResponse {
        path: request.path,
        version: value.1,
        value: value.0,
    }))
}

async fn write(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::WriteRequest>,
) -> ApiResult<api::WriteResponse> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::WRITE,
        Some(&request.path),
    )?;

    let plaintext = BASE64
        .decode(request.value.as_bytes())
        .map_err(|_| ApiError::bad_request("value must be base64"))?;

    let version = {
        let keys = state.keys();
        let mut store = state.store();
        let slot = store.begin_write(&request.path)?;
        let sealed =
            SealedVersion::seal(&keys.master, keys.generation, slot.binding(), &plaintext)?;
        let meta = WriteMeta {
            created_by: Some(caller.prefix.as_str().to_owned()),
            comment: request.comment,
        };
        let version = slot.commit(&sealed, &meta)?;

        if !request.tags.is_empty() {
            store.add_tags(&request.path, &request.tags)?;
        }
        version
    };

    record(
        &state,
        &caller,
        Action::Write,
        AuditResult::Success,
        Some(&request.path),
        Some(version),
    )?;
    Ok(Json(api::WriteResponse {
        path: request.path,
        version,
    }))
}

async fn list(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::ListRequest>,
) -> ApiResult<api::ListResponse> {
    let caller = gate(&state, &headers, peer.credentials(), route::LIST, None)?;

    let summaries = state.store().list(&ListFilter {
        prefix: request.prefix,
        tags: request.tags,
        include_empty: false,
    })?;

    // The blanket `list` grant only permits asking the question; each path is still filtered
    // against the caller's policies so a listing cannot reveal paths they may not see.
    let visible = filter_visible(&state, &caller, summaries);

    record(
        &state,
        &caller,
        Action::List,
        AuditResult::Success,
        None,
        None,
    )?;
    Ok(Json(api::ListResponse { secrets: visible }))
}

fn filter_visible(
    state: &SharedState,
    caller: &Authenticated,
    summaries: Vec<sbae_store::SecretSummary>,
) -> Vec<api::SecretSummaryDto> {
    let store = state.store();
    let Ok(policies) = store.policies_for_token(caller.token_id) else {
        return Vec::new();
    };
    drop(store);

    summaries
        .into_iter()
        .filter(|summary| {
            sbae_policy::evaluate(
                &policies,
                &sbae_policy::AccessRequest {
                    path: &summary.path,
                    capability: sbae_proto::Capability::List,
                    tags: &summary.tags,
                },
            )
            .is_allowed()
        })
        .map(|summary| api::SecretSummaryDto {
            path: summary.path,
            current_version: summary.current_version,
            version_count: summary.version_count,
            tags: summary.tags,
            updated_at: rfc3339(summary.updated_at),
        })
        .collect()
}

async fn versions(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::PathRequest>,
) -> ApiResult<api::VersionsResponse> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::VERSIONS,
        Some(&request.path),
    )?;
    let listed = state.store().versions(&request.path)?;

    record(
        &state,
        &caller,
        Action::List,
        AuditResult::Success,
        Some(&request.path),
        None,
    )?;

    Ok(Json(api::VersionsResponse {
        path: request.path,
        versions: listed
            .into_iter()
            .map(|info| api::VersionInfoDto {
                version: info.version,
                state: info.state,
                created_at: rfc3339(info.created_at),
                created_by: info.created_by,
                comment: info.comment,
            })
            .collect(),
    }))
}

async fn rollback(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::RollbackRequest>,
) -> ApiResult<api::Ack> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::ROLLBACK,
        Some(&request.path),
    )?;
    state.store().rollback(&request.path, request.to)?;

    record(
        &state,
        &caller,
        Action::Rollback,
        AuditResult::Success,
        Some(&request.path),
        Some(request.to),
    )?;
    Ok(Json(api::Ack::ok()))
}

async fn delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::DeleteRequest>,
) -> ApiResult<api::Ack> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::DELETE,
        Some(&request.path),
    )?;
    let selector = request
        .version
        .map_or(VersionSelector::Current, VersionSelector::Exact);
    let mode = if request.destroy {
        DeleteMode::Destroy
    } else {
        DeleteMode::Soft
    };

    let removed = state
        .store()
        .delete_version(&request.path, selector, mode)?;

    record(
        &state,
        &caller,
        Action::Delete,
        AuditResult::Success,
        Some(&request.path),
        Some(removed),
    )?;
    Ok(Json(api::Ack::ok()))
}

async fn tag_add(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::TagRequest>,
) -> ApiResult<api::Ack> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::TAG_ADD,
        Some(&request.path),
    )?;
    state.store().add_tags(&request.path, &request.tags)?;

    record(
        &state,
        &caller,
        Action::Tag,
        AuditResult::Success,
        Some(&request.path),
        None,
    )?;
    Ok(Json(api::Ack::ok()))
}

async fn tag_remove(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::TagRemoveRequest>,
) -> ApiResult<api::Ack> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::TAG_REMOVE,
        Some(&request.path),
    )?;
    state.store().remove_tags(&request.path, &request.tags)?;

    record(
        &state,
        &caller,
        Action::Tag,
        AuditResult::Success,
        Some(&request.path),
        None,
    )?;
    Ok(Json(api::Ack::ok()))
}

/// The batched fetch `secretbae exec` makes once per service start.
///
/// Authorized per path, so a profile listing a path the token cannot read is refused outright
/// rather than silently returning a short environment the application then fails on.
async fn resolve(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::ResolveRequest>,
) -> ApiResult<api::ResolveResponse> {
    let targets: Vec<ResolveTarget> = request
        .paths
        .into_iter()
        .map(|path| ResolveTarget {
            path,
            version: None,
        })
        .collect();

    let resolved = resolve_secrets(&state, peer.credentials(), &targets, || {
        extract_token(&headers)
    })?;

    Ok(Json(api::ResolveResponse {
        secrets: resolved
            .into_iter()
            .map(|item| api::ResolvedSecret {
                path: item.path,
                version: item.version,
                value: BASE64.encode(item.plaintext.expose()),
            })
            .collect(),
    }))
}

async fn token_create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::TokenCreateRequest>,
) -> ApiResult<api::TokenCreateResponse> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::TOKEN_CREATE,
        None,
    )?;

    let issued = issue().map_err(|_| ApiError::internal())?;
    let expires_at = request
        .ttl_seconds
        .and_then(|seconds| i64::try_from(seconds).ok())
        .map(|seconds| OffsetDateTime::now_utc() + Duration::seconds(seconds));

    state.store().create_token(&NewToken {
        id: issued.id,
        prefix: &issued.prefix,
        hash: &issued.hash,
        name: &request.name,
        bound_uid: request.bind_uid,
        expires_at,
        policies: &request.policies,
    })?;

    record(
        &state,
        &caller,
        Action::TokenCreate,
        AuditResult::Success,
        None,
        None,
    )?;

    Ok(Json(api::TokenCreateResponse {
        token: issued.secret.expose().to_owned(),
        prefix: issued.prefix.as_str().to_owned(),
        expires_at: expires_at.map(rfc3339),
    }))
}

async fn token_list(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
) -> ApiResult<api::TokenListResponse> {
    gate(
        &state,
        &headers,
        peer.credentials(),
        route::TOKEN_LIST,
        None,
    )?;

    let tokens = state
        .store()
        .list_tokens()?
        .into_iter()
        .map(|summary| api::TokenSummaryDto {
            prefix: summary.record.prefix.as_str().to_owned(),
            name: summary.record.name,
            policies: summary.policies,
            bound_uid: summary.record.bound_uid,
            created_at: rfc3339(summary.created_at),
            expires_at: summary.record.expires_at.map(rfc3339),
            revoked: summary.record.revoked_at.is_some(),
            last_used_at: summary.last_used_at.map(rfc3339),
        })
        .collect();

    Ok(Json(api::TokenListResponse { tokens }))
}

async fn token_revoke(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::TokenRevokeRequest>,
) -> ApiResult<api::Ack> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::TOKEN_REVOKE,
        None,
    )?;

    let prefix = sbae_policy::LookupPrefix::parse(&request.prefix)
        .map_err(|_| ApiError::bad_request("malformed token prefix"))?;
    state.store().revoke_token(&prefix)?;

    record(
        &state,
        &caller,
        Action::TokenRevoke,
        AuditResult::Success,
        None,
        None,
    )?;
    Ok(Json(api::Ack::ok()))
}

async fn policy_put(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::PolicyPutRequest>,
) -> ApiResult<api::Ack> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::POLICY_PUT,
        None,
    )?;

    let policy = sbae_policy::Policy::from_json(&request.document)
        .map_err(|source| ApiError::bad_request(&source.to_string()))?;
    state.store().put_policy(&policy)?;

    record(
        &state,
        &caller,
        Action::PolicyWrite,
        AuditResult::Success,
        None,
        None,
    )?;
    Ok(Json(api::Ack::ok()))
}

async fn policy_list(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
) -> ApiResult<api::PolicyListResponse> {
    gate(
        &state,
        &headers,
        peer.credentials(),
        route::POLICY_LIST,
        None,
    )?;
    Ok(Json(api::PolicyListResponse {
        policies: state.store().list_policy_names()?,
    }))
}

async fn policy_delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::NameRequest>,
) -> ApiResult<api::Ack> {
    let caller = gate(
        &state,
        &headers,
        peer.credentials(),
        route::POLICY_DELETE,
        None,
    )?;
    state.store().delete_policy(&request.name)?;

    record(
        &state,
        &caller,
        Action::PolicyWrite,
        AuditResult::Success,
        None,
        None,
    )?;
    Ok(Json(api::Ack::ok()))
}

async fn audit_verify(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
) -> ApiResult<api::AuditVerifyResponse> {
    gate(
        &state,
        &headers,
        peer.credentials(),
        route::AUDIT_VERIFY,
        None,
    )?;

    let keys = state.keys();
    let store = state.store();
    let outcome = sbae_audit::verify(store.connection(), &keys.audit_key)
        .map_err(|_| ApiError::internal())?;

    Ok(Json(api::AuditVerifyResponse {
        entries: match &outcome {
            sbae_audit::VerificationResult::Valid {
                entries_verified, ..
            } => *entries_verified,
            _ => 0,
        },
        broken_at: outcome
            .broken_seq()
            .map(|seq| i64::try_from(seq.get()).unwrap_or(-1)),
        detail: (!outcome.is_valid()).then(|| outcome.to_string()),
    }))
}

/// Unknown paths answer exactly like a denied one, so probing for routes reveals nothing.
async fn not_found() -> ApiError {
    ApiError::denied()
}
