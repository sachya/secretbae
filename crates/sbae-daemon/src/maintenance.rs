//! Whole-store administrative operations: key rotation, backup and restore.
//!
//! Separated from the per-secret handlers because these three are the only routes that touch
//! the store as a whole, and the only ones whose ordering constraints matter.

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use data_encoding::BASE64;
use sbae_audit::{Action, AuditResult};
use sbae_core::{backup, seal, MasterKey, SealedVersion, VersionBinding};
use sbae_proto::api::{self, route};
use sbae_store::{ExportedSecret, ExportedVersion, StoreError};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::record;
use crate::routes::{gate, rfc3339, ApiError, ApiResult};
use crate::server::PeerInfo;
use crate::SharedState;

/// Rotate the master key.
///
/// Ordering is what makes this safe on a live daemon. The store commits every rewrapped data
/// key and the new sealed master key in one transaction, and the daemon adopts the new key
/// only after that commit succeeds -- so a failure anywhere leaves store and daemon agreeing
/// on the old key rather than half-rotated.
pub async fn rekey(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
) -> ApiResult<api::RekeyResponse> {
    let caller = gate(&state, &headers, peer.credentials(), route::REKEY, None)?;

    let successor = MasterKey::generate()?;
    let successor_audit_key = successor.audit_key()?;

    let (rewrapped, entries, generation) = {
        let keys = state.keys();
        let generation = keys.generation.checked_add(1).ok_or_else(ApiError::internal)?;
        let sealed = seal::seal_master(state.seal(), &successor, generation)?;

        let mut store = state.store();

        // The chain is re-keyed first because that step refuses to run on a chain that does
        // not verify. Doing it here means tampering aborts the whole rotation, rather than
        // being silently re-MAC'd into a valid-looking chain afterwards.
        let entries =
            sbae_audit::rekey_chain(store.connection_mut(), &keys.audit_key, &successor_audit_key)
                .map_err(|_| ApiError::internal())?
                .entries_rekeyed;

        let report = store.rekey_with(&sealed, |binding, version| {
            version.rewrap(&keys.master, &successor, generation, binding).map_err(StoreError::from)
        })?;

        (report.versions_rewrapped, entries, generation)
    };

    state.adopt_rotated_key(successor, generation)?;
    record(&state, &caller, Action::Rekey, AuditResult::Success, None, None)?;

    Ok(Json(api::RekeyResponse {
        versions_rewrapped: rewrapped as u64,
        audit_entries_rekeyed: entries,
        generation,
    }))
}

/// Produce an encrypted backup bundle.
///
/// Plaintext is opened, re-encrypted under the operator's passphrase and dropped inside this
/// handler. Only ciphertext crosses the socket, so the bundle in transit is no more sensitive
/// than the file it is about to be written to.
pub async fn backup(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::BackupRequest>,
) -> ApiResult<api::BackupResponse> {
    let caller = gate(&state, &headers, peer.credentials(), route::BACKUP, None)?;

    if request.passphrase.is_empty() {
        return Err(ApiError::bad_request("a backup passphrase is required"));
    }

    let (bundle, secrets, versions) = {
        let keys = state.keys();
        let store = state.store();

        let mut version_count = 0u64;
        let mut carried = Vec::new();

        for secret in store.export_secrets()? {
            let binding_id = store.secret_id(&secret.path)?;
            let mut versions = Vec::with_capacity(secret.versions.len());

            for version in secret.versions {
                let value = match &version.sealed {
                    Some(sealed) => {
                        let binding = VersionBinding::new(binding_id, version.version.get());
                        Some(BASE64.encode(sealed.open(&keys.master, binding)?.expose()))
                    }
                    None => None,
                };

                version_count += 1;
                versions.push(api::BackupVersion {
                    version: version.version,
                    state: version.state,
                    created_at: rfc3339(version.created_at),
                    created_by: version.created_by,
                    comment: version.comment,
                    value,
                });
            }

            carried.push(api::BackupSecret {
                path: secret.path,
                tags: secret.tags,
                max_versions: secret.max_versions,
                current_version: secret.current_version,
                versions,
            });
        }

        let policies = store.all_policy_documents()?;
        let secret_count = carried.len() as u64;

        let payload = serde_json::to_vec(&api::BackupBundle {
            created_at: rfc3339(OffsetDateTime::now_utc()),
            secrets: carried,
            policies,
        })
        .map_err(|_| ApiError::internal())?;

        (backup::seal_bundle(request.passphrase.as_bytes(), &payload)?, secret_count, version_count)
    };

    record(&state, &caller, Action::Backup, AuditResult::Success, None, None)?;
    Ok(Json(api::BackupResponse { bundle: BASE64.encode(&bundle), secrets, versions }))
}

/// Import a bundle into an empty store.
///
/// Refuses a store that already holds secrets. Merging two histories would produce version
/// numbering no operator could reason about, and silently overwriting would be worse.
pub async fn restore(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<PeerInfo>,
    headers: HeaderMap,
    Json(request): Json<api::RestoreRequest>,
) -> ApiResult<api::RestoreResponse> {
    let caller = gate(&state, &headers, peer.credentials(), route::RESTORE, None)?;

    let raw = BASE64
        .decode(request.bundle.as_bytes())
        .map_err(|_| ApiError::bad_request("bundle must be base64"))?;

    let opened = backup::open_bundle(request.passphrase.as_bytes(), &raw)
        .map_err(|_| ApiError::bad_request("bundle could not be decrypted with that passphrase"))?;

    let bundle: api::BackupBundle = serde_json::from_slice(opened.expose())
        .map_err(|_| ApiError::bad_request("bundle contents are not a recognised backup"))?;

    let (secrets, versions, policies) = {
        let keys = state.keys();
        let mut store = state.store();

        if store.secret_count()? > 0 {
            return Err(ApiError::bad_request(
                "refusing to restore into a store that already holds secrets",
            ));
        }

        let mut version_count = 0u64;
        for secret in &bundle.secrets {
            // Sealed against a fresh id, then re-sealed below once the store assigns the real
            // one: a version's associated data binds the id it will actually live under.
            let placeholder = Uuid::new_v4();
            let mut versions = Vec::with_capacity(secret.versions.len());

            for version in &secret.versions {
                let sealed = match &version.value {
                    Some(value) => {
                        let plaintext = BASE64
                            .decode(value.as_bytes())
                            .map_err(|_| ApiError::bad_request("version value is not base64"))?;
                        Some(SealedVersion::seal(
                            &keys.master,
                            keys.generation,
                            VersionBinding::new(placeholder, version.version.get()),
                            &plaintext,
                        )?)
                    }
                    None => None,
                };

                version_count += 1;
                versions.push(ExportedVersion {
                    version: version.version,
                    state: version.state,
                    created_at: parse_rfc3339(&version.created_at),
                    created_by: version.created_by.clone(),
                    comment: version.comment.clone(),
                    sealed,
                });
            }

            store.import_secret_with_id(
                placeholder,
                &ExportedSecret {
                    path: secret.path.clone(),
                    tags: secret.tags.clone(),
                    max_versions: secret.max_versions,
                    current_version: secret.current_version,
                    versions,
                },
            )?;
        }

        for document in &bundle.policies {
            let policy = sbae_policy::Policy::from_json(document)
                .map_err(|_| ApiError::bad_request("bundle contains an unparseable policy"))?;
            store.put_policy(&policy)?;
        }

        (bundle.secrets.len() as u64, version_count, bundle.policies.len() as u64)
    };

    record(&state, &caller, Action::Restore, AuditResult::Success, None, None)?;
    Ok(Json(api::RestoreResponse { secrets, versions, policies }))
}

/// A timestamp that fails to parse falls back to now rather than aborting the restore: losing
/// an original write time is cosmetic, failing to recover the secret is not.
fn parse_rfc3339(raw: &str) -> OffsetDateTime {
    OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
}
