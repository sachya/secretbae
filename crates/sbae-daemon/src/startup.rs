//! The privileged startup sequence.

use std::path::Path;
use std::sync::Arc;

use sbae_audit::{Action, AuditEntry, AuditResult};
use sbae_core::seal;
use sbae_store::Store;
use std::os::unix::net::UnixListener;

use crate::{
    keyfile, privdrop, server, Config, DaemonError, DaemonState, Result, SharedState,
};

/// Everything that requires root, done once and never again.
///
/// Returns the bound listener and the unsealed state, with the process already running as the
/// unprivileged service account.
pub fn run(config: &Config) -> Result<(UnixListener, SharedState)> {
    if privdrop::current_uid() != 0 {
        return Err(DaemonError::NotRoot);
    }

    // Before the master key exists in this process, so a crash can never dump it to disk.
    privdrop::harden_process()?;
    check_memlock_headroom()?;

    let account = privdrop::resolve_account(&config.user)?;
    let backend = keyfile::load(&config.keyfile)?;

    let store = open_store(&config.store, account)?;
    seed_builtin_policies(&store)?;
    let sealed = store.sealed_master_key()?.ok_or(DaemonError::NotInitialised)?;
    let master = seal::unseal_master(&backend, &sealed)?;

    let listener = server::bind(&config.socket, config.socket_mode, account)?;

    // Everything above needed privilege. Nothing below does.
    privdrop::drop_privileges(account)?;

    let state = DaemonState::new(store, Box::new(backend), master, sealed.generation)?;
    record_unseal(&state)?;

    Ok((listener, Arc::new(state)))
}

/// Minimum `RLIMIT_MEMLOCK` the serving path needs.
///
/// `mlockall(MCL_FUTURE)` succeeds under a small limit because the process is still tiny at
/// that point; the limit only bites later, when the async runtime allocates thread stacks that
/// must also be locked. That surfaces as a panic deep inside the runtime with no mention of
/// memlock, so the condition is caught here instead, where it can name the unit directive that
/// fixes it.
///
/// Measured: ~25 MiB locked at rest, peaking at ~27 MiB across a full write, read, rekey and
/// audit-verify cycle over 1000 secrets holding roughly 2000 versions. The stored data barely
/// registers against the runtime baseline, so this floor is about the runtime, not the store.
/// The shipped unit grants double it.
const MINIMUM_MEMLOCK: u64 = 64 * 1024 * 1024;

fn check_memlock_headroom() -> Result<()> {
    match privdrop::memlock_limit() {
        Some(limit) if limit < MINIMUM_MEMLOCK => Err(DaemonError::MemlockTooLow {
            limit,
            required: MINIMUM_MEMLOCK,
        }),
        _ => Ok(()),
    }
}

/// Open the store and tighten it to the service account.
///
/// Done here rather than in `sbae-store` because only the daemon knows which account it is
/// about to become.
fn open_store(path: &Path, account: privdrop::Account) -> Result<Store> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }

    let store = Store::open(path)?;

    for suffix in ["", "-wal", "-shm"] {
        let sidecar = path.with_extension(format!(
            "{}{suffix}",
            path.extension().and_then(std::ffi::OsStr::to_str).unwrap_or("db")
        ));
        if sidecar.exists() {
            std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600))?;
            chown(&sidecar, account)?;
        }
    }

    if let Some(parent) = path.parent() {
        chown(parent, account)?;
    }

    Ok(store)
}

fn chown(path: &Path, account: privdrop::Account) -> Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;

    if privdrop::chown_raw(&c_path, account) != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// A restart is a security-relevant event: it is the moment the master key re-enters memory.
fn record_unseal(state: &DaemonState) -> Result<()> {
    let keys = state.keys();
    let audit_key = keys.audit_key.clone();
    let mut store = state.store();
    sbae_audit::append(
        store.connection_mut(),
        &audit_key,
        &AuditEntry::new(Action::Unseal, AuditResult::Success)
            .with_peer_uid(sbae_audit::PeerUid::new(privdrop::current_uid())),
    )?;
    Ok(())
}

/// Bootstrap a new deployment: keyfile, store, master key, and one admin token.
///
/// Runs as root and is refused if a keyfile already exists, because generating a second one
/// would leave every secret in the existing store permanently unreadable.
pub fn initialise(config: &Config) -> Result<String> {
    if privdrop::current_uid() != 0 {
        return Err(DaemonError::NotRoot);
    }
    privdrop::harden_process()?;

    let account = privdrop::resolve_account(&config.user)?;
    keyfile::create(&config.keyfile)?;
    let backend = keyfile::load(&config.keyfile)?;

    let mut store = open_store(&config.store, account)?;
    let master = sbae_core::MasterKey::generate()?;
    store.initialise_master_key(&seal::seal_master(&backend, &master, 1)?)?;

    store.put_policy(&sbae_policy::Policy {
        name: ROOT_POLICY.to_owned(),
        rules: vec![sbae_policy::Rule {
            path: sbae_policy::PathPattern::new("**")?,
            capabilities: sbae_proto::Capability::ALL.into_iter().collect(),
            require_tags: Vec::new(),
        }],
        deny: Vec::new(),
    })?;
    seed_builtin_policies(&store)?;

    let issued = sbae_policy::issue()?;
    store.create_token(&sbae_store::NewToken {
        id: issued.id,
        prefix: &issued.prefix,
        hash: &issued.hash,
        name: "root",
        // Bound to root: the bootstrap token should not be usable from an application account.
        bound_uid: Some(0),
        expires_at: None,
        policies: &[ROOT_POLICY.to_owned()],
    })?;

    let audit_key = master.audit_key()?;
    sbae_audit::append(
        store.connection_mut(),
        &audit_key,
        &AuditEntry::new(Action::Init, AuditResult::Success),
    )?;

    Ok(issued.secret.expose().to_owned())
}

/// Name of the policy granting everything, created by `init`. Re-exported from the wire
/// contract so the CLI can refer to the same name without depending on `sbae-policy`.
pub const ROOT_POLICY: &str = sbae_proto::api::BUILTIN_ROOT_POLICY;

/// A policy attached by name (`--unrestricted`) so a first token can be minted without
/// writing a policy document. Grants read, write, delete and list on every path, and
/// deliberately never `admin` -- a token bound to it can read or change any secret but can
/// never create, revoke or repolicy a token.
fn unrestricted_policy() -> Result<sbae_policy::Policy> {
    Ok(sbae_policy::Policy {
        name: sbae_proto::api::BUILTIN_UNRESTRICTED_POLICY.to_owned(),
        rules: vec![sbae_policy::Rule {
            path: sbae_policy::PathPattern::new("**")?,
            capabilities: [
                sbae_proto::Capability::Read,
                sbae_proto::Capability::Write,
                sbae_proto::Capability::Delete,
                sbae_proto::Capability::List,
            ]
            .into_iter()
            .collect(),
            require_tags: Vec::new(),
        }],
        deny: Vec::new(),
    })
}

/// Seed the policies every store should carry, without ever overwriting one an operator has
/// customised. Called on every regular startup as well as `init`, so a store upgraded from a
/// version that predates a built-in policy gains it on its next restart.
fn seed_builtin_policies(store: &sbae_store::Store) -> Result<()> {
    store.ensure_policy_exists(&unrestricted_policy()?)?;
    Ok(())
}
