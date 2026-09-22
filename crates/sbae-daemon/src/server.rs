//! The Unix socket listener.
//!
//! No TCP listener exists anywhere in this binary. The shipped systemd unit additionally sets
//! `RestrictAddressFamilies=AF_UNIX`, so the absence of one is enforced by the kernel rather
//! than resting on this file staying correct.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use sbae_policy::PeerCredentials;
use tokio::net::{UnixListener, UnixStream};

use std::os::unix::net::UnixListener as StdUnixListener;

use crate::{privdrop::Account, Result, SharedState};

/// The identity of the process on the other end of a connection, read from the kernel.
///
/// This is what makes a leaked token useless to another local account: the caller cannot
/// choose these values, because the kernel supplies them.
#[derive(Clone, Copy, Debug)]
pub struct PeerInfo(PeerCredentials);

impl PeerInfo {
    #[must_use]
    pub fn credentials(self) -> PeerCredentials {
        self.0
    }
}

impl Connected<IncomingStream<'_, UnixListener>> for PeerInfo {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self(peer_credentials(stream.io()))
    }
}

/// A connection whose credentials cannot be read is given values that match no real caller,
/// so it fails any uid-bound token rather than being treated as trusted.
fn peer_credentials(stream: &UnixStream) -> PeerCredentials {
    stream.peer_cred().map_or(
        PeerCredentials { uid: u32::MAX, gid: u32::MAX, pid: -1 },
        |cred| PeerCredentials {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid().unwrap_or(-1),
        },
    )
}

/// Bind the socket and hand it to `account`.
///
/// Runs while still root, and therefore before any Tokio runtime exists -- so it binds with
/// the standard library listener and converts it in [`serve`]. Binding here rather than after
/// the runtime starts is what lets the privilege drop happen with no async task in flight.
///
/// A stale socket from an unclean shutdown is removed first, otherwise bind fails and the
/// daemon never comes back after a crash.
pub fn bind(path: &Path, mode: u32, account: Account) -> Result<StdUnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        chown(parent, account)?;
    }

    if path.exists() {
        fs::remove_file(path)?;
    }

    let listener = StdUnixListener::bind(path)?;
    listener.set_nonblocking(true)?;

    // Order matters: restrict the mode before handing ownership over, so the socket is never
    // briefly both world-accessible and owned by the service account.
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    chown(path, account)?;

    Ok(listener)
}

fn chown(path: &Path, account: Account) -> Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;

    // SAFETY: `c_path` is a valid NUL-terminated path that outlives the call, and chown
    // takes integer ids. Delegated to the one module allowed to use `unsafe`.
    let code = crate::privdrop::chown_raw(&c_path, account);
    if code != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub async fn serve(listener: StdUnixListener, state: SharedState) -> Result<()> {
    let listener = UnixListener::from_std(listener)?;
    let router = crate::routes::router(state).into_make_service_with_connect_info::<PeerInfo>();

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Stop accepting on SIGTERM so systemd restarts and reloads are clean.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let Ok(mut terminate) = signal(SignalKind::terminate()) else { return };

    tokio::select! {
        _ = terminate.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
