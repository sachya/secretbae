//! Shared daemon state.

use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};

use sbae_core::{Key32, MasterKey, Seal};
use sbae_store::Store;

/// The unsealed key material, replaced wholesale by a rotation.
///
/// The audit key is derived once and kept beside the master key it came from, so a rotation
/// can never leave the chain being extended under a key derived from the previous master.
pub struct KeyMaterial {
    pub master: MasterKey,
    pub audit_key: Key32,
    pub generation: u32,
}

impl KeyMaterial {
    fn new(master: MasterKey, generation: u32) -> crate::Result<Self> {
        Ok(Self {
            audit_key: master.audit_key()?,
            master,
            generation,
        })
    }
}

/// Everything a request handler needs.
///
/// The master key lives here and nowhere else. It is never written back to disk, never
/// returned by any route, and never copied into a response.
///
/// **Lock order: `keys` before `store`.** Rotation is the only operation that holds both, and
/// taking them in this order everywhere is what keeps it from deadlocking against a request.
pub struct DaemonState {
    keys: RwLock<KeyMaterial>,
    /// Retained from startup because rotation must re-seal the new master key, and after the
    /// privilege drop the daemon can no longer read the root-owned keyfile to rebuild it.
    seal: Box<dyn Seal>,
    /// SQLite serialises writes itself, but a single connection cannot be used concurrently,
    /// so access is funnelled through one lock. Critical sections are local database calls
    /// measured in microseconds and never span an `await`.
    store: Mutex<Store>,
}

pub type SharedState = Arc<DaemonState>;

impl DaemonState {
    pub fn new(
        store: Store,
        seal: Box<dyn Seal>,
        master: MasterKey,
        generation: u32,
    ) -> crate::Result<Self> {
        Ok(Self {
            keys: RwLock::new(KeyMaterial::new(master, generation)?),
            seal,
            store: Mutex::new(store),
        })
    }

    #[must_use]
    pub fn seal(&self) -> &dyn Seal {
        self.seal.as_ref()
    }

    /// A poisoned lock means a handler panicked mid-transaction. Recovering the guard is
    /// correct here because SQLite rolls back an uncommitted transaction when its statement
    /// is dropped, so the database is consistent even though the handler was not.
    pub fn store(&self) -> MutexGuard<'_, Store> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn keys(&self) -> RwLockReadGuard<'_, KeyMaterial> {
        self.keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Swap in a rotated master key.
    ///
    /// Called only after the store has committed the rewrapped data keys, so a failure to
    /// commit leaves the daemon still holding the key that matches what is on disk.
    pub fn adopt_rotated_key(&self, master: MasterKey, generation: u32) -> crate::Result<()> {
        let mut keys = self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *keys = KeyMaterial::new(master, generation)?;
        Ok(())
    }
}
