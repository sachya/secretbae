use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("keyfile {path}: {reason}")]
    Keyfile { path: String, reason: String },

    #[error("{0} failed: {1}")]
    Harden(&'static str, std::io::Error),

    #[error("must start as root to read the keyfile and drop privileges")]
    NotRoot,

    /// Raised before the async runtime starts, because the failure it prevents surfaces as a
    /// panic inside the runtime that says nothing about memory locking.
    #[error(
        "RLIMIT_MEMLOCK is {limit} bytes, below the {required} this daemon needs: \
         mlockall(MCL_FUTURE) locks every allocation for the life of the process"
    )]
    MemlockTooLow { limit: u64, required: u64 },

    /// Raised when the process still holds privilege after the drop was reported as
    /// successful. Startup aborts rather than serving from a root process.
    #[error("privileges were not fully dropped; refusing to serve")]
    PrivilegeDropIncomplete,

    #[error("no such system user: {0}")]
    UnknownUser(String),

    #[error("store is not initialised; run `secretbae init` first")]
    NotInitialised,

    #[error("configuration: {0}")]
    Config(String),

    #[error(transparent)]
    Store(#[from] sbae_store::StoreError),

    #[error(transparent)]
    Crypto(#[from] sbae_core::Error),

    #[error(transparent)]
    Audit(#[from] sbae_audit::AuditError),

    #[error(transparent)]
    Policy(#[from] sbae_policy::PolicyError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, DaemonError>;
