use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    /// Covers "no such path" and "that version is deleted or destroyed" alike.
    ///
    /// The daemon maps authorization failures onto this same variant before answering a
    /// client, so that probing for which paths exist yields no signal.
    #[error("not found")]
    NotFound,

    #[error("a secret already exists at that path")]
    AlreadyExists,

    #[error("store schema is version {found}, this build supports up to {supported}")]
    SchemaTooNew { found: u32, supported: u32 },

    #[error("the store has not been initialised")]
    NotInitialised,

    #[error("the store is already initialised")]
    AlreadyInitialised,

    #[error("stored {what} is corrupt")]
    Corrupt { what: &'static str },

    #[error(transparent)]
    Proto(#[from] sbae_proto::ProtoError),

    #[error(transparent)]
    Policy(#[from] sbae_policy::PolicyError),

    #[error(transparent)]
    Crypto(#[from] sbae_core::Error),

    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = core::result::Result<T, StoreError>;

impl StoreError {
    /// Distinguishes a caller mistake from an operator problem, so the daemon knows whether
    /// to answer 4xx or 5xx without matching on every variant at the call site.
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::NotFound
                | Self::AlreadyExists
                | Self::Proto(_)
                | Self::Policy(_)
                | Self::AlreadyInitialised
        )
    }
}
