//! Error types for audit operations.

use thiserror::Error;

/// Failures encountered when writing to, reading from, or verifying the audit log.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Re-keying a chain that does not verify would re-MAC the tampering into a chain that
    /// then verifies perfectly, destroying the evidence.
    #[error("refusing to re-key a chain that does not verify: {0}")]
    RefusingToRekeyBrokenChain(String),

    /// Action string in the store is not a recognized variant.
    #[error("unknown audit action: {0:?}")]
    UnknownAction(String),

    /// Result string in the store is not a recognized variant.
    #[error("unknown audit result: {0:?}")]
    UnknownResult(String),

    /// Hash column had an unexpected byte count.
    #[error("invalid hash length: expected {expected} bytes, found {found}")]
    InvalidHashLength { expected: usize, found: usize },

    /// Stored row data violates an invariant or cannot be represented.
    #[error("stored audit data is corrupt: {what}")]
    Corrupt { what: &'static str },

    /// Domain type validation failure.
    #[error(transparent)]
    Proto(#[from] sbae_proto::ProtoError),

    /// SQLite storage error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// Cryptographic derivation error.
    #[error(transparent)]
    Core(#[from] sbae_core::Error),
}

pub type Result<T> = core::result::Result<T, AuditError>;
