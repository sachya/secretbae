use thiserror::Error;

/// Failures from validating a domain value.
///
/// These describe *the caller's own input*, so unlike the daemon's authorization errors they
/// can be specific: telling someone their path contains uppercase reveals nothing about the
/// contents of the store.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("invalid secret path {path:?}: {reason}")]
    InvalidPath { path: String, reason: &'static str },

    #[error("invalid tag {what}: {reason}")]
    InvalidTag { what: &'static str, reason: &'static str },

    #[error("invalid version: versions are whole numbers starting at 1")]
    InvalidVersion,

    #[error("invalid version state")]
    InvalidVersionState,

    #[error("unknown capability: expected one of read, write, delete, list, admin")]
    InvalidCapability,
}
