use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    /// Covers every shape of unusable token string. Deliberately undifferentiated: telling a
    /// caller *how* their token was wrong is a probe into the format they have not guessed.
    #[error("malformed token")]
    MalformedToken,

    #[error("invalid path pattern {0:?}: segments must be a literal, '*' or '**'")]
    InvalidPattern(String),

    #[error("malformed policy document: {0}")]
    Malformed(String),

    #[error("the OS entropy source is unavailable")]
    Entropy,

    #[error(transparent)]
    Proto(#[from] sbae_proto::ProtoError),
}

pub type Result<T> = core::result::Result<T, PolicyError>;
