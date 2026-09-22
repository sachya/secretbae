use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Deliberately opaque: a caller must not be able to distinguish a wrong key from a
    /// tampered ciphertext from a mismatched binding, since that distinction is an oracle.
    #[error("decryption failed")]
    Decrypt,

    #[error("the OS entropy source is unavailable")]
    Entropy,

    #[error("key derivation failed")]
    Kdf,

    #[error("malformed {what}: expected {expected} bytes, found {found}")]
    Malformed {
        what: &'static str,
        expected: usize,
        found: usize,
    },

    #[error("unsupported seal backend {0:?}")]
    UnsupportedSeal(String),

    #[error("sealed master key is from format version {found}, this build supports {supported}")]
    SealVersion { found: u16, supported: u16 },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
