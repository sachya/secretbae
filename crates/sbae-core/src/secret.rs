//! Plaintext-carrying types.
//!
//! Everything here exists to make leaking a secret require a deliberate, greppable act
//! (`expose()`), rather than something a stray `{:?}` or `serde::Serialize` can do by accident.

use core::fmt;
use zeroize::ZeroizeOnDrop;

/// A variable-length plaintext secret, wiped on drop.
///
/// Deliberately implements neither `Display`, `Serialize`, nor a revealing `Debug`.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The only route to the plaintext. Callers should keep the borrow as short as possible.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&str> for SecretBytes {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<redacted, {} bytes>)", self.0.len())
    }
}

/// A 32-byte symmetric key.
///
/// Wrapped in distinct newtypes below so that a data key can never be passed where a master
/// key is expected; the compiler enforces the key hierarchy rather than review comments.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    pub const LEN: usize = 32;

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Fresh key from the OS CSPRNG.
    pub fn generate() -> Result<Self, crate::Error> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| crate::Error::Entropy)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

macro_rules! key_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug)]
        pub struct $name(Key32);

        impl $name {
            #[must_use]
            pub fn new(key: Key32) -> Self { Self(key) }

            pub fn generate() -> Result<Self, crate::Error> { Ok(Self(Key32::generate()?)) }

            #[must_use]
            pub(crate) fn raw(&self) -> &Key32 { &self.0 }
        }
    };
}

key_newtype! {
    /// Root of the key hierarchy. Lives only in the daemon's `mlock`ed memory, never on disk
    /// unsealed. Wraps data keys and derives the audit-chain MAC key.
    MasterKey
}

key_newtype! {
    /// Per-secret-version key. A fresh one is generated for every write, which is what makes
    /// master-key rotation cheap: `rekey` rewraps 32-byte data keys instead of re-encrypting
    /// every payload.
    DataKey
}

key_newtype! {
    /// Key-encryption key derived from a seal backend's input material. Wraps the master key
    /// at rest.
    WrapKey
}

impl MasterKey {
    /// Exposed for the audit crate, which derives its MAC key from the master key.
    #[must_use]
    pub fn as_key32(&self) -> &Key32 {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_plaintext() {
        let secret = SecretBytes::from("hunter2");
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains("hunter2"),
            "Debug leaked the secret: {rendered}"
        );
        assert!(rendered.contains('7'), "expected the length to be reported");

        let key = Key32::from_bytes([0xAB; 32]);
        assert_eq!(format!("{key:?}"), "Key32(<redacted>)");
    }

    #[test]
    fn generated_keys_differ() {
        let a = Key32::generate().unwrap();
        let b = Key32::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
    }
}
