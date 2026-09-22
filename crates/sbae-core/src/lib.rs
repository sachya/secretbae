//! Cryptographic core for secretbae.
//!
//! This crate owns the key hierarchy and performs no I/O, which keeps it testable on any
//! platform and keeps every cryptographic decision in one reviewable place.
//!
//! ```text
//! keyfile ──HKDF──► KEK ──wraps──► MasterKey ──wraps──► DataKey ──► one secret version
//!                                       └────HKDF────► audit chain MAC key
//! ```
//!
//! A fresh [`DataKey`] per version is what makes master-key rotation cheap: `rekey` rewraps
//! 32-byte keys rather than re-encrypting every payload.

#![forbid(unsafe_code)]

pub mod aead;
pub mod backup;
pub mod envelope;
pub mod kdf;
pub mod seal;

mod error;
mod secret;

pub use aead::{Nonce, NONCE_LEN};
pub use envelope::{SealedVersion, VersionBinding, WrappedKey};
pub use error::{Error, Result};
pub use seal::{KeyfileSeal, Seal, SealKind, SealedMasterKey};
pub use secret::{DataKey, Key32, MasterKey, SecretBytes, WrapKey};

/// HKDF domain separator for the audit log's MAC key.
///
/// The audit chain is keyed from the master key so that an attacker who can write to the
/// database still cannot recompute a valid chain.
pub const AUDIT_KEY_INFO: &[u8] = b"secretbae/audit/v1";

impl MasterKey {
    /// Derive the audit-chain MAC key.
    pub fn audit_key(&self) -> Result<Key32> {
        kdf::derive(self.as_key32().expose(), AUDIT_KEY_INFO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walks the whole hierarchy the way the daemon does at startup and on write.
    #[test]
    fn full_hierarchy_round_trip() {
        let keyfile = KeyfileSeal::generate_hex().unwrap();
        let backend = KeyfileSeal::from_hex(&keyfile).unwrap();

        let master = MasterKey::generate().unwrap();
        let sealed_master = seal::seal_master(&backend, &master, 1).unwrap();

        // Restart: the daemon has only the keyfile and the sealed blob.
        let stored = sealed_master.to_bytes();
        let recovered = seal::unseal_master(
            &KeyfileSeal::from_hex(&keyfile).unwrap(),
            &SealedMasterKey::from_bytes(&stored).unwrap(),
        )
        .unwrap();

        let binding = VersionBinding::new(uuid::Uuid::from_u128(1), 1);
        let sealed = SealedVersion::seal(&recovered, 1, binding, b"postgres://user:pw@/db").unwrap();
        assert_eq!(sealed.open(&master, binding).unwrap().expose(), b"postgres://user:pw@/db");
    }

    #[test]
    fn audit_key_is_derived_not_the_master_key() {
        let master = MasterKey::generate().unwrap();
        let audit = master.audit_key().unwrap();
        assert_ne!(audit.expose(), master.as_key32().expose());
    }
}
