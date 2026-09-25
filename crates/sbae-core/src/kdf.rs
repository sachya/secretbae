//! Key derivation.
//!
//! Two distinct jobs, deliberately kept apart:
//!
//! * [`derive`] -- HKDF-SHA256, for stretching material that is *already* high-entropy
//!   (the keyfile, the master key). Fast is correct here; there is nothing to brute force.
//! * [`derive_from_passphrase`] -- Argon2id, for material a human chose. Only used for
//!   backup bundles, never on a request path.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{Error, Key32, Result};

/// Argon2id cost parameters for backup passphrases: 64 MiB, 3 passes, 4 lanes.
///
/// Chosen above the OWASP floor because a backup bundle is an offline target -- an attacker
/// who steals one can grind at it indefinitely, so the per-guess cost is the only defence.
const BACKUP_MEMORY_KIB: u32 = 64 * 1024;
const BACKUP_ITERATIONS: u32 = 3;
const BACKUP_LANES: u32 = 4;

/// Salt length for passphrase derivation.
pub const SALT_LEN: usize = 16;

/// Derive a subkey from high-entropy input material, domain-separated by `info`.
///
/// Every call site passes a distinct `info` string so that two subkeys derived from the same
/// master key are computationally unrelated.
pub fn derive(input_material: &[u8], info: &[u8]) -> Result<Key32> {
    let mut okm = [0u8; Key32::LEN];
    Hkdf::<Sha256>::new(None, input_material)
        .expand(info, &mut okm)
        .map_err(|_| Error::Kdf)?;
    Ok(Key32::from_bytes(okm))
}

/// Derive a key from a human-chosen passphrase. Intentionally slow.
pub fn derive_from_passphrase(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Key32> {
    let params = Params::new(
        BACKUP_MEMORY_KIB,
        BACKUP_ITERATIONS,
        BACKUP_LANES,
        Some(Key32::LEN),
    )
    .map_err(|_| Error::Kdf)?;

    let mut okm = [0u8; Key32::LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut okm)
        .map_err(|_| Error::Kdf)?;
    Ok(Key32::from_bytes(okm))
}

pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| Error::Entropy)?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let a = derive(b"input", b"info").unwrap();
        let b = derive(b"input", b"info").unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn info_domain_separates() {
        let a = derive(b"input", b"secretbae/kek/v1").unwrap();
        let b = derive(b"input", b"secretbae/audit/v1").unwrap();
        assert_ne!(
            a.expose(),
            b.expose(),
            "subkeys from one master must be unrelated"
        );
    }

    #[test]
    fn passphrase_derivation_is_deterministic_and_salt_dependent() {
        let salt = [1u8; SALT_LEN];
        let a = derive_from_passphrase(b"correct horse", &salt).unwrap();
        let b = derive_from_passphrase(b"correct horse", &salt).unwrap();
        assert_eq!(a.expose(), b.expose());

        let c = derive_from_passphrase(b"correct horse", &[2u8; SALT_LEN]).unwrap();
        assert_ne!(a.expose(), c.expose());
    }

    #[test]
    fn generated_salts_differ() {
        assert_ne!(generate_salt().unwrap(), generate_salt().unwrap());
    }
}
