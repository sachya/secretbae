//! Backup bundles.
//!
//! A bundle is encrypted under a key derived from a passphrase the operator supplies, and
//! deliberately *not* under the keyfile. The store and its keyfile live on the same
//! filesystem, so if backups were sealed with the keyfile too, one stolen disk image would
//! open both. An independent passphrase is what keeps a stolen backup useless.
//!
//! Argon2id is used here and nowhere else in the system: a passphrase is the one piece of key
//! material with a small enough candidate space to be worth grinding, and a backup is an
//! offline target an attacker can grind at indefinitely.

use crate::{aead, kdf, Error, Nonce, Result, SecretBytes};

const MAGIC: &[u8; 6] = b"SBAEBK";
const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 6 + 2 + kdf::SALT_LEN + aead::NONCE_LEN;

/// Encrypt `plaintext` under `passphrase`.
pub fn seal_bundle(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(Error::Kdf);
    }

    let salt = kdf::generate_salt()?;
    let key = kdf::derive_from_passphrase(passphrase, &salt)?;
    let aad = header_aad(&salt);
    let (nonce, ciphertext) = aead::seal(&key, &aad, plaintext)?;

    let mut bundle = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    bundle.extend_from_slice(MAGIC);
    bundle.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bundle.extend_from_slice(&salt);
    bundle.extend_from_slice(nonce.as_bytes());
    bundle.extend_from_slice(&ciphertext);
    Ok(bundle)
}

/// Decrypt a bundle. A wrong passphrase and a tampered bundle are the same error, because
/// distinguishing them would confirm a guess.
pub fn open_bundle(passphrase: &[u8], bundle: &[u8]) -> Result<SecretBytes> {
    if bundle.len() <= HEADER_LEN || &bundle[..6] != MAGIC {
        return Err(Error::Malformed {
            what: "backup bundle",
            expected: HEADER_LEN + 1,
            found: bundle.len(),
        });
    }

    let format_version = u16::from_le_bytes([bundle[6], bundle[7]]);
    if format_version != FORMAT_VERSION {
        return Err(Error::SealVersion { found: format_version, supported: FORMAT_VERSION });
    }

    let salt: [u8; kdf::SALT_LEN] =
        bundle[8..8 + kdf::SALT_LEN].try_into().map_err(|_| Error::Malformed {
            what: "backup salt",
            expected: kdf::SALT_LEN,
            found: bundle.len(),
        })?;

    let key = kdf::derive_from_passphrase(passphrase, &salt)?;
    let nonce = Nonce::from_slice(&bundle[8 + kdf::SALT_LEN..HEADER_LEN])?;
    aead::open(&key, &nonce, &header_aad(&salt), &bundle[HEADER_LEN..])
}

/// Binds the ciphertext to the header, so the salt cannot be swapped for one whose derived
/// key an attacker already knows.
fn header_aad(salt: &[u8; kdf::SALT_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + kdf::SALT_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    aad.extend_from_slice(salt);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_round_trips() {
        let bundle = seal_bundle(b"correct horse battery staple", b"payload").unwrap();
        let opened = open_bundle(b"correct horse battery staple", &bundle).unwrap();
        assert_eq!(opened.expose(), b"payload");
    }

    #[test]
    fn the_wrong_passphrase_does_not_open_it() {
        let bundle = seal_bundle(b"right", b"payload").unwrap();
        assert!(open_bundle(b"wrong", &bundle).is_err());
    }

    #[test]
    fn the_payload_is_not_recoverable_from_the_bundle_bytes() {
        let bundle = seal_bundle(b"pass", b"postgres://user:pw@/db").unwrap();
        assert!(!bundle.windows(8).any(|window| window == b"postgres"));
    }

    #[test]
    fn tampering_anywhere_in_the_bundle_is_detected() {
        let pristine = seal_bundle(b"pass", b"payload").unwrap();

        for index in [8, 8 + kdf::SALT_LEN, HEADER_LEN] {
            let mut tampered = pristine.clone();
            tampered[index] ^= 0x01;
            assert!(
                open_bundle(b"pass", &tampered).is_err(),
                "flipping byte {index} should be detected"
            );
        }
    }

    /// Swapping in a salt whose derived key the attacker knows must not work.
    #[test]
    fn the_salt_cannot_be_substituted() {
        let mut bundle = seal_bundle(b"pass", b"payload").unwrap();
        bundle[8..8 + kdf::SALT_LEN].copy_from_slice(&[0u8; kdf::SALT_LEN]);
        assert!(open_bundle(b"pass", &bundle).is_err());
    }

    #[test]
    fn two_bundles_of_the_same_payload_differ() {
        let first = seal_bundle(b"pass", b"payload").unwrap();
        let second = seal_bundle(b"pass", b"payload").unwrap();
        assert_ne!(first, second, "a fresh salt and nonce are used each time");
    }

    #[test]
    fn malformed_bundles_are_rejected() {
        assert!(open_bundle(b"pass", &[]).is_err());
        assert!(open_bundle(b"pass", b"SBAEBK").is_err());
        assert!(open_bundle(b"pass", &[0u8; HEADER_LEN + 4]).is_err());
    }

    #[test]
    fn an_empty_passphrase_is_refused() {
        assert!(seal_bundle(b"", b"payload").is_err());
    }
}
