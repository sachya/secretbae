//! Authenticated encryption.
//!
//! XChaCha20-Poly1305 with random nonces. The 24-byte nonce is wide enough that random
//! generation has a negligible collision probability, which removes the need for a persistent
//! counter -- and therefore removes the class of bugs where a restore-from-backup or a crash
//! rewinds that counter and repeats a nonce.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

use crate::{Error, Key32, Result, SecretBytes};

pub const NONCE_LEN: usize = 24;

/// A 24-byte XChaCha20-Poly1305 nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Entropy)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let sized: [u8; NONCE_LEN] = bytes.try_into().map_err(|_| Error::Malformed {
            what: "nonce",
            expected: NONCE_LEN,
            found: bytes.len(),
        })?;
        Ok(Self(sized))
    }
}

/// Encrypt `plaintext`, binding the result to `aad`.
pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<(Nonce, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let nonce = Nonce::generate()?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce.as_bytes()), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Decrypt)?;
    Ok((nonce, ciphertext))
}

/// Decrypt `ciphertext`, requiring that `aad` matches what was supplied at seal time.
pub fn open(key: &Key32, nonce: &Nonce, aad: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    cipher
        .decrypt(XNonce::from_slice(nonce.as_bytes()), Payload { msg: ciphertext, aad })
        .map(SecretBytes::new)
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key32 {
        Key32::from_bytes([7u8; 32])
    }

    #[test]
    fn round_trip() {
        let (nonce, ct) = seal(&key(), b"aad", b"plaintext").unwrap();
        let pt = open(&key(), &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt.expose(), b"plaintext");
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let (_, ct) = seal(&key(), b"", b"plaintext").unwrap();
        assert!(!ct.windows(9).any(|w| w == b"plaintext"));
    }

    #[test]
    fn rejects_wrong_aad() {
        let (nonce, ct) = seal(&key(), b"secret-a", b"v").unwrap();
        assert!(open(&key(), &nonce, b"secret-b", &ct).is_err());
    }

    #[test]
    fn rejects_flipped_bit() {
        let (nonce, mut ct) = seal(&key(), b"aad", b"plaintext").unwrap();
        ct[0] ^= 0x01;
        assert!(open(&key(), &nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let (nonce, ct) = seal(&key(), b"aad", b"plaintext").unwrap();
        assert!(open(&Key32::from_bytes([9u8; 32]), &nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn nonces_do_not_repeat() {
        let (a, _) = seal(&key(), b"", b"x").unwrap();
        let (b, _) = seal(&key(), b"", b"x").unwrap();
        assert_ne!(a, b);
    }
}
