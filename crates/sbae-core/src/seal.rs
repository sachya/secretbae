//! Sealing the master key at rest.
//!
//! A [`Seal`] backend supplies key material; the wrapping itself is written once, here, so
//! that adding a backend (TPM2, `systemd-creds`) is a new implementation of a two-method
//! trait and never a change to the cryptography.

use crate::{aead, Error, Key32, MasterKey, Nonce, Result, WrapKey};

const MAGIC: &[u8; 6] = b"SBAEMK";
const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 6 + 2 + 1 + 4 + aead::NONCE_LEN;

/// Which backend produced a sealed master key. Recorded so that a store can refuse to be
/// opened by the wrong backend with a clear error instead of an opaque decryption failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SealKind {
    Keyfile = 1,
}

impl SealKind {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Keyfile),
            other => Err(Error::UnsupportedSeal(format!("kind {other}"))),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keyfile => "keyfile",
        }
    }
}

/// A source of the key-encryption key that protects the master key at rest.
pub trait Seal: Send + Sync {
    fn kind(&self) -> SealKind;

    /// Produce the key-encryption key. For a keyfile this derives from file contents; for a
    /// future TPM backend this would ask the TPM to unseal it.
    fn wrap_key(&self) -> Result<WrapKey>;
}

/// The master key as stored in the database `meta` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedMasterKey {
    pub kind: SealKind,
    pub generation: u32,
    nonce: Nonce,
    ciphertext: Vec<u8>,
}

impl SealedMasterKey {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(self.nonce.as_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= HEADER_LEN || &bytes[..6] != MAGIC {
            return Err(Error::Malformed {
                what: "sealed master key",
                expected: HEADER_LEN + 1,
                found: bytes.len(),
            });
        }

        let format_version = u16::from_le_bytes([bytes[6], bytes[7]]);
        if format_version != FORMAT_VERSION {
            return Err(Error::SealVersion { found: format_version, supported: FORMAT_VERSION });
        }

        Ok(Self {
            kind: SealKind::from_u8(bytes[8])?,
            generation: u32::from_le_bytes(bytes[9..13].try_into().expect("4 bytes")),
            nonce: Nonce::from_slice(&bytes[13..HEADER_LEN])?,
            ciphertext: bytes[HEADER_LEN..].to_vec(),
        })
    }
}

/// Wrap `master` for storage. The generation is authenticated, so a sealed key cannot be
/// rolled back to an earlier generation without detection.
pub fn seal_master(
    backend: &dyn Seal,
    master: &MasterKey,
    generation: u32,
) -> Result<SealedMasterKey> {
    let kek = backend.wrap_key()?;
    let aad = seal_aad(backend.kind(), generation);
    let (nonce, ciphertext) = aead::seal(kek.raw(), &aad, master.raw().expose())?;
    Ok(SealedMasterKey { kind: backend.kind(), generation, nonce, ciphertext })
}

pub fn unseal_master(backend: &dyn Seal, sealed: &SealedMasterKey) -> Result<MasterKey> {
    if backend.kind() != sealed.kind {
        return Err(Error::UnsupportedSeal(format!(
            "store was sealed with {}, this daemon is configured for {}",
            sealed.kind.as_str(),
            backend.kind().as_str()
        )));
    }

    let kek = backend.wrap_key()?;
    let aad = seal_aad(sealed.kind, sealed.generation);
    let material = aead::open(kek.raw(), &sealed.nonce, &aad, &sealed.ciphertext)?;
    let bytes: [u8; 32] = material.expose().try_into().map_err(|_| Error::Malformed {
        what: "master key",
        expected: 32,
        found: material.len(),
    })?;
    Ok(MasterKey::new(Key32::from_bytes(bytes)))
}

fn seal_aad(kind: SealKind, generation: u32) -> [u8; 5] {
    let mut aad = [0u8; 5];
    aad[0] = kind as u8;
    aad[1..].copy_from_slice(&generation.to_le_bytes());
    aad
}

/// Derives the key-encryption key from the contents of a root-owned keyfile.
///
/// Reading the file, and enforcing that it is `0400 root:root`, is the daemon's job -- this
/// crate stays free of I/O so it remains testable on any platform.
pub struct KeyfileSeal {
    material: Key32,
}

impl KeyfileSeal {
    /// Number of hex characters in a well-formed keyfile.
    pub const HEX_LEN: usize = 64;

    /// Parse keyfile contents. Hex rather than raw bytes because operators copy, back up and
    /// paste these, and binary survives none of those intact.
    pub fn from_hex(contents: &str) -> Result<Self> {
        let trimmed = contents.trim();
        if trimmed.len() != Self::HEX_LEN {
            return Err(Error::Malformed {
                what: "keyfile (expected 64 hex characters)",
                expected: Self::HEX_LEN,
                found: trimmed.len(),
            });
        }

        let mut bytes = [0u8; 32];
        hex::decode_to_slice(trimmed, &mut bytes).map_err(|_| Error::Malformed {
            what: "keyfile (not valid hex)",
            expected: Self::HEX_LEN,
            found: trimmed.len(),
        })?;

        Ok(Self { material: Key32::from_bytes(bytes) })
    }

    /// Fresh keyfile contents for `secretbae init`, ready to write to disk.
    pub fn generate_hex() -> Result<String> {
        Ok(hex::encode(Key32::generate()?.expose()))
    }
}

impl Seal for KeyfileSeal {
    fn kind(&self) -> SealKind {
        SealKind::Keyfile
    }

    fn wrap_key(&self) -> Result<WrapKey> {
        Ok(WrapKey::new(crate::kdf::derive(
            self.material.expose(),
            b"secretbae/kek/v1",
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> KeyfileSeal {
        KeyfileSeal::from_hex(&"ab".repeat(32)).unwrap()
    }

    #[test]
    fn round_trip_through_bytes() {
        let master = MasterKey::generate().unwrap();
        let sealed = seal_master(&backend(), &master, 1).unwrap();

        let decoded = SealedMasterKey::from_bytes(&sealed.to_bytes()).unwrap();
        assert_eq!(decoded, sealed);

        let recovered = unseal_master(&backend(), &decoded).unwrap();
        assert_eq!(recovered.raw().expose(), master.raw().expose());
    }

    #[test]
    fn a_different_keyfile_cannot_unseal() {
        let sealed = seal_master(&backend(), &MasterKey::generate().unwrap(), 1).unwrap();
        let wrong = KeyfileSeal::from_hex(&"cd".repeat(32)).unwrap();
        assert!(unseal_master(&wrong, &sealed).is_err());
    }

    #[test]
    fn rejects_generation_rollback() {
        let mut sealed = seal_master(&backend(), &MasterKey::generate().unwrap(), 4).unwrap();
        sealed.generation = 3;
        assert!(unseal_master(&backend(), &sealed).is_err());
    }

    #[test]
    fn rejects_malformed_keyfiles() {
        assert!(KeyfileSeal::from_hex("").is_err());
        assert!(KeyfileSeal::from_hex("zz").is_err());
        assert!(KeyfileSeal::from_hex(&"zz".repeat(32)).is_err(), "non-hex of the right length");
        assert!(KeyfileSeal::from_hex(&"ab".repeat(31)).is_err(), "too short");
    }

    #[test]
    fn generated_keyfile_is_accepted_and_whitespace_tolerant() {
        let generated = KeyfileSeal::generate_hex().unwrap();
        assert_eq!(generated.len(), KeyfileSeal::HEX_LEN);
        assert!(KeyfileSeal::from_hex(&format!("  {generated}\n")).is_ok());
    }

    #[test]
    fn rejects_truncated_or_corrupt_encoding() {
        let sealed = seal_master(&backend(), &MasterKey::generate().unwrap(), 1).unwrap();
        let bytes = sealed.to_bytes();
        assert!(SealedMasterKey::from_bytes(&bytes[..HEADER_LEN]).is_err());

        let mut wrong_magic = bytes.clone();
        wrong_magic[0] = b'X';
        assert!(SealedMasterKey::from_bytes(&wrong_magic).is_err());
    }
}
