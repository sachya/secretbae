//! Envelope encryption for a single secret version.

use uuid::Uuid;

use crate::{aead, DataKey, Error, MasterKey, Nonce, Result, SecretBytes};

/// Identifies the slot a ciphertext belongs to, and is fed to the AEAD as associated data.
///
/// This is what stops an attacker with write access to the database from moving the
/// production database password's ciphertext into the development row: the bytes only
/// decrypt in the slot they were sealed for.
///
/// It binds the *immutable* `secret_id` rather than the path, so that renaming a secret
/// later can never orphan its own ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionBinding {
    pub secret_id: Uuid,
    pub version: u32,
}

impl VersionBinding {
    #[must_use]
    pub fn new(secret_id: Uuid, version: u32) -> Self {
        Self { secret_id, version }
    }

    fn payload_aad(&self) -> [u8; 20] {
        let mut aad = [0u8; 20];
        aad[..16].copy_from_slice(self.secret_id.as_bytes());
        aad[16..].copy_from_slice(&self.version.to_le_bytes());
        aad
    }

    /// The data key's wrap is additionally bound to the master-key generation, so a wrapped
    /// key from before a `rekey` cannot be replayed after one. The payload AAD deliberately
    /// omits the generation: rewrapping must not require re-encrypting the payload.
    fn wrap_aad(&self, mk_generation: u32) -> [u8; 24] {
        let mut aad = [0u8; 24];
        aad[..20].copy_from_slice(&self.payload_aad());
        aad[20..].copy_from_slice(&mk_generation.to_le_bytes());
        aad
    }
}

/// The wrapped data key, separated from the payload it opens.
///
/// Rotation needs only this. Keeping it its own type is what stops `rekey` from loading every
/// ciphertext in the store in order to rewrite 32 bytes -- the entire point of envelope
/// encryption is that it does not have to, and a flat struct made doing so the easy mistake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub wrapped_dek: Vec<u8>,
    pub dek_nonce: Nonce,
    pub mk_generation: u32,
}

impl WrappedKey {
    /// Move this key from one master key to another. The payload is not involved.
    pub fn rewrap(
        &mut self,
        old: &MasterKey,
        new: &MasterKey,
        new_generation: u32,
        binding: VersionBinding,
    ) -> Result<()> {
        let dek = self.open(old, binding)?;
        let (dek_nonce, wrapped_dek) = aead::seal(
            new.raw(),
            &binding.wrap_aad(new_generation),
            dek.raw().expose(),
        )?;

        self.wrapped_dek = wrapped_dek;
        self.dek_nonce = dek_nonce;
        self.mk_generation = new_generation;
        Ok(())
    }

    fn open(&self, master: &MasterKey, binding: VersionBinding) -> Result<DataKey> {
        let material = aead::open(
            master.raw(),
            &self.dek_nonce,
            &binding.wrap_aad(self.mk_generation),
            &self.wrapped_dek,
        )?;
        let bytes: [u8; 32] = material.expose().try_into().map_err(|_| Error::Malformed {
            what: "wrapped data key",
            expected: 32,
            found: material.len(),
        })?;
        Ok(DataKey::new(crate::Key32::from_bytes(bytes)))
    }
}

/// A secret version at rest: the ciphertext plus the wrapped key that opens it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedVersion {
    pub ciphertext: Vec<u8>,
    pub nonce: Nonce,
    pub key: WrappedKey,
}

impl SealedVersion {
    /// Encrypt `plaintext` under a freshly generated data key, itself wrapped by `master`.
    pub fn seal(
        master: &MasterKey,
        mk_generation: u32,
        binding: VersionBinding,
        plaintext: &[u8],
    ) -> Result<Self> {
        let dek = DataKey::generate()?;
        let (nonce, ciphertext) = aead::seal(dek.raw(), &binding.payload_aad(), plaintext)?;
        let (dek_nonce, wrapped_dek) = aead::seal(
            master.raw(),
            &binding.wrap_aad(mk_generation),
            dek.raw().expose(),
        )?;

        Ok(Self {
            ciphertext,
            nonce,
            key: WrappedKey { wrapped_dek, dek_nonce, mk_generation },
        })
    }

    pub fn open(&self, master: &MasterKey, binding: VersionBinding) -> Result<SecretBytes> {
        let dek = self.key.open(master, binding)?;
        aead::open(dek.raw(), &self.nonce, &binding.payload_aad(), &self.ciphertext)
    }

    /// Move this version from one master key to another without touching the payload.
    ///
    /// Prefer rotating [`WrappedKey`] directly where the ciphertext is not already at hand:
    /// loading a payload only to leave it untouched is what makes a rotation cost memory
    /// proportional to the size of the store.
    pub fn rewrap(
        &mut self,
        old: &MasterKey,
        new: &MasterKey,
        new_generation: u32,
        binding: VersionBinding,
    ) -> Result<()> {
        self.key.rewrap(old, new, new_generation, binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(version: u32) -> VersionBinding {
        VersionBinding::new(Uuid::from_u128(0xDEAD_BEEF), version)
    }

    fn master() -> MasterKey {
        MasterKey::new(crate::Key32::from_bytes([3u8; 32]))
    }

    #[test]
    fn round_trip() {
        let sealed = SealedVersion::seal(&master(), 1, binding(1), b"postgres://x").unwrap();
        assert_eq!(sealed.open(&master(), binding(1)).unwrap().expose(), b"postgres://x");
    }

    #[test]
    fn every_version_gets_a_distinct_data_key() {
        let a = SealedVersion::seal(&master(), 1, binding(1), b"same").unwrap();
        let b = SealedVersion::seal(&master(), 1, binding(2), b"same").unwrap();
        assert_ne!(a.key.wrapped_dek, b.key.wrapped_dek);
        assert_ne!(a.ciphertext, b.ciphertext, "identical plaintext must not yield identical bytes");
    }

    /// The headline property: ciphertext cannot be relocated to another slot.
    #[test]
    fn rejects_ciphertext_moved_to_another_version() {
        let sealed = SealedVersion::seal(&master(), 1, binding(7), b"prod-password").unwrap();
        assert!(sealed.open(&master(), binding(8)).is_err());
    }

    #[test]
    fn rejects_ciphertext_moved_to_another_secret() {
        let sealed = SealedVersion::seal(&master(), 1, binding(1), b"prod-password").unwrap();
        let other = VersionBinding::new(Uuid::from_u128(0x1234), 1);
        assert!(sealed.open(&master(), other).is_err());
    }

    #[test]
    fn rejects_tampered_payload_and_tampered_wrapped_key() {
        let pristine = SealedVersion::seal(&master(), 1, binding(1), b"v").unwrap();

        let mut ct_tampered = pristine.clone();
        ct_tampered.ciphertext[0] ^= 0x01;
        assert!(ct_tampered.open(&master(), binding(1)).is_err());

        let mut dek_tampered = pristine.clone();
        dek_tampered.key.wrapped_dek[0] ^= 0x01;
        assert!(dek_tampered.open(&master(), binding(1)).is_err());
    }

    #[test]
    fn rewrap_preserves_payload_and_invalidates_the_old_master() {
        let (old, new) = (master(), MasterKey::generate().unwrap());
        let mut sealed = SealedVersion::seal(&old, 1, binding(1), b"rotate-me").unwrap();
        let payload_before = sealed.ciphertext.clone();

        sealed.rewrap(&old, &new, 2, binding(1)).unwrap();

        assert_eq!(sealed.ciphertext, payload_before, "rewrap must not re-encrypt the payload");
        assert_eq!(sealed.open(&new, binding(1)).unwrap().expose(), b"rotate-me");
        assert!(sealed.open(&old, binding(1)).is_err(), "the retired master key must stop working");
    }
}
