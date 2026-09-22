//! Loading the seal keyfile, and refusing to run if its permissions are wrong.
//!
//! The keyfile is the only thing standing between an on-disk store and its plaintext, so its
//! mode is treated as part of the security contract rather than as advice. A daemon that
//! started anyway after finding a world-readable master key would be lying about its own
//! threat model.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use sbae_core::KeyfileSeal;
use zeroize::Zeroize;

use crate::{DaemonError, Result};

/// Permission bits a keyfile may have: owner read, optionally owner write. Anything for group
/// or other is a hard failure.
const ALLOWED_MODE_BITS: u32 = 0o600;

/// Read and validate the keyfile, returning a seal backend.
///
/// Must be called while still root, before privileges are dropped.
pub fn load(path: &Path) -> Result<KeyfileSeal> {
    let metadata = fs::metadata(path).map_err(|source| DaemonError::Keyfile {
        path: path.display().to_string(),
        reason: format!("cannot be read: {source}"),
    })?;

    check_permissions(path, metadata.mode(), metadata.uid())?;

    let mut contents = fs::read_to_string(path).map_err(|source| DaemonError::Keyfile {
        path: path.display().to_string(),
        reason: format!("cannot be read: {source}"),
    })?;

    let backend = KeyfileSeal::from_hex(&contents).map_err(|source| DaemonError::Keyfile {
        path: path.display().to_string(),
        reason: source.to_string(),
    });

    contents.zeroize();
    backend
}

/// Reject a keyfile readable by anyone but its owner, or owned by anyone but root.
fn check_permissions(path: &Path, mode: u32, uid: u32) -> Result<()> {
    let permissions = mode & 0o777;

    if permissions & !ALLOWED_MODE_BITS != 0 {
        return Err(DaemonError::Keyfile {
            path: path.display().to_string(),
            reason: format!(
                "has mode {permissions:04o}; it must not be readable or writable by group or \
                 other. Run: chmod 0400 {}",
                path.display()
            ),
        });
    }

    if uid != 0 {
        return Err(DaemonError::Keyfile {
            path: path.display().to_string(),
            reason: format!("is owned by uid {uid}; it must be owned by root"),
        });
    }

    Ok(())
}

/// Write a freshly generated keyfile, refusing to overwrite an existing one.
///
/// Created with mode 0400 before any content is written, so the secret is never briefly
/// visible at a wider mode.
pub fn create(path: &Path) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if path.exists() {
        return Err(DaemonError::Keyfile {
            path: path.display().to_string(),
            reason: "already exists; refusing to overwrite it, which would make every secret \
                     in the store permanently unreadable"
                .to_owned(),
        });
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut material = KeyfileSeal::generate_hex().map_err(|source| DaemonError::Keyfile {
        path: path.display().to_string(),
        reason: source.to_string(),
    })?;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;

    let result = file.write_all(material.as_bytes()).and_then(|()| file.sync_all());
    material.zeroize();
    result?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_keyfile_readable_by_group_or_other_is_refused() {
        for mode in [0o440, 0o444, 0o644, 0o604, 0o777] {
            assert!(
                check_permissions(Path::new("/etc/secretbae/master.key"), mode, 0).is_err(),
                "mode {mode:04o} should be refused"
            );
        }
    }

    #[test]
    fn owner_only_modes_are_accepted() {
        for mode in [0o400, 0o600] {
            assert!(
                check_permissions(Path::new("/etc/secretbae/master.key"), mode, 0).is_ok(),
                "mode {mode:04o} should be accepted"
            );
        }
    }

    #[test]
    fn a_keyfile_not_owned_by_root_is_refused() {
        assert!(check_permissions(Path::new("/etc/secretbae/master.key"), 0o400, 1000).is_err());
    }

    /// The mode check must ignore the file-type bits `stat` reports alongside permissions.
    #[test]
    fn file_type_bits_do_not_affect_the_decision() {
        assert!(check_permissions(Path::new("k"), 0o100_400, 0).is_ok());
    }

    #[test]
    fn creating_a_keyfile_twice_is_refused() {
        let dir = std::env::temp_dir().join(format!("sbae-keyfile-{}", std::process::id()));
        let path = dir.join("master.key");
        let _ = fs::remove_dir_all(&dir);

        create(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
        assert!(create(&path).is_err(), "overwriting would orphan every stored secret");

        let _ = fs::remove_dir_all(&dir);
    }
}
