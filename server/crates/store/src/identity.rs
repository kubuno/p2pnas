//! Node identity: an auto-generated 32-byte data key, persisted to a plain file
//! whose only protection is filesystem permissions (`0600` file inside a `0700`
//! directory). It is NOT wrapped by a passphrase or a hardware key: anyone able
//! to read that file as the service user, or to read a backup of it, holds every
//! secret of the node. Treat the file as the crown jewel it is.
//!
//! Decision 2A: the node has a single content key; per-user isolation is logical.
//! From it we derive the per-file content subkeys (see core), the SQLCipher key
//! for the manifest, and a stable peer id.

use std::path::Path;

use p2pnas_core::crypto::{DataKey, Zeroize, Zeroizing, KEY_LEN};

use crate::error::{Result, StoreError};

pub struct NodeIdentity {
    pub data_key:         DataKey,
    pub manifest_key_hex: String,
    pub peer_id:          String,
}

impl Drop for NodeIdentity {
    fn drop(&mut self) {
        // The SQLCipher key lives here as hex text, so it is as sensitive as the
        // raw key `DataKey` already wipes. Clones handed to `Manifest` outlive
        // this and are the manifest layer's responsibility.
        self.manifest_key_hex.zeroize();
    }
}

impl NodeIdentity {
    /// Load the node key from `<dir>/identity.key`, generating it on first run.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        create_dir_protected(dir)?;
        let key_path = dir.join("identity.key");

        let raw: Zeroizing<[u8; KEY_LEN]> = if key_path.exists() {
            check_key_perms(&key_path)?;
            let bytes = Zeroizing::new(std::fs::read(&key_path)?);
            if bytes.len() != KEY_LEN {
                return Err(StoreError::Integrity("identity.key has wrong length".into()));
            }
            let mut k = Zeroizing::new([0u8; KEY_LEN]);
            k[..].copy_from_slice(&bytes[..]);
            k
        } else {
            // OsRng via core's DataKey::random, then persist.
            let dk = DataKey::random();
            let k = Zeroizing::new(*dk.as_bytes());
            write_protected(&key_path, &k[..])?;
            k
        };

        let data_key = DataKey::from_bytes(*raw);
        // SQLCipher key (hex) and peer id, both derived (never the raw node key).
        let manifest_key_hex = hex::encode(&data_key.derive_raw(b"p2pnas/manifest/v1")?[..]);
        let peer_id = hex::encode(&data_key.derive_raw(b"p2pnas/peer-id/v1")?[..16]);

        Ok(NodeIdentity { data_key, manifest_key_hex, peer_id })
    }
}

/// Create the identity directory with `0700` and tighten it if it already exists:
/// `create_dir_all` alone applies the process umask, which on most distributions
/// leaves `0755` — world-traversable, so any local user can stat the key file and
/// watch it appear.
#[cfg(unix)]
fn create_dir_protected(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn create_dir_protected(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// Refuse to start on a key file readable beyond its owner. A restore, an `rsync
/// -a` from another box or a `cp` under a loose umask silently widens the mode,
/// and the node would happily keep serving with its master key world-readable.
#[cfg(unix)]
fn check_key_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(StoreError::Integrity(format!(
            "{} is accessible beyond its owner (mode {:04o}); refusing to start — \
             fix it with `chmod 600 {}` and rotate the node key if it may have leaked",
            path.display(),
            mode,
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_protected(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    // Without this, a crash between write and writeback can leave a zero-length
    // or truncated key file — and a lost node key means every file and the whole
    // manifest are permanently unreadable. Durability here is not optional.
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_protected(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique scratch directory; the tests never touch a database.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("p2pnas-identity-test-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn generated_key_is_stable_across_loads() {
        let dir = scratch("stable");
        let a = NodeIdentity::load_or_create(&dir).unwrap();
        let b = NodeIdentity::load_or_create(&dir).unwrap();
        assert_eq!(a.peer_id, b.peer_id);
        assert_eq!(a.manifest_key_hex, b.manifest_key_hex);
        // 32 derived bytes rendered as hex.
        assert_eq!(a.manifest_key_hex.len(), KEY_LEN * 2);
        assert_eq!(a.peer_id.len(), 32);
        // The derived secrets must never be the node key itself.
        assert_ne!(a.manifest_key_hex, hex::encode(a.data_key.as_bytes()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("dirmode");
        NodeIdentity::load_or_create(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "identity directory must not be group/world accessible");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn loose_key_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        NodeIdentity::load_or_create(&dir).unwrap();

        let key_path = dir.join("identity.key");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(NodeIdentity::load_or_create(&dir).is_err());

        // Back to owner-only: the node starts again.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(NodeIdentity::load_or_create(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_key_file_is_rejected() {
        let dir = scratch("truncated");
        create_dir_protected(&dir).unwrap();
        write_protected(&dir.join("identity.key"), &[0u8; 8]).unwrap();
        assert!(NodeIdentity::load_or_create(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
