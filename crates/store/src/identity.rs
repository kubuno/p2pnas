//! Node identity: an auto-generated 32-byte data key, persisted protected.
//!
//! Decision 2A: the node has a single content key; per-user isolation is logical.
//! From it we derive the per-file content subkeys (see core), the SQLCipher key
//! for the manifest, and a stable peer id.

use std::path::Path;

use p2pnas_core::crypto::DataKey;

use crate::error::{Result, StoreError};

pub struct NodeIdentity {
    pub data_key:         DataKey,
    pub manifest_key_hex: String,
    pub peer_id:          String,
}

impl NodeIdentity {
    /// Load the node key from `<dir>/identity.key`, generating it on first run.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let key_path = dir.join("identity.key");

        let raw: [u8; 32] = if key_path.exists() {
            let bytes = std::fs::read(&key_path)?;
            bytes
                .try_into()
                .map_err(|_| StoreError::Integrity("identity.key has wrong length".into()))?
        } else {
            let mut k = [0u8; 32];
            // OsRng via core's DataKey::random, then persist.
            let dk = DataKey::random();
            k.copy_from_slice(dk.as_bytes());
            write_protected(&key_path, &k)?;
            k
        };

        let data_key = DataKey::from_bytes(raw);
        // SQLCipher key (hex) and peer id, both derived (never the raw node key).
        let manifest_key_hex = hex::encode(data_key.derive_raw(b"p2pnas/manifest/v1"));
        let peer_id = hex::encode(&data_key.derive_raw(b"p2pnas/peer-id/v1")[..16]);

        Ok(NodeIdentity { data_key, manifest_key_hex, peer_id })
    }
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
    Ok(())
}

#[cfg(not(unix))]
fn write_protected(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}
