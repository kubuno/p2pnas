//! Local shard store: raw erasure shards on disk, addressed by fragment id.
//! Files are fanned out into 256 sub-directories (first hex byte) to keep
//! directory sizes reasonable. In phase 3 most shards move to remote peers; the
//! local store keeps this node's own hosted shards.

use std::path::{Path, PathBuf};

use crate::error::{Result, StoreError};

/// A fragment id is `blake3(...)[..16]` hex-encoded (see `manifest::fragment_id`):
/// exactly 32 lowercase hex characters, always. Anything else is either a bug or,
/// far more dangerously, a path-traversal attempt — the id reaches this store
/// straight from the P2P wire (`GetShard`/`StoreShard`/`DeleteShard`), so a value
/// like `/…/identity/identity.key` or `../manifest.db` would otherwise let an
/// unauthenticated peer read the node's master key or overwrite arbitrary files
/// (`Path::join` with an absolute component silently replaces the base). We
/// therefore refuse any id that is not this exact shape, before it ever touches
/// a path.
fn is_valid_fragment_id(fragment_id: &str) -> bool {
    fragment_id.len() == 32
        && fragment_id.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Clone)]
pub struct ChunkStore {
    root: PathBuf,
}

impl ChunkStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ChunkStore { root: root.into() }
    }

    /// Fallible on purpose: callers must handle a rejected id rather than get a
    /// silently attacker-controlled path. Only the two-char fan-out prefix and
    /// the id itself compose the path, both proven hex here.
    fn path(&self, fragment_id: &str) -> Result<PathBuf> {
        if !is_valid_fragment_id(fragment_id) {
            return Err(StoreError::InvalidFragmentId);
        }
        let prefix = &fragment_id[0..2];
        Ok(self.root.join(prefix).join(fragment_id))
    }

    pub fn write(&self, fragment_id: &str, data: &[u8]) -> Result<()> {
        let p = self.path(fragment_id)?;
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(p, data)?;
        Ok(())
    }

    pub fn read(&self, fragment_id: &str) -> Result<Vec<u8>> {
        std::fs::read(self.path(fragment_id)?).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound
            } else {
                StoreError::Io(e)
            }
        })
    }

    pub fn delete(&self, fragment_id: &str) -> Result<()> {
        match std::fs::remove_file(self.path(fragment_id)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    pub fn exists(&self, fragment_id: &str) -> bool {
        // An invalid id cannot name a stored shard: report absence rather than
        // probing a bogus path.
        match self.path(fragment_id) {
            Ok(p) => Path::new(&p).exists(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_absolute_ids() {
        let bad = [
            "/var/lib/kubuno/modules/p2pnas/identity/identity.key",
            "./../identity/identity.key",
            "../manifest.db",
            "abc",                                   // too short
            "",                                      // empty
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",       // 32 non-hex
            "0123456789abcdef0123456789abcdef0",     // 33 chars
        ];
        for id in bad {
            assert!(!is_valid_fragment_id(id), "should reject {id:?}");
        }
    }

    #[test]
    fn accepts_real_fragment_ids() {
        // Shape produced by `manifest::fragment_id`.
        assert!(is_valid_fragment_id("0123456789abcdef0123456789abcdef"));
    }
}
