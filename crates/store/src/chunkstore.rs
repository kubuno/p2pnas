//! Local shard store: raw erasure shards on disk, addressed by fragment id.
//! Files are fanned out into 256 sub-directories (first hex byte) to keep
//! directory sizes reasonable. In phase 3 most shards move to remote peers; the
//! local store keeps this node's own hosted shards.

use std::path::{Path, PathBuf};

use crate::error::{Result, StoreError};

#[derive(Clone)]
pub struct ChunkStore {
    root: PathBuf,
}

impl ChunkStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ChunkStore { root: root.into() }
    }

    fn path(&self, fragment_id: &str) -> PathBuf {
        let prefix = fragment_id.get(0..2).unwrap_or("00");
        self.root.join(prefix).join(fragment_id)
    }

    pub fn write(&self, fragment_id: &str, data: &[u8]) -> Result<()> {
        let p = self.path(fragment_id);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(p, data)?;
        Ok(())
    }

    pub fn read(&self, fragment_id: &str) -> Result<Vec<u8>> {
        std::fs::read(self.path(fragment_id)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound
            } else {
                StoreError::Io(e)
            }
        })
    }

    pub fn delete(&self, fragment_id: &str) -> Result<()> {
        match std::fs::remove_file(self.path(fragment_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    pub fn exists(&self, fragment_id: &str) -> bool {
        Path::new(&self.path(fragment_id)).exists()
    }
}
