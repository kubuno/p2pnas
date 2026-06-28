//! Orchestration: tie the core pipeline to the manifest + local shard store.
//! Synchronous (the server wraps these in `spawn_blocking`). No networking yet —
//! all 14 shards of every chunk are stored locally (phase 3 distributes them).

use chrono::Utc;
use rand::RngCore;

use p2pnas_core::{
    chunker::restore,
    erasure::{self, DATA_SHARDS, TOTAL_SHARDS},
    pipeline::{self, PipelineConfig},
};

use crate::{
    chunkstore::ChunkStore,
    error::{Result, StoreError},
    identity::NodeIdentity,
    manifest::{self, ChunkRow, FileRow, Manifest, ShardRow},
};

pub struct PushResult {
    pub file_id:      String,
    pub size:         i64,
    /// Actual bytes written to the local shard store (data + parity).
    pub stored_bytes: i64,
    /// Plaintext + stored bytes of the file this push overwrote (0 if new) — so
    /// the caller can adjust quota accounting by the net delta.
    pub replaced_size:   i64,
    pub replaced_stored: i64,
}

/// Encrypt + erasure-code `data` and store it for `user_id` under `path`.
/// Overwrites any existing file at the same path (a fresh `file_id` is minted so
/// the per-file subkey/nonce invariant always holds).
pub fn push(
    id: &NodeIdentity,
    manifest: &Manifest,
    store: &ChunkStore,
    user_id: &str,
    path: &str,
    data: &[u8],
) -> Result<PushResult> {
    let mut rnd = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let file_id = hex::encode(rnd);

    let chunks = pipeline::process(data, &id.data_key, file_id.as_bytes(), PipelineConfig::default())?;
    // Exact on-disk cost: each chunk stores 14 shards of `shard_len` bytes.
    let stored_bytes: i64 = chunks.iter().map(|c| (TOTAL_SHARDS * c.shard_len) as i64).sum();

    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;

    // Replace any previous version at this path (and free its shards).
    let (replaced_size, replaced_stored) = match manifest::get_file_by_path(&tx, user_id, path)? {
        Some(prev) => {
            for frag in manifest::delete_file(&tx, user_id, &prev.file_id)? {
                store.delete(&frag)?;
            }
            (prev.size, prev.stored_bytes)
        }
        None => (0, 0),
    };

    manifest::insert_file(
        &tx,
        &FileRow {
            file_id:      file_id.clone(),
            user_id:      user_id.to_string(),
            path:         path.to_string(),
            size:         data.len() as i64,
            stored_bytes,
            chunk_count:  chunks.len() as i64,
            created_at:   Utc::now().to_rfc3339(),
        },
    )?;

    for c in &chunks {
        let cid = manifest::chunk_id(&file_id, c.index);
        manifest::insert_chunk(
            &tx,
            &ChunkRow {
                chunk_id:      cid.clone(),
                file_id:       file_id.clone(),
                idx:           c.index as i64,
                nonce:         c.nonce.to_vec(),
                is_compressed: c.is_compressed,
                plaintext_len: c.plaintext_len as i64,
                cipher_len:    c.cipher.len() as i64,
                shard_len:     c.shard_len as i64,
            },
        )?;

        // 10 data shards (slices of the sealed buffer, padded to shard_len) + 4 parity.
        for i in 0..TOTAL_SHARDS {
            let frag = manifest::fragment_id(&cid, i);
            let bytes = if i < DATA_SHARDS {
                pad_shard(erasure::data_shard(&c.cipher, c.shard_len, i).unwrap_or(&[]), c.shard_len)
            } else {
                c.recovery[i - DATA_SHARDS].clone()
            };
            store.write(&frag, &bytes)?;
            let hash = manifest::shard_hash(&bytes);
            manifest::insert_shard(&tx, &ShardRow {
                fragment_id: frag, chunk_id: cid.clone(), shard_index: i as i64, location: "local".into(), hash,
            })?;
        }
    }

    tx.commit()?;
    Ok(PushResult { file_id, size: data.len() as i64, stored_bytes, replaced_size, replaced_stored })
}

/// Read + reconstruct + decrypt a file back to its plaintext bytes.
pub fn pull(id: &NodeIdentity, manifest: &Manifest, store: &ChunkStore, user_id: &str, file_id: &str) -> Result<Vec<u8>> {
    let conn = manifest.connect()?;
    let file = manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)?;
    let chunks = manifest::get_chunks(&conn, file_id)?;

    let sealer = id.data_key.file_subkey(file_id.as_bytes()).sealer()?;
    let mut out = Vec::with_capacity(file.size as usize);

    for c in &chunks {
        let shards = manifest::get_shards(&conn, &c.chunk_id)?;
        let mut present: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
        for s in &shards {
            if let Some(slot) = present.get_mut(s.shard_index as usize) {
                *slot = Some(store.read(&s.fragment_id)?);
            }
        }
        let mut cipher = erasure::reconstruct(&present, c.cipher_len as usize)?;
        let plain = sealer.open(c.idx as u64, &mut cipher)?;
        out.extend_from_slice(&restore(plain, c.is_compressed)?);
    }
    Ok(out)
}

pub fn list(manifest: &Manifest, user_id: &str) -> Result<Vec<FileRow>> {
    let conn = manifest.connect()?;
    manifest::list_files(&conn, user_id)
}

/// Delete a file; returns its manifest row (for quota accounting: size + stored).
pub fn delete(manifest: &Manifest, store: &ChunkStore, user_id: &str, file_id: &str) -> Result<FileRow> {
    let conn = manifest.connect()?;
    let file = manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)?;
    for frag in manifest::delete_file(&conn, user_id, file_id)? {
        store.delete(&frag)?;
    }
    Ok(file)
}

/// Metadata the async layer needs to fetch a file's shards (local or remote).
pub type ChunkShards = (ChunkRow, Vec<ShardRow>);

/// Read the file + per-chunk shard placement (without fetching shard bytes).
pub fn pull_plan(manifest: &Manifest, user_id: &str, file_id: &str) -> Result<(FileRow, Vec<ChunkShards>)> {
    let conn = manifest.connect()?;
    let file = manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)?;
    let chunks = manifest::get_chunks(&conn, file_id)?;
    let mut out = Vec::with_capacity(chunks.len());
    for c in chunks {
        let shards = manifest::get_shards(&conn, &c.chunk_id)?;
        out.push((c, shards));
    }
    Ok((file, out))
}

/// Reconstruct + decrypt a file from already-fetched shards. `present[i]` per
/// chunk is the bytes of shard `i` (or None if it couldn't be fetched); RS needs
/// at least `DATA_SHARDS` of the 14.
pub fn reassemble(
    id: &NodeIdentity,
    file_id: &str,
    chunks: Vec<(ChunkRow, Vec<Option<Vec<u8>>>)>,
) -> Result<Vec<u8>> {
    let sealer = id.data_key.file_subkey(file_id.as_bytes()).sealer()?;
    let mut out = Vec::new();
    for (c, present) in chunks {
        let mut cipher = erasure::reconstruct(&present, c.cipher_len as usize)?;
        let plain = sealer.open(c.idx as u64, &mut cipher)?;
        out.extend_from_slice(&restore(plain, c.is_compressed)?);
    }
    Ok(out)
}

// ── Folder-aware browsing (the Drive "My Cloud" mount) ───────────────────────

/// A directory's immediate children: explicit + implicit subfolders, and files.
pub struct DirListing {
    pub folders: Vec<String>, // full paths
    pub files:   Vec<FileRow>,
}

/// List the immediate children of directory `dir` ("" = root). Subfolders are the
/// union of explicit (mkdir'd) folders and those implied by nested file paths.
pub fn browse(manifest: &Manifest, user_id: &str, dir: &str) -> Result<DirListing> {
    use std::collections::BTreeSet;
    let conn = manifest.connect()?;
    let dir = dir.trim_matches('/');

    let mut folders: BTreeSet<String> = manifest::folders_in(&conn, user_id, dir)?.into_iter().collect();
    let mut files = Vec::new();
    for f in manifest::list_files(&conn, user_id)? {
        let rel = if dir.is_empty() {
            Some(f.path.as_str())
        } else {
            f.path.strip_prefix(dir).and_then(|r| r.strip_prefix('/'))
        };
        let Some(rel) = rel else { continue };
        if rel.is_empty() {
            continue;
        }
        match rel.split_once('/') {
            Some((child, _)) => {
                let fp = if dir.is_empty() { child.to_string() } else { format!("{dir}/{child}") };
                folders.insert(fp);
            }
            None => files.push(f),
        }
    }
    Ok(DirListing { folders: folders.into_iter().collect(), files })
}

/// Look up a file row by its path (None if absent).
pub fn get_file_by_path(manifest: &Manifest, user_id: &str, path: &str) -> Result<Option<FileRow>> {
    let conn = manifest.connect()?;
    manifest::get_file_by_path(&conn, user_id, path)
}

/// Create a folder (and missing ancestors).
pub fn mkdir(manifest: &Manifest, user_id: &str, path: &str) -> Result<()> {
    let conn = manifest.connect()?;
    manifest::insert_folder(&conn, user_id, path.trim_matches('/'))
}

/// Rename or move a file or folder from `from` to `to` (path change only — no
/// re-encryption; file_ids and shards are untouched). Atomic.
pub fn rename(manifest: &Manifest, user_id: &str, from: &str, to: &str) -> Result<()> {
    let from = from.trim_matches('/');
    let to = to.trim_matches('/');
    if from.is_empty() || to.is_empty() || from == to {
        return Err(StoreError::NotFound);
    }
    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;

    // Ensure the destination's parent exists.
    manifest::insert_folder(&tx, user_id, manifest::dirname(to))?;

    if let Some(file) = manifest::get_file_by_path(&tx, user_id, from)? {
        // Single file.
        manifest::update_file_path(&tx, user_id, &file.file_id, to)?;
    } else {
        // Folder subtree: rewrite every file + folder path under the prefix.
        let files = manifest::files_under(&tx, user_id, from)?;
        let folders = manifest::folders_under(&tx, user_id, from)?;
        if files.is_empty() && folders.is_empty() {
            return Err(StoreError::NotFound);
        }
        for (file_id, path) in files {
            let suffix = &path[from.len()..]; // includes leading '/' (or empty if path==from)
            manifest::update_file_path(&tx, user_id, &file_id, &format!("{to}{suffix}"))?;
        }
        for path in folders {
            let suffix = &path[from.len()..];
            manifest::update_folder_path(&tx, user_id, &path, &format!("{to}{suffix}"))?;
        }
        manifest::insert_folder(&tx, user_id, to)?;
    }
    tx.commit()?;
    Ok(())
}

/// Delete a file or a folder subtree. Returns (plaintext_bytes, stored_bytes)
/// freed, for quota accounting.
pub fn delete_path(manifest: &Manifest, store: &ChunkStore, user_id: &str, path: &str) -> Result<(i64, i64)> {
    let path = path.trim_matches('/');
    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;

    let mut freed_size = 0i64;
    let mut freed_stored = 0i64;

    if let Some(file) = manifest::get_file_by_path(&tx, user_id, path)? {
        freed_size += file.size;
        freed_stored += file.stored_bytes;
        for frag in manifest::delete_file(&tx, user_id, &file.file_id)? {
            store.delete(&frag)?;
        }
    } else {
        let files = manifest::files_under(&tx, user_id, path)?;
        if files.is_empty() && !manifest::folder_exists(&tx, user_id, path)? {
            return Err(StoreError::NotFound);
        }
        for (file_id, _) in files {
            if let Some(f) = manifest::get_file(&tx, user_id, &file_id)? {
                freed_size += f.size;
                freed_stored += f.stored_bytes;
            }
            for frag in manifest::delete_file(&tx, user_id, &file_id)? {
                store.delete(&frag)?;
            }
        }
        manifest::delete_folder_subtree(&tx, user_id, path)?;
    }
    tx.commit()?;
    Ok((freed_size, freed_stored))
}

/// Every file across all users (node-wide repair/scrub).
pub fn list_all(manifest: &Manifest) -> Result<Vec<FileRow>> {
    let conn = manifest.connect()?;
    manifest::list_all_files(&conn)
}

/// Rebuild every shard of a chunk from the surviving ones. `present[i]` holds
/// shard `i`'s bytes (or None if it must be regenerated); RS needs ≥ DATA_SHARDS.
/// Returns the 14 shard byte-vectors in index order, byte-identical to the
/// originals (RS + padding are deterministic) — the repair path re-places only
/// the ones that were lost.
pub fn regen_chunk_shards(present: &[Option<Vec<u8>>], cipher_len: usize) -> Result<Vec<Vec<u8>>> {
    let cipher = erasure::reconstruct(present, cipher_len)?;
    Ok(erasure::encode(&cipher)?)
}

/// Write a shard into this node's local store.
pub fn write_local(store: &ChunkStore, fragment_id: &str, bytes: &[u8]) -> Result<()> {
    store.write(fragment_id, bytes)
}

/// Record a shard's new home ('local' or a peer_id) after distribution.
pub fn set_location(manifest: &Manifest, fragment_id: &str, location: &str) -> Result<()> {
    let conn = manifest.connect()?;
    manifest::set_shard_location(&conn, fragment_id, location)
}

/// Read a locally-held shard's bytes (None if absent).
pub fn read_local(store: &ChunkStore, fragment_id: &str) -> Option<Vec<u8>> {
    store.read(fragment_id).ok()
}

/// True if `bytes` match `expected` (empty `expected` = legacy row, skip check).
pub fn verify_hash(bytes: &[u8], expected: &str) -> bool {
    expected.is_empty() || manifest::shard_hash(bytes) == expected
}

/// Read a local shard and verify its content hash; None if missing or corrupt.
pub fn read_local_verified(store: &ChunkStore, fragment_id: &str, expected: &str) -> Option<Vec<u8>> {
    let bytes = store.read(fragment_id).ok()?;
    if verify_hash(&bytes, expected) {
        Some(bytes)
    } else {
        tracing::warn!(fragment_id, "local shard failed integrity check (corrupt) — treating as lost");
        None
    }
}

/// Pad a (possibly short, last) data-shard slice to the uniform shard length so
/// stored shards are RS-ready for later decode; full shards are returned as-is.
fn pad_shard(slice: &[u8], shard_len: usize) -> Vec<u8> {
    if slice.len() == shard_len {
        slice.to_vec()
    } else {
        let mut v = vec![0u8; shard_len];
        v[..slice.len()].copy_from_slice(slice);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_list_pull_delete_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("p2pnas-test-{}", std::process::id()));
        let id = NodeIdentity::load_or_create(&tmp.join("identity")).unwrap();
        let manifest = Manifest::new(tmp.join("manifest.db"), id.manifest_key_hex.clone());
        let store = ChunkStore::new(tmp.join("chunks"));

        let user = "11111111-1111-1111-1111-111111111111";
        let data: Vec<u8> = (0..5_000_003u32).map(|i| (i.wrapping_mul(2654435761)) as u8).collect();

        let res = push(&id, &manifest, &store, user, "docs/report.bin", &data).unwrap();
        assert_eq!(res.size, data.len() as i64);

        let files = list(&manifest, user).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "docs/report.bin");

        let got = pull(&id, &manifest, &store, user, &res.file_id).unwrap();
        assert_eq!(got, data);

        let freed = delete(&manifest, &store, user, &res.file_id).unwrap();
        assert_eq!(freed.size, data.len() as i64);
        assert!(list(&manifest, user).unwrap().is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
