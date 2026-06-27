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
            manifest::insert_shard(&tx, &ShardRow { fragment_id: frag, chunk_id: cid.clone(), shard_index: i as i64 })?;
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
