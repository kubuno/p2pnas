//! The data-parallel upload pipeline.
//!
//! ptopnas processed chunks **sequentially on one core** (read → zstd-3 → AES-GCM
//! with a fresh allocation → RS). Here every chunk of a file flows through
//! `compress? → encrypt in-place → erasure-encode` **in parallel across all
//! cores** (rayon), sharing a single per-file AES key schedule.

use std::sync::Arc;

use rayon::prelude::*;

use crate::chunker::{maybe_compress, DEFAULT_CHUNK_SIZE, DEFAULT_ENTROPY_SKIP, FAST_ZSTD_LEVEL};
use crate::crypto::{DataKey, NONCE_BYTES};
use crate::erasure;
use crate::error::CoreError;

#[derive(Clone, Copy)]
pub struct PipelineConfig {
    pub chunk_size: usize,
    pub entropy_skip: f64,
    pub zstd_level: i32,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        PipelineConfig {
            chunk_size: DEFAULT_CHUNK_SIZE,
            entropy_skip: DEFAULT_ENTROPY_SKIP,
            zstd_level: FAST_ZSTD_LEVEL,
        }
    }
}

/// Output for one chunk. Zero-copy: `cipher` IS the 10 data shards (striped on
/// demand with `erasure::data_shard`); only the 4 `recovery` shards are newly
/// allocated. Plus the metadata needed to reverse the pipeline.
pub struct ProcessedChunk {
    pub index: usize,
    pub nonce: [u8; NONCE_BYTES],
    pub is_compressed: bool,
    /// Plaintext length of this chunk before compression/encryption.
    pub plaintext_len: usize,
    /// The sealed buffer (ciphertext||tag) = the data-shard region.
    pub cipher: Vec<u8>,
    /// Shard length (each data/recovery shard is exactly this many bytes).
    pub shard_len: usize,
    /// The 4 parity shards.
    pub recovery: Vec<Vec<u8>>,
}

/// Run the full upload pipeline for one file, in parallel.
pub fn process(
    data: &[u8],
    data_key: &DataKey,
    file_id: &[u8],
    cfg: PipelineConfig,
) -> Result<Vec<ProcessedChunk>, CoreError> {
    // One subkey + one key schedule for the whole file, shared read-only across
    // worker threads (RNG-free, so no lock contention). `par_chunks` streams the
    // input without an upfront split copy.
    let sealer = Arc::new(data_key.file_subkey(file_id).sealer()?);

    data.par_chunks(cfg.chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            let plaintext_len = chunk.len();
            // Own the chunk with room for the GCM tag already reserved, so the
            // in-place seal never reallocates the (4 MiB) buffer.
            let mut owned = Vec::with_capacity(chunk.len() + crate::crypto::TAG_LEN);
            owned.extend_from_slice(chunk);
            // 1. compress only if the entropy probe says it's worth it
            let (mut buf, is_compressed) = maybe_compress(owned, cfg.entropy_skip, cfg.zstd_level);
            // 2. encrypt in place under a deterministic per-chunk nonce
            let nonce = sealer.seal(&mut buf, index as u64)?;
            // 3. erasure: data shards stay as slices of `buf`, only parity is allocated
            let (shard_len, recovery) = erasure::encode_recovery(&buf)?;
            Ok(ProcessedChunk {
                index,
                nonce,
                is_compressed,
                plaintext_len,
                cipher: buf,
                shard_len,
                recovery,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunker::restore;
    use crate::crypto::ChunkSealer;

    // Happy path: all data shards are present (kept in `cipher`), so just open it.
    fn reassemble(file_id: &[u8], key: &DataKey, chunks: &[ProcessedChunk]) -> Vec<u8> {
        let sealer: ChunkSealer = key.file_subkey(file_id).sealer().unwrap();
        let mut out = Vec::new();
        for c in chunks {
            let mut cipher = c.cipher.clone();
            let plain = sealer.open(c.index as u64, &mut cipher).unwrap();
            out.extend_from_slice(&restore(plain, c.is_compressed).unwrap());
        }
        out
    }

    #[test]
    fn pipeline_roundtrip_compressible() {
        let key = DataKey::random();
        let data = vec![0xABu8; 9 * 1024 * 1024 + 123]; // compressible, spans chunks
        let cfg = PipelineConfig::default();
        let chunks = process(&data, &key, b"file-1", cfg).unwrap();
        assert!(chunks.iter().any(|c| c.is_compressed));
        assert_eq!(reassemble(b"file-1", &key, &chunks), data);
    }

    #[test]
    fn pipeline_roundtrip_incompressible() {
        let key = DataKey::random();
        let data: Vec<u8> = (0..5_000_000u32).map(|i| (i.wrapping_mul(2654435761)) as u8).collect();
        let cfg = PipelineConfig::default();
        let chunks = process(&data, &key, b"file-2", cfg).unwrap();
        assert!(chunks.iter().all(|c| !c.is_compressed)); // entropy probe skipped it
        assert_eq!(reassemble(b"file-2", &key, &chunks), data);
    }
}
