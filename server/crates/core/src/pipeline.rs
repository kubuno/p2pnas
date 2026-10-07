//! The data-parallel upload pipeline.
//!
//! ptopnas processed chunks **sequentially on one core** (read → zstd-3 → AES-GCM
//! with a fresh allocation → RS). Here every chunk of a file flows through
//! `compress? → encrypt in-place → erasure-encode` **in parallel across all
//! cores** (rayon), sharing a single per-file AES key schedule.

use std::sync::Arc;

use rayon::prelude::*;

use crate::chunker::{maybe_compress, DEFAULT_CHUNK_SIZE, DEFAULT_ENTROPY_SKIP, FAST_ZSTD_LEVEL};
use crate::crypto::{DataKey, FileCipher, KeyScheme, NONCE_BYTES};
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

/// Run the full upload pipeline for one file, in parallel, under the **legacy
/// v1** scheme (node-wide subkey over the file id, empty AAD).
///
/// Kept byte-for-byte compatible for the read path and the benches; new writes
/// should call [`process_v2`].
pub fn process(
    data: &[u8],
    data_key: &DataKey,
    file_id: &[u8],
    cfg: PipelineConfig,
) -> Result<Vec<ProcessedChunk>, CoreError> {
    process_with_scheme(data, data_key, KeyScheme::V1, &[], file_id, cfg)
}

/// Run the pipeline under the **v2** scheme: the subkey is bound to `user_id`
/// and every chunk's tag authenticates (scheme, user, file, chunk_count, index).
///
/// Same output shape as [`process`] — only the key and the tag change — so the
/// storage layer stores it identically, plus the file's `key_scheme`.
pub fn process_v2(
    data: &[u8],
    data_key: &DataKey,
    user_id: &[u8],
    file_id: &[u8],
    cfg: PipelineConfig,
) -> Result<Vec<ProcessedChunk>, CoreError> {
    process_with_scheme(data, data_key, KeyScheme::V2, user_id, file_id, cfg)
}

/// Number of chunks [`process_with_scheme`] will produce for `len` bytes.
///
/// The v2 AAD binds the total chunk count, which must therefore be known *before*
/// sealing the first chunk — hence this closed form rather than a count taken
/// after the fact. It has to agree exactly with `par_chunks(chunk_size)`.
pub fn chunk_count_for(len: usize, chunk_size: usize) -> Result<u64, CoreError> {
    if chunk_size == 0 {
        return Err(CoreError::Crypto("chunk size must be non-zero"));
    }
    Ok(len.div_ceil(chunk_size) as u64)
}

/// Shared implementation of [`process`] / [`process_v2`].
pub fn process_with_scheme(
    data: &[u8],
    data_key: &DataKey,
    scheme: KeyScheme,
    user_id: &[u8],
    file_id: &[u8],
    cfg: PipelineConfig,
) -> Result<Vec<ProcessedChunk>, CoreError> {
    let chunk_count = chunk_count_for(data.len(), cfg.chunk_size)?;
    // One subkey + one key schedule (and, in v2, one precomputed AAD prefix) for
    // the whole file, shared read-only across worker threads (RNG-free, so no lock
    // contention). `par_chunks` streams the input without an upfront split copy.
    let cipher = Arc::new(FileCipher::new(data_key, scheme, user_id, file_id, chunk_count)?);

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
            let nonce = cipher.seal_chunk(&mut buf, index as u64)?;
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
        let sealer: ChunkSealer = key.file_subkey(file_id).unwrap().sealer().unwrap();
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

    /// v1 must keep producing the exact bytes it always did: the default path and
    /// the explicitly-v1 path have to be indistinguishable, ciphertext included.
    #[test]
    fn v1_output_is_unchanged_by_the_scheme_plumbing() {
        let key = DataKey::random();
        let data = vec![0x5Au8; 300_000];
        let cfg = PipelineConfig::default();
        let a = process(&data, &key, b"file-v1", cfg).unwrap();
        let b = process_with_scheme(&data, &key, KeyScheme::V1, b"ignored-user", b"file-v1", cfg)
            .unwrap();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.cipher, y.cipher);
            assert_eq!(x.nonce, y.nonce);
        }
    }

    /// Happy-path v2 reassembly, mirroring what `store::service` will do.
    fn reassemble_v2(
        user_id: &[u8],
        file_id: &[u8],
        key: &DataKey,
        chunks: &[ProcessedChunk],
    ) -> Result<Vec<u8>, CoreError> {
        let cipher = FileCipher::new(key, KeyScheme::V2, user_id, file_id, chunks.len() as u64)?;
        let mut out = Vec::new();
        for c in chunks {
            let mut buf = c.cipher.clone();
            let plain = cipher.open_chunk(c.index as u64, &mut buf)?;
            out.extend_from_slice(&restore(plain, c.is_compressed)?);
        }
        Ok(out)
    }

    #[test]
    fn pipeline_v2_roundtrip_and_owner_binding() {
        let key = DataKey::random();
        let data = vec![0xC3u8; 9 * 1024 * 1024 + 7]; // spans several chunks
        let cfg = PipelineConfig::default();
        let chunks = process_v2(&data, &key, b"user-a", b"file-3", cfg).unwrap();
        assert_eq!(chunks.len() as u64, chunk_count_for(data.len(), cfg.chunk_size).unwrap());
        assert_eq!(reassemble_v2(b"user-a", b"file-3", &key, &chunks).unwrap(), data);

        // Another user's identity must not open it, even with the right file id
        // and the same node key — this is the isolation the audit asked for.
        assert!(reassemble_v2(b"user-b", b"file-3", &key, &chunks).is_err());
        // Nor may a v1 reader: the schemes derive different subkeys.
        let count = chunks.len() as u64;
        let v1 = FileCipher::new(&key, KeyScheme::V1, b"user-a", b"file-3", count).unwrap();
        let mut buf = chunks[0].cipher.clone();
        assert!(v1.open_chunk(0, &mut buf).is_err());
    }

    /// Dropping the trailing chunks of a v2 file must not yield a valid short
    /// file: every tag asserts the total chunk count.
    #[test]
    fn pipeline_v2_rejects_truncation() {
        let key = DataKey::random();
        let data = vec![0x11u8; 9 * 1024 * 1024];
        let cfg = PipelineConfig::default();
        let chunks = process_v2(&data, &key, b"user-a", b"file-4", cfg).unwrap();
        assert!(chunks.len() >= 2, "test needs a multi-chunk file");

        let truncated = &chunks[..chunks.len() - 1];
        assert!(reassemble_v2(b"user-a", b"file-4", &key, truncated).is_err());
    }
}
