//! Reed-Solomon erasure coding (SIMD).
//!
//! Uses `reed-solomon-simd` (AVX2/SSSE3/NEON) instead of ptopnas's software
//! `reed-solomon-erasure`. Default scheme: 10 data + 4 parity = any 4 of 14
//! shards may be lost.

use crate::error::CoreError;

pub const DATA_SHARDS: usize = 10;
pub const PARITY_SHARDS: usize = 4;
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

/// reed-solomon-simd requires each shard to be a non-zero multiple of 64 bytes.
fn shard_len(cipher_len: usize) -> usize {
    let per = cipher_len.div_ceil(DATA_SHARDS).max(64);
    per.div_ceil(64) * 64
}

/// Filesystem block size assumed for storage accounting.
///
/// Each shard is stored as its OWN file, so it occupies whole filesystem blocks:
/// a 128-byte shard still consumes a full 4 KiB block. Counting the logical shard
/// length instead under-reports the real footprint by up to ~32× for tiny files,
/// which let the node believe it had far more free capacity than it did — and let
/// a host accept more than it could actually hold. 4096 is the near-universal
/// default (ext4/xfs/btrfs); the correction matters for small shards, where the
/// error was huge, and is negligible for large ones whatever the true block size.
pub const STORAGE_BLOCK_SIZE: usize = 4096;

/// Real bytes a shard of `shard_len` occupies on disk: its length rounded up to
/// whole filesystem blocks, since every shard is a separate file.
pub fn shard_disk_cost(shard_len: usize) -> usize {
    shard_len.div_ceil(STORAGE_BLOCK_SIZE) * STORAGE_BLOCK_SIZE
}

/// Stripe `cipher` (ciphertext||tag) into `DATA_SHARDS` equal padded shards.
fn data_shards(cipher: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let sl = shard_len(cipher.len());
    let mut padded = vec![0u8; sl * DATA_SHARDS];
    padded[..cipher.len()].copy_from_slice(cipher);
    let shards = padded.chunks_exact(sl).map(|c| c.to_vec()).collect();
    (shards, sl)
}

/// Zero-copy encode: the `DATA_SHARDS` data shards are **slices of `cipher`**
/// (the sealed buffer is kept as-is and striped on the fly), so we only allocate
/// the `PARITY_SHARDS` recovery shards. Returns `(shard_len, recovery_shards)`.
///
/// This replaces the allocation-heavy `encode` on the hot path: it avoids the
/// padded copy + 10 per-shard `to_vec` that triggered `mmap`/page-zeroing churn.
pub fn encode_recovery(cipher: &[u8]) -> Result<(usize, Vec<Vec<u8>>), CoreError> {
    let sl = shard_len(cipher.len());
    let full = cipher.len() / sl; // # of shards fully covered by cipher
    let rem = cipher.len() - full * sl;

    // At most one partial shard needs a temp; trailing shards are all-zero pads.
    let zero = vec![0u8; sl];
    let mut partial = vec![0u8; sl];
    if rem > 0 {
        partial[..rem].copy_from_slice(&cipher[full * sl..]);
    }

    let originals = (0..DATA_SHARDS).map(|i| {
        if i < full {
            &cipher[i * sl..(i + 1) * sl]
        } else if i == full && rem > 0 {
            &partial[..]
        } else {
            &zero[..]
        }
    });

    let recovery = reed_solomon_simd::encode(DATA_SHARDS, PARITY_SHARDS, originals)
        .map_err(|e| CoreError::Erasure(e.to_string()))?;
    Ok((sl, recovery))
}

/// Borrow data shard `i` (a slice of `cipher`), or `None` past the end.
/// Used for distribution and reconstruction without copying the data shards.
pub fn data_shard(cipher: &[u8], sl: usize, i: usize) -> Option<&[u8]> {
    let start = i * sl;
    if start >= cipher.len() {
        return None;
    }
    Some(&cipher[start..((i + 1) * sl).min(cipher.len())])
}

/// Materialise all 14 shards (10 data + 4 parity). Convenience for tests and
/// non-hot paths — the hot pipeline uses `encode_recovery` instead.
pub fn encode(cipher: &[u8]) -> Result<Vec<Vec<u8>>, CoreError> {
    let (mut shards, _sl) = data_shards(cipher);
    let recovery = reed_solomon_simd::encode(DATA_SHARDS, PARITY_SHARDS, &shards)
        .map_err(|e| CoreError::Erasure(e.to_string()))?;
    shards.extend(recovery);
    Ok(shards)
}

/// Reconstruct the original `cipher` (length `cipher_len`) from any
/// `DATA_SHARDS` surviving shards. `present[i]` is `Some` if shard `i` is held.
pub fn reconstruct(present: &[Option<Vec<u8>>], cipher_len: usize) -> Result<Vec<u8>, CoreError> {
    // Fast path (the local, no-loss case): every data shard is present, so just
    // concatenate them and trim the padding — no RS decode needed.
    if present.iter().take(DATA_SHARDS).all(|s| s.is_some()) {
        let mut out = Vec::with_capacity(cipher_len);
        for s in present.iter().take(DATA_SHARDS) {
            out.extend_from_slice(s.as_ref().unwrap());
        }
        out.truncate(cipher_len);
        return Ok(out);
    }

    let original: Vec<(usize, &Vec<u8>)> = present
        .iter()
        .take(DATA_SHARDS)
        .enumerate()
        .filter_map(|(i, s)| s.as_ref().map(|v| (i, v)))
        .collect();
    let recovery: Vec<(usize, &Vec<u8>)> = present
        .iter()
        .skip(DATA_SHARDS)
        .enumerate()
        .filter_map(|(i, s)| s.as_ref().map(|v| (i, v)))
        .collect();

    let restored = reed_solomon_simd::decode(
        DATA_SHARDS,
        PARITY_SHARDS,
        original.iter().map(|(i, v)| (*i, v.as_slice())),
        recovery.iter().map(|(i, v)| (*i, v.as_slice())),
    )
    .map_err(|e| CoreError::Erasure(e.to_string()))?;

    // Reassemble data shards 0..DATA_SHARDS in order (present ones + restored).
    let sl = present
        .iter()
        .flatten()
        .map(|v| v.len())
        .next()
        .ok_or(CoreError::Erasure("no shards".into()))?;
    let mut out = vec![0u8; sl * DATA_SHARDS];
    for i in 0..DATA_SHARDS {
        let shard = present[i]
            .as_deref()
            .or_else(|| restored.get(&i).map(|v| v.as_slice()))
            .ok_or(CoreError::Erasure("missing data shard after decode".into()))?;
        out[i * sl..(i + 1) * sl].copy_from_slice(shard);
    }
    out.truncate(cipher_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_disk_cost_rounds_up_to_blocks() {
        // A tiny shard still costs a whole block — this is the ~32× under-count
        // the accounting fix is about.
        assert_eq!(shard_disk_cost(1), STORAGE_BLOCK_SIZE);
        assert_eq!(shard_disk_cost(128), STORAGE_BLOCK_SIZE);
        assert_eq!(shard_disk_cost(STORAGE_BLOCK_SIZE), STORAGE_BLOCK_SIZE);
        assert_eq!(shard_disk_cost(STORAGE_BLOCK_SIZE + 1), 2 * STORAGE_BLOCK_SIZE);
        // A full 4 MiB chunk's shard (~419 KiB) is already block-aligned enough
        // that the correction is under 0.8%.
        let big = shard_len(4 * 1024 * 1024 + 16);
        assert!(shard_disk_cost(big) as f64 <= big as f64 * 1.008);
    }

    #[test]
    fn roundtrip_with_four_losses() {
        let cipher: Vec<u8> = (0..100_003u32).map(|i| (i ^ (i >> 3)) as u8).collect();
        let shards = encode(&cipher).unwrap();
        assert_eq!(shards.len(), TOTAL_SHARDS);

        // Drop 4 arbitrary shards (the max tolerable).
        let mut present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for &i in &[0usize, 3, 9, 12] {
            present[i] = None;
        }
        let restored = reconstruct(&present, cipher.len()).unwrap();
        assert_eq!(restored, cipher);
    }
}
