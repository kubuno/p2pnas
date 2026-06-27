//! Chunking + *gated* compression.
//!
//! ptopnas ran `zstd::encode_all(level 3)` on **every** chunk — including already
//! compressed media, where it burns CPU for zero gain and caps the whole pipeline
//! at zstd's throughput. Here a cheap **entropy probe** on a small sample decides
//! whether compression is even worth attempting, and we use a fast level.

pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Fast zstd level used when the entropy probe says a chunk looks compressible.
pub const FAST_ZSTD_LEVEL: i32 = 1;

/// Bytes of a chunk sampled to estimate entropy (cheap, cache-friendly).
const ENTROPY_SAMPLE: usize = 16 * 1024;

/// Above this estimated entropy (bits/byte, 0..8) a chunk is treated as
/// incompressible and compression is skipped entirely.
pub const DEFAULT_ENTROPY_SKIP: f64 = 7.8;

/// Shannon entropy (bits per byte) of `sample`, in [0, 8].
pub fn sample_entropy(sample: &[u8]) -> f64 {
    if sample.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for &b in sample {
        hist[b as usize] += 1;
    }
    let len = sample.len() as f64;
    let mut h = 0.0;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Decide-and-compress. Takes ownership so the "skip" path is **zero-copy**
/// (returns the original buffer untouched). Returns `(buffer, is_compressed)`.
pub fn maybe_compress(data: Vec<u8>, entropy_skip: f64, level: i32) -> (Vec<u8>, bool) {
    let sample = &data[..data.len().min(ENTROPY_SAMPLE)];
    if sample_entropy(sample) >= entropy_skip {
        return (data, false); // incompressible — don't even try
    }
    match zstd::encode_all(&data[..], level) {
        Ok(c) if c.len() < data.len() => (c, true),
        _ => (data, false),
    }
}

/// Reverse of `maybe_compress`.
pub fn restore(data: &[u8], is_compressed: bool) -> std::io::Result<Vec<u8>> {
    if is_compressed {
        zstd::decode_all(data)
    } else {
        Ok(data.to_vec())
    }
}

/// Split a byte slice into owned 4 MiB chunks (one copy — models a disk read).
pub fn split_chunks(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    data.chunks(chunk_size).map(|c| c.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_data_high_entropy_skips_compression() {
        let data: Vec<u8> = (0..4096).map(|i| (i * 2654435761usize) as u8).collect();
        let (_, compressed) = maybe_compress(data, DEFAULT_ENTROPY_SKIP, FAST_ZSTD_LEVEL);
        // pseudo-random bytes should not be (uselessly) compressed
        assert!(!compressed);
    }

    #[test]
    fn repetitive_data_compresses() {
        let data = vec![7u8; 64 * 1024];
        let (out, compressed) = maybe_compress(data.clone(), DEFAULT_ENTROPY_SKIP, FAST_ZSTD_LEVEL);
        assert!(compressed);
        assert!(out.len() < data.len());
        assert_eq!(restore(&out, true).unwrap(), data);
    }

    #[test]
    fn entropy_bounds() {
        assert!(sample_entropy(&[]) == 0.0);
        assert!(sample_entropy(&[0u8; 1000]) < 0.001); // single symbol → ~0
    }
}
