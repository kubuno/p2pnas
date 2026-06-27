//! P0 benchmark — proves the diagnosis: the bottleneck is *around* the cipher,
//! not the cipher. Compares, on 4 MiB / 64 MiB buffers:
//!   1. AEAD primitive: aws-lc-rs (in-place) vs RustCrypto aes-gcm (allocating).
//!   2. Compression policy: blind zstd-3 (ptopnas) vs entropy-gated.
//!   3. SIMD Reed-Solomon encode.
//!   4. Full pipeline: ptopnas-style (sequential, zstd-3, alloc) vs new
//!      (parallel, entropy-gated, in-place). Reported as throughput.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use p2pnas_core::{
    chunker::{maybe_compress, DEFAULT_ENTROPY_SKIP, FAST_ZSTD_LEVEL},
    crypto::DataKey,
    erasure,
    pipeline::{self, PipelineConfig},
};

/// New pipeline run SEQUENTIALLY (entropy-gate + aws-lc in-place + RS), no rayon,
/// no upfront split copy — isolates "is parallelism the regression?".
fn new_seq(data: &[u8], key: &DataKey, cfg: PipelineConfig) {
    let sealer = key.file_subkey(b"f").sealer().unwrap();
    for (i, chunk) in data.chunks(cfg.chunk_size).enumerate() {
        let (mut buf, _c) = maybe_compress(chunk.to_vec(), cfg.entropy_skip, cfg.zstd_level);
        sealer.seal(&mut buf, i as u64).unwrap();
        black_box(erasure::encode_recovery(&buf).unwrap()); // zero-copy data shards
    }
}

/// Sequential, but WITHOUT erasure — isolates the cost of the RS striping copies.
fn new_seq_no_rs(data: &[u8], key: &DataKey, cfg: PipelineConfig) {
    let sealer = key.file_subkey(b"f").sealer().unwrap();
    for (i, chunk) in data.chunks(cfg.chunk_size).enumerate() {
        let (mut buf, _c) = maybe_compress(chunk.to_vec(), cfg.entropy_skip, cfg.zstd_level);
        sealer.seal(&mut buf, i as u64).unwrap();
        black_box(&buf);
    }
}

const MIB: usize = 1024 * 1024;

/// Pseudo-random (incompressible) bytes — models already-compressed media.
fn incompressible(n: usize) -> Vec<u8> {
    (0..n as u64).map(|i| (i.wrapping_mul(6364136223846793005) >> 33) as u8).collect()
}

/// Highly compressible bytes — models logs / text / sparse data.
fn compressible(n: usize) -> Vec<u8> {
    let pattern = b"the quick brown fox jumps over the lazy dog 0123456789\n";
    (0..n).map(|i| pattern[i % pattern.len()]).collect()
}

// ── 1. AEAD primitive ────────────────────────────────────────────────────────
fn bench_aead(c: &mut Criterion) {
    let mut g = c.benchmark_group("aead_4MiB");
    g.throughput(Throughput::Bytes(4 * MIB as u64));
    let plain = incompressible(4 * MIB);

    let key = DataKey::random();
    let sealer = key.file_subkey(b"bench").sealer().unwrap();
    g.bench_function("aws-lc-rs in-place", |b| {
        b.iter_batched(
            || plain.clone(),
            |mut buf| {
                let n = sealer.seal(&mut buf, 0).unwrap();
                black_box((buf, n));
            },
            criterion::BatchSize::LargeInput,
        )
    });

    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    let rc_key = [0x42u8; 32];
    g.bench_function("RustCrypto alloc", |b| {
        b.iter(|| {
            let cipher = Aes256Gcm::new((&rc_key).into());
            let ct = cipher.encrypt(Nonce::from_slice(&[0u8; 12]), plain.as_ref()).unwrap();
            black_box(ct);
        })
    });
    g.finish();
}

// ── 2. Compression policy ────────────────────────────────────────────────────
fn bench_compression(c: &mut Criterion) {
    let mut g = c.benchmark_group("compress_4MiB");
    g.throughput(Throughput::Bytes(4 * MIB as u64));
    for (kind, data) in [("incompressible", incompressible(4 * MIB)), ("compressible", compressible(4 * MIB))] {
        g.bench_with_input(BenchmarkId::new("ptopnas zstd-3 always", kind), &data, |b, d| {
            b.iter(|| {
                let out = zstd::encode_all(d.as_slice(), 3).unwrap();
                black_box(out);
            })
        });
        g.bench_with_input(BenchmarkId::new("entropy-gated", kind), &data, |b, d| {
            b.iter_batched(
                || d.clone(),
                |buf| black_box(maybe_compress(buf, DEFAULT_ENTROPY_SKIP, FAST_ZSTD_LEVEL)),
                criterion::BatchSize::LargeInput,
            )
        });
    }
    g.finish();
}

// ── 3. SIMD Reed-Solomon ─────────────────────────────────────────────────────
fn bench_erasure(c: &mut Criterion) {
    let mut g = c.benchmark_group("rs_encode_4MiB");
    g.throughput(Throughput::Bytes(4 * MIB as u64));
    let cipher = incompressible(4 * MIB + 16);
    g.bench_function("reed-solomon-simd 10+4", |b| {
        b.iter(|| black_box(erasure::encode(&cipher).unwrap()))
    });
    g.finish();
}

// ── 4. Full pipeline (headline) ──────────────────────────────────────────────
/// ptopnas-style: sequential, blind zstd-3, RustCrypto allocating AES-GCM, RS.
fn ptopnas_style(data: &[u8], key: &[u8; 32]) {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    for chunk in data.chunks(4 * MIB) {
        let comp = zstd::encode_all(chunk, 3).unwrap();
        let payload = if comp.len() < chunk.len() { comp } else { chunk.to_vec() };
        let cipher = Aes256Gcm::new(key.into()); // fresh key schedule per chunk, like ptopnas
        let ct = cipher.encrypt(Nonce::from_slice(&[0u8; 12]), payload.as_ref()).unwrap();
        black_box(erasure::encode(&ct).unwrap());
    }
}

fn bench_pipeline(c: &mut Criterion) {
    let mut g = c.benchmark_group("pipeline_64MiB");
    g.sample_size(20);
    let size = 64 * MIB;
    g.throughput(Throughput::Bytes(size as u64));
    let key = DataKey::random();
    let rc_key = [0x42u8; 32];
    let cfg = PipelineConfig::default();

    for (kind, data) in [("incompressible", incompressible(size)), ("compressible", compressible(size))] {
        g.bench_with_input(BenchmarkId::new("ptopnas-style", kind), &data, |b, d| {
            b.iter(|| ptopnas_style(d, &rc_key))
        });
        g.bench_with_input(BenchmarkId::new("p2pnas seq", kind), &data, |b, d| {
            b.iter(|| new_seq(d, &key, cfg))
        });
        g.bench_with_input(BenchmarkId::new("p2pnas seq no-RS", kind), &data, |b, d| {
            b.iter(|| new_seq_no_rs(d, &key, cfg))
        });
        g.bench_with_input(BenchmarkId::new("p2pnas parallel", kind), &data, |b, d| {
            b.iter(|| black_box(pipeline::process(d, &key, b"f", cfg).unwrap()))
        });
    }
    g.finish();
}

criterion_group!(benches, bench_aead, bench_compression, bench_erasure, bench_pipeline);
criterion_main!(benches);
