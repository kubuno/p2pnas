# p2pnas — Phase 0 performance findings

> Goal: a content pipeline that is **very fast without weakening security**.
> ptopnas felt slow; P0 proves *why* and fixes the root causes. Measure first.

## Method
`cargo bench` (criterion) on the chunk pipeline, `RUSTFLAGS="-C target-cpu=native"`.
Reference box: **AMD Ryzen 5 5600X** (Zen 3, `aes`+`pclmulqdq`+`vaes`), 4 cores visible.
Two inputs: **incompressible** (≈ media / already-encrypted) and **compressible** (≈ logs / text).

## Diagnosis — the bottleneck was *around* the cipher, not the cipher
1. **Blind `zstd -3` on every chunk** (ptopnas) — caps the pipeline at ~1.7 GiB/s and
   wastes 100% CPU on incompressible data. → entropy-probe gate + fast level.
2. **Allocation-heavy erasure** — materialising 14 shards per chunk (`to_vec` ×10 +
   padded copy) triggered `mmap`/page-zeroing churn and **collapsed RS to 0.23 GiB/s**
   (vs 2.2 GiB/s for the RS math itself). → zero-copy striping (data shards are slices
   of the sealed buffer; only the 4 parity shards are allocated).
3. **RNG lock on the nonce** — `RandomizedNonceKey` takes aws-lc's RNG lock per seal,
   serialising threads and slowing even single-thread. → **deterministic counter nonce**
   (= chunk index under a per-file subkey): unique by construction, no RNG, no birthday
   bound.
4. **Software AES** is not the issue — aws-lc-rs (AES-NI/VAES) does ~3.9 GiB/s.

## Results (64 MiB, GiB/s, median)
| | ptopnas-style | p2pnas seq | p2pnas seq (no RS) | p2pnas parallel |
|---|---|---|---|---|
| incompressible | 1.46 | **1.63** | 3.26 | 1.05 |
| compressible | 3.93 | 4.88 | 5.03 | **9.75** |

Primitive: AEAD 4 MiB — aws-lc-rs **3.90 GiB/s** vs RustCrypto 1.48 GiB/s (**2.6×**).

## Takeaways
- **aws-lc-rs + in-place + deterministic nonce + zero-copy erasure** are kept — each is a
  measured win and none weakens the security model.
- On **compressible** data the pipeline is CPU-bound → data-parallelism scales (**2.5×**).
- On **incompressible** data the pipeline is **memory-bandwidth-bound** (RS streams the full
  chunk); naive per-chunk parallelism saturates RAM and can be *slower* than sequential on a
  4-core box. Next steps: bound the worker count, cut RS memory traffic, or pipeline the
  stages (encrypt while the next reads) rather than fan out per chunk. Expected to scale
  further on server CPUs with more cores / memory channels.

## Reproduce
```bash
RUSTFLAGS="-C target-cpu=native" cargo bench --bench pipeline
```
