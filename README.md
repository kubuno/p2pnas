# p2pnas — Kubuno module

Encrypted, self-healing **peer-to-peer NAS** for Kubuno. Each user gets a
**"My Cloud"** backed by storage shared across a *network of acquaintances*;
admins allocate per-user quotas. Successor to the standalone `ptopnas` project.

## Architecture (decisions)
- **In-process** pipeline + P2P (no separate daemon).
- **One node identity** (auto-generated key); per-user isolation is *logical*
  (manifest namespace), not cryptographic.
- **SQLCipher manifest** = encrypted file/chunk/shard index (source of truth);
  **PostgreSQL `p2pnas` schema** = control plane (quotas, peers, jobs, events).
- Content crypto: **AES-256-GCM (aws-lc-rs)**, in-place, per-file HKDF subkey,
  deterministic counter nonce. Erasure: **Reed-Solomon SIMD 10+4**, zero-copy.

## Layout
```
crates/core      performance core: chunker, crypto, erasure, pipeline (P0)
crates/server    Kubuno module: Axum API on :3123, registers with the core (P1)
migrations/      PostgreSQL p2pnas schema
module.toml      module descriptor (id, port 3123, admin pages, events)
BENCHMARKS.md    P0 performance findings
```

## Status
- **P0 — perf core**: done (see `BENCHMARKS.md`). 9 tests, criterion benches.
- **P1 — module skeleton**: done. Registers with the core, PG schema, API
  (`/status`, `/quota/me`, `/admin/quotas`, `/admin/peers`).
- Next: P2 (local pipeline + manifest + "My Cloud" UI), P3 (P2P + quotas +
  resilience), P4 (settings), P5 (drive "storage provider" integration).

## Develop
```bash
cargo test                                   # core round-trips
RUSTFLAGS="-C target-cpu=native" cargo bench  # perf
cargo build --release --bin kubuno-p2pnas    # module binary
bash build_deb.sh                            # package (.deb)
```
