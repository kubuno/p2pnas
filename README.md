<!--
  SPDX-FileCopyrightText: 2026 Kubuno contributors
  SPDX-License-Identifier: AGPL-3.0-or-later
-->

<div align="center">

<img src="https://raw.githubusercontent.com/kubuno/core/main/.github/logo.png" alt="Kubuno logo" width="120">

# Kubuno — P2P NAS

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-edition_2021-orange.svg)
![Module](https://img.shields.io/badge/Kubuno-module-4D38DB.svg)
![Status](https://img.shields.io/badge/status-alpha-yellow.svg)

**Encrypted, self-healing peer-to-peer storage for [Kubuno](https://github.com/kubuno/core) — the self-hosted, libre (AGPLv3) cloud platform, a sovereign alternative to Google Workspace and Microsoft 365.**

Each user gets a **"My Cloud"** space backed by storage shared across a *network of
acquaintances*: nodes that host each other's encrypted pieces, so a file survives
the loss of several of them. Administrators allocate per-user quotas.

</div>

---

## Features

- **"My Cloud" in Drive** — the storage appears inside [Drive](https://github.com/kubuno/drive) as a mount, not as a separate app: files are browsed, uploaded and shared like any other.
- **Encrypted end to end on the storage side** — AES-256-GCM, with a per-file key derived from a key tied to the file's owner; hosts only ever hold ciphertext.
- **Erasure coding** — Reed-Solomon 10 + 4: a file is split into 14 shards, any 10 of which rebuild it. Shards are spread across **failure zones**, not just across peers.
- **Self-healing** — lost or rotten shards are detected (silent disk corruption included) and rebuilt in the background; repairs do not restart when a peer is only briefly offline.
- **Fast reads** — a download does not wait for slow or offline peers once enough shards have arrived.
- **Space-efficient** — small files are packed instead of wasting whole shards, unchanged re-uploads are not stored twice, and compressible data takes less room on hosts.
- **Safe by design** — crash-safe overwrites, a trash for deleted files and folders, a short version history, and quotas that concurrent uploads cannot exceed.
- **Node resilience** — the node backs its own index up to its peers automatically, and can be backed up and restored, so a dead disk is not the end of its data.
- **Fair sharing** — space held for a long-absent peer is reclaimed gradually and reciprocally.
- **Hardened peer network** — peers must prove their identity, shards can only be read or deleted by their owner, the peer directory cannot be used to scan a private network, and the listener resists denial of service.
- **Administration** — node overview, per-user quotas and contribution, peers, maintenance and retention, all in the Kubuno admin console (Modules ▸ p2pnas).
- **Choose your database** — the control plane runs on PostgreSQL, MySQL/MariaDB or SQLite, like the rest of the platform.

## Architecture

```
core (kubuno/core)  ──proxy──►  kubuno-p2pnas (this repo, :3123)
                                  ├─ crates/core    chunker · crypto · erasure · pipeline
                                  ├─ crates/store   encrypted manifest (SQLCipher)
                                  ├─ crates/p2p     peer network, discovery, shard exchange
                                  └─ crates/server  Axum API, admin pages, registers with the core
```

- **In-process** pipeline and P2P network — no separate daemon.
- **One node identity** (a generated key); per-user isolation is logical (manifest namespace) and cryptographic (per-owner keys).
- **SQLCipher manifest** — the encrypted file / chunk / shard index, source of truth for the data.
- **Control plane** — quotas, peers, jobs and events in the `p2pnas` schema of the instance database.
- **Frontend** — `frontend/`: the "My Cloud" mount for Drive and the admin views, loaded at runtime by the core.

Performance findings for the core pipeline are in [`BENCHMARKS.md`](BENCHMARKS.md).

## Install

Modules install as a **Kubuno package (`.kbpkg`)** — a single, self-contained archive the Kubuno server unpacks itself (in pure Rust, identically on Linux, Windows and macOS).

```bash
bash build_kbpkg.sh --install        # build → install into the store → restart the core
```

Or install a prebuilt `.kbpkg`:

```bash
sudo kubuno modules:install dist/p2pnas-<version>-<os>-<arch>.kbpkg
sudo systemctl restart kubuno
```

A `.kbpkg` is attached to every tagged [GitHub Release](https://github.com/kubuno/p2pnas/releases).

## Build & development

**Requirements:** Rust ≥ 1.82, Node.js ≥ 24.

```bash
cargo test                                    # pipeline round-trips
RUSTFLAGS="-C target-cpu=native" cargo bench  # performance
cargo build --release --bin kubuno-p2pnas     # module binary
cd frontend && npm ci && npm run build        # runtime-loaded frontend
bash build_kbpkg.sh                           # → dist/p2pnas-<version>-<os>-<arch>.kbpkg
```

## Configuration

Copy `config.toml.example` → `config.toml`, or use environment variables. See `module.toml` for the manifest (id, port `3123`, admin pages, settings).

## Tech stack

Rust 2021 · Axum · Tokio · aws-lc-rs (AES-256-GCM) · Reed-Solomon SIMD · SQLCipher · SQLx (PostgreSQL · MySQL/MariaDB · SQLite) — React 19 · TypeScript · Vite.

## Security

Please report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md).

## Contributing

Issues and pull requests are welcome. For any significant change, please open an issue first.

## License

[AGPL-3.0-or-later](https://github.com/kubuno/core/blob/main/LICENSE) © Kubuno contributors.
