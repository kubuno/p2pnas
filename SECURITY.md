# Security Policy

Kubuno is a self-hosted platform that people run to hold their own data. We take
security reports seriously and are grateful to those who disclose responsibly.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through either channel:

- **GitHub Security Advisories** — use the *Report a vulnerability* button under
  the **Security** tab of this repository (preferred: it keeps the discussion
  private and lets us credit you).
- **Email** — `security@toiledev.com`. Encrypt with our PGP key if the details
  are sensitive (key fingerprint published at the project website).

Please include, as far as you can:

- the component and version (`/api/v1/health` reports the running version, or see
  `/etc/kubuno/VERSIONS` in a Docker install);
- a description of the issue and its impact;
- steps to reproduce, a proof of concept, or affected source locations;
- any suggested remediation.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | within **72 hours** |
| Initial assessment and severity triage | within **7 days** |
| Fix or mitigation plan communicated | within **30 days** |
| Public disclosure (coordinated) | after a fix is released, by agreement |

We will keep you informed of progress, credit you in the release notes and the
advisory unless you prefer to stay anonymous, and coordinate the disclosure
timeline with you.

## Threat model

p2pnas stores files by splitting them into chunks, **encrypting each chunk**, then
erasure-coding the ciphertext into 10 data + 4 parity shards and placing shards on
other nodes. The order matters: encryption happens *before* erasure coding, so a
shard never contains plaintext, only a slice of AES-256-GCM ciphertext.

This section states what that design does and does not defend against, so you can
judge whether it fits your situation. It describes the software as it is today,
not as it is meant to become.

### Protected against

- **A peer that hosts your shards.** Shards leave the node already encrypted with
  AES-256-GCM under a per-file subkey that never leaves the owning node. A host
  sees opaque bytes; even holding every shard of a chunk yields nothing without
  the key.
- **A peer that alters the shards it holds.** The manifest records a BLAKE3 hash
  for each shard. A modified shard fails that check on read (and its GCM tag would
  fail decryption anyway); the repair pass rebuilds it from the remaining shards.
- **A peer that loses or withholds data.** Liveness probes, proof-of-storage
  challenges and periodic repair detect missing shards and re-replicate them
  elsewhere. This is an availability property, not a confidentiality one.
- **Reading the node's disk *without* its key file.** The manifest is a SQLCipher
  database and locally stored shards are ciphertext; neither is readable without
  `identity.key`.
- **A stolen backup bundle.** The administrative backup export is sealed with a
  key derived from an operator-chosen passphrase (Argon2id), independent of the
  node key.

### Not protected against

- **The operator of the node.** This is the most important limitation. A node has
  **one content key** (`identity.key`); it encrypts the data of *every* user of
  the instance, and the manifest key is derived from it. Isolation between users
  is **logical** — a `user_id` filter in every manifest query — **not
  cryptographic**. Anyone who can read that file (the service user, root, or the
  holder of any copy of the data directory) can decrypt every account's files.
  If your threat model includes the person who runs the server, p2pnas as it
  stands is not the right tool.
- **Theft of the disk, or of an unprotected copy of the data directory.**
  `identity.key` lives in the same data directory as `manifest.db` and the local
  shards it protects, so a raw disk or filesystem-level backup carries the lock
  and the key together. Full-disk encryption on the node is what covers this; the
  file permissions set at install time are a local-user boundary, not an at-rest
  one.
- **Impersonation between peers.** Peers are **not yet cryptographically
  authenticated**. A peer id is simply a value claimed during the handshake;
  nothing binds it to a key pair, and no signature is verified. Trust in the peer
  set is currently administrative — an administrator adds the peers this node will
  deal with — and an attacker who can reach the peer-to-peer port and get itself
  into that list can be handed shards to host, and can answer for an id it does
  not own.
- **Observers of the peer-to-peer network.** The transport is plain TCP carrying
  length-prefixed JSON frames: **no TLS, no Noise handshake**. Shard payloads are
  ciphertext, but everything around them is in the clear — fragment identifiers,
  shard indexes and sizes, which node stores what for whom, and when it is read or
  written. Anyone on the path can therefore map storage relationships and observe
  access patterns even though they cannot read the contents. Run the peer-to-peer
  port over a network you trust, or tunnel it, if metadata matters to you.
- **A compromised core, or anything holding the module's internal secret.**
  The module authenticates callers from a token signed by the core with the shared
  internal secret. That secret is the whole boundary: whoever holds it can mint a
  token for any user, administrator included, and act as them.
- **Denying to a host that you store data with it.** Hosts record which owner peer
  id each shard belongs to; hosting relationships are not anonymous.

## Scope

In scope: the code in this repository and the official distributions we publish
(`.deb`, `.rpm`, Windows/macOS installers, the Docker image).

Out of scope: vulnerabilities in third-party dependencies already tracked
upstream (report those upstream; tell us if a pinned version leaves us exposed),
issues that require a compromised host or physical access, and findings against a
misconfigured deployment that departs from the hardening guidance in the docs.

## Supported versions

Security fixes land on the latest released minor version. Because Kubuno is a
polyrepo, each component (core and each module) is versioned and released
independently; report against the component and version where you observed the
issue.
