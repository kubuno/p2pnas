//! Cold-storage backup of the node's recovery secrets.
//!
//! The manifest (`manifest.db`, SQLCipher) is the ONLY source of the random
//! file ids, nonces, shard locations and hashes; without it the shards scattered
//! across peers are unreadable. And `identity.key` is the root from which the
//! manifest's key, every file subkey and the peer id derive. Together they are a
//! single point of failure: lose the node's disk and every user's data is gone,
//! even though ~10 of 14 shards per chunk still live on peers.
//!
//! This module produces a single encrypted bundle {identity.key + a consistent
//! manifest snapshot} that an administrator downloads and keeps OFF the node, and
//! restores onto a fresh machine. The bundle is sealed under an admin passphrase
//! (Argon2id → key → AES-256-GCM), so the downloaded file — which contains the
//! master key — is safe at rest wherever it is stored.
//!
//! Layout of the encrypted bundle:
//!   MAGIC(8) | VERSION(1) | SALT(16) | ciphertext(plaintext + 16-byte GCM tag)
//! Plaintext, once decrypted:
//!   identity_key(32) | manifest_len(u64 BE) | manifest_bytes
//!
//! The bottom half of this file implements the AUTOMATIC counterpart of the same
//! idea — a manifest snapshot erasure-coded onto the peers, with no human in the
//! loop and no passphrase. See the section header down there for its format.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use p2pnas_core::{
    crypto::{ChunkSealer, DataKey},
    erasure::{self, DATA_SHARDS, TOTAL_SHARDS},
};

use crate::{
    error::{Result, StoreError},
    manifest::{self, Manifest},
};

const MAGIC: &[u8; 8] = b"KBP2PBK1";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const IDENTITY_LEN: usize = 32;
/// Domain-separated info for the bundle subkey (distinct from file/manifest/peer).
const BUNDLE_INFO: &[u8] = b"p2pnas/backup-bundle/v1";
/// A short passphrase makes the whole cold backup worthless; refuse it.
const MIN_PASSPHRASE_LEN: usize = 12;

fn err(msg: &str) -> StoreError {
    StoreError::Integrity(msg.into())
}

/// Argon2id( passphrase, salt ) → 32-byte key-encryption key.
fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut kek = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|_| err("key derivation failed"))?;
    Ok(kek)
}

/// Seal `plaintext` under `passphrase`. A fresh random salt makes the derived key
/// unique per bundle, so the fixed counter nonce (index 0) is never reused.
fn seal_bundle(mut plaintext: Vec<u8>, passphrase: &str) -> Result<Vec<u8>> {
    use rand::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let kek = derive_kek(passphrase, &salt)?;

    let sealer = DataKey::from_bytes(kek).file_subkey(BUNDLE_INFO)?.sealer()?;
    sealer.seal(&mut plaintext, 0)?; // appends the GCM tag

    let mut out = Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + plaintext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&plaintext);
    Ok(out)
}

/// Reverse of `seal_bundle`. A wrong passphrase fails the GCM tag check.
fn open_bundle(blob: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let header = MAGIC.len() + 1 + SALT_LEN;
    if blob.len() < header {
        return Err(err("backup file too short or not a p2pnas backup"));
    }
    if &blob[..MAGIC.len()] != MAGIC {
        return Err(err("not a p2pnas backup file"));
    }
    if blob[MAGIC.len()] != VERSION {
        return Err(err("unsupported backup version"));
    }
    let salt = &blob[MAGIC.len() + 1..header];
    let kek = derive_kek(passphrase, salt)?;

    let sealer = DataKey::from_bytes(kek).file_subkey(BUNDLE_INFO)?.sealer()?;
    let mut cipher = blob[header..].to_vec();
    let plain = sealer
        .open(0, &mut cipher)
        .map_err(|_| err("wrong passphrase or corrupt backup"))?;
    Ok(plain.to_vec())
}

fn encode_plaintext(identity: &[u8], manifest_bytes: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(IDENTITY_LEN + 8 + manifest_bytes.len());
    p.extend_from_slice(identity);
    p.extend_from_slice(&(manifest_bytes.len() as u64).to_be_bytes());
    p.extend_from_slice(manifest_bytes);
    p
}

/// Read a big-endian `u64` from an exactly-8-byte slice. Fallible rather than
/// `unwrap`ed: every length field below is parsed from bytes that came off the
/// wire or off disk, and the release profile aborts on panic.
fn be_u64(bytes: &[u8]) -> Result<u64> {
    let a: [u8; 8] = bytes.try_into().map_err(|_| err("malformed length field"))?;
    Ok(u64::from_be_bytes(a))
}

/// Same for a big-endian `u32`.
fn be_u32(bytes: &[u8]) -> Result<u32> {
    let a: [u8; 4] = bytes.try_into().map_err(|_| err("malformed length field"))?;
    Ok(u32::from_be_bytes(a))
}

fn decode_plaintext(plain: &[u8]) -> Result<(&[u8], &[u8])> {
    if plain.len() < IDENTITY_LEN + 8 {
        return Err(err("backup contents truncated"));
    }
    let identity = &plain[..IDENTITY_LEN];
    let len = be_u64(&plain[IDENTITY_LEN..IDENTITY_LEN + 8])? as usize;
    let rest = &plain[IDENTITY_LEN + 8..];
    if rest.len() != len {
        return Err(err("backup manifest length mismatch"));
    }
    Ok((identity, rest))
}

fn identity_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("identity").join("identity.key")
}

fn manifest_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("manifest.db")
}

/// Build an encrypted cold-storage backup bundle. Requires the passphrase that
/// will later be needed to restore it.
pub fn export(data_dir: &Path, manifest: &Manifest, passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(err("passphrase too short (at least 12 characters)"));
    }

    // Consistent snapshot of the manifest, written next to it then read back.
    let snap = data_dir.join("manifest.snapshot.tmp");
    manifest.snapshot_to(&snap)?;
    let manifest_bytes = std::fs::read(&snap);
    let _ = std::fs::remove_file(&snap); // best-effort cleanup regardless
    let manifest_bytes = manifest_bytes?;

    let identity = std::fs::read(identity_path(data_dir))?;
    if identity.len() != IDENTITY_LEN {
        return Err(err("identity.key has unexpected length"));
    }

    let plaintext = encode_plaintext(&identity, &manifest_bytes);
    seal_bundle(plaintext, passphrase)
}

/// Restore a backup bundle onto THIS node. Refuses to run when the node already
/// holds data, so a restore can never clobber a live node — it is meant for a
/// fresh install recovering a dead one. The module must be restarted afterwards
/// to reload the restored identity and reopen the manifest under its key.
pub fn import(data_dir: &Path, manifest: &Manifest, passphrase: &str, blob: &[u8]) -> Result<()> {
    ensure_fresh_node(manifest)?;

    let plain = open_bundle(blob, passphrase)?;
    let (identity, manifest_bytes) = decode_plaintext(&plain)?;

    // Write the manifest first, then the identity: if anything fails, the node is
    // left without a mismatched identity pointing at an absent manifest.
    let mdest = manifest_path(data_dir);
    if let Some(parent) = mdest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomic(&mdest, manifest_bytes)?;

    let idest = identity_path(data_dir);
    if let Some(parent) = idest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_identity(&idest, identity)?;
    Ok(())
}

/// Refuse to run a restore on a node that already holds files.
///
/// A restore overwrites `manifest.db` wholesale, so running one on a live node
/// would erase the only index of everything that node currently stores — the
/// exact disaster the backup exists to prevent. Restores are for a fresh install
/// standing in for a dead machine, and nothing else.
///
/// A manifest that cannot even be opened counts as empty: on a brand-new node the
/// file does not exist yet, and that is precisely when a restore is legitimate.
pub fn ensure_fresh_node(manifest: &Manifest) -> Result<()> {
    let existing = manifest
        .connect()
        .and_then(|conn| manifest::list_all_files(&conn))
        .map(|files| files.len())
        .unwrap_or(0);
    if existing > 0 {
        return Err(err(
            "this node already holds data; restore is only for a fresh node",
        ));
    }
    Ok(())
}

/// Write `bytes` to `path` via a temp file + rename so a crash never leaves a
/// half-written file in place of the real one.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("restore.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn write_identity(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_identity(path: &Path, bytes: &[u8]) -> Result<()> {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, bytes)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Automatic distributed backup of the manifest
// ─────────────────────────────────────────────────────────────────────────────
//
// The cold bundle above is only as good as the administrator's discipline: a node
// whose disk dies before anyone ever pressed "download" is unrecoverable, even
// though ~10 of every 14 shards are still sitting on peers. This section is the
// automatic version — the node periodically pushes an encrypted, erasure-coded
// snapshot of its own manifest onto the peers it already trusts with shards.
//
// The hard part is not the encryption, it is ADDRESSING. A restore starts with no
// manifest, so it cannot look up which fragments to ask for; the fragment ids must
// therefore be *recomputable from the node key alone*:
//
//     fragment_id = hex(blake3(DOMAIN ‖ peer_id ‖ version ‖ shard_index)[..16])
//
// `peer_id` re-derives from `identity.key`, and `version` is a day number (see
// [`manifest_backup_version_now`]), so a fresh machine holding only the identity
// file can regenerate every id of every recent backup and simply ask around.
//
// Formats, both fixed-width and therefore unambiguous:
//
//   Sealed blob PLAINTEXT (what the peers never see):
//     MB_MAGIC(8) | MB_FORMAT(1) | version(u64 BE) | peer_id(32 ASCII)
//       | snapshot_len(u64 BE) | snapshot bytes
//   …sealed with AES-256-GCM under a key derived from the node master key
//   (domain `p2pnas/manifest-backup/v1`, bound to peer_id + version), tag
//   appended. Nothing precedes the ciphertext: the magic is INSIDE the
//   authenticated plaintext, so no header can be tampered with unnoticed. The
//   snapshot is already SQLCipher-encrypted under the manifest key; this layer
//   adds authentication and makes the artefact independent of the SQLite format.
//
//   Stored shard ENVELOPE (one per erasure shard, what a peer holds):
//     MS_MAGIC(8) | MS_FORMAT(1) | version(u64 BE) | shard_index(1)
//       | shard_len(u32 BE) | blob_len(u64 BE) | blob_hash(16) | shard bytes
//   The envelope is what makes a shard self-describing: reconstruction needs the
//   blob length and the shard index, and after a disaster there is no manifest
//   left to hold them. `blob_hash` (BLAKE3, truncated) both groups the shards of
//   one blob and proves the reconstruction before it is decrypted.

/// Domain separating every secret and every identifier of the automatic backup
/// from the node's other derived material (file subkeys, manifest key, peer id,
/// P2P signing key) and from the ordinary fragment id space.
pub const MANIFEST_BACKUP_DOMAIN: &[u8] = b"p2pnas/manifest-backup/v1";

const MB_MAGIC: &[u8; 8] = b"KBP2PMB1";
const MB_FORMAT: u8 = 1;
/// `MB_MAGIC | MB_FORMAT | version | peer_id | snapshot_len`.
const MB_HEADER: usize = 8 + 1 + 8 + PEER_ID_LEN + 8;

const MS_MAGIC: &[u8; 8] = b"KBP2PMS1";
const MS_FORMAT: u8 = 1;
/// Truncated BLAKE3 of the sealed blob, carried by every envelope.
const BLOB_HASH_LEN: usize = 16;
/// `MS_MAGIC | MS_FORMAT | version | shard_index | shard_len | blob_len | hash`.
const MS_HEADER: usize = 8 + 1 + 8 + 1 + 4 + 8 + BLOB_HASH_LEN;

/// A peer id is `hex(derive_raw("p2pnas/peer-id/v1")[..16])` — always 32 chars.
const PEER_ID_LEN: usize = 32;

/// Seconds in a day: the granularity of a backup version.
const DAY_SECS: u64 = 24 * 60 * 60;

/// Temp file the snapshot is vacuumed into before being sealed. Distinct from the
/// cold bundle's, so a manual export and the background job can never race for
/// the same path.
const SNAPSHOT_TMP: &str = "manifest.autobackup.tmp";

/// The backup version for *now*: the number of whole days since the Unix epoch.
///
/// Deriving the version from the clock rather than from a counter is what makes
/// the whole scheme survivable. A counter would have to live somewhere — and the
/// two places it could live (the manifest, the control-plane database) are
/// exactly the ones a disaster may have taken with it. A day number is
/// reproducible on a bare machine from the clock alone, so a restore can walk
/// candidate versions backwards from today without consulting any state.
///
/// It also pins the frequency policy: at most one backup per day, since a second
/// run on the same day recomputes the same version and the same ids.
pub fn manifest_backup_version_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / DAY_SECS)
        .unwrap_or(0)
}

/// The deterministic address of one shard of one backup.
///
/// `hex(blake3(DOMAIN ‖ peer_id ‖ version ‖ shard_index)[..16])` — 32 lowercase
/// hex characters, the only shape [`crate::ChunkStore`] accepts (anything else is
/// rejected as a path-traversal attempt before it can touch a path).
///
/// The concatenation needs no length prefixes to be injective: `peer_id` is a
/// fixed 32-character hex string and the two integers are fixed-width, so no two
/// distinct triples can produce the same input.
pub fn manifest_backup_fragment_id(peer_id: &str, version: u64, shard_index: usize) -> String {
    let mut h = blake3::Hasher::new();
    h.update(MANIFEST_BACKUP_DOMAIN);
    h.update(peer_id.as_bytes());
    h.update(&version.to_be_bytes());
    h.update(&(shard_index as u32).to_be_bytes());
    hex::encode(&h.finalize().as_bytes()[..16])
}

/// The AEAD key protecting one backup: HKDF over the node master key, bound to
/// `(peer_id, version)`.
///
/// Binding the VERSION into the key is not decoration. The sealer uses a counter
/// nonce, and a fixed key would mean every backup reusing nonce 0 — a repeated
/// (key, nonce) under GCM leaks both plaintexts via their XOR and makes forgery
/// possible. A per-version key makes nonce 0 unique by construction, and it stays
/// safe even if the clock jumps backwards and a version number is revisited with
/// different content: only the *same* version can collide, and a revisited
/// version simply overwrites its own shards.
fn manifest_backup_sealer(key: &DataKey, peer_id: &str, version: u64) -> Result<ChunkSealer> {
    let raw = key.derive_v2(MANIFEST_BACKUP_DOMAIN, &[peer_id.as_bytes(), &version.to_be_bytes()])?;
    let subkey = DataKey::from_bytes(*raw).file_subkey(MANIFEST_BACKUP_DOMAIN)?;
    let sealer = subkey.sealer()?;
    Ok(sealer)
}

/// BLAKE3 of the sealed blob, truncated. Not a secret and not a MAC (the GCM tag
/// is): it only has to tell one reconstruction attempt from another.
fn blob_hash(blob: &[u8]) -> [u8; BLOB_HASH_LEN] {
    let mut out = [0u8; BLOB_HASH_LEN];
    out.copy_from_slice(&blake3::hash(blob).as_bytes()[..BLOB_HASH_LEN]);
    out
}

/// Seal a manifest snapshot into the blob that gets erasure-coded onto the peers.
pub fn seal_manifest_snapshot(
    key: &DataKey,
    peer_id: &str,
    version: u64,
    snapshot: &[u8],
) -> Result<Vec<u8>> {
    if peer_id.len() != PEER_ID_LEN {
        return Err(err("peer id has unexpected length"));
    }
    let mut plain = Vec::with_capacity(MB_HEADER + snapshot.len() + 16);
    plain.extend_from_slice(MB_MAGIC);
    plain.push(MB_FORMAT);
    plain.extend_from_slice(&version.to_be_bytes());
    plain.extend_from_slice(peer_id.as_bytes());
    plain.extend_from_slice(&(snapshot.len() as u64).to_be_bytes());
    plain.extend_from_slice(snapshot);

    // Nonce 0 is safe because the key is unique per (node, version) — see
    // `manifest_backup_sealer`.
    manifest_backup_sealer(key, peer_id, version)?.seal(&mut plain, 0)?;
    Ok(plain)
}

/// Reverse of [`seal_manifest_snapshot`]: authenticate and return the snapshot.
///
/// Fails on the wrong node key, the wrong version, or a single flipped bit. The
/// header checks that follow the tag verification are therefore redundancy, not
/// security — they turn "this is not what we expected" into a message an operator
/// can act on.
pub fn open_manifest_snapshot(
    key: &DataKey,
    peer_id: &str,
    version: u64,
    blob: &[u8],
) -> Result<Vec<u8>> {
    let sealer = manifest_backup_sealer(key, peer_id, version)?;
    let mut buf = blob.to_vec();
    let plain = sealer.open(0, &mut buf).map_err(|_| {
        err("manifest backup failed authentication (wrong node key, wrong version, or corrupt)")
    })?;

    if plain.len() < MB_HEADER {
        return Err(err("manifest backup truncated"));
    }
    if &plain[..8] != MB_MAGIC || plain[8] != MB_FORMAT {
        return Err(err("not a p2pnas manifest backup"));
    }
    let stored_version = be_u64(&plain[9..17])?;
    if stored_version != version {
        return Err(err("manifest backup belongs to another version"));
    }
    let stored_peer = &plain[17..17 + PEER_ID_LEN];
    if stored_peer != peer_id.as_bytes() {
        return Err(err("manifest backup belongs to another node"));
    }
    let len = be_u64(&plain[17 + PEER_ID_LEN..MB_HEADER])? as usize;
    let body = &plain[MB_HEADER..];
    if body.len() != len {
        return Err(err("manifest backup length mismatch"));
    }
    Ok(body.to_vec())
}

/// One stored shard, decoded from its envelope.
#[derive(Clone, Debug)]
pub struct ManifestBackupShard {
    pub version:     u64,
    pub shard_index: usize,
    /// Length of the sealed blob these shards reconstruct — needed to trim the
    /// erasure padding, and unavailable anywhere else after a disaster.
    pub blob_len:    usize,
    pub blob_hash:   [u8; BLOB_HASH_LEN],
    pub data:        Vec<u8>,
}

/// Erasure-code a sealed blob into [`TOTAL_SHARDS`] self-describing envelopes,
/// ready to be handed to peers (index `i` of the returned vector is shard `i`).
pub fn encode_manifest_backup_shards(version: u64, blob: &[u8]) -> Result<Vec<Vec<u8>>> {
    let shards = erasure::encode(blob)?;
    let hash = blob_hash(blob);
    let mut out = Vec::with_capacity(shards.len());
    for (i, s) in shards.iter().enumerate() {
        let mut e = Vec::with_capacity(MS_HEADER + s.len());
        e.extend_from_slice(MS_MAGIC);
        e.push(MS_FORMAT);
        e.extend_from_slice(&version.to_be_bytes());
        e.push(i as u8);
        e.extend_from_slice(&(s.len() as u32).to_be_bytes());
        e.extend_from_slice(&(blob.len() as u64).to_be_bytes());
        e.extend_from_slice(&hash);
        e.extend_from_slice(s);
        out.push(e);
    }
    Ok(out)
}

/// Parse one envelope fetched from a peer. Everything is validated before it is
/// used: the bytes arrive from a remote that is free to answer with anything.
pub fn decode_manifest_backup_shard(bytes: &[u8]) -> Result<ManifestBackupShard> {
    if bytes.len() < MS_HEADER {
        return Err(err("backup shard too short"));
    }
    if &bytes[..8] != MS_MAGIC || bytes[8] != MS_FORMAT {
        return Err(err("not a p2pnas manifest backup shard"));
    }
    let version = be_u64(&bytes[9..17])?;
    let shard_index = bytes[17] as usize;
    if shard_index >= TOTAL_SHARDS {
        return Err(err("backup shard index out of range"));
    }
    let shard_len = be_u32(&bytes[18..22])? as usize;
    let blob_len = be_u64(&bytes[22..30])? as usize;
    if blob_len == 0 {
        return Err(err("backup shard declares an empty blob"));
    }
    let mut hash = [0u8; BLOB_HASH_LEN];
    hash.copy_from_slice(&bytes[30..MS_HEADER]);
    let data = &bytes[MS_HEADER..];
    if data.len() != shard_len {
        return Err(err("backup shard length mismatch"));
    }
    Ok(ManifestBackupShard {
        version,
        shard_index,
        blob_len,
        blob_hash: hash,
        data: data.to_vec(),
    })
}

/// Rebuild the sealed blob from any [`DATA_SHARDS`] or more shards of one version.
///
/// Two hostile-peer cases are handled explicitly, because Reed-Solomon in erasure
/// mode is NOT error-correcting — one silently altered shard poisons the whole
/// reconstruction:
///
///   - **Disagreeing envelopes.** The `(blob_len, blob_hash)` pair is decided by
///     majority, and shards that disagree are dropped. A single peer therefore
///     cannot steer the reconstruction by lying about the geometry.
///   - **A corrupt payload.** The result is checked against `blob_hash` before it
///     is ever decrypted. On failure, and only when there are spare shards, each
///     shard is excluded in turn and the reconstruction retried — a bounded
///     `TOTAL_SHARDS` extra attempts that recovers from one bad copy.
pub fn reassemble_manifest_backup(shards: &[ManifestBackupShard]) -> Result<Vec<u8>> {
    if shards.len() < DATA_SHARDS {
        return Err(err("not enough backup shards to reconstruct"));
    }

    // Majority geometry. The list is at most TOTAL_SHARDS long, so a linear tally
    // is both the simplest and the fastest thing here.
    let mut tally: Vec<((usize, [u8; BLOB_HASH_LEN]), usize)> = Vec::new();
    for s in shards {
        let key = (s.blob_len, s.blob_hash);
        match tally.iter_mut().find(|(k, _)| *k == key) {
            Some((_, n)) => *n += 1,
            None => tally.push((key, 1)),
        }
    }
    let ((blob_len, hash), _) = tally
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .ok_or_else(|| err("no backup shards"))?;

    let mut present: Vec<Option<Vec<u8>>> = (0..TOTAL_SHARDS).map(|_| None).collect();
    let mut shard_len = 0usize;
    let mut kept = 0usize;
    for s in shards {
        // `decode_manifest_backup_shard` already bounds the index, but this type is
        // public: never let a hand-built value index out of the slot array.
        if s.shard_index >= TOTAL_SHARDS || s.blob_len != blob_len || s.blob_hash != hash {
            continue;
        }
        // Every shard of one blob has the same padded length; a stray one would
        // make the reconstruction panic-free but meaningless.
        if shard_len == 0 {
            shard_len = s.data.len();
        }
        if s.data.len() != shard_len || present[s.shard_index].is_some() {
            continue;
        }
        present[s.shard_index] = Some(s.data.clone());
        kept += 1;
    }
    if kept < DATA_SHARDS {
        return Err(err("not enough consistent backup shards to reconstruct"));
    }

    if let Some(blob) = try_rebuild(&present, blob_len, &hash) {
        return Ok(blob);
    }
    // One of the copies is corrupt. With spare shards we can find out which.
    if kept > DATA_SHARDS {
        for (i, slot) in present.iter().enumerate() {
            if slot.is_none() {
                continue;
            }
            let mut without = present.clone();
            without[i] = None;
            if let Some(blob) = try_rebuild(&without, blob_len, &hash) {
                tracing::warn!(shard_index = i, "manifest backup: discarded a corrupt shard copy");
                return Ok(blob);
            }
        }
    }
    Err(err("manifest backup shards do not reconstruct a valid blob"))
}

/// One reconstruction attempt, accepted only if it matches the expected hash.
fn try_rebuild(
    present: &[Option<Vec<u8>>],
    blob_len: usize,
    hash: &[u8; BLOB_HASH_LEN],
) -> Option<Vec<u8>> {
    let blob = erasure::reconstruct(present, blob_len).ok()?;
    (blob_hash(&blob) == *hash).then_some(blob)
}

/// A built backup, ready to be distributed.
pub struct ManifestBackupBlob {
    pub version:      u64,
    pub snapshot_len: usize,
    pub blob_len:     usize,
    /// The [`TOTAL_SHARDS`] envelopes, in shard-index order.
    pub shards:       Vec<Vec<u8>>,
}

/// Snapshot → seal → erasure-code, all in one blocking step (this is the whole
/// "A + C" of the backup; the placement is the caller's business).
///
/// The snapshot goes through `VACUUM INTO`, which takes a whole-database read
/// lock and yields a coherent copy even while the manifest is being written to —
/// so this is safe to run from a background job on a live node.
pub fn build_manifest_backup(
    data_dir: &Path,
    manifest: &Manifest,
    key: &DataKey,
    peer_id: &str,
    version: u64,
) -> Result<ManifestBackupBlob> {
    let snap = data_dir.join(SNAPSHOT_TMP);
    manifest.snapshot_to(&snap)?;
    let snapshot = std::fs::read(&snap);
    // Best-effort cleanup whatever happened: the snapshot is a full plaintext-
    // structured copy of the index and must not linger on disk.
    let _ = std::fs::remove_file(&snap);
    let snapshot = snapshot?;

    let blob = seal_manifest_snapshot(key, peer_id, version, &snapshot)?;
    let shards = encode_manifest_backup_shards(version, &blob)?;
    Ok(ManifestBackupBlob {
        version,
        snapshot_len: snapshot.len(),
        blob_len: blob.len(),
        shards,
    })
}

/// Install a recovered snapshot as this node's `manifest.db`.
///
/// Same guard as [`import`] — a restore is only ever legitimate on a node that
/// holds nothing — and the same atomic write, so an interrupted restore can never
/// leave a half-written manifest where the real one used to be. The module must
/// be restarted afterwards: the running process holds an open handle on the old
/// database.
pub fn restore_manifest_db(data_dir: &Path, manifest: &Manifest, snapshot: &[u8]) -> Result<()> {
    ensure_fresh_node(manifest)?;
    let dest = manifest_path(data_dir);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomic(&dest, snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bundle() {
        let identity = [7u8; IDENTITY_LEN];
        let manifest_bytes = b"pretend this is a SQLCipher database".to_vec();
        let plaintext = encode_plaintext(&identity, &manifest_bytes);
        let blob = seal_bundle(plaintext, "correct horse battery").unwrap();

        let plain = open_bundle(&blob, "correct horse battery").unwrap();
        let (id, man) = decode_plaintext(&plain).unwrap();
        assert_eq!(id, identity);
        assert_eq!(man, &manifest_bytes[..]);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let plaintext = encode_plaintext(&[1u8; IDENTITY_LEN], b"data");
        let blob = seal_bundle(plaintext, "correct horse battery").unwrap();
        assert!(open_bundle(&blob, "wrong passphrase!!").is_err());
    }

    #[test]
    fn tampered_bundle_rejected() {
        let plaintext = encode_plaintext(&[1u8; IDENTITY_LEN], b"data");
        let mut blob = seal_bundle(plaintext, "correct horse battery").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(open_bundle(&blob, "correct horse battery").is_err());
    }

    // ── Automatic distributed backup ────────────────────────────────────────

    /// Plausible peer ids: 32 hex characters, exactly what `NodeIdentity` derives.
    const PEER_A: &str = "00112233445566778899aabbccddeeff";
    const PEER_B: &str = "ffeeddccbbaa99887766554433221100";

    fn node_key(byte: u8) -> DataKey {
        DataKey::from_bytes([byte; 32])
    }

    /// Something big enough to stripe over 10 shards and compress badly.
    fn fake_snapshot(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 37) ^ (i >> 5)) as u8).collect()
    }

    #[test]
    fn fragment_ids_are_deterministic_and_store_valid() {
        let a = PEER_A;
        let b = PEER_B;

        // Same inputs → same id, always. This is the property the whole restore
        // path rests on: a fresh machine recomputes these from identity.key alone.
        for i in 0..TOTAL_SHARDS {
            assert_eq!(
                manifest_backup_fragment_id(a, 20_000, i),
                manifest_backup_fragment_id(a, 20_000, i)
            );
        }

        // Every component actually separates.
        assert_ne!(
            manifest_backup_fragment_id(a, 20_000, 0),
            manifest_backup_fragment_id(a, 20_001, 0)
        );
        assert_ne!(
            manifest_backup_fragment_id(a, 20_000, 0),
            manifest_backup_fragment_id(a, 20_000, 1)
        );
        assert_ne!(
            manifest_backup_fragment_id(a, 20_000, 0),
            manifest_backup_fragment_id(b, 20_000, 0)
        );

        // …and no two of one backup's 14 ids collide.
        let ids: std::collections::HashSet<String> =
            (0..TOTAL_SHARDS).map(|i| manifest_backup_fragment_id(a, 20_000, i)).collect();
        assert_eq!(ids.len(), TOTAL_SHARDS);

        // The shape ChunkStore accepts — proven by actually storing under it,
        // since the validator itself is private to that module.
        let root = std::env::temp_dir()
            .join(format!("p2pnas-mbackup-ids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = crate::ChunkStore::new(&root);
        for id in &ids {
            assert_eq!(id.len(), 32);
            assert!(id.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
            store.write(id, b"shard").expect("ChunkStore must accept a backup fragment id");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn blob_round_trip_and_key_binding() {
        let key = node_key(3);
        let a = PEER_A;
        let snapshot = fake_snapshot(4096);

        let blob = seal_manifest_snapshot(&key, a, 20_000, &snapshot).unwrap();
        assert_ne!(blob[..64], snapshot[..64], "the snapshot must not appear in clear");
        assert_eq!(open_manifest_snapshot(&key, a, 20_000, &blob).unwrap(), snapshot);

        // Another version, another node, another master key: all refused, because
        // the AEAD key is bound to (master key, peer_id, version).
        assert!(open_manifest_snapshot(&key, a, 20_001, &blob).is_err());
        assert!(open_manifest_snapshot(&key, PEER_B, 20_000, &blob).is_err());
        assert!(open_manifest_snapshot(&node_key(4), a, 20_000, &blob).is_err());
    }

    #[test]
    fn tampered_blob_is_rejected() {
        let key = node_key(3);
        let a = PEER_A;
        let mut blob = seal_manifest_snapshot(&key, a, 20_000, &fake_snapshot(2048)).unwrap();
        blob[100] ^= 0x01;
        assert!(open_manifest_snapshot(&key, a, 20_000, &blob).is_err());
    }

    /// End to end, minus the network: snapshot → seal → 14 shards → lose 4 →
    /// reconstruct → decrypt.
    #[test]
    fn reconstructs_from_exactly_data_shards() {
        let key = node_key(9);
        let a = PEER_A;
        let snapshot = fake_snapshot(70_000);
        let blob = seal_manifest_snapshot(&key, a, 20_123, &snapshot).unwrap();
        let envelopes = encode_manifest_backup_shards(20_123, &blob).unwrap();
        assert_eq!(envelopes.len(), TOTAL_SHARDS);

        // Keep exactly DATA_SHARDS of them, and deliberately not the first ten:
        // the parity shards must be usable in place of missing data shards.
        let kept: Vec<ManifestBackupShard> = [0usize, 2, 3, 5, 6, 7, 9, 11, 12, 13]
            .iter()
            .map(|i| decode_manifest_backup_shard(&envelopes[*i]).unwrap())
            .collect();
        assert_eq!(kept.len(), DATA_SHARDS);

        let rebuilt = reassemble_manifest_backup(&kept).unwrap();
        assert_eq!(rebuilt, blob);
        assert_eq!(open_manifest_snapshot(&key, a, 20_123, &rebuilt).unwrap(), snapshot);
    }

    #[test]
    fn one_shard_short_is_refused() {
        let blob = seal_manifest_snapshot(&node_key(9), PEER_A, 20_123, &fake_snapshot(9000)).unwrap();
        let envelopes = encode_manifest_backup_shards(20_123, &blob).unwrap();
        let kept: Vec<ManifestBackupShard> = envelopes[..DATA_SHARDS - 1]
            .iter()
            .map(|e| decode_manifest_backup_shard(e).unwrap())
            .collect();
        assert!(reassemble_manifest_backup(&kept).is_err());
    }

    #[test]
    fn a_corrupt_shard_is_detected_and_routed_around() {
        let key = node_key(9);
        let a = PEER_A;
        let snapshot = fake_snapshot(50_000);
        let blob = seal_manifest_snapshot(&key, a, 20_123, &snapshot).unwrap();
        let envelopes = encode_manifest_backup_shards(20_123, &blob).unwrap();

        // A hostile (or rotting) peer returns shard 4 with a flipped byte. Erasure
        // coding is not error-correcting, so this MUST be caught by the hash.
        let mut poisoned = envelopes.clone();
        let last = poisoned[4].len() - 1;
        poisoned[4][last] ^= 0xff;

        // With exactly DATA_SHARDS, there is no way around it: refuse rather than
        // hand back a silently wrong manifest.
        let bare: Vec<ManifestBackupShard> = poisoned[..DATA_SHARDS]
            .iter()
            .map(|e| decode_manifest_backup_shard(e).unwrap())
            .collect();
        assert!(reassemble_manifest_backup(&bare).is_err());

        // With the parity shards available, the bad copy is excluded and the blob
        // still comes back intact.
        let all: Vec<ManifestBackupShard> = poisoned
            .iter()
            .map(|e| decode_manifest_backup_shard(e).unwrap())
            .collect();
        let rebuilt = reassemble_manifest_backup(&all).unwrap();
        assert_eq!(rebuilt, blob);
        assert_eq!(open_manifest_snapshot(&key, a, 20_123, &rebuilt).unwrap(), snapshot);
    }

    #[test]
    fn envelopes_from_a_hostile_peer_are_validated() {
        let blob = seal_manifest_snapshot(&node_key(9), PEER_A, 7, &fake_snapshot(1024)).unwrap();
        let good = encode_manifest_backup_shards(7, &blob).unwrap().remove(0);

        assert!(decode_manifest_backup_shard(&good).is_ok());
        assert!(decode_manifest_backup_shard(&[]).is_err());
        assert!(decode_manifest_backup_shard(&good[..MS_HEADER - 1]).is_err());
        // Truncated payload: the declared shard_len no longer matches.
        assert!(decode_manifest_backup_shard(&good[..good.len() - 1]).is_err());

        let mut wrong_magic = good.clone();
        wrong_magic[0] ^= 0xff;
        assert!(decode_manifest_backup_shard(&wrong_magic).is_err());

        // A shard index outside the 14 slots would index out of bounds later.
        let mut wrong_index = good.clone();
        wrong_index[17] = TOTAL_SHARDS as u8;
        assert!(decode_manifest_backup_shard(&wrong_index).is_err());
    }

    /// A version number must be strictly increasing over time and stable within
    /// a day — the two properties the restore scan and the nonce safety rely on.
    #[test]
    fn version_is_a_day_number() {
        let v = manifest_backup_version_now();
        assert!(v > 19_000, "day number since the epoch, not a timestamp: {v}");
        assert_eq!(v, manifest_backup_version_now());
    }
}
