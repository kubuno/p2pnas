//! Orchestration: tie the core pipeline to the manifest + local shard store.
//! Synchronous (the server wraps these in `spawn_blocking`). No networking yet —
//! all 14 shards of every chunk are stored locally (phase 3 distributes them).

use chrono::Utc;
use rand::RngCore;

use p2pnas_core::{
    chunker::restore as decompress,
    crypto::{blake3_hex, FileCipher, KeyScheme},
    erasure::{self, DATA_SHARDS, TOTAL_SHARDS},
    pipeline::{self, PipelineConfig, ProcessedChunk},
};

use crate::{
    chunkstore::ChunkStore,
    error::{Result, StoreError},
    identity::NodeIdentity,
    manifest::{self, ChunkRow, FileRow, Manifest, ShardRow},
};

/// A shard that lives on a remote peer: `(fragment_id, peer_location)`. Returned
/// by the delete/overwrite paths so the caller can have the hosting peer drop it.
pub type RemoteShard = (String, String);

pub struct PushResult {
    pub file_id:      String,
    pub size:         i64,
    /// Actual bytes written to the local shard store (data + parity).
    pub stored_bytes: i64,
    /// The version this push pushed aside, if the path was already taken. It is
    /// KEPT (as a version), so nothing is refunded — its `size` and `stored_bytes`
    /// are reported only so the caller can tell the user what the trash/versions
    /// are now holding on their behalf.
    pub superseded_file_id: Option<String>,
    pub superseded_size:    i64,
    pub superseded_stored:  i64,
    /// The upload was byte-for-byte what is already stored at this path, so
    /// nothing was written and no version was created. The caller must refund
    /// whatever it reserved: this upload cost no space at all.
    pub unchanged: bool,
}

/// Encrypt + erasure-code `data` and store it for `user_id` under `path`.
///
/// A push on an occupied path does not overwrite: `push` has always minted a fresh
/// random `file_id` (the per-file subkey/nonce invariant demands it), so the
/// previous version is already a complete, self-consistent file with its own
/// chunks and shards. It is simply marked `superseded` and keeps every byte it
/// had — that is the whole cost of versioning here. It stops being listed, stays
/// restorable, and is reclaimed later by the retention sweep.
pub fn push(
    id: &NodeIdentity,
    manifest: &Manifest,
    store: &ChunkStore,
    user_id: &str,
    path: &str,
    data: &[u8],
) -> Result<PushResult> {
    // Re-uploading identical bytes is the common case for a sync client that
    // re-pushes files it has not touched. Without this check each pass would
    // store a whole new version — multiplying the parc by the version cap for no
    // new content at all, and charging the user's quota for every copy. Hashing
    // the body costs a BLAKE3 pass (~1 GiB/s), invisible next to encryption.
    let content_hash = blake3_hex(data);
    {
        let conn = manifest.connect()?;
        if let Some(prev) = manifest::get_file_by_path(&conn, user_id, path)? {
            if prev.size == data.len() as i64 && prev.content_hash.as_deref() == Some(content_hash.as_str()) {
                return Ok(PushResult {
                    file_id:            prev.file_id,
                    size:               prev.size,
                    stored_bytes:       0,
                    superseded_file_id: None,
                    superseded_size:    0,
                    superseded_stored:  0,
                    unchanged:          true,
                });
            }
        }
    }

    let file_id = mint_file_id();

    // New writes use scheme v2: the subkey is bound to the OWNER, and every chunk
    // authenticates its file, position and total count. `push` always mints a fresh
    // file_id, so no already-stored version is affected — the parc migrates as files
    // are rewritten.
    let chunks = pipeline::process_v2(
        data,
        &id.data_key,
        user_id.as_bytes(),
        file_id.as_bytes(),
        PipelineConfig::default(),
    )?;
    // Real on-disk cost: each chunk stores 14 shards, and each shard is a separate
    // file occupying whole filesystem blocks (`shard_disk_cost`) — not just its
    // logical length, which under-counted a small file's footprint by up to ~32×.
    let stored_bytes: i64 = chunks
        .iter()
        .map(|c| (TOTAL_SHARDS * erasure::shard_disk_cost(c.shard_len)) as i64)
        .sum();

    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;

    let now = Utc::now().to_rfc3339();

    // Step the previous version aside rather than destroying it: it keeps its rows,
    // its chunks and its shards, and only loses the path (parked on a tombstone key
    // by `supersede_file`, so `UNIQUE (user_id, path)` lets the new row take it).
    // The new version joins the SAME lineage, which is what makes "show me the
    // history of this file" a single indexed lookup — and what makes it survive a
    // later rename, since a lineage is not a path.
    let (superseded_file_id, superseded_size, superseded_stored, lineage) =
        match manifest::get_file_by_path(&tx, user_id, path)? {
            Some(prev) => {
                manifest::supersede_file(&tx, user_id, &prev.file_id, &now)?;
                (Some(prev.file_id), prev.size, prev.stored_bytes, prev.lineage)
            }
            None => (None, 0, 0, file_id.clone()),
        };

    manifest::insert_file(
        &tx,
        &FileRow {
            file_id:       file_id.clone(),
            user_id:       user_id.to_string(),
            path:          path.to_string(),
            size:          data.len() as i64,
            stored_bytes,
            chunk_count:   chunks.len() as i64,
            created_at:    now,
            deleted_at:    None,
            superseded_at: None,
            lineage,
            key_scheme:    KeyScheme::V2.as_i64(),
            content_hash:  Some(content_hash),
            pack_id:       None,
            pack_offset:   None,
            pack_len:      None,
        },
    )?;

    write_chunk_rows(store, &tx, &file_id, &chunks)?;

    tx.commit()?;
    // Nothing to free here any more: the previous version is retained, so no shard
    // — local or remote — is orphaned by an overwrite. Reclaiming its space is the
    // retention sweep's job (`purge_retired`), which is also the only place that
    // hands remote shards back for deletion on their hosts.
    Ok(PushResult {
        file_id,
        size: data.len() as i64,
        stored_bytes,
        superseded_file_id,
        superseded_size,
        superseded_stored,
        unchanged: false,
    })
}

/// Read + reconstruct + decrypt a file back to its plaintext bytes.
pub fn pull(id: &NodeIdentity, manifest: &Manifest, store: &ChunkStore, user_id: &str, file_id: &str) -> Result<Vec<u8>> {
    let conn = manifest.connect()?;
    let file = manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)?;

    // A pack member owns no chunks: its bytes are a plaintext range of its
    // container. Reading a small member therefore costs reconstructing and
    // decrypting the WHOLE pack (~PACK_TARGET) — the accepted price of packing,
    // paid on the (rare) read instead of on every stored byte.
    if let Some(pack_id) = file.pack_id.clone() {
        let pack_row = manifest::get_file(&conn, user_id, &pack_id)?.ok_or_else(|| {
            StoreError::Integrity(format!("pack {pack_id} of member {file_id} is missing"))
        })?;
        // Packs never nest; a chained pack_id means a corrupt manifest, and
        // recursing on it would never terminate.
        if pack_row.pack_id.is_some() {
            return Err(StoreError::Integrity(format!("pack {pack_id} is itself a pack member")));
        }
        drop(conn);
        // Depth-1 recursion by the guard above: the container is self-contained.
        let pack_plain = pull(id, manifest, store, user_id, &pack_id)?;
        return member_slice(&pack_plain, &file);
    }

    let chunks = manifest::get_chunks(&conn, file_id)?;

    // The read path must reproduce exactly the scheme used at write time.
    let cipher_ctx = FileCipher::new(
        &id.data_key,
        KeyScheme::from_i64(file.key_scheme)?,
        file.user_id.as_bytes(),
        file_id.as_bytes(),
        file.chunk_count as u64,
    )?;
    let mut out = Vec::with_capacity(file.size as usize);

    for c in &chunks {
        let shards = manifest::get_shards(&conn, &c.chunk_id)?;
        let mut present: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
        for s in &shards {
            if let Some(slot) = present.get_mut(s.shard_index as usize) {
                *slot = Some(store.read(&s.fragment_id)?);
            }
        }
        let mut cipher = erasure::reconstruct(&present, c.cipher_len as usize)?;
        let plain = cipher_ctx.open_chunk(c.idx as u64, &mut cipher)?;
        out.extend_from_slice(&decompress(plain, c.is_compressed)?);
    }
    Ok(out)
}

/// The files the user currently sees (trashed ones and old versions excluded).
pub fn list(manifest: &Manifest, user_id: &str) -> Result<Vec<FileRow>> {
    let conn = manifest.connect()?;
    manifest::list_files(&conn, user_id)
}

/// The user's trash, most recently deleted first.
pub fn list_trash(manifest: &Manifest, user_id: &str) -> Result<Vec<FileRow>> {
    let conn = manifest.connect()?;
    manifest::list_trashed(&conn, user_id)
}

/// Every stored version of the file `file_id` belongs to — the current one
/// included — newest first. Works from any version of the lineage, so a client
/// holding an old file_id can still walk the history.
pub fn list_versions(manifest: &Manifest, user_id: &str, file_id: &str) -> Result<Vec<FileRow>> {
    let conn = manifest.connect()?;
    let file = manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)?;
    manifest::list_lineage(&conn, user_id, &file.lineage)
}

/// Every row a user owns, whatever its state. For the account-deletion sweep,
/// which must leave nothing behind — not a trashed file, not an old version.
pub fn list_all_of_user(manifest: &Manifest, user_id: &str) -> Result<Vec<FileRow>> {
    let conn = manifest.connect()?;
    manifest::list_user_rows(&conn, user_id)
}

/// Delete the local shards among `frags`, returning the ones that live on remote
/// peers as `(fragment_id, peer_location)` so the caller can have them deleted
/// there too.
///
/// Historically only the local store was freed on delete/overwrite: the ~10 of 14
/// shards placed on peers were never told to drop, so a host's usage grew without
/// bound and the network eventually refused all new placement (contribution cap).
/// A local delete failure is logged and skipped — freeing space is best-effort and
/// must never abort a user-visible delete.
///
/// Every caller is now a PERMANENT delete (`purge_file`, `empty_trash`,
/// `purge_retired`): trashing a file or superseding a version frees nothing, which
/// is precisely what makes them reversible.
fn purge_local_collect_remote(store: &ChunkStore, frags: Vec<RemoteShard>) -> Vec<RemoteShard> {
    let mut remote = Vec::new();
    for (frag, location) in frags {
        if location == "local" {
            if let Err(e) = store.delete(&frag) {
                tracing::warn!(fragment_id = %frag, error = %e, "local shard delete failed");
            }
        } else {
            remote.push((frag, location));
        }
    }
    remote
}

/// Move a file to the trash. Nothing is destroyed and nothing is freed: the row,
/// its chunks and its shards stay exactly as they are, it simply stops being
/// listed and gives its path back. Returns the row as it now reads (with
/// `deleted_at` set).
///
/// Idempotent: trashing an already-trashed file returns it unchanged.
pub fn trash(manifest: &Manifest, user_id: &str, file_id: &str) -> Result<FileRow> {
    let conn = manifest.connect()?;
    let file = manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)?;
    if file.deleted_at.is_some() {
        return Ok(file);
    }
    // An old version is not something the user can delete from a listing: it is
    // reached through the version history, and removed with `purge_file`.
    if file.superseded_at.is_some() {
        return Err(StoreError::NotFound);
    }
    manifest::trash_file(&conn, user_id, file_id, &Utc::now().to_rfc3339())?;
    manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)
}

/// What a trash / purge operation moved, for the caller's accounting and for
/// telling the user what happened.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrashSummary {
    pub files:        usize,
    pub size:         i64,
    pub stored_bytes: i64,
}

impl TrashSummary {
    fn add(&mut self, f: &FileRow) {
        self.files += 1;
        self.size += f.size;
        self.stored_bytes += f.stored_bytes;
    }
}

/// Move a file — or a whole folder subtree — to the trash, by path.
///
/// The explicit folder rows under `path` are removed (they hold no data), and a
/// restore re-creates the ancestors of each file it brings back, so a folder
/// deleted by mistake reappears with its contents.
pub fn trash_path(manifest: &Manifest, user_id: &str, path: &str) -> Result<TrashSummary> {
    let path = path.trim_matches('/');
    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;
    let now = Utc::now().to_rfc3339();
    let mut summary = TrashSummary::default();

    if let Some(file) = manifest::get_file_by_path(&tx, user_id, path)? {
        manifest::trash_file(&tx, user_id, &file.file_id, &now)?;
        summary.add(&file);
    } else {
        let files = manifest::files_under(&tx, user_id, path)?;
        if files.is_empty() && !manifest::folder_exists(&tx, user_id, path)? {
            return Err(StoreError::NotFound);
        }
        for (file_id, _) in files {
            if let Some(f) = manifest::get_file(&tx, user_id, &file_id)? {
                summary.add(&f);
            }
            manifest::trash_file(&tx, user_id, &file_id, &now)?;
        }
        manifest::delete_folder_subtree(&tx, user_id, path)?;
    }
    tx.commit()?;
    Ok(summary)
}

/// Bring a trashed file — or an older version — back as the live file at its
/// path, or at `new_path` when one is given.
///
/// If something already occupies the target path it is NOT overwritten: it becomes
/// a version of its own lineage (exactly as an upload would make it), so a restore
/// can never be the thing that loses data. Not a single shard moves — restoring is
/// a metadata operation.
pub fn restore(manifest: &Manifest, user_id: &str, file_id: &str, new_path: Option<&str>) -> Result<FileRow> {
    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;

    let file = manifest::get_file(&tx, user_id, file_id)?.ok_or(StoreError::NotFound)?;
    if file.is_live() {
        // Nothing to restore — say so rather than silently doing nothing.
        return Err(StoreError::NotFound);
    }
    let target = new_path.unwrap_or(&file.path).trim_matches('/');
    if target.is_empty() {
        return Err(StoreError::NotFound);
    }

    let now = Utc::now().to_rfc3339();
    if let Some(current) = manifest::get_file_by_path(&tx, user_id, target)? {
        if current.file_id != file.file_id {
            manifest::supersede_file(&tx, user_id, &current.file_id, &now)?;
        }
    }
    // A file restored into a folder that was deleted with it needs that folder back.
    manifest::insert_folder(&tx, user_id, manifest::dirname(target))?;
    manifest::restore_file(&tx, user_id, file_id, target)?;
    tx.commit()?; // ends the borrow of `conn`, which is reused for the read-back
    manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)
}

/// Permanently delete ONE file row (live, trashed or superseded) and free its
/// shards. Returns the row (for quota accounting: size + stored) and the remote
/// shards `(fragment_id, peer_location)` the caller must have the hosting peers
/// drop.
///
/// This is the only single-file path that actually destroys data.
pub fn purge_file(
    manifest: &Manifest,
    store: &ChunkStore,
    user_id: &str,
    file_id: &str,
) -> Result<(FileRow, Vec<RemoteShard>)> {
    let conn = manifest.connect()?;
    let file = manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)?;
    let frags = manifest::purge_file_row(&conn, user_id, file_id)?;
    let remote = purge_local_collect_remote(store, frags);
    Ok((file, remote))
}

/// Permanently delete everything in a user's trash. Old versions are NOT touched:
/// emptying the trash is about the files the user chose to delete, not about the
/// history of the ones they kept (the retention sweep ages those out).
pub fn empty_trash(
    manifest: &Manifest,
    store: &ChunkStore,
    user_id: &str,
) -> Result<(TrashSummary, Vec<RemoteShard>)> {
    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;
    let mut summary = TrashSummary::default();
    // Collected inside the transaction, acted on only after it commits: the shard
    // store is not rolled back with the DB, so freeing shards first would lose data
    // if the transaction failed.
    let mut frags: Vec<RemoteShard> = Vec::new();
    for f in manifest::list_trashed(&tx, user_id)? {
        frags.extend(manifest::purge_file_row(&tx, user_id, &f.file_id)?);
        summary.add(&f);
    }
    tx.commit()?;
    let remote = purge_local_collect_remote(store, frags);
    Ok((summary, remote))
}

/// How long the safety net holds on to bytes nobody asked for any more.
///
/// Ceilings, not promises: whichever rule fires first wins, so a file rewritten
/// every minute is bounded by `keep_versions` while one rewritten twice a year is
/// bounded by `version_days`.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    /// Days a trashed file stays restorable.
    pub trash_days:    i64,
    /// Days an old version stays restorable.
    pub version_days:  i64,
    /// How many PREVIOUS versions of a file are kept regardless of age (the
    /// current one is never counted here and never purged by the sweep).
    pub keep_versions: i64,
}

impl Default for RetentionPolicy {
    /// A month of trash, a quarter of history, three versions deep.
    ///
    /// For a system whose whole point is to spend as little of the hosts' space as
    /// possible, the version depth is the dominant knob: keeping ten versions caps
    /// a frequently-rewritten file's footprint at ~15× its content, three at ~5.6×.
    /// Three is still enough to walk back a couple of bad saves, which is what a
    /// version history is actually used for; a longer history is a per-instance
    /// choice an operator can raise, not a sensible default for the stated goal.
    fn default() -> Self {
        RetentionPolicy { trash_days: 30, version_days: 90, keep_versions: 3 }
    }
}

/// Plaintext and stored bytes reclaimed for one account: `(user_id, size, stored)`.
pub type FreedPerUser = (String, i64, i64);

/// What one retention sweep reclaimed.
pub struct PurgeReport {
    pub files:  usize,
    /// Per account, so the caller can give each user's quota back exactly what was
    /// freed for them.
    pub freed:  Vec<FreedPerUser>,
    /// Shards on peers, in the same shape as [`purge_file`] returns — feed them to
    /// the `gc_remote` job or the space is freed here and nowhere else.
    pub remote: Vec<RemoteShard>,
}

/// Reclaim what the safety net no longer needs to hold: trashed files past
/// `trash_days`, old versions past `version_days`, and old versions beyond
/// `keep_versions` whatever their age.
///
/// Runs across every user (it is a node-wide sweep, not a per-request operation)
/// and is safe to run as often as you like: a sweep that finds nothing does
/// nothing.
pub fn purge_retired(
    manifest: &Manifest,
    store: &ChunkStore,
    policy: RetentionPolicy,
) -> Result<PurgeReport> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;

    let mut candidates = manifest::trashed_before(&tx, &cutoff(policy.trash_days))?;
    candidates.extend(manifest::superseded_before(&tx, &cutoff(policy.version_days))?);
    candidates.extend(manifest::superseded_beyond(&tx, policy.keep_versions.max(0))?);
    // Fourth rule, independent of any age: history whose lineage has nothing left
    // to restore. Waiting out the retention window for versions nobody can ever
    // recover would just hold a user's quota hostage for months.
    candidates.extend(manifest::superseded_orphans(&tx)?);

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut freed: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut frags: Vec<RemoteShard> = Vec::new();
    let mut files = 0usize;
    for (user_id, file_id, size, stored) in candidates {
        // The three rules overlap by design (an old version can be both too old and
        // beyond the count cap); purging a row twice would double-refund its bytes.
        if !seen.insert(file_id.clone()) {
            continue;
        }
        frags.extend(manifest::purge_file_row(&tx, &user_id, &file_id)?);
        let entry = freed.entry(user_id).or_insert((0, 0));
        entry.0 += size;
        entry.1 += stored;
        files += 1;
    }
    tx.commit()?;

    let remote = purge_local_collect_remote(store, frags);
    if files > 0 {
        tracing::info!(files, remote = remote.len(), "p2pnas retention: purged expired trash and versions");
    }
    Ok(PurgeReport {
        files,
        freed: freed.into_iter().map(|(user, (size, stored))| (user, size, stored)).collect(),
        remote,
    })
}

/// `days` ago, RFC3339 — the form every state stamp is written in, so the
/// comparison stays a plain string comparison in SQL.
///
/// `days` is clamped to a century before being converted: a policy read from
/// configuration must never be able to overflow a duration. A negative value would
/// mean "purge into the future", i.e. everything, so it clamps to zero — "purge
/// what has already expired" — instead.
fn cutoff(days: i64) -> String {
    match chrono::Duration::try_days(days.clamp(0, 36_500)) {
        Some(d) => (Utc::now() - d).to_rfc3339(),
        // Unreachable after the clamp; a cutoff of "now" simply expires nothing new.
        None => Utc::now().to_rfc3339(),
    }
}

/// Metadata the async layer needs to fetch a file's shards (local or remote).
pub type ChunkShards = (ChunkRow, Vec<ShardRow>);

/// Read the file + per-chunk shard placement (without fetching shard bytes).
pub fn pull_plan(manifest: &Manifest, user_id: &str, file_id: &str) -> Result<(FileRow, Vec<ChunkShards>)> {
    let conn = manifest.connect()?;
    let file = manifest::get_file(&conn, user_id, file_id)?.ok_or(StoreError::NotFound)?;
    let chunks = manifest::get_chunks(&conn, file_id)?;
    let mut out = Vec::with_capacity(chunks.len());
    for c in chunks {
        let shards = manifest::get_shards(&conn, &c.chunk_id)?;
        out.push((c, shards));
    }
    Ok((file, out))
}

/// Reconstruct + decrypt a file from already-fetched shards. `present[i]` per
/// chunk is the bytes of shard `i` (or None if it couldn't be fetched); RS needs
/// at least `DATA_SHARDS` of the 14.
pub fn reassemble(
    id: &NodeIdentity,
    file: &FileRow,
    chunks: Vec<(ChunkRow, Vec<Option<Vec<u8>>>)>,
) -> Result<Vec<u8>> {
    // Bound to the row's OWN user_id, not to whoever asked: the cryptographic
    // check must be about the real owner of the data.
    let cipher_ctx = FileCipher::new(
        &id.data_key,
        KeyScheme::from_i64(file.key_scheme)?,
        file.user_id.as_bytes(),
        file.file_id.as_bytes(),
        file.chunk_count as u64,
    )?;
    let mut out = Vec::new();
    for (c, present) in chunks {
        let mut cipher = erasure::reconstruct(&present, c.cipher_len as usize)?;
        let plain = cipher_ctx.open_chunk(c.idx as u64, &mut cipher)?;
        out.extend_from_slice(&decompress(plain, c.is_compressed)?);
    }
    Ok(out)
}

// ── Folder-aware browsing (the Drive "My Cloud" mount) ───────────────────────

/// A directory's immediate children: explicit + implicit subfolders, and files.
pub struct DirListing {
    pub folders: Vec<String>, // full paths
    pub files:   Vec<FileRow>,
}

/// List the immediate children of directory `dir` ("" = root). Subfolders are the
/// union of explicit (mkdir'd) folders and those implied by nested file paths.
pub fn browse(manifest: &Manifest, user_id: &str, dir: &str) -> Result<DirListing> {
    use std::collections::BTreeSet;
    let conn = manifest.connect()?;
    let dir = dir.trim_matches('/');

    let mut folders: BTreeSet<String> = manifest::folders_in(&conn, user_id, dir)?.into_iter().collect();
    let mut files = Vec::new();
    for f in manifest::list_files(&conn, user_id)? {
        let rel = if dir.is_empty() {
            Some(f.path.as_str())
        } else {
            f.path.strip_prefix(dir).and_then(|r| r.strip_prefix('/'))
        };
        let Some(rel) = rel else { continue };
        if rel.is_empty() {
            continue;
        }
        match rel.split_once('/') {
            Some((child, _)) => {
                let fp = if dir.is_empty() { child.to_string() } else { format!("{dir}/{child}") };
                folders.insert(fp);
            }
            None => files.push(f),
        }
    }
    Ok(DirListing { folders: folders.into_iter().collect(), files })
}

/// Look up a file row by its path (None if absent).
pub fn get_file_by_path(manifest: &Manifest, user_id: &str, path: &str) -> Result<Option<FileRow>> {
    let conn = manifest.connect()?;
    manifest::get_file_by_path(&conn, user_id, path)
}

/// Create a folder (and missing ancestors).
pub fn mkdir(manifest: &Manifest, user_id: &str, path: &str) -> Result<()> {
    let conn = manifest.connect()?;
    manifest::insert_folder(&conn, user_id, path.trim_matches('/'))
}

/// Rename or move a file or folder from `from` to `to` (path change only — no
/// re-encryption; file_ids and shards are untouched). Atomic.
pub fn rename(manifest: &Manifest, user_id: &str, from: &str, to: &str) -> Result<()> {
    let from = from.trim_matches('/');
    let to = to.trim_matches('/');
    if from.is_empty() || to.is_empty() || from == to {
        return Err(StoreError::NotFound);
    }
    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;

    // Ensure the destination's parent exists.
    manifest::insert_folder(&tx, user_id, manifest::dirname(to))?;

    if let Some(file) = manifest::get_file_by_path(&tx, user_id, from)? {
        // Single file.
        manifest::update_file_path(&tx, user_id, &file.file_id, to)?;
    } else {
        // Folder subtree: rewrite every file + folder path under the prefix.
        let files = manifest::files_under(&tx, user_id, from)?;
        let folders = manifest::folders_under(&tx, user_id, from)?;
        if files.is_empty() && folders.is_empty() {
            return Err(StoreError::NotFound);
        }
        for (file_id, path) in files {
            let suffix = &path[from.len()..]; // includes leading '/' (or empty if path==from)
            manifest::update_file_path(&tx, user_id, &file_id, &format!("{to}{suffix}"))?;
        }
        for path in folders {
            let suffix = &path[from.len()..];
            manifest::update_folder_path(&tx, user_id, &path, &format!("{to}{suffix}"))?;
        }
        manifest::insert_folder(&tx, user_id, to)?;
    }
    tx.commit()?;
    Ok(())
}

/// Every file across all users (node-wide repair/scrub).
pub fn list_all(manifest: &Manifest) -> Result<Vec<FileRow>> {
    let conn = manifest.connect()?;
    manifest::list_all_files(&conn)
}

/// Aggregate manifest stats for the metrics endpoint: (file_count, chunk_count,
/// stored_bytes) across all users.
pub fn node_stats(manifest: &Manifest) -> Result<(i64, i64, i64)> {
    let files = list_all(manifest)?;
    let file_count = files.len() as i64;
    let chunk_count = files.iter().map(|f| f.chunk_count).sum();
    let stored_bytes = files.iter().map(|f| f.stored_bytes).sum();
    Ok((file_count, chunk_count, stored_bytes))
}

/// Rebuild every shard of a chunk from the surviving ones. `present[i]` holds
/// shard `i`'s bytes (or None if it must be regenerated); RS needs ≥ DATA_SHARDS.
/// Returns the 14 shard byte-vectors in index order, byte-identical to the
/// originals (RS + padding are deterministic) — the repair path re-places only
/// the ones that were lost.
pub fn regen_chunk_shards(present: &[Option<Vec<u8>>], cipher_len: usize) -> Result<Vec<Vec<u8>>> {
    let cipher = erasure::reconstruct(present, cipher_len)?;
    Ok(erasure::encode(&cipher)?)
}

/// Write a shard into this node's local store.
pub fn write_local(store: &ChunkStore, fragment_id: &str, bytes: &[u8]) -> Result<()> {
    store.write(fragment_id, bytes)
}

/// Record a shard's new home ('local' or a peer_id) after distribution.
pub fn set_location(manifest: &Manifest, fragment_id: &str, location: &str) -> Result<()> {
    let conn = manifest.connect()?;
    manifest::set_shard_location(&conn, fragment_id, location)
}

/// Read a locally-held shard's bytes (None if absent).
pub fn read_local(store: &ChunkStore, fragment_id: &str) -> Option<Vec<u8>> {
    store.read(fragment_id).ok()
}

/// True if `bytes` match `expected` (empty `expected` = legacy row, skip check).
pub fn verify_hash(bytes: &[u8], expected: &str) -> bool {
    expected.is_empty() || manifest::shard_hash(bytes) == expected
}

/// Read a local shard and verify its content hash; None if missing or corrupt.
pub fn read_local_verified(store: &ChunkStore, fragment_id: &str, expected: &str) -> Option<Vec<u8>> {
    let bytes = store.read(fragment_id).ok()?;
    if verify_hash(&bytes, expected) {
        Some(bytes)
    } else {
        tracing::warn!(fragment_id, "local shard failed integrity check (corrupt) — treating as lost");
        None
    }
}

/// Persist one processed chunk set for `file_id`: the chunk rows, the shard rows
/// and the shard bytes themselves (local store). Shared by `push` and the pack
/// writer, so both write byte-identical structures.
fn write_chunk_rows(
    store: &ChunkStore,
    conn: &rusqlite::Connection,
    file_id: &str,
    chunks: &[ProcessedChunk],
) -> Result<()> {
    for c in chunks {
        let cid = manifest::chunk_id(file_id, c.index);
        manifest::insert_chunk(
            conn,
            &ChunkRow {
                chunk_id:      cid.clone(),
                file_id:       file_id.to_string(),
                idx:           c.index as i64,
                nonce:         c.nonce.to_vec(),
                is_compressed: c.is_compressed,
                plaintext_len: c.plaintext_len as i64,
                cipher_len:    c.cipher.len() as i64,
                shard_len:     c.shard_len as i64,
            },
        )?;

        // 10 data shards (slices of the sealed buffer, padded to shard_len) + 4 parity.
        for i in 0..TOTAL_SHARDS {
            let frag = manifest::fragment_id(&cid, i);
            let bytes = if i < DATA_SHARDS {
                pad_shard(erasure::data_shard(&c.cipher, c.shard_len, i).unwrap_or(&[]), c.shard_len)
            } else {
                c.recovery[i - DATA_SHARDS].clone()
            };
            store.write(&frag, &bytes)?;
            let hash = manifest::shard_hash(&bytes);
            manifest::insert_shard(conn, &ShardRow {
                fragment_id: frag, chunk_id: cid.clone(), shard_index: i as i64, location: "local".into(), hash,
            })?;
        }
    }
    Ok(())
}

/// Pad a (possibly short, last) data-shard slice to the uniform shard length so
/// stored shards are RS-ready for later decode; full shards are returned as-is.
fn pad_shard(slice: &[u8], shard_len: usize) -> Vec<u8> {
    if slice.len() == shard_len {
        slice.to_vec()
    } else {
        let mut v = vec![0u8; shard_len];
        v[..slice.len()].copy_from_slice(slice);
        v
    }
}

// ── Small-file packing ───────────────────────────────────────────────────────
//
// Why: every file, however tiny, is erasure-coded into 14 shards, each stored as
// its own file occupying whole 4 KiB filesystem blocks — a 1 KiB file really
// costs ~57 KiB on disk plus 14 manifest shard rows. Packing N small files into
// one ~1 MiB container that goes through the pipeline ONCE amortises that fixed
// cost across all of them (~1.4× instead of ~56×) and divides the shard/row
// count by two orders of magnitude.
//
// How: a pack is an ordinary `files` row (hidden behind `PACK_PATH_PREFIX`, the
// same trick retired rows use) whose plaintext is the members' bytes followed by
// a self-describing index trailer. The pipeline, crypto, erasure coding, chunk
// and shard handling are strictly unchanged — the pack's file_id plays exactly
// the role any file_id plays, so no cryptographic invariant is touched. A member
// becomes a `(pack_id, pack_offset, pack_len)` triplet over that plaintext.
//
// Packing is DEFERRED, not write-time: small files are first stored on the
// normal path, then a background pass regroups them. That keeps the upload path
// untouched, leaves no half-open pack to lose on a crash, and reuses the
// existing read path to gather the members' bytes.

/// Files at or below this size are candidates for packing. Above it, the fixed
/// per-file overhead (block rounding × 14 shards) is already small relative to
/// the content, and packing would only add read amplification.
pub const SMALL_MAX: usize = 256 * 1024;

/// Target plaintext size of one pack. Large enough to amortise the per-file
/// pipeline overhead across ~dozens of small files, small enough that reading
/// one member (which reconstructs the whole pack) stays cheap.
pub const PACK_TARGET: usize = 1024 * 1024;

/// Trailer magic closing a pack's plaintext. With the index and its length in
/// front of it, a pack can be re-inventoried from its bytes alone — a recovery
/// net if the manifest's member rows are ever lost.
pub const PACK_MAGIC: [u8; 8] = *b"P2PNPAK1";

/// One member going into a pack: its manifest id and its plaintext.
pub struct PackEntry {
    pub file_id: String,
    pub data:    Vec<u8>,
}

/// What writing (or rewriting) one pack did, for the caller's accounting.
pub struct PackResult {
    /// Id of the pack written (None when a memberless pack was purged with no
    /// replacement).
    pub pack_id: Option<String>,
    /// Plaintext size of the new pack (members + index trailer).
    pub pack_size: i64,
    /// Disk cost of the new pack's shards — what the node's `used_bytes` gains.
    pub pack_stored_bytes: i64,
    /// Member rows now pointing at the new pack.
    pub members: usize,
    /// Disk cost released by the storage this pack replaced (the members' own
    /// shards, or the old pack's) — what the node's `used_bytes` gives back.
    pub freed_stored_bytes: i64,
    /// Replaced shards hosted on peers, in the `gc_remote` shape.
    pub remote: Vec<RemoteShard>,
}

/// What one repack pass over a user's small files achieved.
#[derive(Debug, Default)]
pub struct RepackReport {
    pub packs:        usize,
    pub files_packed: usize,
    /// Plaintext bytes moved into packs.
    pub bytes_packed: i64,
    /// Disk cost of the members' former autonomous shards, now released.
    pub stored_freed: i64,
    /// Disk cost of the new packs' shards.
    pub stored_added: i64,
    /// Replaced remote shards to hand to the remote GC.
    pub remote:       Vec<RemoteShard>,
}

/// A member's place in a pack's self-describing index: `(file_id, offset, len)`.
pub type PackIndexEntry = (String, u64, u64);

/// A member's byte range in the pack plaintext: `(offset, len)`.
pub type PackRange = (u64, u64);

/// Build a pack's plaintext from its members:
/// `member0 ‖ … ‖ index ‖ len(index) u32 BE ‖ MAGIC`, where the index holds one
/// `lp(file_id) ‖ offset u64 BE ‖ len u64 BE` per member (lp = u32 BE
/// length-prefixed). Returns the plaintext and each member's `(offset, len)`.
pub fn build_pack(entries: &[PackEntry]) -> Result<(Vec<u8>, Vec<PackRange>)> {
    let payload: usize = entries.iter().map(|e| e.data.len()).sum();
    let mut plain = Vec::with_capacity(payload + entries.len() * 64 + 12);
    let mut ranges = Vec::with_capacity(entries.len());
    for e in entries {
        ranges.push((plain.len() as u64, e.data.len() as u64));
        plain.extend_from_slice(&e.data);
    }
    let index_start = plain.len();
    for (e, (off, len)) in entries.iter().zip(&ranges) {
        let id = e.file_id.as_bytes();
        let id_len = u32::try_from(id.len())
            .map_err(|_| StoreError::Integrity(format!("file id of {} too long for a pack index", e.file_id)))?;
        plain.extend_from_slice(&id_len.to_be_bytes());
        plain.extend_from_slice(id);
        plain.extend_from_slice(&off.to_be_bytes());
        plain.extend_from_slice(&len.to_be_bytes());
    }
    let index_len = u32::try_from(plain.len() - index_start)
        .map_err(|_| StoreError::Integrity("pack index too large".into()))?;
    plain.extend_from_slice(&index_len.to_be_bytes());
    plain.extend_from_slice(&PACK_MAGIC);
    Ok((plain, ranges))
}

/// Pop `n` bytes off the front of `cur` (None when it is too short).
fn take<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if cur.len() < n {
        return None;
    }
    let (head, rest) = cur.split_at(n);
    *cur = rest;
    Some(head)
}

/// Re-read a pack's member index from its plaintext trailer — the recovery path
/// for a manifest that lost its member rows, and what the tests use to check the
/// on-disk format. The manifest columns remain the fast path for normal reads.
pub fn parse_pack_index(pack_plain: &[u8]) -> Result<Vec<PackIndexEntry>> {
    let corrupt = |what: &str| StoreError::Integrity(format!("pack trailer: {what}"));
    let magic_at = pack_plain
        .len()
        .checked_sub(PACK_MAGIC.len())
        .filter(|_| pack_plain.ends_with(&PACK_MAGIC))
        .ok_or_else(|| corrupt("missing magic"))?;
    let len_at = magic_at.checked_sub(4).ok_or_else(|| corrupt("truncated before index length"))?;
    let len_bytes: [u8; 4] = pack_plain[len_at..magic_at].try_into().map_err(|_| corrupt("bad index length"))?;
    let index_len = u32::from_be_bytes(len_bytes) as usize;
    let index_at = len_at.checked_sub(index_len).ok_or_else(|| corrupt("index longer than the pack"))?;

    let mut cur = &pack_plain[index_at..len_at];
    let mut out = Vec::new();
    while !cur.is_empty() {
        let entry = read_index_entry(&mut cur).ok_or_else(|| corrupt("malformed index entry"))?;
        out.push(entry);
    }
    Ok(out)
}

/// One `lp(file_id) ‖ offset ‖ len` record off the front of a pack index (None
/// when the remaining bytes cannot carry one).
fn read_index_entry(cur: &mut &[u8]) -> Option<PackIndexEntry> {
    let id_len: [u8; 4] = take(cur, 4)?.try_into().ok()?;
    let id = take(cur, u32::from_be_bytes(id_len) as usize)?;
    let off: [u8; 8] = take(cur, 8)?.try_into().ok()?;
    let len: [u8; 8] = take(cur, 8)?.try_into().ok()?;
    Some((
        String::from_utf8(id.to_vec()).ok()?,
        u64::from_be_bytes(off),
        u64::from_be_bytes(len),
    ))
}

/// The member's plaintext: the `[pack_offset, pack_offset + pack_len)` range of
/// its pack's plaintext, bounds-checked against corruption.
pub fn member_slice(pack_plain: &[u8], member: &FileRow) -> Result<Vec<u8>> {
    let range_err = || StoreError::Integrity(format!("member {} has an invalid pack range", member.file_id));
    let (off, len) = match (member.pack_offset, member.pack_len) {
        (Some(o), Some(l)) => (o, l),
        _ => return Err(range_err()),
    };
    let (off, len) = match (usize::try_from(off), usize::try_from(len)) {
        (Ok(o), Ok(l)) => (o, l),
        _ => return Err(range_err()),
    };
    let end = off.checked_add(len).ok_or_else(range_err)?;
    let slice = pack_plain.get(off..end).ok_or_else(range_err)?;
    Ok(slice.to_vec())
}

/// Encrypt + erasure-code a pack's plaintext under `pack_id` and write all its
/// rows (file, chunks, shards) through the caller's open transaction. The same
/// pipeline `push` uses, with a fresh id and thus a fresh subkey and nonces.
///
/// Like `push`, the shard bytes hit the local store before the transaction
/// commits: a rollback can at worst strand unreferenced shard files (the same
/// exposure `push` accepts) — never the reverse, rows pointing at absent bytes.
fn insert_pack_row(
    id: &NodeIdentity,
    store: &ChunkStore,
    conn: &rusqlite::Connection,
    user_id: &str,
    pack_id: &str,
    plain: &[u8],
) -> Result<i64> {
    let chunks = pipeline::process_v2(
        plain,
        &id.data_key,
        user_id.as_bytes(),
        pack_id.as_bytes(),
        PipelineConfig::default(),
    )?;
    let stored_bytes: i64 = chunks
        .iter()
        .map(|c| (TOTAL_SHARDS * erasure::shard_disk_cost(c.shard_len)) as i64)
        .sum();
    manifest::insert_file(
        conn,
        &FileRow {
            file_id:       pack_id.to_string(),
            user_id:       user_id.to_string(),
            path:          manifest::pack_key(pack_id),
            size:          plain.len() as i64,
            stored_bytes,
            chunk_count:   chunks.len() as i64,
            created_at:    Utc::now().to_rfc3339(),
            deleted_at:    None,
            superseded_at: None,
            lineage:       pack_id.to_string(),
            key_scheme:    KeyScheme::V2.as_i64(),
            content_hash:  Some(blake3_hex(plain)),
            pack_id:       None,
            pack_offset:   None,
            pack_len:      None,
        },
    )?;
    write_chunk_rows(store, conn, pack_id, &chunks)?;
    Ok(stored_bytes)
}

/// A fresh random file id, in the same form `push` mints.
fn mint_file_id() -> String {
    let mut rnd = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    hex::encode(rnd)
}

/// Group packing (or compaction) candidates into pack loads: consecutive files
/// (they arrive path-ordered, so folder neighbours pack together) up to
/// `PACK_TARGET` plaintext per pack. Groups of one are dropped — packing a lone
/// file adds a container row and frees nothing.
pub fn plan_packs(files: Vec<FileRow>, target: i64) -> Vec<Vec<FileRow>> {
    let mut groups: Vec<Vec<FileRow>> = Vec::new();
    let mut group: Vec<FileRow> = Vec::new();
    let mut bytes = 0i64;
    for f in files {
        if !group.is_empty() && bytes + f.size > target {
            groups.push(std::mem::take(&mut group));
            bytes = 0;
        }
        bytes += f.size;
        group.push(f);
    }
    if !group.is_empty() {
        groups.push(group);
    }
    groups.retain(|g| g.len() >= 2);
    groups
}

/// Move the given files' bytes into one new pack, atomically.
///
/// In a single manifest transaction: every member row is re-checked (still
/// present, still self-contained, same size as the plaintext handed in — a
/// mismatch means the world moved under the caller and the whole pack is rolled
/// back), its own chunks are dropped (collecting their shard locations), and the
/// row is pointed at `(pack_id, offset, len)` with `chunk_count = 0`. The pack
/// row and its chunks/shards are written through the same transaction. Only
/// AFTER the commit are the members' old shards freed locally; the peer-hosted
/// ones are returned for the remote GC — the collect-in-tx / act-after-commit
/// motif every purge path here follows.
///
/// A member trashed or superseded since it was selected still packs correctly:
/// a file_id's content is immutable (overwrites mint new ids), so the row keeps
/// meaning the same bytes whatever its listing state.
pub fn pack_files(
    id: &NodeIdentity,
    manifest: &Manifest,
    store: &ChunkStore,
    user_id: &str,
    entries: &[PackEntry],
) -> Result<PackResult> {
    if entries.is_empty() {
        return Err(StoreError::Integrity("cannot build an empty pack".into()));
    }
    let (plain, ranges) = build_pack(entries)?;
    let pack_id = mint_file_id();

    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;
    let mut freed = 0i64;
    let mut frags: Vec<RemoteShard> = Vec::new();
    for (e, (off, len)) in entries.iter().zip(&ranges) {
        let row = manifest::get_file(&tx, user_id, &e.file_id)?.ok_or_else(|| {
            StoreError::Integrity(format!("file {} vanished while being packed", e.file_id))
        })?;
        // A row already in a pack (a duplicate entry ends up here too, since the
        // first assignment marks it) or whose size no longer matches its bytes
        // must abort the pack, not be packed wrong.
        if row.pack_id.is_some() || row.size != e.data.len() as i64 {
            return Err(StoreError::Integrity(format!("file {} changed while being packed", e.file_id)));
        }
        freed += row.stored_bytes;
        frags.extend(manifest::strip_file_chunks(&tx, user_id, &e.file_id)?);
        manifest::assign_to_pack(&tx, user_id, &e.file_id, &pack_id, *off as i64, *len as i64)?;
    }
    let stored = insert_pack_row(id, store, &tx, user_id, &pack_id, &plain)?;
    tx.commit()?;

    let remote = purge_local_collect_remote(store, frags);
    Ok(PackResult {
        pack_id: Some(pack_id),
        pack_size: plain.len() as i64,
        pack_stored_bytes: stored,
        members: entries.len(),
        freed_stored_bytes: freed,
        remote,
    })
}

/// Rewrite a pack around its `survivors` (every row still referencing it), or
/// purge it outright when nothing references it any more.
///
/// Deleting a member only stamps its row (trash semantics — nothing freed, fully
/// restorable); the dead bytes in the pack are reclaimed here, once enough
/// members have been PURGED that the pack is mostly garbage. Same transaction
/// shape as [`pack_files`]: repoint the survivors to a new pack, drop the old
/// pack row (its chunks and shards cascade), commit, then free/return the old
/// shards.
///
/// Every row still pointing at `old_pack_id` must be among `survivors` —
/// trashed and superseded members included, or purging the old pack would
/// destroy bytes a restore still needs. A missing one aborts the compaction.
pub fn compact_pack(
    id: &NodeIdentity,
    manifest: &Manifest,
    store: &ChunkStore,
    user_id: &str,
    old_pack_id: &str,
    survivors: &[PackEntry],
) -> Result<PackResult> {
    let mut conn = manifest.connect()?;
    let tx = conn.transaction()?;

    let old = manifest::get_file(&tx, user_id, old_pack_id)?.ok_or(StoreError::NotFound)?;
    if !old.is_pack() {
        return Err(StoreError::Integrity(format!("{old_pack_id} is not a pack")));
    }
    let members = manifest::pack_members(&tx, user_id, old_pack_id)?;
    let carried: std::collections::BTreeSet<&str> = survivors.iter().map(|e| e.file_id.as_str()).collect();
    for m in &members {
        if !carried.contains(m.file_id.as_str()) {
            return Err(StoreError::Integrity(format!(
                "member {} of pack {old_pack_id} is not among the compaction survivors",
                m.file_id
            )));
        }
    }

    // Nothing references the pack: it is pure dead weight, purge it directly.
    if survivors.is_empty() {
        let frags = manifest::purge_file_row(&tx, user_id, old_pack_id)?;
        tx.commit()?;
        let remote = purge_local_collect_remote(store, frags);
        return Ok(PackResult {
            pack_id: None,
            pack_size: 0,
            pack_stored_bytes: 0,
            members: 0,
            freed_stored_bytes: old.stored_bytes,
            remote,
        });
    }

    let (plain, ranges) = build_pack(survivors)?;
    let new_pack_id = mint_file_id();
    for (e, (off, len)) in survivors.iter().zip(&ranges) {
        let row = manifest::get_file(&tx, user_id, &e.file_id)?.ok_or_else(|| {
            StoreError::Integrity(format!("file {} vanished while being compacted", e.file_id))
        })?;
        // Survivors must come FROM the pack being rewritten with unchanged sizes;
        // anything else means the caller sliced a stale plaintext.
        if row.pack_id.as_deref() != Some(old_pack_id) || row.size != e.data.len() as i64 {
            return Err(StoreError::Integrity(format!("file {} changed while being compacted", e.file_id)));
        }
        manifest::assign_to_pack(&tx, user_id, &e.file_id, &new_pack_id, *off as i64, *len as i64)?;
    }
    let stored = insert_pack_row(id, store, &tx, user_id, &new_pack_id, &plain)?;
    let frags = manifest::purge_file_row(&tx, user_id, old_pack_id)?;
    tx.commit()?;

    let remote = purge_local_collect_remote(store, frags);
    Ok(PackResult {
        pack_id: Some(new_pack_id),
        pack_size: plain.len() as i64,
        pack_stored_bytes: stored,
        members: survivors.len(),
        freed_stored_bytes: old.stored_bytes,
        remote,
    })
}

/// Regroup one user's small self-contained files into packs, reading their
/// plaintext through the LOCAL pull path — suitable for a node whose shards are
/// still local (and for tests). The server-side pass reads over the network
/// instead and drives [`pack_files`] itself with the same planning helpers.
pub fn repack_small_files(
    id: &NodeIdentity,
    manifest: &Manifest,
    store: &ChunkStore,
    user_id: &str,
) -> Result<RepackReport> {
    let candidates = {
        let conn = manifest.connect()?;
        manifest::packable_files(&conn, user_id, SMALL_MAX as i64)?
    };
    let mut report = RepackReport::default();
    for group in plan_packs(candidates, PACK_TARGET as i64) {
        let mut entries = Vec::with_capacity(group.len());
        for f in &group {
            entries.push(PackEntry {
                file_id: f.file_id.clone(),
                data:    pull(id, manifest, store, user_id, &f.file_id)?,
            });
        }
        let r = pack_files(id, manifest, store, user_id, &entries)?;
        report.packs += 1;
        report.files_packed += r.members;
        report.bytes_packed += entries.iter().map(|e| e.data.len() as i64).sum::<i64>();
        report.stored_freed += r.freed_stored_bytes;
        report.stored_added += r.pack_stored_bytes;
        report.remote.extend(r.remote);
    }
    Ok(report)
}

/// One user's packing candidates (see `manifest::packable_files`).
pub fn list_packable(manifest: &Manifest, user_id: &str) -> Result<Vec<FileRow>> {
    let conn = manifest.connect()?;
    manifest::packable_files(&conn, user_id, SMALL_MAX as i64)
}

/// The users a node-wide repack pass should visit.
pub fn users_with_packable(manifest: &Manifest) -> Result<Vec<String>> {
    let conn = manifest.connect()?;
    manifest::packable_user_ids(&conn, SMALL_MAX as i64)
}

/// Every pack on the node with its referenced bytes and member count.
pub fn list_pack_occupancy(manifest: &Manifest) -> Result<Vec<manifest::PackOccupancy>> {
    let conn = manifest.connect()?;
    manifest::pack_occupancy(&conn)
}

/// Every row (whatever its state) whose bytes live in `pack_id`.
pub fn list_pack_members(manifest: &Manifest, user_id: &str, pack_id: &str) -> Result<Vec<FileRow>> {
    let conn = manifest.connect()?;
    manifest::pack_members(&conn, user_id, pack_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "11111111-1111-1111-1111-111111111111";

    /// A node of its own (identity + manifest + shard store) in a fresh directory.
    /// Tests share a process, so the name has to make the path unique.
    struct TestNode {
        dir:      std::path::PathBuf,
        id:       NodeIdentity,
        manifest: Manifest,
        store:    ChunkStore,
    }

    fn node(name: &str) -> TestNode {
        let dir = std::env::temp_dir().join(format!("p2pnas-test-{}-{name}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let id = NodeIdentity::load_or_create(&dir.join("identity")).unwrap();
        let manifest = Manifest::new(dir.join("manifest.db"), id.manifest_key_hex.clone());
        let store = ChunkStore::new(dir.join("chunks"));
        TestNode { dir, id, manifest, store }
    }

    impl Drop for TestNode {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn bytes(n: usize, seed: u32) -> Vec<u8> {
        (0..n as u32).map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed)) as u8).collect()
    }

    #[test]
    fn push_list_pull_purge_roundtrip() {
        let n = node("roundtrip");
        let data = bytes(5_000_003, 0);

        let res = push(&n.id, &n.manifest, &n.store, USER, "docs/report.bin", &data).unwrap();
        assert_eq!(res.size, data.len() as i64);
        assert!(res.superseded_file_id.is_none());

        let files = list(&n.manifest, USER).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "docs/report.bin");

        let got = pull(&n.id, &n.manifest, &n.store, USER, &res.file_id).unwrap();
        assert_eq!(got, data);

        let (freed, remote) = purge_file(&n.manifest, &n.store, USER, &res.file_id).unwrap();
        assert_eq!(freed.size, data.len() as i64);
        // Single-node test: every shard was local, so nothing is left for remote GC.
        assert!(remote.is_empty());
        assert!(list(&n.manifest, USER).unwrap().is_empty());
    }

    #[test]
    fn a_deleted_file_is_hidden_but_comes_back_intact() {
        let n = node("trash");
        let data = bytes(300_000, 7);
        let res = push(&n.id, &n.manifest, &n.store, USER, "docs/a.txt", &data).unwrap();

        let trashed = trash(&n.manifest, USER, &res.file_id).unwrap();
        assert!(trashed.deleted_at.is_some());
        // Gone from the listing and from the folder view…
        assert!(list(&n.manifest, USER).unwrap().is_empty());
        assert!(browse(&n.manifest, USER, "docs").unwrap().files.is_empty());
        assert!(get_file_by_path(&n.manifest, USER, "docs/a.txt").unwrap().is_none());
        // …but present in the trash, and its bytes were NOT freed.
        let bin = list_trash(&n.manifest, USER).unwrap();
        assert_eq!(bin.len(), 1);
        assert_eq!(bin[0].path, "docs/a.txt");
        assert_eq!(pull(&n.id, &n.manifest, &n.store, USER, &res.file_id).unwrap(), data);

        let back = restore(&n.manifest, USER, &res.file_id, None).unwrap();
        assert!(back.is_live());
        assert_eq!(back.path, "docs/a.txt");
        assert_eq!(list(&n.manifest, USER).unwrap().len(), 1);
        assert!(list_trash(&n.manifest, USER).unwrap().is_empty());
        assert_eq!(pull(&n.id, &n.manifest, &n.store, USER, &res.file_id).unwrap(), data);
    }

    #[test]
    fn the_path_of_a_trashed_file_can_be_reused() {
        let n = node("reuse");
        let first = push(&n.id, &n.manifest, &n.store, USER, "a.txt", &bytes(1_000, 1)).unwrap();
        trash(&n.manifest, USER, &first.file_id).unwrap();

        // The UNIQUE(user_id, path) constraint must not stand in the way.
        let second = push(&n.id, &n.manifest, &n.store, USER, "a.txt", &bytes(2_000, 2)).unwrap();
        // A brand-new lineage: the trashed file is not "the previous version" of it.
        assert!(second.superseded_file_id.is_none());
        assert_eq!(list(&n.manifest, USER).unwrap().len(), 1);
        assert_eq!(list_trash(&n.manifest, USER).unwrap().len(), 1);

        // Restoring the trashed one now finds its path taken: the occupant becomes a
        // version instead of being clobbered, and nothing is lost either way.
        restore(&n.manifest, USER, &first.file_id, None).unwrap();
        let live = list(&n.manifest, USER).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].file_id, first.file_id);
        assert_eq!(pull(&n.id, &n.manifest, &n.store, USER, &second.file_id).unwrap(), bytes(2_000, 2));
    }

    #[test]
    fn overwriting_keeps_the_previous_version() {
        let n = node("versions");
        let v1 = bytes(120_000, 3);
        let v2 = bytes(90_000, 4);
        let first = push(&n.id, &n.manifest, &n.store, USER, "doc.bin", &v1).unwrap();
        let second = push(&n.id, &n.manifest, &n.store, USER, "doc.bin", &v2).unwrap();

        // The overwrite reported what it set aside, and kept it.
        assert_eq!(second.superseded_file_id.as_deref(), Some(first.file_id.as_str()));
        assert_eq!(second.superseded_size, v1.len() as i64);
        assert_eq!(list(&n.manifest, USER).unwrap().len(), 1);

        // Both versions readable, history visible from either id.
        assert_eq!(pull(&n.id, &n.manifest, &n.store, USER, &first.file_id).unwrap(), v1);
        assert_eq!(pull(&n.id, &n.manifest, &n.store, USER, &second.file_id).unwrap(), v2);
        let hist = list_versions(&n.manifest, USER, &first.file_id).unwrap();
        assert_eq!(hist.len(), 2);
        assert_eq!(hist[0].file_id, second.file_id); // newest first

        // Restoring v1 makes it current again and demotes v2 to a version.
        restore(&n.manifest, USER, &first.file_id, None).unwrap();
        let live = list(&n.manifest, USER).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].file_id, first.file_id);
        assert_eq!(list_versions(&n.manifest, USER, &first.file_id).unwrap().len(), 2);
    }

    #[test]
    fn a_trashed_folder_comes_back_with_its_contents() {
        let n = node("folder");
        mkdir(&n.manifest, USER, "work/notes").unwrap();
        let a = push(&n.id, &n.manifest, &n.store, USER, "work/notes/a.txt", &bytes(500, 5)).unwrap();
        let b = push(&n.id, &n.manifest, &n.store, USER, "work/notes/b.txt", &bytes(700, 6)).unwrap();

        let summary = trash_path(&n.manifest, USER, "work").unwrap();
        assert_eq!(summary.files, 2);
        assert!(list(&n.manifest, USER).unwrap().is_empty());
        assert!(browse(&n.manifest, USER, "").unwrap().folders.is_empty());

        restore(&n.manifest, USER, &a.file_id, None).unwrap();
        restore(&n.manifest, USER, &b.file_id, None).unwrap();
        // The folder rows deleted with the subtree are re-created on restore.
        assert_eq!(browse(&n.manifest, USER, "work").unwrap().folders, vec!["work/notes".to_string()]);
        assert_eq!(browse(&n.manifest, USER, "work/notes").unwrap().files.len(), 2);
    }

    #[test]
    fn purging_frees_the_space_and_hands_back_the_remote_shards() {
        let n = node("purge");
        let v1 = bytes(60_000, 8);
        let first = push(&n.id, &n.manifest, &n.store, USER, "doc.bin", &v1).unwrap();
        let second = push(&n.id, &n.manifest, &n.store, USER, "doc.bin", &bytes(60_000, 9)).unwrap();
        let gone = push(&n.id, &n.manifest, &n.store, USER, "trashme.bin", &bytes(40_000, 10)).unwrap();
        trash(&n.manifest, USER, &gone.file_id).unwrap();

        // Pretend one of v1's shards was placed on a peer, so the sweep has
        // something to hand back for remote deletion.
        let (_, chunks) = pull_plan(&n.manifest, USER, &first.file_id).unwrap();
        let frag = chunks[0].1[0].fragment_id.clone();
        set_location(&n.manifest, &frag, "peer-xyz").unwrap();

        // Nothing has expired yet with the default policy.
        let quiet = purge_retired(&n.manifest, &n.store, RetentionPolicy::default()).unwrap();
        assert_eq!(quiet.files, 0);
        assert!(quiet.remote.is_empty());
        assert_eq!(list_versions(&n.manifest, USER, &second.file_id).unwrap().len(), 2);

        // Now age everything out at once (0 days, 0 versions kept).
        let policy = RetentionPolicy { trash_days: 0, version_days: 0, keep_versions: 0 };
        let report = purge_retired(&n.manifest, &n.store, policy).unwrap();
        assert_eq!(report.files, 2); // the old version + the trashed file
        assert_eq!(report.freed.len(), 1);
        assert_eq!(report.freed[0].0, USER);
        assert_eq!(report.freed[0].1, v1.len() as i64 + 40_000);
        // The peer-hosted shard is returned in the `delete` shape, ready for gc_remote.
        assert_eq!(report.remote, vec![(frag, "peer-xyz".to_string())]);

        // The current version is untouched; the trash and the history are empty.
        assert_eq!(list(&n.manifest, USER).unwrap().len(), 1);
        assert!(list_trash(&n.manifest, USER).unwrap().is_empty());
        assert_eq!(list_versions(&n.manifest, USER, &second.file_id).unwrap().len(), 1);
    }

    #[test]
    fn emptying_the_trash_leaves_the_live_files_alone() {
        let n = node("empty");
        let keep = push(&n.id, &n.manifest, &n.store, USER, "keep.txt", &bytes(1_000, 11)).unwrap();
        let drop1 = push(&n.id, &n.manifest, &n.store, USER, "drop.txt", &bytes(2_000, 12)).unwrap();
        trash(&n.manifest, USER, &drop1.file_id).unwrap();

        let (summary, remote) = empty_trash(&n.manifest, &n.store, USER).unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.size, 2_000);
        assert!(remote.is_empty());
        assert!(list_trash(&n.manifest, USER).unwrap().is_empty());
        assert_eq!(list(&n.manifest, USER).unwrap().len(), 1);
        assert_eq!(list(&n.manifest, USER).unwrap()[0].file_id, keep.file_id);
    }

    // ── Small-file packing ───────────────────────────────────────────────────

    /// Push three small files and repack them: one pack, every member read back
    /// byte-identical, the container invisible everywhere, the trailer parsable.
    #[test]
    fn packed_members_read_back_identical() {
        let n = node("pack-roundtrip");
        let payloads = [bytes(3_000, 21), bytes(5_000, 22), bytes(8_000, 23)];
        let mut ids = Vec::new();
        for (i, p) in payloads.iter().enumerate() {
            ids.push(push(&n.id, &n.manifest, &n.store, USER, &format!("small/f{i}.bin"), p).unwrap().file_id);
        }

        let report = repack_small_files(&n.id, &n.manifest, &n.store, USER).unwrap();
        assert_eq!(report.packs, 1);
        assert_eq!(report.files_packed, 3);
        assert!(report.stored_freed > report.stored_added, "packing must shrink the disk footprint");
        assert!(report.remote.is_empty()); // single node: everything was local

        // Every member reads back identical, and shows up exactly as before.
        for (fid, p) in ids.iter().zip(&payloads) {
            assert_eq!(&pull(&n.id, &n.manifest, &n.store, USER, fid).unwrap(), p);
        }
        let listed = list(&n.manifest, USER).unwrap();
        assert_eq!(listed.len(), 3);
        assert!(listed.iter().all(|f| !f.is_pack()));
        assert_eq!(browse(&n.manifest, USER, "small").unwrap().files.len(), 3);

        // The container itself: readable by id, hidden by path, self-describing.
        let member = pull_plan(&n.manifest, USER, &ids[0]).unwrap().0;
        let pack_id = member.pack_id.clone().unwrap();
        assert_eq!(member.chunk_count, 0);
        assert_eq!(member.stored_bytes, 0);
        let pack_plain = pull(&n.id, &n.manifest, &n.store, USER, &pack_id).unwrap();
        let index = parse_pack_index(&pack_plain).unwrap();
        assert_eq!(index.len(), 3);
        assert_eq!(index[0].0, ids[0]);
        assert_eq!(index.iter().map(|e| e.2).sum::<u64>(), 16_000);
    }

    /// Deleting a member is trash semantics: hidden from listings, restorable,
    /// and its bytes stay readable inside the pack the whole time.
    #[test]
    fn a_trashed_member_stays_readable_and_restorable() {
        let n = node("pack-trash");
        let a = push(&n.id, &n.manifest, &n.store, USER, "a.txt", &bytes(2_000, 24)).unwrap();
        let b = push(&n.id, &n.manifest, &n.store, USER, "b.txt", &bytes(2_500, 25)).unwrap();
        repack_small_files(&n.id, &n.manifest, &n.store, USER).unwrap();

        trash(&n.manifest, USER, &a.file_id).unwrap();
        let listed = list(&n.manifest, USER).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].file_id, b.file_id);
        assert_eq!(list_trash(&n.manifest, USER).unwrap().len(), 1);
        assert_eq!(pull(&n.id, &n.manifest, &n.store, USER, &a.file_id).unwrap(), bytes(2_000, 24));

        restore(&n.manifest, USER, &a.file_id, None).unwrap();
        assert_eq!(list(&n.manifest, USER).unwrap().len(), 2);
        assert_eq!(pull(&n.id, &n.manifest, &n.store, USER, &a.file_id).unwrap(), bytes(2_000, 24));
    }

    /// Purging members leaves dead bytes in the pack; compaction rewrites it
    /// around the survivors and a memberless pack is purged outright.
    #[test]
    fn compaction_rewrites_survivors_and_frees_the_old_pack() {
        let n = node("pack-compact");
        let a = push(&n.id, &n.manifest, &n.store, USER, "a.bin", &bytes(9_000, 26)).unwrap();
        let b = push(&n.id, &n.manifest, &n.store, USER, "b.bin", &bytes(2_000, 27)).unwrap();
        let c = push(&n.id, &n.manifest, &n.store, USER, "c.bin", &bytes(1_500, 28)).unwrap();
        repack_small_files(&n.id, &n.manifest, &n.store, USER).unwrap();
        let old_pack = pull_plan(&n.manifest, USER, &a.file_id).unwrap().0.pack_id.unwrap();

        // Purge the big member: its row goes, its bytes turn dead in the pack.
        purge_file(&n.manifest, &n.store, USER, &a.file_id).unwrap();
        let occ = list_pack_occupancy(&n.manifest).unwrap();
        assert_eq!(occ.len(), 1);
        assert_eq!((occ[0].1, occ[0].2), (3_500, 2));

        // Compact around the survivors, read through the (still intact) pack.
        let survivors: Vec<PackEntry> = [&b, &c]
            .iter()
            .map(|f| PackEntry {
                file_id: f.file_id.clone(),
                data:    pull(&n.id, &n.manifest, &n.store, USER, &f.file_id).unwrap(),
            })
            .collect();
        let res = compact_pack(&n.id, &n.manifest, &n.store, USER, &old_pack, &survivors).unwrap();
        let new_pack = res.pack_id.clone().unwrap();
        assert_ne!(new_pack, old_pack);
        assert!(res.pack_size < 9_000, "the dead member's bytes must be gone from the new pack");
        assert!(res.remote.is_empty());

        // Old pack gone, survivors intact and repointed.
        assert!(get_file_by_path(&n.manifest, USER, "a.bin").unwrap().is_none());
        assert!(pull(&n.id, &n.manifest, &n.store, USER, &old_pack).is_err());
        assert_eq!(pull(&n.id, &n.manifest, &n.store, USER, &b.file_id).unwrap(), bytes(2_000, 27));
        assert_eq!(pull(&n.id, &n.manifest, &n.store, USER, &c.file_id).unwrap(), bytes(1_500, 28));

        // Purge the survivors too: the pack has no members left and is dropped.
        purge_file(&n.manifest, &n.store, USER, &b.file_id).unwrap();
        purge_file(&n.manifest, &n.store, USER, &c.file_id).unwrap();
        let res = compact_pack(&n.id, &n.manifest, &n.store, USER, &new_pack, &[]).unwrap();
        assert!(res.pack_id.is_none());
        assert!(res.freed_stored_bytes > 0);
        assert!(list_pack_occupancy(&n.manifest).unwrap().is_empty());
    }

    /// A file above `SMALL_MAX` is never a candidate, and a lone small file is
    /// left alone — packing it would add a row and free nothing.
    #[test]
    fn oversized_and_lone_files_are_never_packed() {
        let n = node("pack-limits");
        let big = push(&n.id, &n.manifest, &n.store, USER, "big.bin", &bytes(SMALL_MAX + 1, 29)).unwrap();
        let lone = push(&n.id, &n.manifest, &n.store, USER, "lone.txt", &bytes(1_000, 30)).unwrap();

        let report = repack_small_files(&n.id, &n.manifest, &n.store, USER).unwrap();
        assert_eq!(report.packs, 0);
        assert_eq!(report.files_packed, 0);
        for fid in [&big.file_id, &lone.file_id] {
            assert!(pull_plan(&n.manifest, USER, fid).unwrap().0.pack_id.is_none());
        }

        // A second small file gives the lone one a companion; the big one still
        // stays out.
        let pal = push(&n.id, &n.manifest, &n.store, USER, "pal.txt", &bytes(1_200, 31)).unwrap();
        let report = repack_small_files(&n.id, &n.manifest, &n.store, USER).unwrap();
        assert_eq!((report.packs, report.files_packed), (1, 2));
        assert!(pull_plan(&n.manifest, USER, &big.file_id).unwrap().0.pack_id.is_none());
        assert!(pull_plan(&n.manifest, USER, &pal.file_id).unwrap().0.pack_id.is_some());
    }
}
