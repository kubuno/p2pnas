//! Automatic distributed backup of the manifest — and the disaster recovery that
//! makes it worth having.
//!
//! The cold bundle (`GET /admin/backup`) already protects a node whose
//! administrator remembered to download it. This module protects the one who
//! didn't: once a day the node vacuums a consistent snapshot of `manifest.db`,
//! seals it under a key derived from its own master key, erasure-codes it into
//! the same 10+4 scheme as user data, and pushes the 14 shards onto the peers it
//! already trusts. Nothing is kept locally — the disk we are insuring against is
//! precisely the one that dies.
//!
//! The addressing is what makes recovery possible at all: fragment ids are
//! `blake3(domain ‖ peer_id ‖ version ‖ shard_index)`, and `peer_id` re-derives
//! from `identity.key`. A brand-new machine holding only that 32-byte file can
//! therefore recompute every id of every recent backup and simply ask around —
//! no manifest, no database, no notes. See `p2pnas_store::backup` for the format.
//!
//! Two problems have no purely technical answer, and are handled by policy:
//!
//!   - **Where do the peers come from?** Their addresses live in the PostgreSQL
//!     control plane, which a disaster may or may not have taken down with the
//!     node. If it survived, `p2pnas.peers` is used as-is. If it didn't, the
//!     restore accepts a list of addresses from the administrator (`peers` in the
//!     request body) — the one piece of knowledge a human has to keep, and it is
//!     public information, unlike the key.
//!   - **Which version is the latest?** Versions are day numbers, so the restore
//!     walks candidates backwards from today until it finds one whose shards are
//!     actually out there. No counter to lose.

use std::sync::Arc;

use p2pnas_core::erasure::{DATA_SHARDS, TOTAL_SHARDS};
use p2pnas_p2p::P2pMessage;
use p2pnas_store::backup::{self, ManifestBackupShard};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    errors::{P2pError, Result},
    state::AppState,
};

/// How many daily versions stay on the peers.
///
/// One week. The point of keeping more than one is not redundancy — erasure
/// coding already provides that — but *time*: a manifest that gets damaged and
/// then faithfully backed up in its damaged state is only recoverable if an
/// earlier copy is still around, and a week is the shortest window in which a
/// human plausibly notices and reacts. Beyond that the copies are pure cost, paid
/// in the peers' disks, so they are actively deleted rather than left to rot.
const KEEP_VERSIONS: u64 = 7;

/// How far past `KEEP_VERSIONS` each run sweeps for shards to delete.
///
/// The sweep is blind (it asks peers to drop ids that may never have existed,
/// which they answer idempotently) because there is no reliable record of which
/// versions were written: the events table is itself purged after 30 days. A
/// 30-day trailing window means a node offline for up to a month still cleans up
/// everything it left behind when it comes back. Older orphans, if a node stays
/// dark for longer, are reclaimed by the hosts' own retention sweep — the same
/// backstop that covers its ordinary shards.
const SWEEP_DEPTH: u64 = 30;

/// Default number of days a restore scans backwards when no version is given.
const DEFAULT_LOOKBACK_DAYS: u64 = 90;
/// Hard cap on that scan: each candidate costs one round of probes to every peer.
const MAX_LOOKBACK_DAYS: u64 = 400;

/// Largest shard a peer will host (`p2p::MAX_HOSTED_SHARD`). A manifest whose
/// snapshot exceeds ~80 MB would produce shards above it and be refused by every
/// peer, so we say so once, clearly, instead of logging 14 rejections.
const MAX_PEER_SHARD_BYTES: usize = 8 * 1024 * 1024;

/// Outcome of one backup pass, surfaced in the logs and in `/admin/manifest-backup`.
#[derive(Default, Serialize)]
pub struct ManifestBackupReport {
    pub version:        u64,
    /// This version was already placed (the job ran twice in one day).
    pub skipped:        bool,
    pub snapshot_bytes: usize,
    pub blob_bytes:     usize,
    pub shards_placed:  usize,
    pub peers_used:     usize,
    /// True once at least `DATA_SHARDS` shards are out there — the point from
    /// which this version is actually recoverable.
    pub recoverable:    bool,
    pub versions_swept: usize,
    pub delete_acks:    usize,
}

/// What a successful restore did.
#[derive(Serialize)]
pub struct ManifestRestoreOutcome {
    pub version:         u64,
    pub snapshot_bytes:  usize,
    pub shards_used:     usize,
    pub peers_tried:     usize,
    pub versions_probed: usize,
}

/// peer_id → address, for the peers that answered a liveness probe just now.
type ReachablePeers = Vec<(String, String)>;

// ─────────────────────────────────────────────────────────────────────────────
// Backup
// ─────────────────────────────────────────────────────────────────────────────

/// Run one backup pass. Best-effort by design: every failure is logged and
/// recorded as an event, never propagated — a job that fails loudly once a day is
/// a job an operator learns to ignore.
pub async fn run_backup(st: &AppState) -> ManifestBackupReport {
    let version = backup::manifest_backup_version_now();
    let mut rep = ManifestBackupReport { version, ..Default::default() };

    // Idempotence: the ticker, a manual trigger and the stale-job requeue can all
    // ask for the same day. Recomputing it would be harmless (same ids, same
    // overwrite) but would re-vacuum and re-upload the whole manifest for nothing.
    if already_placed(st, version).await {
        tracing::debug!(version, "manifest backup already placed today");
        rep.skipped = true;
        return rep;
    }

    let peers = reachable_peers(st).await;
    rep.peers_used = peers.len();
    if peers.is_empty() {
        tracing::warn!(
            version,
            "manifest backup: no reachable peer — the manifest is NOT protected against a disk loss"
        );
        emit(st, "manifest_backup_failed", json!({ "version": version, "reason": "no reachable peer" })).await;
        return rep;
    }

    let data_dir = std::path::PathBuf::from(&st.settings.storage.data_dir);
    let (man, id) = (st.manifest.clone(), st.identity.clone());
    let built = tokio::task::spawn_blocking(move || {
        backup::build_manifest_backup(&data_dir, &man, &id.data_key, &id.peer_id, version)
    })
    .await;
    let built = match built {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            tracing::error!(version, error = %e, "manifest backup: snapshot or sealing failed");
            emit(st, "manifest_backup_failed", json!({ "version": version, "reason": e.to_string() })).await;
            return rep;
        }
        Err(e) => {
            tracing::error!(version, error = %e, "manifest backup: build task failed");
            return rep;
        }
    };
    rep.snapshot_bytes = built.snapshot_len;
    rep.blob_bytes = built.blob_len;

    let shard_bytes = built.shards.first().map(Vec::len).unwrap_or(0);
    if shard_bytes > MAX_PEER_SHARD_BYTES {
        tracing::error!(
            version,
            shard_bytes,
            limit = MAX_PEER_SHARD_BYTES,
            "manifest backup: the snapshot is too large for a peer to host — every placement would be refused"
        );
        emit(st, "manifest_backup_failed", json!({ "version": version, "reason": "snapshot too large for the shard size limit" })).await;
        return rep;
    }

    // Round-robin over the peers (sorted by peer id, so the spread is stable from
    // one day to the next). With ≥ 4 peers no host ends up with more than
    // PARITY_SHARDS shards, which is the same single-failure invariant the repair
    // pass enforces for user data. With fewer, the backup still protects against
    // the case it exists for — OUR disk dying — and that is the honest trade.
    for (i, shard) in built.shards.iter().enumerate() {
        let (peer_id, addr) = &peers[i % peers.len()];
        let frag = backup::manifest_backup_fragment_id(&st.identity.peer_id, version, i);
        if place(st, addr, &frag, i as i32, shard).await {
            rep.shards_placed += 1;
        } else {
            tracing::warn!(version, shard_index = i, peer_id = %peer_id, "manifest backup: placement refused");
        }
    }

    rep.recoverable = rep.shards_placed >= DATA_SHARDS;
    if rep.recoverable {
        tracing::info!(
            version,
            placed = rep.shards_placed,
            peers = rep.peers_used,
            snapshot_bytes = rep.snapshot_bytes,
            "manifest backup distributed"
        );
        emit(
            st,
            "manifest_backup",
            json!({
                "version": version,
                "shards_placed": rep.shards_placed,
                "peers": rep.peers_used,
                "snapshot_bytes": rep.snapshot_bytes,
            }),
        )
        .await;
        // Only prune once THIS version is safely out there. Deleting last week's
        // copies while today's failed would be the one way this feature could
        // destroy the very thing it protects.
        sweep_old_versions(st, &peers, version, &mut rep).await;
    } else {
        tracing::warn!(
            version,
            placed = rep.shards_placed,
            needed = DATA_SHARDS,
            "manifest backup: too few shards placed to be recoverable"
        );
        emit(
            st,
            "manifest_backup_failed",
            json!({ "version": version, "shards_placed": rep.shards_placed, "needed": DATA_SHARDS }),
        )
        .await;
    }
    rep
}

/// Has a recoverable backup already been recorded for this version?
async fn already_placed(st: &AppState, version: u64) -> bool {
    let found: std::result::Result<Option<i32>, sqlx::Error> = sqlx::query_scalar(
        "SELECT 1 FROM p2pnas.events WHERE kind = 'manifest_backup' AND payload->>'version' = $1 LIMIT 1",
    )
    .bind(version.to_string())
    .fetch_optional(&st.db)
    .await;
    match found {
        Ok(v) => v.is_some(),
        Err(e) => {
            // Losing this check only costs a redundant pass; refusing to back up
            // because a SELECT failed would cost the backup itself.
            tracing::warn!(error = %e, "manifest backup: could not check today's version — running anyway");
            false
        }
    }
}

/// The peers that answered a liveness probe just now, sorted by peer id.
async fn reachable_peers(st: &AppState) -> ReachablePeers {
    let rows: Vec<(String, String)> =
        match sqlx::query_as("SELECT peer_id, addr FROM p2pnas.peers WHERE peer_id <> $1")
            .bind(&st.identity.peer_id)
            .fetch_all(&st.db)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "manifest backup: peer table read failed");
                return Vec::new();
            }
        };

    let mut set = tokio::task::JoinSet::new();
    for (pid, addr) in rows {
        let (me, port) = (st.identity.peer_id.clone(), st.settings.server.port);
        set.spawn(async move {
            let up = p2pnas_p2p::ping(&addr, &me, port).await.is_ok();
            (pid, addr, up)
        });
    }
    let mut out: ReachablePeers = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok((pid, addr, true)) = r {
            out.push((pid, addr));
        }
    }
    out.sort();
    out
}

/// Hand one shard to a peer. Signed, like every outbound write: a peer running in
/// strict mode drops anything whose sender has not proven its identity.
async fn place(st: &AppState, addr: &str, frag: &str, shard_index: i32, bytes: &[u8]) -> bool {
    let msg = P2pMessage::StoreShard {
        fragment_id:   frag.to_string(),
        owner_peer_id: st.identity.peer_id.clone(),
        shard_index,
        data:          bytes.to_vec(),
    };
    matches!(
        crate::p2p::signed_request(&st.identity, st.settings.server.port, addr, &msg).await,
        Ok(P2pMessage::Ack { .. })
    )
}

/// Ask every peer to drop the shards of the versions that have aged out.
///
/// Without this, a daily backup would leak a full manifest copy per day onto the
/// peers, forever — recreating exactly the unbounded growth the shard retention
/// work has just fixed. Deletions are addressed by the same deterministic ids, so
/// no bookkeeping is needed to find them.
async fn sweep_old_versions(
    st: &AppState,
    peers: &[(String, String)],
    current: u64,
    rep: &mut ManifestBackupReport,
) {
    let Some(newest_stale) = current.checked_sub(KEEP_VERSIONS) else { return };
    let oldest = newest_stale.saturating_sub(SWEEP_DEPTH);

    for v in oldest..=newest_stale {
        // One version at a time, all of its (shard × peer) deletions in parallel:
        // bounded fan-out (14 × peers) and a short pass even against slow hosts.
        let mut set = tokio::task::JoinSet::new();
        for i in 0..TOTAL_SHARDS {
            let frag = backup::manifest_backup_fragment_id(&st.identity.peer_id, v, i);
            for (_, addr) in peers {
                let identity: Arc<p2pnas_store::NodeIdentity> = st.identity.clone();
                let (port, addr, frag) = (st.settings.server.port, addr.clone(), frag.clone());
                let owner = st.identity.peer_id.clone();
                set.spawn(async move {
                    let msg = P2pMessage::DeleteShard { fragment_id: frag, owner_peer_id: owner };
                    matches!(
                        crate::p2p::signed_request(&identity, port, &addr, &msg).await,
                        Ok(P2pMessage::Ack { .. })
                    )
                });
            }
        }
        while let Some(r) = set.join_next().await {
            if matches!(r, Ok(true)) {
                rep.delete_acks += 1;
            }
        }
        rep.versions_swept += 1;
    }
}

/// Append a control-plane event (best effort — an unrecorded event never stops a
/// backup, but a failure to record one is worth a log line).
async fn emit(st: &AppState, kind: &str, payload: Value) {
    if let Err(e) = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ($1, $2)")
        .bind(kind)
        .bind(payload)
        .execute(&st.db)
        .await
    {
        tracing::error!(kind, error = %e, "recording a manifest backup event");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Restore
// ─────────────────────────────────────────────────────────────────────────────

/// Recover `manifest.db` from the peers, onto a node that holds nothing.
///
/// `extra_peers` are addresses supplied by the administrator; they are merged with
/// whatever `p2pnas.peers` still holds, so the procedure works both when the
/// control-plane database survived the incident and when it didn't. `version`
/// pins one specific day (for a deliberate rollback); left out, the scan walks
/// back `lookback_days` from today and takes the first version it can rebuild.
pub async fn restore(
    st: &AppState,
    extra_peers: &[String],
    version: Option<u64>,
    lookback_days: Option<u64>,
) -> Result<ManifestRestoreOutcome> {
    // Fail before touching the network: a restore must never clobber a live node.
    let man = st.manifest.clone();
    tokio::task::spawn_blocking(move || backup::ensure_fresh_node(&man))
        .await
        .map_err(|_| P2pError::BadRequest("vérification préalable impossible".into()))?
        .map_err(|e| P2pError::BadRequest(e.to_string()))?;

    let addrs = restore_peer_addresses(st, extra_peers).await;
    if addrs.is_empty() {
        return Err(P2pError::BadRequest(
            "aucun pair connu : fournissez `peers` (une liste d'adresses ip:port) — sans pair, \
             les fragments de la sauvegarde sont introuvables"
                .into(),
        ));
    }

    let today = backup::manifest_backup_version_now();
    let candidates: Vec<u64> = match version {
        Some(v) => vec![v],
        None => {
            let depth = lookback_days.unwrap_or(DEFAULT_LOOKBACK_DAYS).clamp(1, MAX_LOOKBACK_DAYS);
            (0..=depth).filter_map(|d| today.checked_sub(d)).collect()
        }
    };

    let mut probed = 0usize;
    for v in candidates {
        probed += 1;
        let found = probe_version(st, &addrs, v).await;
        if found.len() < DATA_SHARDS {
            continue;
        }
        tracing::info!(version = v, shards = found.len(), "manifest restore: candidate version found");
        let Some((snapshot, used)) = fetch_and_open(st, v, &found).await else {
            tracing::warn!(version = v, "manifest restore: version present but unusable — trying an older one");
            continue;
        };

        let data_dir = std::path::PathBuf::from(&st.settings.storage.data_dir);
        let man = st.manifest.clone();
        let snap_len = snapshot.len();
        tokio::task::spawn_blocking(move || backup::restore_manifest_db(&data_dir, &man, &snapshot))
            .await
            .map_err(|_| P2pError::BadRequest("écriture du manifeste impossible".into()))?
            .map_err(|e| P2pError::BadRequest(e.to_string()))?;

        tracing::warn!(version = v, snapshot_bytes = snap_len, "manifest restored from peers — restart the module");
        emit(st, "manifest_restored", json!({ "version": v, "snapshot_bytes": snap_len, "shards_used": used })).await;
        return Ok(ManifestRestoreOutcome {
            version:         v,
            snapshot_bytes:  snap_len,
            shards_used:     used,
            peers_tried:     addrs.len(),
            versions_probed: probed,
        });
    }

    Err(P2pError::BadRequest(format!(
        "aucune sauvegarde du manifeste retrouvée après {probed} version(s) auprès de {} pair(s) — \
         élargissez `lookback_days` ou fournissez d'autres adresses de pairs",
        addrs.len()
    )))
}

/// Peer addresses to interrogate: the control plane's, if it still answers, plus
/// whatever the administrator typed in.
async fn restore_peer_addresses(st: &AppState, extra: &[String]) -> Vec<String> {
    let mut addrs: Vec<String> =
        match sqlx::query_scalar("SELECT addr FROM p2pnas.peers WHERE peer_id <> $1")
            .bind(&st.identity.peer_id)
            .fetch_all(&st.db)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                // The chicken-and-egg case: the database went down with the node.
                // Not fatal — the administrator can name the peers by hand.
                tracing::warn!(error = %e, "manifest restore: peer table unavailable — using only the supplied addresses");
                Vec::new()
            }
        };
    addrs.extend(extra.iter().map(|a| a.trim().to_string()).filter(|a| !a.is_empty()));
    addrs.sort();
    addrs.dedup();
    addrs
}

/// Which shards of `version` exist, and on which peer. `HasShard` carries no
/// payload, so scanning many candidate versions stays cheap.
async fn probe_version(st: &AppState, addrs: &[String], version: u64) -> Vec<(usize, String)> {
    let mut set = tokio::task::JoinSet::new();
    for i in 0..TOTAL_SHARDS {
        let frag = backup::manifest_backup_fragment_id(&st.identity.peer_id, version, i);
        for addr in addrs {
            let (addr, frag) = (addr.clone(), frag.clone());
            set.spawn(async move {
                let present = p2pnas_p2p::has_shard(&addr, &frag).await.unwrap_or(false);
                (i, addr, present)
            });
        }
    }
    let mut host: Vec<Option<String>> = vec![None; TOTAL_SHARDS];
    while let Some(r) = set.join_next().await {
        let Ok((i, addr, true)) = r else { continue };
        // First answer wins: one reachable host per shard is all a fetch needs.
        if host[i].is_none() {
            host[i] = Some(addr);
        }
    }
    host.into_iter().enumerate().filter_map(|(i, a)| a.map(|a| (i, a))).collect()
}

/// Pull the located shards, rebuild the blob and decrypt it. `None` means this
/// version cannot be turned back into a manifest — the caller then tries an older
/// one rather than giving up.
async fn fetch_and_open(st: &AppState, version: u64, found: &[(usize, String)]) -> Option<(Vec<u8>, usize)> {
    let mut set = tokio::task::JoinSet::new();
    for (i, addr) in found {
        let frag = backup::manifest_backup_fragment_id(&st.identity.peer_id, version, *i);
        let addr = addr.clone();
        // Plain (unsigned) request: reads need no proof of who is asking, and the
        // payload is useless to anyone without the node key anyway.
        set.spawn(async move {
            match p2pnas_p2p::request(&addr, &P2pMessage::GetShard { fragment_id: frag }).await {
                Ok(P2pMessage::ShardData { data, .. }) => Some(data),
                _ => None,
            }
        });
    }

    let mut shards: Vec<ManifestBackupShard> = Vec::new();
    while let Some(r) = set.join_next().await {
        let Ok(Some(bytes)) = r else { continue };
        match backup::decode_manifest_backup_shard(&bytes) {
            Ok(s) if s.version == version => shards.push(s),
            Ok(s) => tracing::warn!(got = s.version, want = version, "manifest restore: shard of another version"),
            Err(e) => tracing::warn!(error = %e, "manifest restore: undecodable shard envelope"),
        }
    }
    if shards.len() < DATA_SHARDS {
        return None;
    }
    let used = shards.len();

    let blob = backup::reassemble_manifest_backup(&shards)
        .map_err(|e| tracing::warn!(version, error = %e, "manifest restore: reconstruction failed"))
        .ok()?;
    let snapshot =
        backup::open_manifest_snapshot(&st.identity.data_key, &st.identity.peer_id, version, &blob)
            .map_err(|e| tracing::warn!(version, error = %e, "manifest restore: decryption failed"))
            .ok()?;
    Some((snapshot, used))
}

/// The versions this node believes it has distributed, most recent first (from
/// the control-plane event log — informational, the restore never relies on it).
pub async fn recorded_versions(st: &AppState, limit: i64) -> Vec<Value> {
    type Row = (Value, chrono::DateTime<chrono::Utc>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT payload, created_at FROM p2pnas.events WHERE kind = 'manifest_backup' ORDER BY id DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();
    rows.into_iter()
        .map(|(payload, at)| json!({ "payload": payload, "created_at": at.to_rfc3339() }))
        .collect()
}
