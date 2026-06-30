//! Self-healing repair pass. Scans every file's shard placement, detects shards
//! whose host has become unreachable, and — as long as at least `DATA_SHARDS` of a
//! chunk's 14 shards are still reachable — reconstructs the chunk and re-replicates
//! the lost shards onto healthy locations (this node or a reachable peer).
//!
//! This is what turns the round-robin *spread* (phase 3b) into genuine durability:
//! a chunk placed so that no location holds more than `PARITY_SHARDS` shards stays
//! recoverable across a single failure, and a repair pass restores the redundancy
//! before a second failure can take it below the reconstruction threshold.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::json;

use p2pnas_core::erasure::{DATA_SHARDS, PARITY_SHARDS, TOTAL_SHARDS};
use p2pnas_p2p::P2pMessage;
use p2pnas_store::{ChunkRow, ShardRow};

use crate::state::AppState;

#[derive(Default, Serialize)]
pub struct RepairReport {
    pub files_scanned:       usize,
    pub chunks_scanned:      usize,
    pub chunks_healthy:      usize,
    pub chunks_repaired:     usize,
    pub shards_replaced:     usize,
    pub chunks_unrepairable: usize,
    pub peers_total:         usize,
    pub peers_reachable:     usize,
}

/// Run a full node-wide repair pass. Best-effort: any error on a single file or
/// chunk is logged and skipped so one bad file never aborts the whole sweep.
pub async fn repair_all(st: &AppState) -> RepairReport {
    let mut rep = RepairReport::default();

    // 1. Determine which peers are live right now (a Ping round-trip). Only
    //    reachable peers are valid repair targets; their reliability is refreshed.
    let peers: Vec<(String, String)> =
        sqlx::query_as("SELECT peer_id, addr FROM p2pnas.peers WHERE peer_id <> $1")
            .bind(&st.identity.peer_id)
            .fetch_all(&st.db)
            .await
            .unwrap_or_default();
    rep.peers_total = peers.len();

    // Probe all peers CONCURRENTLY (one node with many offline peers must not
    // serialize 8×timeout). The slow network part runs in parallel; the fast DB
    // bookkeeping (which takes row locks) is then done sequentially, so concurrent
    // repair passes can't contend on the same peer rows for the whole probe time.
    let mut set = tokio::task::JoinSet::new();
    for (pid, addr) in &peers {
        let (id, port, pid, addr) = (st.identity.peer_id.clone(), st.settings.server.port, pid.clone(), addr.clone());
        set.spawn(async move {
            let probe = p2pnas_p2p::ping_observed(&addr, &id, port).await.ok();
            (pid, addr, probe)
        });
    }
    let mut probes = Vec::with_capacity(peers.len());
    while let Some(r) = set.join_next().await {
        if let Ok(x) = r {
            probes.push(x);
        }
    }

    let mut reachable: HashMap<String, String> = HashMap::new();
    let mut observed: HashMap<String, usize> = HashMap::new(); // public IP → vote count
    for (pid, addr, probe) in probes {
        let rtt = probe.as_ref().map(|(r, _)| *r);
        if let Some((_, Some(ip))) = &probe {
            *observed.entry(ip.clone()).or_default() += 1;
        }
        let just_down = record_peer_health(st, &pid, rtt).await;
        if just_down {
            tracing::warn!(peer_id = %pid, "peer marked down after repeated failures");
            let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('peer_down', $1)")
                .bind(json!({ "peer_id": pid, "addr": addr }))
                .execute(&st.db)
                .await;
        }
        if rtt.is_some() {
            reachable.insert(pid, addr);
        }
    }
    rep.peers_reachable = reachable.len();
    detect_self_ip_change(st, observed).await;

    // 2. Every file across all users.
    let man = st.manifest.clone();
    let files = match tokio::task::spawn_blocking(move || p2pnas_store::service::list_all(&man)).await {
        Ok(Ok(f)) => f,
        _ => return rep,
    };

    for file in files {
        rep.files_scanned += 1;
        let man = st.manifest.clone();
        let (uid, fid) = (file.user_id.clone(), file.file_id.clone());
        let plan = match tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid, &fid)).await {
            Ok(Ok((_, chunks))) => chunks,
            _ => continue,
        };
        for (chunk, shards) in plan {
            rep.chunks_scanned += 1;
            repair_chunk(st, &reachable, &chunk, shards, &mut rep).await;
        }
    }
    rep
}

/// Repair one chunk if any of its shards have become unreachable.
async fn repair_chunk(
    st: &AppState,
    reachable: &HashMap<String, String>,
    chunk: &ChunkRow,
    shards: Vec<ShardRow>,
    rep: &mut RepairReport,
) {
    // Index the shard rows (push always writes all 14).
    let mut shard_at: Vec<Option<ShardRow>> = (0..TOTAL_SHARDS).map(|_| None).collect();
    for s in shards {
        let i = s.shard_index as usize;
        if i < TOTAL_SHARDS {
            shard_at[i] = Some(s);
        }
    }

    // Which shards are still reachable?
    let mut reach = [false; TOTAL_SHARDS];
    for i in 0..TOTAL_SHARDS {
        if let Some(s) = &shard_at[i] {
            reach[i] = shard_reachable(st, reachable, s).await;
        }
    }
    let reachable_count = reach.iter().filter(|b| **b).count();
    let missing: Vec<usize> = (0..TOTAL_SHARDS).filter(|&i| shard_at[i].is_some() && !reach[i]).collect();

    if missing.is_empty() {
        rep.chunks_healthy += 1;
        return;
    }
    if reachable_count < DATA_SHARDS {
        rep.chunks_unrepairable += 1;
        emit_unrepairable(st, chunk, reachable_count).await;
        tracing::warn!(chunk = %chunk.chunk_id, reachable_count, "chunk unrepairable: too few shards reachable");
        return;
    }

    // Fetch DATA_SHARDS reachable shards (enough to reconstruct the cipher).
    let mut present: Vec<Option<Vec<u8>>> = (0..TOTAL_SHARDS).map(|_| None).collect();
    let mut got = 0usize;
    for i in 0..TOTAL_SHARDS {
        if got >= DATA_SHARDS {
            break;
        }
        if reach[i] {
            if let Some(s) = &shard_at[i] {
                if let Some(bytes) = fetch_shard(st, reachable, s).await {
                    present[i] = Some(bytes);
                    got += 1;
                }
            }
        }
    }
    if got < DATA_SHARDS {
        rep.chunks_unrepairable += 1;
        tracing::warn!(chunk = %chunk.chunk_id, got, "chunk unrepairable: shard fetch fell short");
        return;
    }

    // Deterministically regenerate all 14 shards from the survivors.
    let cipher_len = chunk.cipher_len as usize;
    let all = match tokio::task::spawn_blocking(move || {
        p2pnas_store::service::regen_chunk_shards(&present, cipher_len)
    })
    .await
    {
        Ok(Ok(v)) => v,
        _ => {
            rep.chunks_unrepairable += 1;
            tracing::warn!(chunk = %chunk.chunk_id, "chunk regeneration failed");
            return;
        }
    };

    // Count shards-per-location among the survivors, so re-placement keeps the
    // single-failure invariant (≤ PARITY_SHARDS per location) where it can.
    let mut loc_count: HashMap<String, usize> = HashMap::new();
    for i in 0..TOTAL_SHARDS {
        if reach[i] {
            if let Some(s) = &shard_at[i] {
                *loc_count.entry(s.location.clone()).or_default() += 1;
            }
        }
    }

    let mut repaired_any = false;
    for &i in &missing {
        let frag = shard_at[i].as_ref().map(|s| s.fragment_id.clone()).unwrap_or_default();
        let Some(bytes) = all.get(i).cloned() else { continue };
        let target = choose_target(&loc_count, reachable);
        if place_shard(st, reachable, &target, &frag, &bytes).await {
            let (man, frag2, loc) = (st.manifest.clone(), frag.clone(), target.clone());
            let _ = tokio::task::spawn_blocking(move || p2pnas_store::service::set_location(&man, &frag2, &loc)).await;
            *loc_count.entry(target).or_default() += 1;
            rep.shards_replaced += 1;
            repaired_any = true;
        }
    }
    if repaired_any {
        rep.chunks_repaired += 1;
    }
}

/// Pick the healthy location holding the fewest shards of this chunk (spreads to
/// preserve fault tolerance). Candidates: this node + every reachable peer.
fn choose_target(loc_count: &HashMap<String, usize>, reachable: &HashMap<String, String>) -> String {
    let mut candidates: Vec<String> = vec!["local".to_string()];
    candidates.extend(reachable.keys().cloned());
    candidates
        .into_iter()
        .min_by_key(|c| loc_count.get(c).copied().unwrap_or(0))
        .unwrap_or_else(|| "local".to_string())
}

/// Is a shard still retrievable AND intact where the manifest says it lives?
/// Remote shards are proof-of-storage audited (content hash compared to the
/// manifest), so a peer that silently corrupted/dropped the data — which a bare
/// `HasShard` would not catch — is treated as a loss and re-replicated.
async fn shard_reachable(st: &AppState, reachable: &HashMap<String, String>, s: &ShardRow) -> bool {
    if s.location == "local" {
        st.store.exists(&s.fragment_id)
    } else if let Some(addr) = reachable.get(&s.location) {
        match p2pnas_p2p::audit_shard(addr, &s.fragment_id).await {
            // Empty manifest hash = legacy shard → fall back to mere presence.
            Ok(h) if !h.is_empty() => s.hash.is_empty() || h == s.hash,
            _ => false,
        }
    } else {
        false
    }
}

/// Fetch a shard's bytes (local read or P2P GetShard).
pub(crate) async fn fetch_shard(st: &AppState, reachable: &HashMap<String, String>, s: &ShardRow) -> Option<Vec<u8>> {
    if s.location == "local" {
        let (store, frag) = (st.store.clone(), s.fragment_id.clone());
        tokio::task::spawn_blocking(move || p2pnas_store::service::read_local(&store, &frag)).await.ok().flatten()
    } else if let Some(addr) = reachable.get(&s.location) {
        match p2pnas_p2p::request(addr, &P2pMessage::GetShard { fragment_id: s.fragment_id.clone() }).await {
            Ok(P2pMessage::ShardData { data, .. }) => Some(data),
            _ => None,
        }
    } else {
        None
    }
}

/// Drop a shard from a location ("local" or a reachable peer_id) after it has been
/// re-placed elsewhere (used by the locality rebalance to free the old copy).
pub(crate) async fn drop_shard(st: &AppState, reachable: &HashMap<String, String>, location: &str, frag: &str) {
    if location == "local" {
        let (store, f) = (st.store.clone(), frag.to_string());
        let _ = tokio::task::spawn_blocking(move || store.delete(&f)).await;
    } else if let Some(addr) = reachable.get(location) {
        let _ = p2pnas_p2p::request(
            addr,
            &P2pMessage::DeleteShard { fragment_id: frag.to_string(), owner_peer_id: st.identity.peer_id.clone() },
        )
        .await;
    }
}

/// Place a shard on a target location ("local" or a reachable peer_id).
pub(crate) async fn place_shard(st: &AppState, reachable: &HashMap<String, String>, target: &str, frag: &str, bytes: &[u8]) -> bool {
    if target == "local" {
        let (store, frag2, data) = (st.store.clone(), frag.to_string(), bytes.to_vec());
        return tokio::task::spawn_blocking(move || p2pnas_store::service::write_local(&store, &frag2, &data))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
    }
    let Some(addr) = reachable.get(target) else { return false };
    let msg = P2pMessage::StoreShard {
        fragment_id:   frag.to_string(),
        owner_peer_id: st.identity.peer_id.clone(),
        data:          bytes.to_vec(),
    };
    matches!(p2pnas_p2p::request(addr, &msg).await, Ok(P2pMessage::Ack { .. }))
}

/// Consecutive failed probes before a peer is marked `down` (and excluded from
/// new placements until it answers again).
const DOWN_THRESHOLD: i32 = 5;

/// Update a peer's reliability after a liveness probe (EWMA toward 100 or 0), its
/// measured round-trip latency (EWMA, ms), and its consecutive-failure / status
/// flag. `rtt` is Some(ms) when the peer answered, None when it didn't. Returns
/// true if the peer just went from active → down (so the caller can repair).
async fn record_peer_health(st: &AppState, peer_id: &str, rtt: Option<f64>) -> bool {
    if let Some(rtt_ms) = rtt {
        let _ = sqlx::query(
            "UPDATE p2pnas.peers
             SET reliability_score = LEAST(100.0, reliability_score * 0.8 + 20.0),
                 rtt_ms = CASE WHEN rtt_ms IS NULL THEN $2 ELSE rtt_ms * 0.7 + $2 * 0.3 END,
                 consecutive_failures = 0, status = 'active', last_seen = now()
             WHERE peer_id = $1",
        )
        .bind(peer_id)
        .bind(rtt_ms)
        .execute(&st.db)
        .await;
        return false;
    }
    // Failure: decay score, bump the failure counter, flip to 'down' at the
    // threshold. RETURNING tells us whether this probe crossed the line.
    let row: Option<(i32, String)> = sqlx::query_as(
        "UPDATE p2pnas.peers
         SET reliability_score = GREATEST(0.0, reliability_score * 0.8),
             consecutive_failures = consecutive_failures + 1,
             status = CASE WHEN consecutive_failures + 1 >= $2 THEN 'down' ELSE status END
         WHERE peer_id = $1
         RETURNING consecutive_failures, status",
    )
    .bind(peer_id)
    .bind(DOWN_THRESHOLD)
    .fetch_optional(&st.db)
    .await
    .ok()
    .flatten();
    matches!(row, Some((f, s)) if s == "down" && f == DOWN_THRESHOLD)
}

/// Compare the consensus public IP (majority of what peers observed) to the last
/// known one. On a change, record it, emit an `ip_changed` event, and enqueue a
/// locality rebalance so data can be re-homed nearer the node's new location.
async fn detect_self_ip_change(st: &AppState, observed: HashMap<String, usize>) {
    let Some((ip, _)) = observed.into_iter().max_by_key(|(_, n)| *n) else { return };
    let prev: Option<String> = sqlx::query_scalar("SELECT public_ip FROM p2pnas.node_local WHERE id = 1")
        .fetch_one(&st.db)
        .await
        .ok()
        .flatten();
    if prev.as_deref() == Some(ip.as_str()) {
        return; // unchanged
    }
    let _ = sqlx::query("UPDATE p2pnas.node_local SET public_ip = $1, updated_at = now() WHERE id = 1")
        .bind(&ip)
        .execute(&st.db)
        .await;
    if let Some(old) = prev {
        // Always record the change; only auto-trigger a rebalance if we haven't
        // re-homed recently (hysteresis against a flapping IP).
        let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('ip_changed', $1)")
            .bind(json!({ "old": old, "new": ip }))
            .execute(&st.db)
            .await;
        let recent: Option<bool> = sqlx::query_scalar(
            "SELECT last_rebalance_at > now() - interval '30 minutes' FROM p2pnas.node_local WHERE id = 1",
        )
        .fetch_one(&st.db)
        .await
        .ok()
        .flatten();
        if recent == Some(true) {
            tracing::info!(old = %old, new = %ip, "public IP changed but rebalanced recently — skipping (cooldown)");
        } else {
            tracing::info!(old = %old, new = %ip, "public IP changed — enqueueing locality rebalance");
            crate::jobs::enqueue(&st.db, "rebalance_locality", json!({ "reason": "ip_changed" })).await;
        }
    }
}

/// Log a data-loss-risk event for a chunk that can no longer be reconstructed.
async fn emit_unrepairable(st: &AppState, chunk: &ChunkRow, reachable_count: usize) {
    let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('chunk_unrepairable', $1)")
        .bind(json!({
            "chunk_id": chunk.chunk_id,
            "file_id": chunk.file_id,
            "reachable_shards": reachable_count,
            "needed": DATA_SHARDS,
        }))
        .execute(&st.db)
        .await;
}

/// The minimum number of distinct locations needed for single-failure durability
/// (so no location must hold more than `PARITY_SHARDS` shards). Exposed for the
/// upload path's durability warning.
pub fn min_locations_for_durability() -> usize {
    TOTAL_SHARDS.div_ceil(PARITY_SHARDS)
}
