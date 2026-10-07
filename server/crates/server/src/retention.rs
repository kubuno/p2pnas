//! Retention / reciprocity sweep — host side.
//!
//! This node hosts shards for other peers (`hosted_shards`). When an owner stops
//! coming online it stops contributing to everyone else's durability, so we
//! gradually reclaim the space its data uses here. But generously, reversibly,
//! and in proportion to how much it contributed — because a node being offline is
//! not proof of bad faith (it may be down for reasons beyond its control).
//!
//! Absence is `now − peers.last_seen`. The instance thresholds (grace / reclaim /
//! evict, in days) are the network's backbone; each is STRETCHED per owner by a
//! reliability factor derived from `peers.reliability_score`, so a dependable
//! owner keeps its data far longer than a free-rider. That stretch is the margin:
//! we do for you what you do for us, with a margin.
//!
//! On top of that, `peers.threshold_days` is this host's OWN generosity toward a
//! given peer — extra days it chooses to grant, independently of the instance
//! policy. The instance sets the floor the network needs to stay healthy; each
//! host decides what more it is willing to offer to a peer it knows.
//!
//! Stages — each host acts LOCALLY on its own hosted shards. There is
//! deliberately no "delete X's data" network message: that would be a mass
//! destruction primitive, especially while peers are not yet cryptographically
//! authenticated.
//!   present / grace  → nothing is removed.
//!   reclaim          → shed the PARITY shards we host (index ≥ data count). The
//!                      data shards alone still reconstruct the file, so the owner
//!                      loses nothing and can be made whole on return — this is
//!                      the reversible margin.
//!   evict            → remove everything we host for that owner.
//!
//! Shards whose index is unknown (`-1`, hosted before this was tracked) are never
//! treated as parity, so they are only ever removed at full eviction.

use chrono::{DateTime, Utc};
use kubuno_db::params;
use serde_json::json;

use p2pnas_core::erasure::DATA_SHARDS;

use crate::state::AppState;

/// Run one retention sweep across every owner we host shards for.
pub async fn sweep(st: &AppState) {
    let inst = st.instance();

    let owners: Vec<String> = st
        .db
        .fetch_all_as::<(String,)>("SELECT DISTINCT owner_peer_id FROM p2pnas.hosted_shards", params![])
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(o,)| o)
        .collect();

    for owner in owners {
        // Absence reference: the owner's last liveness, or — if we never recorded
        // one — when we last received data from it. Reliability credits only a
        // known peer; an owner no longer in `peers` gets none.
        let row: Option<(Option<DateTime<Utc>>, f64, i32)> = st
            .db
            .fetch_optional_as(
                "SELECT last_seen, reliability_score, threshold_days FROM p2pnas.peers WHERE peer_id = $1",
                params![&owner],
            )
            .await
            .ok()
            .flatten();

        let (reference, reliability, generosity_days) = match row {
            Some((Some(seen), rel, grace)) => (seen, rel, grace),
            Some((None, rel, grace)) => (fallback_reference(st, &owner).await, rel, grace),
            // An owner no longer in `peers` earns neither reliability credit nor
            // extra generosity.
            None => (fallback_reference(st, &owner).await, 0.0, 0),
        };

        let absent_days = (Utc::now() - reference).num_seconds() as f64 / 86_400.0;
        // Reliable owners earn up to +50% on every threshold, unreliable ones
        // down to −50%.
        let factor = (0.5 + reliability / 100.0).clamp(0.5, 1.5);
        // `peers.threshold_days` is this node's OWN generosity toward that peer:
        // extra days granted on top of the instance policy, settable per peer. The
        // instance sets the network's backbone, each host decides what more it is
        // willing to offer — which is the whole reciprocity idea. Negative values
        // are ignored: generosity can only ever add time, never take it away.
        let generosity = generosity_days.max(0) as f64;
        let reclaim_at = inst.retention_reclaim_days as f64 * factor + generosity;
        let evict_at = inst.retention_evict_days as f64 * factor + generosity;

        if absent_days >= evict_at {
            let (n, freed) = reclaim(st, &owner, false).await;
            if n > 0 {
                emit(st, "owner_evicted", &owner, n, freed, absent_days).await;
            }
        } else if absent_days >= reclaim_at {
            let (n, freed) = reclaim(st, &owner, true).await;
            if n > 0 {
                emit(st, "owner_reclaimed", &owner, n, freed, absent_days).await;
            }
        }
        // Below reclaim (present / grace): nothing to remove. We already stop
        // placing new shards on peers marked `down`, which covers the grace step.
    }
}

/// When we have no `last_seen` for an owner, fall back to the most recent time we
/// accepted a shard from it. If even that is missing, treat it as just-seen (do
/// nothing) rather than risk reclaiming on no evidence.
async fn fallback_reference(st: &AppState, owner: &str) -> DateTime<Utc> {
    let latest: Option<Option<DateTime<Utc>>> = st
        .db
        .fetch_optional_scalar::<DateTime<Utc>>(
            "SELECT MAX(stored_at) FROM p2pnas.hosted_shards WHERE owner_peer_id = $1",
            params![owner],
        )
        .await
        .ok();
    latest.flatten().unwrap_or_else(Utc::now)
}

/// Remove hosted shards for `owner` — parity only (`parity_only`) or all of them
/// — from both the shard store and the bookkeeping, and give the freed bytes back
/// to the contribution budget. Returns (count removed, bytes freed).
async fn reclaim(st: &AppState, owner: &str, parity_only: bool) -> (usize, i64) {
    let rows: Vec<(String, i64)> = if parity_only {
        st.db
            .fetch_all_as(
                "SELECT fragment_id, size_bytes FROM p2pnas.hosted_shards
                 WHERE owner_peer_id = $1 AND shard_index >= $2",
                params![owner, DATA_SHARDS as i32],
            )
            .await
    } else {
        st.db
            .fetch_all_as(
                "SELECT fragment_id, size_bytes FROM p2pnas.hosted_shards WHERE owner_peer_id = $1",
                params![owner],
            )
            .await
    }
    .unwrap_or_default();

    let mut freed = 0i64;
    let mut removed = 0usize;
    for (frag, size) in rows {
        let (store, f) = (st.store.clone(), frag.clone());
        let _ = tokio::task::spawn_blocking(move || store.delete(&f)).await;
        let ok = st
            .db
            .execute("DELETE FROM p2pnas.hosted_shards WHERE fragment_id = $1", params![&frag])
            .await
            .map(|n| n > 0)
            .unwrap_or(false);
        if ok {
            freed += size;
            removed += 1;
        }
    }
    if freed > 0 {
        let be = st.db.backend();
        let (now, greatest) = (be.now(), crate::greatest(be));
        let _ = st
            .db
            .execute(
                &format!(
                    "UPDATE p2pnas.node_local
                        SET hosted_bytes = {greatest}(hosted_bytes - $1, 0), updated_at = {now}
                      WHERE id = 1"
                ),
                params![freed],
            )
            .await;
    }
    (removed, freed)
}

async fn emit(st: &AppState, kind: &str, owner: &str, shards: usize, freed: i64, absent_days: f64) {
    tracing::info!(kind, owner, shards, freed, absent_days = absent_days.round(), "retention sweep acted on an absent owner");
    let _ = st
        .db
        .execute(
            "INSERT INTO p2pnas.events (kind, payload) VALUES ($1, $2)",
            params![
                kind,
                json!({
                    "owner_peer_id": owner,
                    "shards_removed": shards,
                    "bytes_freed": freed,
                    "absent_days": absent_days.round(),
                })
            ],
        )
        .await;
}
