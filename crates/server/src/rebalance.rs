//! Locality rebalance: re-home shards toward the latency-optimal layout.
//!
//! Repair fixes *lost* shards; this pass *moves* healthy ones. After the node's
//! latency picture changes (a peer got slower, or the node itself moved — see the
//! `ip_changed` trigger), the current placement may no longer be the nearest. For
//! every file we recompute the ideal latency-aware layout and move each shard
//! that sits somewhere other than where it should — fetch from its current home,
//! store at the target, update the manifest, then drop the old copy.
//!
//! Conservative: a shard is only moved once its new copy is confirmed stored
//! (place → manifest → drop), and only reachable shards are touched (lost ones
//! are the repair pass's job).

use std::collections::HashMap;

use serde::Serialize;

use p2pnas_core::erasure::{PARITY_SHARDS, TOTAL_SHARDS};

use crate::{placement, repair, state::AppState};

#[derive(Default, Serialize)]
pub struct RebalanceReport {
    pub files_scanned:   usize,
    pub shards_moved:    usize,
    pub peers_reachable: usize,
}

pub async fn rebalance_all(st: &AppState) -> RebalanceReport {
    let mut rep = RebalanceReport::default();

    // Live peers (excluding 'down'), measured fresh and sorted near → far so the
    // plan's peer indices line up with ascending latency.
    let candidates: Vec<(String, String)> =
        sqlx::query_as("SELECT peer_id, addr FROM p2pnas.peers WHERE peer_id <> $1 AND status <> 'down'")
            .bind(&st.identity.peer_id)
            .fetch_all(&st.db)
            .await
            .unwrap_or_default();
    let mut live: Vec<(String, String, f64)> = Vec::new();
    for (pid, addr) in candidates {
        if let Ok(rtt) = p2pnas_p2p::ping_rtt(&addr, &st.identity.peer_id, st.settings.server.port).await {
            live.push((pid, addr, rtt));
        }
    }
    live.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
    rep.peers_reachable = live.len();
    if live.is_empty() {
        return rep; // nothing to rebalance onto
    }
    let reachable: HashMap<String, String> = live.iter().map(|(p, a, _)| (p.clone(), a.clone())).collect();
    let sorted_ids: Vec<String> = live.iter().map(|(p, _, _)| p.clone()).collect();
    let rtts: Vec<f64> = live.iter().map(|(_, _, r)| *r).collect();

    // Ideal layout (same for every chunk): shard index i → location.
    let layout = placement::plan_placement(&rtts, TOTAL_SHARDS, PARITY_SHARDS);

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
        for (_chunk, shards) in plan {
            for s in shards {
                let desired = match layout.get(s.shard_index as usize).copied().flatten() {
                    None => "local".to_string(),
                    Some(p) => match sorted_ids.get(p) {
                        Some(id) => id.clone(),
                        None => continue,
                    },
                };
                if s.location == desired {
                    continue; // already optimal
                }
                // Fetch the current (reachable) copy; skip if we can't get it
                // intact — repair will deal with a missing/corrupt shard.
                let Some(bytes) = repair::fetch_shard(st, &reachable, &s).await else { continue };
                if !s.hash.is_empty() && p2pnas_p2p::content_hash(&bytes) != s.hash {
                    continue;
                }
                // place → manifest → drop old (safe ordering: a crash mid-way
                // leaves either the old or both copies, never zero).
                if repair::place_shard(st, &reachable, &desired, &s.fragment_id, &bytes).await {
                    let (m, frag, loc) = (st.manifest.clone(), s.fragment_id.clone(), desired.clone());
                    let _ = tokio::task::spawn_blocking(move || p2pnas_store::service::set_location(&m, &frag, &loc)).await;
                    repair::drop_shard(st, &reachable, &s.location, &s.fragment_id).await;
                    rep.shards_moved += 1;
                }
            }
        }
    }
    if rep.shards_moved > 0 {
        tracing::info!(moved = rep.shards_moved, files = rep.files_scanned, "locality rebalance moved shards");
    }
    rep
}
