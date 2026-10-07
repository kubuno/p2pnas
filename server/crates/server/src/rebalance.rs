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

use kubuno_db::params;
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
    let candidates: Vec<(String, String, Option<String>, f64)> = st
        .db
        .fetch_all_as(
            "SELECT peer_id, addr, zone, reliability_score
               FROM p2pnas.peers WHERE peer_id <> $1 AND status <> 'down'",
            params![&st.identity.peer_id],
        )
        .await
        .unwrap_or_default();
    let mut live: Vec<(String, String, f64, Option<String>, f64)> = Vec::new();
    for (pid, addr, zone, rel) in candidates {
        if let Ok(rtt) = p2pnas_p2p::ping_rtt(&addr, &st.identity.peer_id, st.settings.server.port).await {
            live.push((pid, addr, rtt, zone, rel));
        }
    }
    live.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
    rep.peers_reachable = live.len();
    if live.is_empty() {
        return rep; // nothing to rebalance onto
    }
    let reachable: HashMap<String, String> = live.iter().map(|(p, a, ..)| (p.clone(), a.clone())).collect();
    let sorted_ids: Vec<String> = live.iter().map(|(p, ..)| p.clone()).collect();

    // Ideal layout (same for every chunk): shard index i → location.
    //
    // This MUST use the same zone-aware rule as the initial placement. With the
    // latency-only plan, every rebalance pass would pull shards back onto the
    // nearest neighbours — undoing the failure-domain spread it had just been
    // given, and moving data across the network forever to do it.
    let peer_candidates: Vec<placement::PeerCandidate> = live
        .iter()
        .map(|(_, addr, rtt, zone, rel)| placement::PeerCandidate {
            rtt_ms:      *rtt,
            zone:        zone.clone().or_else(|| placement::zone_of_addr(addr)),
            reliability: *rel,
        })
        .collect();
    let layout = placement::plan_placement_zoned(&peer_candidates, None, TOTAL_SHARDS, PARITY_SHARDS);

    let man = st.manifest.clone();
    let files = match tokio::task::spawn_blocking(move || p2pnas_store::service::list_all(&man)).await {
        Ok(Ok(f)) => f,
        _ => return rep,
    };

    // Target shard COUNT per location (which specific shard sits where doesn't
    // matter — any shard reconstructs). Count-based moves only touch the delta, so
    // a placement that already matches the target distribution is left untouched
    // (built-in hysteresis: no churn when the optimum is unchanged).
    let mut target: HashMap<String, usize> = HashMap::new();
    for loc in &layout {
        let id = match loc {
            None => "local".to_string(),
            Some(p) => match sorted_ids.get(*p) {
                Some(id) => id.clone(),
                None => continue,
            },
        };
        *target.entry(id).or_default() += 1;
    }

    for file in files {
        rep.files_scanned += 1;
        let man = st.manifest.clone();
        let (uid, fid) = (file.user_id.clone(), file.file_id.clone());
        let plan = match tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid, &fid)).await {
            Ok(Ok((_, chunks))) => chunks,
            _ => continue,
        };
        for (_chunk, shards) in plan {
            // Group this chunk's shards by current location.
            let mut current: HashMap<String, Vec<_>> = HashMap::new();
            for s in shards {
                current.entry(s.location.clone()).or_default().push(s);
            }

            // Donors: shards beyond a location's target, but only REACHABLE ones we
            // can actually relocate (unreachable excess is the repair pass's job).
            let mut pool = Vec::new();
            for (loc, mut here) in current.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>() {
                let keep = target.get(&loc).copied().unwrap_or(0);
                let reachable_here = loc == "local" || reachable.contains_key(&loc);
                while here.len() > keep && reachable_here {
                    if let Some(s) = here.pop() {
                        pool.push(s);
                    }
                }
                current.insert(loc, here);
            }

            // Receivers (near → far: local first, then peers by ascending rtt) take
            // from the pool until they reach their target.
            let mut receivers: Vec<String> = vec!["local".to_string()];
            receivers.extend(sorted_ids.iter().cloned());
            for loc in receivers {
                let want = target.get(&loc).copied().unwrap_or(0);
                let have = current.get(&loc).map(|v| v.len()).unwrap_or(0);
                for _ in have..want {
                    let Some(s) = pool.pop() else { break };
                    if move_shard(st, &reachable, &s, &loc).await {
                        rep.shards_moved += 1;
                    }
                }
            }
        }
    }

    if rep.shards_moved > 0 {
        tracing::info!(moved = rep.shards_moved, files = rep.files_scanned, "locality rebalance moved shards");
    }
    let _ = st
        .db
        .execute(
            &format!("UPDATE p2pnas.node_local SET last_rebalance_at = {} WHERE id = 1", st.db.backend().now()),
            params![],
        )
        .await;
    rep
}

/// Move one shard from its current home to `dest` ("local" or a peer_id):
/// fetch (verified) → place → manifest → drop old. Safe ordering — a crash mid-way
/// leaves either the old or both copies, never zero. Returns true on success.
async fn move_shard(
    st: &AppState,
    reachable: &HashMap<String, String>,
    s: &p2pnas_store::ShardRow,
    dest: &str,
) -> bool {
    if s.location == dest {
        return false;
    }
    let Some(bytes) = repair::fetch_shard(st, reachable, s).await else { return false };
    if !s.hash.is_empty() && p2pnas_p2p::content_hash(&bytes) != s.hash {
        return false;
    }
    if !repair::place_shard(st, reachable, dest, &s.fragment_id, s.shard_index as i32, &bytes).await {
        return false;
    }
    let (m, frag, loc) = (st.manifest.clone(), s.fragment_id.clone(), dest.to_string());
    let _ = tokio::task::spawn_blocking(move || p2pnas_store::service::set_location(&m, &frag, &loc)).await;
    repair::drop_shard(st, reachable, &s.location, &s.fragment_id).await;
    true
}
