use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
    Extension, Json,
};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};

use p2pnas_core::erasure::{DATA_SHARDS, PARITY_SHARDS, TOTAL_SHARDS};
use p2pnas_p2p::P2pMessage;
use p2pnas_store::{ChunkRow, FileRow, ShardRow};

use crate::{
    errors::{P2pError, Result},
    middleware::P2pUser,
    state::AppState,
};

#[derive(Deserialize)]
pub struct PathQuery {
    pub path: String,
}

#[derive(Deserialize)]
pub struct DirQuery {
    /// Directory to list ("" or absent = root).
    pub path: Option<String>,
}

#[derive(Deserialize)]
pub struct PathBody {
    pub path: String,
}

#[derive(Deserialize)]
pub struct RenameBody {
    pub from: String,
    pub to:   String,
}

fn join_err<E>(_: E) -> P2pError {
    P2pError::BadRequest("internal task error".into())
}

/// Upload (encrypt + erasure-code + store) a file into the user's My Cloud.
pub async fn upload(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Query(q): Query<PathQuery>,
    body: Bytes,
) -> Result<Json<Value>> {
    let path = q.path.trim().to_string();
    if path.is_empty() {
        return Err(P2pError::BadRequest("query parameter `path` is required".into()));
    }
    let size = body.len() as i64;

    // Per-file ceiling, checked HERE and not only by the router's body limit: the
    // router's limit is frozen at construction, this one is the administrator's
    // and takes effect the minute they change it.
    let max_upload = st.instance().max_upload_bytes;
    if size > max_upload {
        return Err(P2pError::BadRequest(format!(
            "file too large: {size} > {max_upload} bytes allowed per upload"
        )));
    }

    // An account that has never been allocated anything is granted the instance
    // default here, materialised as a real row (see `crate::quotas`).
    let (quota, used) = crate::quotas::ensure(&st, user.id).await?;

    // Check AND charge in one statement. Reading `used_bytes`, deciding, then
    // writing it back as a separate step is a race with a window as wide as the
    // upload itself: two requests both read a usage neither had spent yet, both
    // conclude there is room, and the account ends up over its ceiling with no
    // error anywhere. The conditional UPDATE takes the row lock, re-evaluates the
    // ceiling against the value in the table at that instant, and charges the
    // upload atomically — the loser simply updates no row.
    //
    // An overwrite is charged its full new size and nothing is given back: the
    // version it replaces is KEPT as a restorable version, so those bytes are still
    // stored, still on peers, and still the user's (see `TRASH_COUNTS_AGAINST_QUOTA`).
    let reserved: Option<i64> = sqlx::query_scalar(
        "UPDATE p2pnas.user_quota
            SET used_bytes = used_bytes + $2, updated_at = now()
          WHERE user_id = $1 AND used_bytes + $2 <= quota_bytes
      RETURNING used_bytes",
    )
    .bind(user.id)
    .bind(size)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, user_id = %user.id, size, "p2pnas upload: quota reservation failed");
        P2pError::Db(e)
    })?;
    if reserved.is_none() {
        // No row matched: either the account has no quota row at all, or charging
        // this upload would cross the ceiling. The figures below are the ones read
        // a moment ago and are only indicative — the decision was taken under the
        // row lock, on the current value.
        // The trash and the version history count too (deliberately — the bytes are
        // really there), so say so: emptying the trash is the one remedy the user
        // can apply without an administrator.
        return Err(P2pError::BadRequest(format!(
            "quota exceeded: {used} + {size} > {quota} bytes \
             (empty your My Cloud trash and old versions, or ask an admin to raise your quota)"
        )));
    }

    let (id, man, store) = (st.identity.clone(), st.manifest.clone(), st.store.clone());
    let uid = user.id.to_string();
    let data = body.to_vec();
    let pushed = tokio::task::spawn_blocking(move || {
        p2pnas_store::service::push(&id, &man, &store, &uid, &path, &data)
    })
    .await;

    // The quota was debited BEFORE the bytes were written, so every path that
    // leaves without a stored file must hand it back — otherwise a failing upload
    // silently eats the user's allowance until an administrator notices.
    let res = match pushed {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            tracing::error!(error = %e, user_id = %user.id, "p2pnas upload: store push failed — refunding the quota reservation");
            adjust_user_used(&st, user.id, -size).await;
            return Err(e.into());
        }
        Err(e) => {
            tracing::error!(error = %e, user_id = %user.id, "p2pnas upload: store task did not complete — refunding the quota reservation");
            adjust_user_used(&st, user.id, -size).await;
            return Err(join_err(e));
        }
    };

    // Identical re-upload: nothing was written, no version was created. Refund the
    // whole reservation and stop here — charging for it, or re-running the peer
    // distribution, would make a sync client that re-pushes untouched files eat
    // its owner's quota for no new content.
    if res.unchanged {
        adjust_user_used(&st, user.id, -size).await;
        return Ok(Json(json!({
            "file_id": res.file_id,
            "path": q.path,
            "size": res.size,
            "unchanged": true,
        })));
    }

    // Settle the reservation now that the outcome is known. There is nothing to
    // refund on an overwrite any more — the previous version is retained, not
    // destroyed — so this only corrects the reservation if the stored size ever
    // differed from the body we charged for.
    adjust_user_used(&st, user.id, res.size - size).await;

    // Node-wide stored bytes (data + parity, every user). Best-effort: the file IS
    // stored at this point, so a bookkeeping failure is logged rather than reported
    // as a failed upload the client would retry — a retry would store it twice.
    // The full new cost is added and none subtracted: the superseded version's
    // shards are still on disk until the retention sweep reclaims them.
    let stored_delta = res.stored_bytes;
    if let Err(e) =
        sqlx::query("UPDATE p2pnas.node_local SET used_bytes = GREATEST(used_bytes + $1, 0), updated_at = now() WHERE id = 1")
            .bind(stored_delta)
            .execute(&st.db)
            .await
    {
        tracing::error!(error = %e, stored_delta, "p2pnas upload: node storage accounting update failed");
    }

    // Nothing is orphaned by an overwrite any more: the previous version keeps its
    // shards (local AND remote) until it ages out of the version history, which is
    // what `purge_retired_now` reclaims — remote shards included.

    // Best-effort: spread the shards across peers (round-robin over [self] + peers).
    distribute_shards(&st, user.id, &res.file_id).await;

    Ok(Json(json!({
        "file_id": res.file_id,
        "path": q.path,
        "size": res.size,
        // Non-null when this upload replaced a file: the id of the version now kept
        // in the history, so a client can offer "undo" without a second lookup.
        "superseded_file_id": res.superseded_file_id,
    })))
}

/// Move a user's accounted usage by `delta` (negative = refund), clamped at zero.
///
/// Best-effort by design: it is called once the bytes have already been written or
/// already been given up, so there is nothing left to abort — the drift is logged
/// instead, since a 500 here would tell the client an upload failed that did not.
async fn adjust_user_used(st: &AppState, user: uuid::Uuid, delta: i64) {
    if delta == 0 {
        return;
    }
    if let Err(e) = sqlx::query(
        "UPDATE p2pnas.user_quota SET used_bytes = GREATEST(used_bytes + $2, 0), updated_at = now() WHERE user_id = $1",
    )
    .bind(user)
    .bind(delta)
    .execute(&st.db)
    .await
    {
        tracing::error!(error = %e, user_id = %user, delta, "p2pnas: quota accounting adjustment failed");
    }
}

/// Enqueue deletion of remote shards on the peers that host them (no-op when the
/// list is empty). Runs asynchronously with bounded retry (see `jobs::gc_remote`)
/// so a slow or offline peer never blocks a user-visible delete.
async fn enqueue_remote_gc(st: &AppState, remote: Vec<(String, String)>) {
    if remote.is_empty() {
        return;
    }
    crate::jobs::enqueue(&st.db, "gc_remote", json!({ "shards": remote, "attempt": 0 })).await;
}

/// Spread a file's shards over peers, **latency-aware**: each chunk's shards are
/// placed by `placement::plan_placement` (prefer near peers, cap every location
/// at PARITY for single-failure durability). Shards that can't be placed remotely
/// stay local. No peers → everything stays local.
/// A peer as read for placement: (peer_id, addr, country, zone, reliability).
type PeerPlacementRow = (String, String, Option<String>, Option<String>, f64);
/// A peer that cleared the jurisdiction filter: (peer_id, addr, zone, reliability).
type VettedPeer = (String, String, Option<String>, f64);
/// A peer that answered a probe: (peer_id, addr, rtt_ms, zone, reliability).
type LivePeer = (String, String, f64, Option<String>, f64);

async fn distribute_shards(st: &AppState, user: uuid::Uuid, file_id: &str) {
    // Skip peers already flagged `down` — they're known-bad, no point pinging.
    // `zone` and `reliability_score` ride along so placement can keep a chunk's
    // shards out of a single failure domain and prefer dependable hosts.
    let all_peers: Vec<PeerPlacementRow> = sqlx::query_as(
        "SELECT peer_id, addr, country, zone, reliability_score
           FROM p2pnas.peers WHERE peer_id <> $1 AND status <> 'down'",
    )
    .bind(&st.identity.peer_id)
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();

    // Jurisdiction constraint: only place on peers in an allowed country. Country
    // is resolved by the maps GeoIP service (cached in peers.country). If maps is
    // unavailable we CANNOT vet peers, so we keep everything local rather than risk
    // violating the constraint — and surface why.
    //
    // Source of the list: the admin console wins when it holds one, otherwise
    // config.toml stands. A BLANK console field means "nothing said here", never
    // "no constraint" — clearing a textarea must not silently lift a restriction
    // an operator wrote into the file.
    let instance_allow = st.instance().jurisdiction_allow;
    let allow = if instance_allow.is_empty() {
        st.settings.discovery.geoip_allow.clone()
    } else {
        instance_allow
    };
    // (peer_id, addr, zone, reliability)
    let all_peers: Vec<VettedPeer> = if allow.is_empty() {
        all_peers.into_iter().map(|(pid, addr, _, zone, rel)| (pid, addr, zone, rel)).collect()
    } else {
        let mut kept = Vec::new();
        for (pid, addr, country, zone, rel) in all_peers {
            let country = match country {
                Some(c) => Some(c),
                None => {
                    let ip = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(&addr).to_string();
                    match crate::maps_geoip::country(st, user, &ip).await {
                        crate::maps_geoip::GeoOutcome::Resolved(c) => {
                            if let Some(cc) = &c {
                                let _ = sqlx::query("UPDATE p2pnas.peers SET country = $1 WHERE peer_id = $2")
                                    .bind(cc).bind(&pid).execute(&st.db).await;
                            }
                            c
                        }
                        crate::maps_geoip::GeoOutcome::Unavailable => {
                            tracing::warn!("jurisdiction constraint set but maps GeoIP unavailable — keeping shards local");
                            let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('geo_unavailable', $1)")
                                .bind(serde_json::json!({ "reason": "maps module GeoIP unavailable; cannot enforce jurisdiction" }))
                                .execute(&st.db)
                                .await;
                            return; // fail safe: do not distribute onto un-vetted peers
                        }
                    }
                }
            };
            if crate::placement::jurisdiction_allowed(&allow, country.as_deref()) {
                kept.push((pid, addr, zone, rel));
            }
        }
        kept
    };

    // Probe liveness AND measure latency; keep only peers that answer.
    // (peer_id, addr, rtt_ms, zone, reliability)
    let mut live: Vec<LivePeer> = Vec::new();
    for (pid, addr, zone, rel) in all_peers {
        if let Ok(rtt) = p2pnas_p2p::ping_rtt(&addr, &st.identity.peer_id, st.settings.server.port).await {
            live.push((pid, addr, rtt, zone, rel));
        }
    }
    if live.is_empty() {
        return;
    }
    // Sort near → far so failover walks outward and indexing matches the plan.
    live.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
    let peers: Vec<(String, String)> = live.iter().map(|(p, a, ..)| (p.clone(), a.clone())).collect();

    // Durability note: need ≥ ceil(TOTAL/PARITY) locations to survive 1 failure.
    let locations = peers.len() + 1;
    if TOTAL_SHARDS.div_ceil(locations) > p2pnas_core::erasure::PARITY_SHARDS {
        tracing::warn!(
            locations,
            "low durability: too few peers to survive a single failure (need ≥ {} locations)",
            crate::repair::min_locations_for_durability()
        );
    }

    let (man, uid, fid) = (st.manifest.clone(), user.to_string(), file_id.to_string());
    let plan = match tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid, &fid)).await {
        Ok(Ok((_, chunks))) => chunks,
        _ => return,
    };

    // Latency-aware plan (same for every chunk: shard index i → location).
    // Failure-domain aware: capping only per peer let the latency-first choice pile
    // a chunk's shards onto neighbours sharing one box, one power strip, one
    // outage — which RS 10+4 does not survive. The zone recorded for the peer wins
    // over one derived from its address, so an operator can describe a topology no
    // IP range reveals.
    let candidates: Vec<crate::placement::PeerCandidate> = live
        .iter()
        .map(|(_, addr, rtt, zone, rel)| crate::placement::PeerCandidate {
            rtt_ms:      *rtt,
            zone:        zone.clone().or_else(|| crate::placement::zone_of_addr(addr)),
            reliability: *rel,
        })
        .collect();
    let layout = crate::placement::plan_placement_zoned(
        &candidates,
        None,
        TOTAL_SHARDS,
        p2pnas_core::erasure::PARITY_SHARDS,
    );

    // Each remote placement records its PRIMARY peer index; the task fails over to
    // the next (next-nearest) peers if the primary doesn't Ack.
    let mut placements: Vec<(String, usize, i32)> = Vec::new(); // (fragment_id, primary peer index, shard index)
    for (_chunk, shards) in plan {
        for s in shards {
            // Some(p) → peer p; None → keep on self.
            if let Some(p) = layout.get(s.shard_index as usize).copied().flatten() {
                placements.push((s.fragment_id, p, s.shard_index as i32));
            }
        }
    }

    // Move shards to their targets concurrently — one in-flight StoreShard per
    // placement instead of strictly sequential round-trips.
    let peers = Arc::new(peers);
    let mut set = tokio::task::JoinSet::new();
    for (frag, primary, shard_index) in placements {
        let st = st.clone();
        let peers = peers.clone();
        set.spawn(async move {
            let (store, f) = (st.store.clone(), frag.clone());
            let Ok(Some(bytes)) = tokio::task::spawn_blocking(move || p2pnas_store::service::read_local(&store, &f)).await else { return };
            // Try the primary peer, then fail over to the next ones (up to 3).
            for off in 0..peers.len().min(3) {
                let (peer_id, addr) = peers[(primary + off) % peers.len()].clone();
                let msg = P2pMessage::StoreShard {
                    fragment_id: frag.clone(),
                    owner_peer_id: st.identity.peer_id.clone(),
                    shard_index,
                    data: bytes.clone(),
                };
                if let Ok(P2pMessage::Ack { .. }) =
                    crate::p2p::signed_request(&st.identity, st.settings.server.port, &addr, &msg).await
                {
                    let (man, f2, pid) = (st.manifest.clone(), frag.clone(), peer_id);
                    let _ = tokio::task::spawn_blocking(move || p2pnas_store::service::set_location(&man, &f2, &pid)).await;
                    let (store2, f3) = (st.store.clone(), frag.clone());
                    let _ = tokio::task::spawn_blocking(move || store2.delete(&f3)).await;
                    return;
                }
            }
            // No peer accepted it → leave the shard local (still recoverable).
        });
    }
    while set.join_next().await.is_some() {}
}

/// Per-file durability: how many of each chunk's shards are currently reachable,
/// and whether the file is fully redundant / still recoverable / at risk.
pub async fn file_health(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Path(file_id): Path<String>,
) -> Result<Json<Value>> {
    let uid = user.id.to_string();
    let (file, plan) = fetch_plan(&st, &uid, &file_id).await?;
    // A pack member has no shards of its own: its durability IS its container's,
    // so measure the pack's shards while reporting the member's identity.
    let plan = match &file.pack_id {
        Some(pack_id) => fetch_plan(&st, &uid, pack_id).await?.1,
        None => plan,
    };

    // Which peers are live right now?
    let peers: Vec<(String, String)> = sqlx::query_as("SELECT peer_id, addr FROM p2pnas.peers")
        .fetch_all(&st.db)
        .await
        .unwrap_or_default();
    let mut live: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (pid, addr) in &peers {
        if p2pnas_p2p::ping(addr, &st.identity.peer_id, st.settings.server.port).await.is_ok() {
            live.insert(pid.clone(), addr.clone());
        }
    }

    let mut min_reachable = TOTAL_SHARDS;
    for (_chunk, shards) in &plan {
        let mut reachable = 0usize;
        for s in shards {
            let ok = if s.location == "local" {
                st.store.exists(&s.fragment_id)
            } else if let Some(addr) = live.get(&s.location) {
                p2pnas_p2p::has_shard(addr, &s.fragment_id).await.unwrap_or(false)
            } else {
                false
            };
            if ok {
                reachable += 1;
            }
        }
        min_reachable = min_reachable.min(reachable);
    }

    // Margin = reachable shards above the reconstruction floor; ≥ PARITY means we
    // can still lose a whole location's worth and rebuild.
    let recoverable = min_reachable >= DATA_SHARDS;
    let margin = min_reachable.saturating_sub(DATA_SHARDS);
    Ok(Json(json!({
        "file_id": file.file_id,
        "path": file.path,
        "size": file.size,
        "chunks": plan.len(),
        "data_shards": DATA_SHARDS,
        "total_shards": TOTAL_SHARDS,
        "min_reachable": min_reachable,
        "fully_redundant": min_reachable >= TOTAL_SHARDS,
        "recoverable": recoverable,
        "single_failure_safe": margin >= PARITY_SHARDS,
        "at_risk": !recoverable || margin < PARITY_SHARDS,
    })))
}

/// Placement map of a file: where each shard physically lives (this node or a
/// peer), with the peer's latency / country / status — so the admin can SEE how
/// data is distributed geographically and by latency.
pub async fn file_placement(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Path(file_id): Path<String>,
) -> Result<Json<Value>> {
    let uid = user.id.to_string();
    let (man, uid2, fid) = (st.manifest.clone(), uid.clone(), file_id.clone());
    let (file, plan) = tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid2, &fid))
        .await
        .map_err(join_err)??;

    // peer_id → (rtt_ms, country, status) for labelling remote shards.
    type PeerMeta = (String, Option<f64>, Option<String>, String);
    let peers: Vec<PeerMeta> = sqlx::query_as("SELECT peer_id, rtt_ms, country, status FROM p2pnas.peers")
        .fetch_all(&st.db)
        .await
        .unwrap_or_default();
    let meta: std::collections::HashMap<String, (Option<f64>, Option<String>, String)> =
        peers.into_iter().map(|(p, r, c, s)| (p, (r, c, s))).collect();

    let mut by_location: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut chunks = Vec::with_capacity(plan.len());
    for (chunk, shards) in &plan {
        let mut shard_views = Vec::with_capacity(shards.len());
        for s in shards {
            *by_location.entry(s.location.clone()).or_default() += 1;
            let view = if s.location == "local" {
                json!({ "shard_index": s.shard_index, "kind": "local", "location": "local" })
            } else {
                let m = meta.get(&s.location);
                json!({
                    "shard_index": s.shard_index, "kind": "peer", "location": s.location,
                    "rtt_ms": m.and_then(|x| x.0), "country": m.and_then(|x| x.1.clone()),
                    "status": m.map(|x| x.2.clone()),
                })
            };
            shard_views.push(view);
        }
        chunks.push(json!({ "idx": chunk.idx, "shards": shard_views }));
    }

    let locations: Vec<Value> = by_location
        .iter()
        .map(|(loc, count)| {
            if loc == "local" {
                json!({ "id": "local", "kind": "local", "count": count })
            } else {
                let m = meta.get(loc);
                json!({
                    "id": loc, "kind": "peer", "count": count,
                    "rtt_ms": m.and_then(|x| x.0), "country": m.and_then(|x| x.1.clone()),
                    "status": m.map(|x| x.2.clone()),
                })
            }
        })
        .collect();

    Ok(Json(json!({
        "file_id": file.file_id, "path": file.path,
        "chunks": chunks, "locations": locations,
    })))
}

/// List the user's files.
pub async fn list(State(st): State<AppState>, Extension(user): Extension<P2pUser>) -> Result<Json<Value>> {
    let man = st.manifest.clone();
    let uid = user.id.to_string();
    let files = tokio::task::spawn_blocking(move || p2pnas_store::service::list(&man, &uid))
        .await
        .map_err(join_err)??;
    Ok(Json(json!({ "files": files })))
}

/// How many chunks of a file are fetched at the same time. A read that finishes
/// chunk N before it even asks for chunk N+1 pays the whole file's worth of
/// network round-trips end to end; a small window overlaps them while keeping the
/// peak bounded (W chunks × 14 shards in flight, never the whole file).
const READ_CHUNK_WINDOW: usize = 4;

/// One chunk's fetched shards, tagged with its position in the file: the window
/// below lets chunks complete out of order, and reassembly needs file order.
type ChunkFetch = (usize, ChunkRow, Vec<Option<Vec<u8>>>);

/// peer_id → address, shared read-only by every shard fetch of a download.
type PeerAddrs = std::collections::HashMap<String, String>;

/// Fetch one shard (local read or P2P `GetShard`), verified against the manifest
/// hash. Returns its index and bytes, or `None` when it is absent, unreachable or
/// corrupt — all three are simply "lost" as far as erasure decoding is concerned.
///
/// The integrity check is not optional. Reed-Solomon used as an *erasure* code
/// cannot detect a bad shard, so a peer answering `GetShard` with flipped bytes
/// would silently poison the reconstructed cipher and the file would fail to
/// decrypt; verifying first turns "corrupt" back into "lost", which erasure
/// handles. (Rows with an empty hash are legacy and skip the check, as elsewhere.)
async fn fetch_shard_for_read(
    st: &AppState,
    peers: &PeerAddrs,
    s: &ShardRow,
) -> (usize, Option<Vec<u8>>) {
    let idx = s.shard_index as usize;
    if s.location == "local" {
        let (store, frag, hash) = (st.store.clone(), s.fragment_id.clone(), s.hash.clone());
        let bytes = tokio::task::spawn_blocking(move || p2pnas_store::service::read_local_verified(&store, &frag, &hash))
            .await
            .ok()
            .flatten();
        return (idx, bytes);
    }
    let Some(addr) = peers.get(&s.location) else { return (idx, None) };
    let msg = P2pMessage::GetShard { fragment_id: s.fragment_id.clone() };
    // Short connect budget: an offline host must cost a moment, not five seconds
    // per chunk (see `READ_CONNECT_TIMEOUT`).
    match p2pnas_p2p::client::request_with_timeout(addr, &msg, p2pnas_p2p::client::READ_CONNECT_TIMEOUT).await {
        Ok(P2pMessage::ShardData { data, .. }) if p2pnas_store::service::verify_hash(&data, &s.hash) => (idx, Some(data)),
        Ok(P2pMessage::ShardData { .. }) => {
            tracing::warn!(
                fragment_id = %s.fragment_id,
                location = %s.location,
                "shard failed its integrity check on read — treating as lost"
            );
            (idx, None)
        }
        _ => (idx, None),
    }
}

/// Gather one chunk's shards, stopping the moment `DATA_SHARDS` verified shards
/// are in hand.
///
/// All 14 are requested at once and the first 10 answers win: any 10 of the 14
/// reconstruct the chunk, so waiting for the remaining tasks would mean paying the
/// slowest holder's latency — or a dead host's full timeout — for bytes nothing
/// needs. Dropping the `JoinSet` cancels whatever is still in flight.
async fn fetch_chunk_shards(
    st: &AppState,
    peers: &Arc<PeerAddrs>,
    shards: Vec<ShardRow>,
) -> Vec<Option<Vec<u8>>> {
    let mut present: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    let mut set = tokio::task::JoinSet::new();
    for s in shards {
        let (st, peers) = (st.clone(), peers.clone());
        set.spawn(async move { fetch_shard_for_read(&st, &peers, &s).await });
    }
    let mut got = 0usize;
    while let Some(res) = set.join_next().await {
        let Ok((idx, Some(bytes))) = res else { continue };
        let Some(cell) = present.get_mut(idx) else { continue };
        if cell.is_none() {
            *cell = Some(bytes);
            got += 1;
        }
        if got >= DATA_SHARDS {
            break;
        }
    }
    present
}

/// Start the next chunk of `queue` if there is one (no-op once drained), so the
/// caller can keep exactly `READ_CHUNK_WINDOW` chunks in flight.
fn spawn_chunk_fetch<I>(
    set: &mut tokio::task::JoinSet<ChunkFetch>,
    st: &AppState,
    peers: &Arc<PeerAddrs>,
    queue: &mut I,
) where
    I: Iterator<Item = (usize, p2pnas_store::service::ChunkShards)>,
{
    let Some((i, (chunk, shards))) = queue.next() else { return };
    let (st, peers) = (st.clone(), peers.clone());
    set.spawn(async move {
        let present = fetch_chunk_shards(&st, &peers, shards).await;
        (i, chunk, present)
    });
}

/// Gather a file's shards (local + peers), reconstruct and decrypt → plaintext.
///
/// A pack member owns no shards: its bytes are a plaintext range of its
/// container, so reading it means reconstructing the WHOLE pack (up to
/// `PACK_TARGET`) and slicing — the read-amplification cost packing accepts in
/// exchange for its ~40× write/storage saving on small files.
async fn reconstruct_file(st: &AppState, uid: &str, file_id: &str) -> Result<Vec<u8>> {
    let (file, plan) = fetch_plan(st, uid, file_id).await?;
    let Some(pack_id) = file.pack_id.clone() else {
        return fetch_and_reassemble(st, file, plan).await;
    };
    let (pack, pack_plan) = fetch_plan(st, uid, &pack_id).await?;
    // Packs never nest; a chained pack_id means a corrupt manifest, and
    // following it would loop.
    if pack.pack_id.is_some() {
        return Err(p2pnas_store::StoreError::Integrity(format!("pack {pack_id} is itself a pack member")).into());
    }
    let plain = fetch_and_reassemble(st, pack, pack_plan).await?;
    p2pnas_store::service::member_slice(&plain, &file).map_err(Into::into)
}

/// Placement plan of one file (which shard lives where), off the blocking pool.
async fn fetch_plan(
    st: &AppState,
    uid: &str,
    file_id: &str,
) -> Result<(FileRow, Vec<p2pnas_store::service::ChunkShards>)> {
    let (man, uid2, fid) = (st.manifest.clone(), uid.to_string(), file_id.to_string());
    tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid2, &fid))
        .await
        .map_err(join_err)?
        .map_err(Into::into)
}

/// Fetch a plan's shards (local + peers), reconstruct and decrypt → plaintext.
async fn fetch_and_reassemble(
    st: &AppState,
    file: FileRow,
    plan: Vec<p2pnas_store::service::ChunkShards>,
) -> Result<Vec<u8>> {
    // 2. peer_id → addr lookup for remote fetches. Peers already flagged `down` are
    //    left out, like the write path does: their shards are precisely what the
    //    erasure code exists to survive, and letting every one of a file's hundreds
    //    of chunks re-discover that a known-dead host is dead adds one timeout per
    //    chunk for bytes we will not get anyway.
    let peers: PeerAddrs =
        match sqlx::query_as::<_, (String, String)>("SELECT peer_id, addr FROM p2pnas.peers WHERE status <> 'down'")
            .fetch_all(&st.db)
            .await
        {
            Ok(rows) => rows.into_iter().collect(),
            Err(e) => {
                // Not fatal: local shards alone may still carry the file.
                tracing::error!(error = %e, "p2pnas read: peer lookup failed — remote shards will be treated as lost");
                PeerAddrs::new()
            }
        };
    let peers = Arc::new(peers);

    // 3. Fetch the chunks through a sliding window of `READ_CHUNK_WINDOW`.
    let mut fetched: Vec<ChunkFetch> = Vec::with_capacity(plan.len());
    let mut queue = plan.into_iter().enumerate();
    let mut set: tokio::task::JoinSet<ChunkFetch> = tokio::task::JoinSet::new();
    for _ in 0..READ_CHUNK_WINDOW {
        spawn_chunk_fetch(&mut set, st, &peers, &mut queue);
    }
    while let Some(res) = set.join_next().await {
        fetched.push(res.map_err(join_err)?);
        spawn_chunk_fetch(&mut set, st, &peers, &mut queue);
    }

    // 4. Reconstruct + decrypt — back in file order.
    fetched.sort_by_key(|(i, _, _)| *i);
    let chunks_fetched: Vec<(ChunkRow, Vec<Option<Vec<u8>>>)> =
        fetched.into_iter().map(|(_, chunk, present)| (chunk, present)).collect();
    // The manifest row travels with the data: decryption is bound to the file's
    // real owner and its chunk count, which is what makes a truncated or
    // cross-file chunk detectable.
    let (id, row) = (st.identity.clone(), file);
    tokio::task::spawn_blocking(move || p2pnas_store::service::reassemble(&id, &row, chunks_fetched))
        .await
        .map_err(join_err)?
        .map_err(Into::into)
}

/// Download a file by its id.
pub async fn download(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Path(file_id): Path<String>,
) -> Result<Response> {
    let bytes = reconstruct_file(&st, &user.id.to_string(), &file_id).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

/// Download a file by its path (the path-based "My Cloud" mount).
pub async fn download_path(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Query(q): Query<PathQuery>,
) -> Result<Response> {
    let uid = user.id.to_string();
    let (man, uid2, path) = (st.manifest.clone(), uid.clone(), q.path.clone());
    let file = tokio::task::spawn_blocking(move || p2pnas_store::service::get_file_by_path(&man, &uid2, &path))
        .await
        .map_err(join_err)??
        .ok_or(P2pError::NotFound)?;
    let bytes = reconstruct_file(&st, &uid, &file.file_id).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

// ── Folder-aware "My Cloud" browsing (parity with Drive's Mon Drive) ─────────

/// List a directory's immediate children (folders + files).
pub async fn browse(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Query(q): Query<DirQuery>,
) -> Result<Json<Value>> {
    let (man, uid, dir) = (st.manifest.clone(), user.id.to_string(), q.path.unwrap_or_default());
    let listing = tokio::task::spawn_blocking(move || p2pnas_store::service::browse(&man, &uid, &dir))
        .await
        .map_err(join_err)??;
    let folders: Vec<Value> = listing
        .folders
        .iter()
        .map(|p| json!({ "name": p.rsplit('/').next().unwrap_or(p), "path": p }))
        .collect();
    let files: Vec<Value> = listing
        .files
        .iter()
        .map(|f| json!({
            "name": f.path.rsplit('/').next().unwrap_or(&f.path),
            "path": f.path,
            "file_id": f.file_id,
            "size": f.size,
            "created_at": f.created_at,
        }))
        .collect();
    Ok(Json(json!({ "folders": folders, "files": files })))
}

/// Create a folder.
pub async fn mkdir(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Json(body): Json<PathBody>,
) -> Result<Json<Value>> {
    let (man, uid, path) = (st.manifest.clone(), user.id.to_string(), body.path.clone());
    tokio::task::spawn_blocking(move || p2pnas_store::service::mkdir(&man, &uid, &path))
        .await
        .map_err(join_err)??;
    Ok(Json(json!({ "created": body.path })))
}

/// Rename or move a file/folder (path change only — no re-encryption).
pub async fn rename(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Json(body): Json<RenameBody>,
) -> Result<Json<Value>> {
    let (man, uid, from, to) = (st.manifest.clone(), user.id.to_string(), body.from.clone(), body.to.clone());
    tokio::task::spawn_blocking(move || p2pnas_store::service::rename(&man, &uid, &from, &to))
        .await
        .map_err(join_err)??;
    Ok(Json(json!({ "from": body.from, "to": body.to })))
}

// ── Trash, versions and permanent deletion ───────────────────────────────────
//
// Accounting policy, decided once and applied everywhere below.
//
// **A file in the trash — and an old version — still counts against the user's
// quota.** The bytes are genuinely there: on this node's disk and on the peers
// hosting its shards. Discounting them would mean the node promises capacity it
// does not have, and the first thing that breaks is a stranger's placement
// request, not the user's own upload. Counting them also gives the trash the only
// pressure that ever empties it — the user sees their allowance shrink and clears
// it, instead of a hidden pile growing until an administrator notices.
//
// Consequences, in one place:
//   trash / overwrite → nothing is credited back (nothing was freed);
//   restore           → nothing changes (nothing had been freed);
//   purge / sweep     → the user's quota AND the node's stored bytes are credited,
//                       and the shards on peers are handed to `gc_remote`.
const TRASH_COUNTS_AGAINST_QUOTA: bool = true;

/// Retention defaults for the sweep (see `service::RetentionPolicy`).
///
/// Constants for now, deliberately: turning them into administrable settings means
/// touching `config::instance` and the admin console, which is a change of its own.
/// They are the values `RetentionPolicy::default()` documents.
fn retention_policy() -> p2pnas_store::service::RetentionPolicy {
    p2pnas_store::service::RetentionPolicy::default()
}

/// Move a file or a folder subtree to the trash (by path).
///
/// Nothing is freed and no quota is credited — see `TRASH_COUNTS_AGAINST_QUOTA`.
pub async fn delete_path(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Json(body): Json<PathBody>,
) -> Result<Json<Value>> {
    let (man, uid, path) = (st.manifest.clone(), user.id.to_string(), body.path.clone());
    let summary = tokio::task::spawn_blocking(move || p2pnas_store::service::trash_path(&man, &uid, &path))
        .await
        .map_err(join_err)??;
    Ok(Json(json!({
        "trashed": body.path,
        "files": summary.files,
        "size": summary.size,
        // Explicit, so no client has to guess whether its quota display moved.
        "quota_freed": 0,
    })))
}

/// Move a file to the trash (by id). Restorable until it is purged.
pub async fn delete(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Path(file_id): Path<String>,
) -> Result<Json<Value>> {
    let (man, uid) = (st.manifest.clone(), user.id.to_string());
    let file = tokio::task::spawn_blocking(move || p2pnas_store::service::trash(&man, &uid, &file_id))
        .await
        .map_err(join_err)??;
    Ok(Json(json!({
        "trashed": file.file_id,
        "path": file.path,
        "deleted_at": file.deleted_at,
        "quota_freed": 0,
    })))
}

/// A single file, named by id, with an optional destination path.
#[derive(Deserialize)]
pub struct FileIdBody {
    pub file_id: String,
    /// Restore only: where to put it back (defaults to the path it had).
    #[serde(default)]
    pub path:    Option<String>,
}

/// The user's trash: what they deleted, still restorable.
pub async fn trash_list(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
) -> Result<Json<Value>> {
    let (man, uid) = (st.manifest.clone(), user.id.to_string());
    let files = tokio::task::spawn_blocking(move || p2pnas_store::service::list_trash(&man, &uid))
        .await
        .map_err(join_err)??;
    let bytes: i64 = files.iter().map(|f| f.size).sum();
    Ok(Json(json!({
        "files": files,
        "bytes": bytes,
        "counts_against_quota": TRASH_COUNTS_AGAINST_QUOTA,
        "retention_days": retention_policy().trash_days,
    })))
}

/// Every stored version of a file, newest first (the current one included).
pub async fn versions(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Path(file_id): Path<String>,
) -> Result<Json<Value>> {
    let (man, uid) = (st.manifest.clone(), user.id.to_string());
    let versions = tokio::task::spawn_blocking(move || p2pnas_store::service::list_versions(&man, &uid, &file_id))
        .await
        .map_err(join_err)??;
    let policy = retention_policy();
    Ok(Json(json!({
        "versions": versions,
        "keep_versions": policy.keep_versions,
        "retention_days": policy.version_days,
    })))
}

/// Restore a trashed file — or an older version — as the live file at its path.
///
/// One handler for both because it is one operation: a version and a trashed file
/// are the same kind of retired row. If the target path is occupied, the occupant
/// becomes a version rather than being overwritten, so a restore never loses data.
/// No quota movement: the bytes were never given back.
pub async fn restore(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Json(body): Json<FileIdBody>,
) -> Result<Json<Value>> {
    let (man, uid, fid, to) = (st.manifest.clone(), user.id.to_string(), body.file_id, body.path);
    let file = tokio::task::spawn_blocking(move || {
        p2pnas_store::service::restore(&man, &uid, &fid, to.as_deref())
    })
    .await
    .map_err(join_err)??;
    Ok(Json(json!({ "restored": file.file_id, "path": file.path, "size": file.size })))
}

/// Permanently delete one trashed file or one old version. Irreversible — this is
/// the only per-file path that destroys data, and the quota is credited here.
pub async fn purge(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Json(body): Json<FileIdBody>,
) -> Result<Json<Value>> {
    let (man, store, uid, fid) = (st.manifest.clone(), st.store.clone(), user.id.to_string(), body.file_id);
    let (file, remote) =
        tokio::task::spawn_blocking(move || p2pnas_store::service::purge_file(&man, &store, &uid, &fid))
            .await
            .map_err(join_err)??;
    credit_freed_space(&st, user.id, file.size, file.stored_bytes).await?;
    enqueue_remote_gc(&st, remote).await;
    Ok(Json(json!({ "purged": file.file_id, "path": file.path, "quota_freed": file.size })))
}

/// Permanently delete everything in the user's trash. Old versions of files they
/// still have are left alone — the sweep ages those out.
pub async fn empty_trash(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
) -> Result<Json<Value>> {
    let (man, store, uid) = (st.manifest.clone(), st.store.clone(), user.id.to_string());
    let (summary, remote) =
        tokio::task::spawn_blocking(move || p2pnas_store::service::empty_trash(&man, &store, &uid))
            .await
            .map_err(join_err)??;
    credit_freed_space(&st, user.id, summary.size, summary.stored_bytes).await?;
    enqueue_remote_gc(&st, remote).await;
    Ok(Json(json!({ "purged": summary.files, "quota_freed": summary.size })))
}

/// Give a permanent deletion's bytes back to the account and to the node.
///
/// `GREATEST(..., 0)` on both: these counters are corrected by several paths and
/// must never be allowed to go negative, which would hand out capacity that does
/// not exist.
async fn credit_freed_space(st: &AppState, user: uuid::Uuid, size: i64, stored: i64) -> Result<()> {
    sqlx::query(
        "UPDATE p2pnas.user_quota SET used_bytes = GREATEST(used_bytes - $2, 0), updated_at = now() WHERE user_id = $1",
    )
    .bind(user)
    .bind(size)
    .execute(&st.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, user_id = %user, size, "p2pnas purge: quota credit failed");
        P2pError::Db(e)
    })?;
    sqlx::query(
        "UPDATE p2pnas.node_local SET used_bytes = GREATEST(used_bytes - $1, 0), updated_at = now() WHERE id = 1",
    )
    .bind(stored)
    .execute(&st.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, stored, "p2pnas purge: node storage accounting update failed");
        P2pError::Db(e)
    })?;
    Ok(())
}

/// Run the retention sweep now: reclaim trash and versions that have expired,
/// give each account its bytes back, and hand the peer-hosted shards to
/// `gc_remote`. Returns (files purged, plaintext bytes reclaimed).
///
/// Node-wide, so it is not a user-facing operation: call it from the background
/// worker (a `gc_trash` job) and from the admin console.
pub async fn purge_retired_now(st: &AppState) -> (usize, i64) {
    let (man, store, policy) = (st.manifest.clone(), st.store.clone(), retention_policy());
    let report = match tokio::task::spawn_blocking(move || {
        p2pnas_store::service::purge_retired(&man, &store, policy)
    })
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "p2pnas retention sweep: manifest error");
            return (0, 0);
        }
        Err(e) => {
            tracing::error!(error = %e, "p2pnas retention sweep: task did not complete");
            return (0, 0);
        }
    };

    // Per account, because a quota is per account. Best-effort per row: one user's
    // failed credit must not strand the others' — the alternative is a sweep that
    // freed the bytes but told nobody.
    let mut freed_size = 0i64;
    let mut freed_stored = 0i64;
    for (user_id, size, stored) in report.freed {
        freed_size += size;
        freed_stored += stored;
        let Ok(uid) = user_id.parse::<uuid::Uuid>() else {
            tracing::error!(user_id = %user_id, "p2pnas retention sweep: unparsable user id in the manifest");
            continue;
        };
        if let Err(e) = sqlx::query(
            "UPDATE p2pnas.user_quota SET used_bytes = GREATEST(used_bytes - $2, 0), updated_at = now() WHERE user_id = $1",
        )
        .bind(uid)
        .bind(size)
        .execute(&st.db)
        .await
        {
            tracing::error!(error = %e, %uid, size, "p2pnas retention sweep: quota credit failed");
        }
    }
    if freed_stored > 0 {
        if let Err(e) = sqlx::query(
            "UPDATE p2pnas.node_local SET used_bytes = GREATEST(used_bytes - $1, 0), updated_at = now() WHERE id = 1",
        )
        .bind(freed_stored)
        .execute(&st.db)
        .await
        {
            tracing::error!(error = %e, freed_stored, "p2pnas retention sweep: node accounting failed");
        }
    }

    enqueue_remote_gc(st, report.remote).await;
    if report.files > 0 {
        tracing::info!(files = report.files, freed_size, freed_stored, "p2pnas retention sweep complete");
        let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('trash_purged', $1)")
            .bind(json!({ "files": report.files, "bytes": freed_size, "stored_bytes": freed_stored }))
            .execute(&st.db)
            .await;
    }
    (report.files, freed_size)
}

/// Admin: run the retention sweep on demand instead of waiting for the job.
pub async fn run_retention_purge(State(st): State<AppState>) -> Result<Json<Value>> {
    let (files, bytes) = purge_retired_now(&st).await;
    Ok(Json(json!({ "purged": files, "bytes_freed": bytes })))
}

// ── Small-file packing: repack + pack compaction ─────────────────────────────
//
// Accounting for packs, in one place. The user's quota debits `size` (plaintext)
// and a member keeps its `size`, so packing moves NO quota at all. What moves is
// the node's `used_bytes`: a member's own shards are released and the pack's
// shards (via `shard_disk_cost`, computed inside `push`/`pack_files`) are added —
// always charged to the PACK, never to a member (whose `stored_bytes` is 0),
// otherwise the same physical shards would be counted once per member.

/// Live-bytes percentage under which a pack is worth rewriting: below half, the
/// majority of what its 14 shards hold is bytes no row references any more, so a
/// rewrite pays for itself. (`pack.size` includes the index trailer, so the ratio
/// is slightly conservative — a pack compacts a touch later, never earlier.)
const PACK_COMPACT_MIN_LIVE_PCT: i64 = 50;

/// What a repack or compaction pass moved, for the caller and the admin reply.
pub struct RepackTotals {
    pub packs:        usize,
    pub files:        usize,
    /// Net change to the node's stored bytes (negative = space reclaimed).
    pub stored_delta: i64,
}

/// Move the node's stored-bytes counter by `delta` (negative = freed), clamped
/// at zero. Best-effort like `adjust_user_used`, and for the same reason: the
/// shards have already moved, so a bookkeeping failure is drift to log, not an
/// operation to fail.
async fn adjust_node_stored(st: &AppState, delta: i64) {
    if delta == 0 {
        return;
    }
    if let Err(e) = sqlx::query(
        "UPDATE p2pnas.node_local SET used_bytes = GREATEST(used_bytes + $1, 0), updated_at = now() WHERE id = 1",
    )
    .bind(delta)
    .execute(&st.db)
    .await
    {
        tracing::error!(error = %e, delta, "p2pnas packing: node storage accounting update failed");
    }
}

/// Settle one written pack: node accounting, remote GC of the shards it
/// replaced, and distribution of its (all-local) shards like a fresh upload's.
async fn settle_pack_write(st: &AppState, user_id: &str, r: p2pnas_store::service::PackResult) -> i64 {
    let delta = r.pack_stored_bytes - r.freed_stored_bytes;
    adjust_node_stored(st, delta).await;
    enqueue_remote_gc(st, r.remote).await;
    if let Some(pack_id) = r.pack_id.as_deref() {
        match user_id.parse::<uuid::Uuid>() {
            Ok(uid) => distribute_shards(st, uid, pack_id).await,
            Err(e) => {
                tracing::error!(user_id = %user_id, error = %e, "p2pnas packing: unparsable user id — pack shards stay local")
            }
        }
    }
    delta
}

/// Regroup every user's small self-contained files into packs (deferred packing:
/// the files were stored on the normal path first, so a crash anywhere here
/// loses nothing — at worst a group stays autonomous until the next pass).
///
/// Node-wide and not user-facing: call it from the background worker (a
/// `repack_small` job) and from the admin console.
pub async fn repack_all_now(st: &AppState) -> RepackTotals {
    let mut totals = RepackTotals { packs: 0, files: 0, stored_delta: 0 };
    let man = st.manifest.clone();
    let users = match tokio::task::spawn_blocking(move || p2pnas_store::service::users_with_packable(&man)).await {
        Ok(Ok(users)) => users,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "p2pnas repack: could not list candidate users");
            return totals;
        }
        Err(e) => {
            tracing::error!(error = %e, "p2pnas repack: candidate task did not complete");
            return totals;
        }
    };

    for user in users {
        let (man, u) = (st.manifest.clone(), user.clone());
        let candidates = match tokio::task::spawn_blocking(move || p2pnas_store::service::list_packable(&man, &u)).await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::error!(user_id = %user, error = %e, "p2pnas repack: could not list packable files");
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "p2pnas repack: listing task did not complete");
                continue;
            }
        };
        for group in p2pnas_store::service::plan_packs(candidates, p2pnas_store::service::PACK_TARGET as i64) {
            // Gather every member's plaintext over the normal (network-capable)
            // read path — the members' shards may already live on peers.
            let mut entries = Vec::with_capacity(group.len());
            for f in &group {
                match reconstruct_file(st, &user, &f.file_id).await {
                    Ok(data) => {
                        entries.push(p2pnas_store::service::PackEntry { file_id: f.file_id.clone(), data })
                    }
                    Err(e) => {
                        // One unreadable member forfeits its whole group: better
                        // left autonomous for the repair pass than packed around
                        // a hole.
                        tracing::warn!(file_id = %f.file_id, error = %e, "p2pnas repack: member unreadable — skipping its group");
                        entries.clear();
                        break;
                    }
                }
            }
            if entries.is_empty() {
                continue;
            }
            let (id, man, store, u) = (st.identity.clone(), st.manifest.clone(), st.store.clone(), user.clone());
            let packed = tokio::task::spawn_blocking(move || {
                p2pnas_store::service::pack_files(&id, &man, &store, &u, &entries)
            })
            .await;
            match packed {
                Ok(Ok(r)) => {
                    totals.packs += 1;
                    totals.files += r.members;
                    totals.stored_delta += settle_pack_write(st, &user, r).await;
                }
                // A failed pack rolls back whole: the files simply stay
                // autonomous and the next pass retries them.
                Ok(Err(e)) => {
                    tracing::warn!(user_id = %user, error = %e, "p2pnas repack: pack write failed — files stay autonomous")
                }
                Err(e) => tracing::error!(error = %e, "p2pnas repack: pack task did not complete"),
            }
        }
    }

    if totals.packs > 0 {
        tracing::info!(
            packs = totals.packs,
            files = totals.files,
            stored_delta = totals.stored_delta,
            "p2pnas repack: small files regrouped into packs"
        );
        let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('repacked', $1)")
            .bind(json!({ "packs": totals.packs, "files": totals.files, "stored_delta": totals.stored_delta }))
            .execute(&st.db)
            .await;
    }
    totals
}

/// Rewrite the packs that are mostly dead bytes (rows purged since they were
/// packed) around their surviving members, and drop the memberless ones.
///
/// Node-wide, like the retention sweep it complements: retention purges member
/// ROWS, compaction is what turns those purges into reclaimed shards.
pub async fn compact_packs_now(st: &AppState) -> RepackTotals {
    let mut totals = RepackTotals { packs: 0, files: 0, stored_delta: 0 };
    let man = st.manifest.clone();
    let occupancy = match tokio::task::spawn_blocking(move || p2pnas_store::service::list_pack_occupancy(&man)).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "p2pnas compaction: could not read pack occupancy");
            return totals;
        }
        Err(e) => {
            tracing::error!(error = %e, "p2pnas compaction: occupancy task did not complete");
            return totals;
        }
    };

    for (pack, live_bytes, members) in occupancy {
        if members > 0 && live_bytes * 100 >= pack.size * PACK_COMPACT_MIN_LIVE_PCT {
            continue; // still mostly live — rewriting it would cost more than it frees
        }
        let survivors = if members == 0 {
            Vec::new()
        } else {
            // Read the old pack once, slice every surviving member out of it.
            let plain = match reconstruct_file(st, &pack.user_id, &pack.file_id).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(pack_id = %pack.file_id, error = %e, "p2pnas compaction: pack unreadable — skipped");
                    continue;
                }
            };
            let (man, u, pid) = (st.manifest.clone(), pack.user_id.clone(), pack.file_id.clone());
            let rows =
                match tokio::task::spawn_blocking(move || p2pnas_store::service::list_pack_members(&man, &u, &pid))
                    .await
                {
                    Ok(Ok(rows)) => rows,
                    Ok(Err(e)) => {
                        tracing::error!(pack_id = %pack.file_id, error = %e, "p2pnas compaction: could not list members");
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "p2pnas compaction: member task did not complete");
                        continue;
                    }
                };
            let mut entries = Vec::with_capacity(rows.len());
            let mut sliced_ok = true;
            for m in rows {
                match p2pnas_store::service::member_slice(&plain, &m) {
                    Ok(data) => entries.push(p2pnas_store::service::PackEntry { file_id: m.file_id, data }),
                    Err(e) => {
                        tracing::error!(pack_id = %pack.file_id, error = %e, "p2pnas compaction: member range corrupt — pack left as is");
                        sliced_ok = false;
                        break;
                    }
                }
            }
            if !sliced_ok || entries.is_empty() {
                continue;
            }
            entries
        };

        let (id, man, store, u, old) = (
            st.identity.clone(),
            st.manifest.clone(),
            st.store.clone(),
            pack.user_id.clone(),
            pack.file_id.clone(),
        );
        let compacted = tokio::task::spawn_blocking(move || {
            p2pnas_store::service::compact_pack(&id, &man, &store, &u, &old, &survivors)
        })
        .await;
        match compacted {
            Ok(Ok(r)) => {
                totals.packs += 1;
                totals.files += r.members;
                totals.stored_delta += settle_pack_write(st, &pack.user_id, r).await;
            }
            Ok(Err(e)) => {
                tracing::warn!(pack_id = %pack.file_id, error = %e, "p2pnas compaction: pack rewrite failed — left as is")
            }
            Err(e) => tracing::error!(error = %e, "p2pnas compaction: compaction task did not complete"),
        }
    }

    if totals.packs > 0 {
        tracing::info!(
            packs = totals.packs,
            stored_delta = totals.stored_delta,
            "p2pnas compaction: sparse packs rewritten"
        );
        let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('packs_compacted', $1)")
            .bind(json!({ "packs": totals.packs, "stored_delta": totals.stored_delta }))
            .execute(&st.db)
            .await;
    }
    totals
}

/// Admin: pack the small self-contained files into containers now, instead of
/// waiting for the background job.
pub async fn run_repack(State(st): State<AppState>) -> Result<Json<Value>> {
    let t = repack_all_now(&st).await;
    Ok(Json(json!({ "packs": t.packs, "files_packed": t.files, "stored_delta": t.stored_delta })))
}

/// Admin: compact the sparse packs now, instead of waiting for the background job.
pub async fn run_pack_compaction(State(st): State<AppState>) -> Result<Json<Value>> {
    let t = compact_packs_now(&st).await;
    Ok(Json(json!({ "packs_compacted": t.packs, "stored_delta": t.stored_delta })))
}
