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

    // Quota check (conservative: doesn't pre-credit an overwrite).
    let (quota, used): (i64, i64) =
        sqlx::query_as("SELECT quota_bytes, used_bytes FROM p2pnas.user_quota WHERE user_id = $1")
            .bind(user.id)
            .fetch_optional(&st.db)
            .await?
            .unwrap_or((0, 0));
    if used + size > quota {
        return Err(P2pError::BadRequest(format!(
            "quota exceeded: {used} + {size} > {quota} bytes (ask an admin to raise your My Cloud quota)"
        )));
    }

    let (id, man, store) = (st.identity.clone(), st.manifest.clone(), st.store.clone());
    let uid = user.id.to_string();
    let data = body.to_vec();
    let res = tokio::task::spawn_blocking(move || {
        p2pnas_store::service::push(&id, &man, &store, &uid, &path, &data)
    })
    .await
    .map_err(join_err)??;

    // Adjust accounting by the net delta (overwrites refund the old version).
    sqlx::query("UPDATE p2pnas.user_quota SET used_bytes = used_bytes + $2, updated_at = now() WHERE user_id = $1")
        .bind(user.id)
        .bind(res.size - res.replaced_size)
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE p2pnas.node_local SET used_bytes = used_bytes + $1, updated_at = now() WHERE id = 1")
        .bind(res.stored_bytes - res.replaced_stored)
        .execute(&st.db)
        .await?;

    // Best-effort: spread the shards across peers (round-robin over [self] + peers).
    distribute_shards(&st, &user.id.to_string(), &res.file_id).await;

    Ok(Json(json!({ "file_id": res.file_id, "path": q.path, "size": res.size })))
}

/// Spread a file's shards over peers, **latency-aware**: each chunk's shards are
/// placed by `placement::plan_placement` (prefer near peers, cap every location
/// at PARITY for single-failure durability). Shards that can't be placed remotely
/// stay local. No peers → everything stays local.
async fn distribute_shards(st: &AppState, user_id: &str, file_id: &str) {
    // Skip peers already flagged `down` — they're known-bad, no point pinging.
    let all_peers: Vec<(String, String)> =
        sqlx::query_as("SELECT peer_id, addr FROM p2pnas.peers WHERE peer_id <> $1 AND status <> 'down'")
            .bind(&st.identity.peer_id)
            .fetch_all(&st.db)
            .await
            .unwrap_or_default();

    // Probe liveness AND measure latency; keep only peers that answer.
    let mut live: Vec<(String, String, f64)> = Vec::new(); // (peer_id, addr, rtt_ms)
    for (pid, addr) in all_peers {
        if let Ok(rtt) = p2pnas_p2p::ping_rtt(&addr, &st.identity.peer_id, st.settings.server.port).await {
            live.push((pid, addr, rtt));
        }
    }
    if live.is_empty() {
        return;
    }
    // Sort near → far so failover walks outward and indexing matches the plan.
    live.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
    let peers: Vec<(String, String)> = live.iter().map(|(p, a, _)| (p.clone(), a.clone())).collect();
    let rtts: Vec<f64> = live.iter().map(|(_, _, r)| *r).collect();

    // Durability note: need ≥ ceil(TOTAL/PARITY) locations to survive 1 failure.
    let locations = peers.len() + 1;
    if TOTAL_SHARDS.div_ceil(locations) > p2pnas_core::erasure::PARITY_SHARDS {
        tracing::warn!(
            locations,
            "low durability: too few peers to survive a single failure (need ≥ {} locations)",
            crate::repair::min_locations_for_durability()
        );
    }

    let (man, uid, fid) = (st.manifest.clone(), user_id.to_string(), file_id.to_string());
    let plan = match tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid, &fid)).await {
        Ok(Ok((_, chunks))) => chunks,
        _ => return,
    };

    // Latency-aware plan (same for every chunk: shard index i → location).
    let layout = crate::placement::plan_placement(&rtts, TOTAL_SHARDS, p2pnas_core::erasure::PARITY_SHARDS);

    // Each remote placement records its PRIMARY peer index; the task fails over to
    // the next (next-nearest) peers if the primary doesn't Ack.
    let mut placements: Vec<(String, usize)> = Vec::new(); // (fragment_id, primary peer index)
    for (_chunk, shards) in plan {
        for s in shards {
            // Some(p) → peer p; None → keep on self.
            if let Some(p) = layout.get(s.shard_index as usize).copied().flatten() {
                placements.push((s.fragment_id, p));
            }
        }
    }

    // Move shards to their targets concurrently — one in-flight StoreShard per
    // placement instead of strictly sequential round-trips.
    let peers = Arc::new(peers);
    let mut set = tokio::task::JoinSet::new();
    for (frag, primary) in placements {
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
                    data: bytes.clone(),
                };
                if let Ok(P2pMessage::Ack { .. }) = p2pnas_p2p::request(&addr, &msg).await {
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
    let (man, uid2, fid) = (st.manifest.clone(), uid.clone(), file_id.clone());
    let (file, plan) = tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid2, &fid))
        .await
        .map_err(join_err)??;

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

/// List the user's files.
pub async fn list(State(st): State<AppState>, Extension(user): Extension<P2pUser>) -> Result<Json<Value>> {
    let man = st.manifest.clone();
    let uid = user.id.to_string();
    let files = tokio::task::spawn_blocking(move || p2pnas_store::service::list(&man, &uid))
        .await
        .map_err(join_err)??;
    Ok(Json(json!({ "files": files })))
}

/// Gather a file's shards (local + peers), reconstruct and decrypt → plaintext.
async fn reconstruct_file(st: &AppState, uid: &str, file_id: &str) -> Result<Vec<u8>> {
    // 1. Placement plan (which shard lives where).
    let (man, uid2, fid) = (st.manifest.clone(), uid.to_string(), file_id.to_string());
    let (_file, plan) = tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid2, &fid))
        .await
        .map_err(join_err)??;

    // 2. peer_id → addr lookup for remote fetches.
    let peers: Vec<(String, String)> = sqlx::query_as("SELECT peer_id, addr FROM p2pnas.peers")
        .fetch_all(&st.db)
        .await
        .unwrap_or_default();

    // 3. Gather every shard (local read or P2P GetShard); RS tolerates losses.
    //    Each chunk's shards are fetched concurrently (parallel local reads +
    //    in-flight GetShard round-trips) rather than one at a time.
    let mut chunks_fetched = Vec::with_capacity(plan.len());
    for (chunk, shards) in plan {
        let mut present: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
        let mut set = tokio::task::JoinSet::new();
        for s in shards {
            let st = st.clone();
            let peers = peers.clone();
            set.spawn(async move {
                let idx = s.shard_index as usize;
                let bytes = if s.location == "local" {
                    // Integrity-checked read: a corrupt local shard is treated as
                    // lost (RS reconstructs it from the others).
                    let (store, frag, hash) = (st.store.clone(), s.fragment_id.clone(), s.hash.clone());
                    tokio::task::spawn_blocking(move || p2pnas_store::service::read_local_verified(&store, &frag, &hash))
                        .await
                        .ok()
                        .flatten()
                } else if let Some((_, addr)) = peers.iter().find(|(pid, _)| pid == &s.location) {
                    match p2pnas_p2p::request(addr, &P2pMessage::GetShard { fragment_id: s.fragment_id.clone() }).await {
                        // Verify the peer returned the bytes we expect.
                        Ok(P2pMessage::ShardData { data, .. })
                            if s.hash.is_empty() || p2pnas_p2p::content_hash(&data) == s.hash =>
                        {
                            Some(data)
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                (idx, bytes)
            });
        }
        while let Some(res) = set.join_next().await {
            if let Ok((idx, bytes)) = res {
                if let Some(cell) = present.get_mut(idx) {
                    *cell = bytes;
                }
            }
        }
        chunks_fetched.push((chunk, present));
    }

    // 4. Reconstruct + decrypt.
    let (id, fid2) = (st.identity.clone(), file_id.to_string());
    tokio::task::spawn_blocking(move || p2pnas_store::service::reassemble(&id, &fid2, chunks_fetched))
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

/// Delete a file or a folder subtree (by path); frees quota.
pub async fn delete_path(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Json(body): Json<PathBody>,
) -> Result<Json<Value>> {
    let (man, store, uid, path) = (st.manifest.clone(), st.store.clone(), user.id.to_string(), body.path.clone());
    let (freed_size, freed_stored) =
        tokio::task::spawn_blocking(move || p2pnas_store::service::delete_path(&man, &store, &uid, &path))
            .await
            .map_err(join_err)??;

    sqlx::query("UPDATE p2pnas.user_quota SET used_bytes = GREATEST(used_bytes - $2, 0), updated_at = now() WHERE user_id = $1")
        .bind(user.id)
        .bind(freed_size)
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE p2pnas.node_local SET used_bytes = GREATEST(used_bytes - $1, 0), updated_at = now() WHERE id = 1")
        .bind(freed_stored)
        .execute(&st.db)
        .await?;
    Ok(Json(json!({ "deleted": body.path })))
}

/// Delete a file and free its quota.
pub async fn delete(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Path(file_id): Path<String>,
) -> Result<Json<Value>> {
    let (man, store) = (st.manifest.clone(), st.store.clone());
    let uid = user.id.to_string();
    let file = tokio::task::spawn_blocking(move || p2pnas_store::service::delete(&man, &store, &uid, &file_id))
        .await
        .map_err(join_err)??;

    sqlx::query("UPDATE p2pnas.user_quota SET used_bytes = GREATEST(used_bytes - $2, 0), updated_at = now() WHERE user_id = $1")
        .bind(user.id)
        .bind(file.size)
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE p2pnas.node_local SET used_bytes = GREATEST(used_bytes - $1, 0), updated_at = now() WHERE id = 1")
        .bind(file.stored_bytes)
        .execute(&st.db)
        .await?;

    Ok(Json(json!({ "deleted": file.file_id, "path": file.path })))
}
