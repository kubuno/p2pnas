use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use p2pnas_core::erasure::TOTAL_SHARDS;
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

/// Move each shard to a peer (round-robin over `[self] + peers`); shards that
/// can't be placed remotely stay local. No peers → everything stays local.
async fn distribute_shards(st: &AppState, user_id: &str, file_id: &str) {
    let peers: Vec<(String, String)> =
        sqlx::query_as("SELECT peer_id, addr FROM p2pnas.peers WHERE peer_id <> $1")
            .bind(&st.identity.peer_id)
            .fetch_all(&st.db)
            .await
            .unwrap_or_default();
    if peers.is_empty() {
        return;
    }

    let (man, uid, fid) = (st.manifest.clone(), user_id.to_string(), file_id.to_string());
    let plan = match tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid, &fid)).await {
        Ok(Ok((_, chunks))) => chunks,
        _ => return,
    };

    let mut slot = 0usize;
    for (_chunk, shards) in plan {
        for s in shards {
            let target = slot % (peers.len() + 1);
            slot += 1;
            if target == 0 {
                continue; // keep on self
            }
            let (peer_id, addr) = peers[target - 1].clone();

            let store = st.store.clone();
            let frag = s.fragment_id.clone();
            let bytes = match tokio::task::spawn_blocking(move || p2pnas_store::service::read_local(&store, &frag)).await {
                Ok(Some(b)) => b,
                _ => continue,
            };

            let msg = P2pMessage::StoreShard {
                fragment_id: s.fragment_id.clone(),
                owner_peer_id: st.identity.peer_id.clone(),
                data: bytes,
            };
            if let Ok(P2pMessage::Ack { .. }) = p2pnas_p2p::request(&addr, &msg).await {
                let (man, frag, pid) = (st.manifest.clone(), s.fragment_id.clone(), peer_id.clone());
                let _ = tokio::task::spawn_blocking(move || p2pnas_store::service::set_location(&man, &frag, &pid)).await;
                let (store, frag2) = (st.store.clone(), s.fragment_id.clone());
                let _ = tokio::task::spawn_blocking(move || store.delete(&frag2)).await;
            }
        }
    }
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

/// Download a file: gather its shards (local + peers), reconstruct, decrypt.
pub async fn download(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Path(file_id): Path<String>,
) -> Result<Response> {
    let uid = user.id.to_string();

    // 1. Read the placement plan (which shard lives where).
    let (man, uid2, fid) = (st.manifest.clone(), uid.clone(), file_id.clone());
    let (_file, plan) = tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid2, &fid))
        .await
        .map_err(join_err)??;

    // 2. peer_id → addr lookup for remote fetches.
    let peers: Vec<(String, String)> = sqlx::query_as("SELECT peer_id, addr FROM p2pnas.peers")
        .fetch_all(&st.db)
        .await
        .unwrap_or_default();

    // 3. Gather every shard (local read or P2P GetShard); RS tolerates losses.
    let mut chunks_fetched = Vec::with_capacity(plan.len());
    for (chunk, shards) in plan {
        let mut present: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
        for s in shards {
            let bytes = if s.location == "local" {
                let (store, frag) = (st.store.clone(), s.fragment_id.clone());
                tokio::task::spawn_blocking(move || p2pnas_store::service::read_local(&store, &frag))
                    .await
                    .ok()
                    .flatten()
            } else if let Some((_, addr)) = peers.iter().find(|(pid, _)| pid == &s.location) {
                match p2pnas_p2p::request(addr, &P2pMessage::GetShard { fragment_id: s.fragment_id.clone() }).await {
                    Ok(P2pMessage::ShardData { data, .. }) => Some(data),
                    _ => None,
                }
            } else {
                None
            };
            if let Some(cell) = present.get_mut(s.shard_index as usize) {
                *cell = bytes;
            }
        }
        chunks_fetched.push((chunk, present));
    }

    // 4. Reconstruct + decrypt.
    let (id, fid2) = (st.identity.clone(), file_id.clone());
    let bytes = tokio::task::spawn_blocking(move || p2pnas_store::service::reassemble(&id, &fid2, chunks_fetched))
        .await
        .map_err(join_err)??;

    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
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
