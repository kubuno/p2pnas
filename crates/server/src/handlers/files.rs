use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

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

    Ok(Json(json!({ "file_id": res.file_id, "path": q.path, "size": res.size })))
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

/// Download (reconstruct + decrypt) a file by id.
pub async fn download(
    State(st): State<AppState>,
    Extension(user): Extension<P2pUser>,
    Path(file_id): Path<String>,
) -> Result<Response> {
    let (id, man, store) = (st.identity.clone(), st.manifest.clone(), st.store.clone());
    let uid = user.id.to_string();
    let bytes = tokio::task::spawn_blocking(move || {
        p2pnas_store::service::pull(&id, &man, &store, &uid, &file_id)
    })
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
