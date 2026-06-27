use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    errors::{P2pError, Result},
    state::AppState,
};

/// List every user's quota (admin only).
pub async fn list_quotas(State(st): State<AppState>) -> Result<Json<Value>> {
    let rows: Vec<(Uuid, i64, i64)> = sqlx::query_as(
        "SELECT user_id, quota_bytes, used_bytes FROM p2pnas.user_quota ORDER BY user_id",
    )
    .fetch_all(&st.db)
    .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, quota, used)| {
            json!({
                "user_id": user_id,
                "quota_bytes": quota,
                "used_bytes": used,
                "available_bytes": (quota - used).max(0),
            })
        })
        .collect();
    Ok(Json(json!({ "quotas": items })))
}

#[derive(Deserialize)]
pub struct SetQuota {
    pub user_id:     Uuid,
    pub quota_bytes: i64,
}

/// Set a user's quota (admin only). Enforces that the sum of all user quotas
/// never exceeds the node's contributed capacity.
pub async fn set_quota(State(st): State<AppState>, Json(body): Json<SetQuota>) -> Result<Json<Value>> {
    if body.quota_bytes < 0 {
        return Err(P2pError::BadRequest("quota_bytes must be ≥ 0".into()));
    }

    let contributed: i64 =
        sqlx::query_scalar("SELECT contributed_bytes FROM p2pnas.node_local WHERE id = 1")
            .fetch_one(&st.db)
            .await?;
    let others: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(quota_bytes), 0)::BIGINT FROM p2pnas.user_quota WHERE user_id <> $1",
    )
    .bind(body.user_id)
    .fetch_one(&st.db)
    .await?;

    if others + body.quota_bytes > contributed {
        return Err(P2pError::BadRequest(format!(
            "allocation exceeds node capacity: {} + {} > {} bytes",
            others, body.quota_bytes, contributed
        )));
    }

    sqlx::query(
        "INSERT INTO p2pnas.user_quota (user_id, quota_bytes, updated_at)
         VALUES ($1, $2, now())
         ON CONFLICT (user_id) DO UPDATE SET quota_bytes = EXCLUDED.quota_bytes, updated_at = now()",
    )
    .bind(body.user_id)
    .bind(body.quota_bytes)
    .execute(&st.db)
    .await?;

    Ok(Json(json!({ "user_id": body.user_id, "quota_bytes": body.quota_bytes })))
}

#[derive(Deserialize)]
pub struct SetContribution {
    pub bytes: i64,
}

/// Set the storage this node contributes to the network (admin only). Cannot drop
/// below what is already used or already allocated to users.
pub async fn set_contribution(State(st): State<AppState>, Json(body): Json<SetContribution>) -> Result<Json<Value>> {
    if body.bytes < 0 {
        return Err(P2pError::BadRequest("bytes must be ≥ 0".into()));
    }
    let used: i64 = sqlx::query_scalar("SELECT used_bytes FROM p2pnas.node_local WHERE id = 1")
        .fetch_one(&st.db)
        .await?;
    let allocated: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(quota_bytes), 0)::BIGINT FROM p2pnas.user_quota")
        .fetch_one(&st.db)
        .await?;
    if body.bytes < used || body.bytes < allocated {
        return Err(P2pError::BadRequest(format!(
            "contribution {} below used {} or allocated {} bytes",
            body.bytes, used, allocated
        )));
    }
    sqlx::query("UPDATE p2pnas.node_local SET contributed_bytes = $1, updated_at = now() WHERE id = 1")
        .bind(body.bytes)
        .execute(&st.db)
        .await?;
    Ok(Json(json!({ "contributed_bytes": body.bytes })))
}

/// List trusted peers (admin only).
pub async fn list_peers(State(st): State<AppState>) -> Result<Json<Value>> {
    let rows: Vec<(String, String, f64, i64)> = sqlx::query_as(
        "SELECT peer_id, addr, reliability_score, contributed_bytes FROM p2pnas.peers ORDER BY reliability_score DESC",
    )
    .fetch_all(&st.db)
    .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|(peer_id, addr, score, contributed)| {
            json!({ "peer_id": peer_id, "addr": addr, "reliability_score": score, "contributed_bytes": contributed })
        })
        .collect();
    Ok(Json(json!({ "peers": items })))
}
