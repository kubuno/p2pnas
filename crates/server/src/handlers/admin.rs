use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    errors::{P2pError, Result},
    repair,
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

#[derive(Deserialize)]
pub struct AddPeer {
    pub addr: String,
}

/// Add a trusted peer (admin only): handshake over P2P, then record it.
pub async fn add_peer(State(st): State<AppState>, Json(body): Json<AddPeer>) -> Result<Json<Value>> {
    let addr = body.addr.trim().to_string();
    if addr.is_empty() {
        return Err(P2pError::BadRequest("addr requis (ip:port)".into()));
    }
    let (peer_id, api_port) =
        p2pnas_p2p::handshake(&addr, &st.identity.peer_id, st.settings.server.port)
            .await
            .map_err(|e| P2pError::BadRequest(format!("handshake échoué: {e}")))?;

    sqlx::query(
        "INSERT INTO p2pnas.peers (peer_id, addr, last_seen) VALUES ($1, $2, now())
         ON CONFLICT (peer_id) DO UPDATE SET addr = EXCLUDED.addr, last_seen = now()",
    )
    .bind(&peer_id)
    .bind(&addr)
    .execute(&st.db)
    .await?;

    Ok(Json(json!({ "peer_id": peer_id, "addr": addr, "api_port": api_port })))
}

/// Trigger a node-wide self-healing repair pass (admin only): probe peer
/// liveness, then re-replicate any shard whose host has gone unreachable.
pub async fn run_repair(State(st): State<AppState>) -> Result<Json<Value>> {
    let report = repair::repair_all(&st).await;
    let report = serde_json::to_value(&report).unwrap_or_default();
    Ok(Json(json!({ "repair": report })))
}

/// Enqueue a repair/rebalance job (admin only) — non-blocking; the worker runs it.
pub async fn rebalance(State(st): State<AppState>) -> Result<Json<Value>> {
    crate::jobs::enqueue(&st.db, "repair", json!({})).await;
    Ok(Json(json!({ "enqueued": "repair" })))
}

/// Node metrics (admin only): storage, peers, jobs, discovery, data-loss risk.
pub async fn metrics(State(st): State<AppState>) -> Result<Json<Value>> {
    let (contributed, used, hosted): (i64, i64, i64) =
        sqlx::query_as("SELECT contributed_bytes, used_bytes, hosted_bytes FROM p2pnas.node_local WHERE id = 1")
            .fetch_one(&st.db)
            .await
            .unwrap_or((0, 0, 0));
    let (peers_total, peers_active, peers_down): (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'active'), COUNT(*) FILTER (WHERE status = 'down') FROM p2pnas.peers",
    )
    .fetch_one(&st.db)
    .await
    .unwrap_or((0, 0, 0));
    let hosted_shards: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM p2pnas.hosted_shards")
        .fetch_one(&st.db)
        .await
        .unwrap_or(0);
    let (jobs_pending, jobs_running): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE state = 'pending'), COUNT(*) FILTER (WHERE state = 'running') FROM p2pnas.jobs",
    )
    .fetch_one(&st.db)
    .await
    .unwrap_or((0, 0));
    let unrepairable: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM p2pnas.events WHERE kind = 'chunk_unrepairable'")
        .fetch_one(&st.db)
        .await
        .unwrap_or(0);

    let man = st.manifest.clone();
    let (files, chunks, stored) = tokio::task::spawn_blocking(move || p2pnas_store::service::node_stats(&man))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or((0, 0, 0));

    Ok(Json(json!({
        "node": {
            "contributed_bytes": contributed, "used_bytes": used, "hosted_bytes": hosted,
            "available_bytes": (contributed - used - hosted).max(0),
        },
        "storage": { "files": files, "chunks": chunks, "stored_bytes": stored, "hosted_shards": hosted_shards },
        "peers": { "total": peers_total, "active": peers_active, "down": peers_down },
        "jobs": { "pending": jobs_pending, "running": jobs_running },
        "discovery": { "mdns": st.settings.discovery.mdns, "dht": st.settings.discovery.dht },
        "risk": { "unrepairable_events": unrepairable },
    })))
}

/// Forget a peer (admin only). Shards currently hosted there stay referenced in
/// the manifest until a repair pass relocates them; removing an unreachable peer
/// lets the next pass treat its shards as lost and re-replicate them.
pub async fn remove_peer(
    State(st): State<AppState>,
    axum::extract::Path(peer_id): axum::extract::Path<String>,
) -> Result<Json<Value>> {
    let n = sqlx::query("DELETE FROM p2pnas.peers WHERE peer_id = $1")
        .bind(&peer_id)
        .execute(&st.db)
        .await?
        .rows_affected();
    Ok(Json(json!({ "removed": peer_id, "found": n > 0 })))
}

/// List trusted peers (admin only).
pub async fn list_peers(State(st): State<AppState>) -> Result<Json<Value>> {
    type Row = (String, String, f64, i64, Option<chrono::DateTime<chrono::Utc>>, Option<f64>, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT peer_id, addr, reliability_score, contributed_bytes, last_seen, rtt_ms, country
         FROM p2pnas.peers ORDER BY reliability_score DESC, peer_id",
    )
    .fetch_all(&st.db)
    .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|(peer_id, addr, score, contributed, last_seen, rtt_ms, country)| {
            json!({
                "peer_id": peer_id,
                "addr": addr,
                "reliability_score": score,
                "contributed_bytes": contributed,
                "last_seen": last_seen.map(|t| t.to_rfc3339()),
                "rtt_ms": rtt_ms,
                "country": country,
            })
        })
        .collect();
    Ok(Json(json!({ "peers": items })))
}

/// Recent control-plane events (admin only): repair / data-loss-risk notices.
pub async fn list_events(State(st): State<AppState>) -> Result<Json<Value>> {
    type Row = (i64, String, Value, chrono::DateTime<chrono::Utc>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, kind, payload, created_at FROM p2pnas.events ORDER BY id DESC LIMIT 50",
    )
    .fetch_all(&st.db)
    .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|(id, kind, payload, created_at)| {
            json!({ "id": id, "kind": kind, "payload": payload, "created_at": created_at.to_rfc3339() })
        })
        .collect();
    Ok(Json(json!({ "events": items })))
}
