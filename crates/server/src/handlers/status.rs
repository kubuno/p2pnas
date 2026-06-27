use axum::{extract::State, Json};
use p2pnas_core::erasure;
use serde_json::{json, Value};

use crate::{errors::Result, state::AppState};

/// Node storage + network status (any authenticated user).
pub async fn status(State(st): State<AppState>) -> Result<Json<Value>> {
    let (contributed, used): (i64, i64) =
        sqlx::query_as("SELECT contributed_bytes, used_bytes FROM p2pnas.node_local WHERE id = 1")
            .fetch_one(&st.db)
            .await?;
    let peers: i64 = sqlx::query_scalar("SELECT count(*) FROM p2pnas.peers")
        .fetch_one(&st.db)
        .await?;

    Ok(Json(json!({
        "module":  "p2pnas",
        "version": env!("CARGO_PKG_VERSION"),
        "node": {
            "contributed_bytes": contributed,
            "used_bytes":        used,
            "available_bytes":   (contributed - used).max(0),
        },
        "peers": peers,
        "erasure": { "data_shards": erasure::DATA_SHARDS, "parity_shards": erasure::PARITY_SHARDS },
    })))
}
