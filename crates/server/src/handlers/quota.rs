use axum::{extract::State, Extension, Json};
use serde_json::{json, Value};

use crate::{errors::Result, middleware::P2pUser, state::AppState};

/// The calling user's own "My Cloud" quota.
pub async fn me(State(st): State<AppState>, Extension(user): Extension<P2pUser>) -> Result<Json<Value>> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT quota_bytes, used_bytes FROM p2pnas.user_quota WHERE user_id = $1")
            .bind(user.id)
            .fetch_optional(&st.db)
            .await?;
    let (quota, used) = row.unwrap_or((0, 0));

    Ok(Json(json!({
        "user_id":         user.id,
        "quota_bytes":     quota,
        "used_bytes":      used,
        "available_bytes": (quota - used).max(0),
    })))
}
