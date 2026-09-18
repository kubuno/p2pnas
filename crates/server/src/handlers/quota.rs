use axum::{extract::State, Extension, Json};
use serde_json::{json, Value};

use crate::{errors::Result, middleware::P2pUser, state::AppState};

/// The calling user's own "My Cloud" quota.
///
/// A read never allocates: an account with no row yet is told what the instance
/// default WOULD grant it (`provisional`), so the client shows the space uploads
/// will actually be allowed rather than a flat zero. The row itself is created by
/// the first upload — see `crate::quotas`.
pub async fn me(State(st): State<AppState>, Extension(user): Extension<P2pUser>) -> Result<Json<Value>> {
    let (quota, used, provisional) = crate::quotas::effective(&st, user.id).await?;

    Ok(Json(json!({
        "user_id":         user.id,
        "quota_bytes":     quota,
        "used_bytes":      used,
        "available_bytes": (quota - used).max(0),
        "provisional":     provisional,
    })))
}
