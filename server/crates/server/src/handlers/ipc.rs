use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::{events, state::AppState};

/// Core → module event delivery (`POST /ipc/events`, internal secret only).
///
/// Always answers `{"ok": true}`: the sender is a fan-out loop, not a user, and
/// an event this module does not subscribe to is not a failure it should retry.
/// What the module DOES act on is logged by the handler that acts on it.
pub async fn ingest(State(st): State<AppState>, Json(body): Json<Value>) -> Json<Value> {
    match serde_json::from_value::<events::P2pnasEvent>(body) {
        Ok(event) => events::handle(event, &st).await,
        // Not a failure: the core may broadcast types p2pnas never asked for.
        Err(e) => tracing::debug!(error = %e, "événement IPC ignoré (type non souscrit)"),
    }
    Json(json!({ "ok": true }))
}
