use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    handlers::{admin, files, health, quota, status},
    middleware::{require_admin, require_auth},
    state::AppState,
};

// Max upload size accepted by the `Bytes` extractor (default is only 2 MiB).
const MAX_UPLOAD: usize = 2 * 1024 * 1024 * 1024; // 2 GiB

pub fn build(state: AppState) -> Router {
    // Admin-only routes (gated after auth by `require_admin`).
    let admin_routes = Router::new()
        .route("/admin/quotas", get(admin::list_quotas).post(admin::set_quota))
        .route("/admin/contribution", post(admin::set_contribution))
        .route("/admin/peers", get(admin::list_peers).post(admin::add_peer))
        .route("/admin/peers/:peer_id", axum::routing::delete(admin::remove_peer))
        .route("/admin/repair", post(admin::run_repair))
        .route_layer(middleware::from_fn(require_admin));

    // Authenticated routes (the core proxy injects the user headers).
    let authed = Router::new()
        .route("/status", get(status::status))
        .route("/quota/me", get(quota::me))
        .route("/files", get(files::list).post(files::upload))
        .route("/files/:id", get(files::download).delete(files::delete))
        .merge(admin_routes)
        .route_layer(middleware::from_fn(require_auth))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD))
        .with_state(state.clone());

    // Public health check.
    let system = Router::new()
        .route("/health", get(health::health))
        .with_state(state);

    Router::new()
        .merge(system)
        .merge(authed)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}
