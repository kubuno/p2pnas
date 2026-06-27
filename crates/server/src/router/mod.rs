use axum::{middleware, routing::get, Router};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    handlers::{admin, health, quota, status},
    middleware::{require_admin, require_auth},
    state::AppState,
};

pub fn build(state: AppState) -> Router {
    // Admin-only routes (gated after auth by `require_admin`).
    let admin_routes = Router::new()
        .route("/admin/quotas", get(admin::list_quotas).post(admin::set_quota))
        .route("/admin/peers", get(admin::list_peers))
        .route_layer(middleware::from_fn(require_admin));

    // Authenticated routes (the core proxy injects the user headers).
    let authed = Router::new()
        .route("/status", get(status::status))
        .route("/quota/me", get(quota::me))
        .merge(admin_routes)
        .route_layer(middleware::from_fn(require_auth))
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
