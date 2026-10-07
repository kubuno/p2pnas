use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;

use crate::{
    handlers::{admin, files, health, ipc, quota, status},
    middleware::{require_admin, require_auth, require_ipc_secret},
    state::AppState,
};

// Transport ceiling of the `Bytes` extractor (its own default is only 2 MiB).
// This is NOT the administrable limit: it is fixed at router construction, so it
// is deliberately set to the highest value the instance setting may take
// (`max_upload_bytes`, capped at 2 GiB by `config::instance`). The limit an
// administrator actually sets is enforced per request in `handlers::files::upload`
// and therefore takes effect without restarting the module.
const MAX_UPLOAD: usize = 2 * 1024 * 1024 * 1024; // 2 GiB

pub fn build(state: AppState) -> Router {
    // Admin-only routes (gated after auth by `require_admin`).
    let admin_routes = Router::new()
        .route("/admin/quotas", get(admin::list_quotas).post(admin::set_quota))
        .route("/admin/contribution", post(admin::set_contribution))
        .route("/admin/peers", get(admin::list_peers).post(admin::add_peer))
        .route("/admin/peers/:peer_id", axum::routing::delete(admin::remove_peer))
        .route("/admin/repair", post(admin::run_repair))
        .route("/admin/events", get(admin::list_events))
        .route("/admin/metrics", get(admin::metrics))
        .route("/admin/rebalance", post(admin::rebalance))
        .route("/admin/retention/purge", post(files::run_retention_purge))
        // Distributed backup of the manifest: its state, an on-demand run, and the
        // recovery that rebuilds it from the peers on a machine that only has the
        // node key back.
        .route("/admin/manifest-backup", get(admin::manifest_backup_status).post(admin::manifest_backup_now))
        .route("/admin/manifest-backup/restore", post(admin::manifest_backup_restore))
        // Small-file packing: regroup tiny files into ~1 MiB containers, and
        // compact containers gone mostly-dead. Both are also on a background timer.
        .route("/admin/repack/run", post(files::run_repack))
        .route("/admin/packs/compact", post(files::run_pack_compaction))
        .route("/admin/backup", get(admin::backup_export))
        .route("/admin/restore", post(admin::backup_restore))
        .route_layer(middleware::from_fn(require_admin));

    // Authenticated routes (the core proxy injects the user headers).
    let authed = Router::new()
        .route("/status", get(status::status))
        .route("/quota/me", get(quota::me))
        .route("/files", get(files::list).post(files::upload))
        .route("/files/:id", get(files::download).delete(files::delete))
        .route("/files/:id/health", get(files::file_health))
        .route("/files/:id/placement", get(files::file_placement))
        // Folder-aware "My Cloud" mount (path-based, parity with Drive).
        .route("/browse", get(files::browse))
        .route("/download", get(files::download_path))
        .route("/folders", post(files::mkdir))
        .route("/rename", post(files::rename))
        .route("/delete", post(files::delete_path))
        // Trash & versions: deleting is now reversible, and an overwrite keeps the
        // version it replaced. `/trash/restore` also restores a past version —
        // it is the same operation on a retired row.
        .route("/trash", get(files::trash_list))
        .route("/trash/restore", post(files::restore))
        .route("/trash/purge", post(files::purge))
        .route("/trash/empty", post(files::empty_trash))
        .route("/files/:id/versions", get(files::versions))
        .merge(admin_routes)
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD))
        .with_state(state.clone());

    // Core → module IPC: no user, gated by the shared internal secret alone.
    let ipc_routes = Router::new()
        .route("/ipc/events", post(ipc::ingest))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_ipc_secret))
        .with_state(state.clone());

    // Public health check.
    let system = Router::new()
        .route("/health", get(health::health))
        .with_state(state);

    // No CORS layer on purpose. This module listens on loopback and is never called
    // by a browser: the frontend talks to the core, which proxies to us server-side
    // and owns the browser-facing CORS policy. The `CorsLayer::permissive()` that
    // used to wrap the whole router therefore protected nothing while advertising
    // `Access-Control-Allow-Origin: *` with any method and any header on every
    // route — admin ones included — and answering their preflights. If the port
    // ever became reachable, that is a standing invitation for a hostile page to
    // read our responses. Any CORS added back belongs on a configured origin list,
    // not on `permissive()`.
    Router::new()
        .merge(system)
        .merge(ipc_routes)
        .merge(authed)
        .layer(TraceLayer::new_for_http())
}
