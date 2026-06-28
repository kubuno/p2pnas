use crate::config::Settings;
use p2pnas_store::{ChunkStore, Manifest, NodeIdentity};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db:       PgPool,
    pub settings: Arc<Settings>,
    pub identity: Arc<NodeIdentity>,
    pub manifest: Arc<Manifest>,
    pub store:    Arc<ChunkStore>,
    /// HTTP client for calling other modules (e.g. the maps GeoIP service) through
    /// the core proxy.
    pub http:     reqwest::Client,
}
