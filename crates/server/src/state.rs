use crate::config::{instance::InstanceConfig, Settings};
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
    /// Instance settings from the admin console, refreshed in the background so
    /// an edit takes effect without restarting the module. A `std::sync` lock
    /// (not a `tokio` one) because callers read a snapshot synchronously; the
    /// critical section only clones a handful of fields.
    pub instance: Arc<std::sync::RwLock<InstanceConfig>>,
}

impl AppState {
    /// A snapshot of the current instance settings. Falls back to the compiled
    /// defaults if the lock was poisoned by a panicking writer — a lost value
    /// must never change a default silently.
    pub fn instance(&self) -> InstanceConfig {
        self.instance.read().map(|c| c.clone()).unwrap_or_default()
    }
}
