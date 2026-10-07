use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

/// The `[database]` section is owned by kubuno-db: which of its fields matter
/// depends on the engine the administrator picks at run time, and the pool is
/// opened by `kubuno_db::connect`.
pub use kubuno_db::DbSettings as DatabaseSettings;

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub server:   ServerSettings,
    pub core:     CoreSettings,
    pub database: DatabaseSettings,
    pub storage:   StorageSettings,
    pub p2p:       P2pSettings,
    pub discovery: DiscoverySettings,
    pub logging:   LoggingSettings,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoverySettings {
    /// Announce + browse `_p2pnas._tcp` on the LAN (zero-config peer discovery).
    pub mdns: bool,
    /// Wide-area discovery via the embedded Kademlia DHT.
    pub dht: bool,
    /// UDP port the DHT node binds (distinct from the TCP P2P port).
    pub dht_port: u16,
    /// Bootstrap nodes (`ip:udp_port`) to join the DHT overlay.
    #[serde(default)]
    pub dht_bootstrap: Vec<String>,
    /// If non-empty, shards may only be placed on peers in these ISO countries
    /// (jurisdiction constraint). Country is resolved via the maps GeoIP service.
    #[serde(default)]
    pub geoip_allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageSettings {
    /// Node data directory: identity key, SQLCipher manifest, local shard store.
    pub data_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct P2pSettings {
    /// Address the embedded P2P listener binds (separate from the HTTP port).
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
}

// `Debug` is implemented by hand for the two secret-bearing config structs
// rather than derived: a single `tracing::debug!(?settings)` or a `{:?}` in an
// error chain would otherwise spill `internal_secret` and the database password
// (and the DB URL, which embeds the password) into the logs. The redacting impls
// keep the rest of the fields visible for diagnostics.
#[derive(Clone, Deserialize)]
pub struct CoreSettings {
    pub url:             String,
    pub internal_secret: String,
}

impl std::fmt::Debug for CoreSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreSettings")
            .field("url", &self.url)
            .field("internal_secret", &"***")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingSettings {
    pub level:  String,
    pub format: LogFormat,
}

impl Settings {
    pub fn load() -> Result<Self, ConfigError> {
        let mut builder = Config::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 3123i64)?
            .set_default("core.url", "http://127.0.0.1:8080")?
            .set_default("core.internal_secret", "")?
            .set_default("database.max_connections", 10i64)?
            .set_default("database.min_connections", 1i64)?
            .set_default("database.connect_timeout", 10i64)?
            .set_default("database.run_migrations", true)?
            .set_default("database.engine", "postgres")?
            // SQLite only: directory holding `<schema>.sqlite`.
            .set_default("database.path", "./data/db")?
            .set_default("storage.data_dir", "/var/lib/kubuno/modules/p2pnas")?
            .set_default("p2p.host", "0.0.0.0")?
            .set_default("p2p.port", 7474i64)?
            .set_default("discovery.mdns", true)?
            .set_default("discovery.dht", false)?
            .set_default("discovery.dht_port", 7475i64)?
            .set_default("logging.level", "info")?
            .set_default("logging.format", "pretty")?
            .add_source(File::with_name("config").required(false))
            .add_source(File::with_name("/etc/kubuno/modules/p2pnas/config").required(false))
            .add_source(Environment::with_prefix("KP").separator("__").try_parsing(true));

        // Variables injected by the core supervisor — highest priority.
        if let Ok(v) = std::env::var("KUBUNO_CORE_URL")        { builder = builder.set_override("core.url",             v)?; }
        if let Ok(v) = std::env::var("KUBUNO_INTERNAL_SECRET") { builder = builder.set_override("core.internal_secret", v)?; }
        if let Ok(v) = std::env::var("KUBUNO_DB_HOST")         { builder = builder.set_override("database.host",     v)?; }
        if let Ok(v) = std::env::var("KUBUNO_DB_PORT")         { builder = builder.set_override("database.port",     v.parse::<i64>().unwrap_or(5432))?; }
        if let Ok(v) = std::env::var("KUBUNO_DB_USER")         { builder = builder.set_override("database.user",     v)?; }
        if let Ok(v) = std::env::var("KUBUNO_DB_PASSWORD")     { builder = builder.set_override("database.password", v)?; }
        if let Ok(v) = std::env::var("KUBUNO_DB_NAME")         { builder = builder.set_override("database.database", v)?; }
        if let Ok(v) = std::env::var("KUBUNO_DB_ENGINE")       { builder = builder.set_override("database.engine",   v)?; }
        if let Ok(v) = std::env::var("KUBUNO_DB_PATH")         { builder = builder.set_override("database.path",     v)?; }

        builder.build()?.try_deserialize()
    }
}
