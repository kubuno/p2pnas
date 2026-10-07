/// The module's database namespace: a PostgreSQL schema, a MySQL database, or the
/// ATTACHed SQLite file — kubuno-db makes `p2pnas.<table>` resolve on all three.
pub const SCHEMA: &str = "p2pnas";

/// The engine's spelling of a two-argument "largest of" — `GREATEST(x, 0)` on
/// PostgreSQL/MySQL, `MAX(x, 0)` on SQLite (which has no `GREATEST`). Used to keep
/// the byte counters from ever going negative, in one placeholder.
pub fn greatest(backend: kubuno_db::dialect::Backend) -> &'static str {
    match backend {
        kubuno_db::dialect::Backend::Sqlite => "MAX",
        _ => "GREATEST",
    }
}

/// The engine's spelling of a two-argument "smallest of" — `LEAST(x, y)` on
/// PostgreSQL/MySQL, `MIN(x, y)` on SQLite. The counterpart of [`greatest`].
pub fn least(backend: kubuno_db::dialect::Backend) -> &'static str {
    match backend {
        kubuno_db::dialect::Backend::Sqlite => "MIN",
        _ => "LEAST",
    }
}

pub mod config;
pub mod discovery;
pub mod errors;
pub mod events;
pub mod handlers;
pub mod jobs;
pub mod manifest_backup;
pub mod maps_geoip;
pub mod middleware;
pub mod p2p;
pub mod placement;
pub mod quotas;
pub mod rebalance;
pub mod repair;
pub mod retention;
pub mod router;
pub mod state;
