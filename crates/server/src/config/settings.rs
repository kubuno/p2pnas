use anyhow::Context;
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub server:   ServerSettings,
    pub core:     CoreSettings,
    pub database: DatabaseSettings,
    pub logging:  LoggingSettings,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CoreSettings {
    pub url:             String,
    pub internal_secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseSettings {
    pub url:             Option<String>,
    pub host:            Option<String>,
    pub port:            Option<u16>,
    pub user:            Option<String>,
    pub password:        Option<String>,
    pub database:        Option<String>,
    pub max_connections: u32,
    pub min_connections: u32,
    #[serde(with = "duration_secs")]
    pub connect_timeout: Duration,
    pub run_migrations:  bool,
}

impl DatabaseSettings {
    pub fn connect_options(&self) -> anyhow::Result<sqlx::postgres::PgConnectOptions> {
        use std::str::FromStr;
        // Explicit fields (injected by the supervisor via KUBUNO_DB_*) take priority.
        if self.host.is_some() || self.user.is_some() {
            let user     = self.user.as_deref().context("database.user requis")?;
            let password = self.password.as_deref().context("database.password requis")?;
            let database = self.database.as_deref().context("database.database requis")?;
            return Ok(sqlx::postgres::PgConnectOptions::new()
                .host(self.host.as_deref().unwrap_or("localhost"))
                .port(self.port.unwrap_or(5432))
                .username(user)
                .password(password)
                .database(database));
        }
        if let Some(url) = &self.url {
            return sqlx::postgres::PgConnectOptions::from_str(url).context("database.url invalide");
        }
        Err(anyhow::anyhow!("database : fournissez host/user/password/database"))
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
            .set_default("server.port", 3119i64)?
            .set_default("core.url", "http://127.0.0.1:8080")?
            .set_default("core.internal_secret", "")?
            .set_default("database.max_connections", 10i64)?
            .set_default("database.min_connections", 1i64)?
            .set_default("database.connect_timeout", 10i64)?
            .set_default("database.run_migrations", true)?
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

        builder.build()?.try_deserialize()
    }
}

mod duration_secs {
    use serde::{Deserialize, Deserializer};
    use std::time::Duration;
    pub fn deserialize<'de, D>(d: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}
