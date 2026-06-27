use anyhow::{Context, Result};
use clap::Parser;
use kubuno_p2pnas::{config::Settings, router, state::AppState};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;

// Per-thread-heap allocator for the whole module: the data-parallel crypto/erasure
// pipeline (rayon) is allocation-heavy, and glibc's arena/mmap contention otherwise
// makes parallel processing *slower* than sequential on memory-bound (incompressible)
// data. See BENCHMARKS.md.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const MODULE_ID: &str = "p2pnas";

// ── module.toml ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Manifest {
    module:        ManifestModule,
    #[serde(default)]
    sidebar_items: Vec<SidebarItemRaw>,
    events:        Option<ManifestEvents>,
}

#[derive(Deserialize)]
struct ManifestModule {
    display_name:  String,
    description:   Option<String>,
    settings_path: Option<String>,
}

#[derive(Deserialize)]
struct SidebarItemRaw {
    id:       String,
    label:    String,
    icon:     String,
    path:     String,
    position: i32,
}

#[derive(Deserialize)]
struct ManifestEvents {
    #[serde(default)]
    subscribed: Vec<String>,
}

fn load_manifest() -> Option<Manifest> {
    let path = if let Ok(dir) = std::env::var("KUBUNO_MODULE_DIR") {
        std::path::PathBuf::from(dir).join("module.toml")
    } else {
        std::env::current_exe().ok()?.parent()?.join("module.toml")
    };
    let content = std::fs::read_to_string(&path)
        .map_err(|e| tracing::warn!(path = %path.display(), error = %e, "module.toml introuvable"))
        .ok()?;
    toml::from_str::<Manifest>(&content)
        .map_err(|e| tracing::error!(path = %path.display(), error = %e, "module.toml invalide"))
        .ok()
}

#[derive(Parser, Debug)]
#[command(name = "kubuno-p2pnas", version, about = "Module p2pnas Kubuno")]
struct Cli {
    #[arg(short, long, env = "KP_CONFIG_FILE")]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    let _cli = Cli::parse();

    let settings = Settings::load().context("Chargement de la configuration")?;

    let subscriber = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&settings.logging.level)),
    );
    match settings.logging.format {
        kubuno_p2pnas::config::LogFormat::Json => subscriber.json().init(),
        kubuno_p2pnas::config::LogFormat::Pretty => subscriber.init(),
    }

    tracing::info!("Kubuno p2pnas v{} démarrage…", env!("CARGO_PKG_VERSION"));

    // Forbid any process execution on the host (kubuno-seccomp). p2pnas embeds the
    // P2P listener in-process and never spawns subprocesses.
    kubuno_seccomp::lock_down_process_execution(MODULE_ID);

    // PostgreSQL pool.
    let opts = settings.database.connect_options()?;
    let pool = PgPoolOptions::new()
        .max_connections(settings.database.max_connections)
        .min_connections(settings.database.min_connections)
        .acquire_timeout(settings.database.connect_timeout)
        .connect_with(opts)
        .await
        .context("Connexion PostgreSQL")?;

    if settings.database.run_migrations {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS p2pnas")
            .execute(&pool)
            .await
            .context("Création du schéma p2pnas")?;

        let migration_opts = settings
            .database
            .connect_options()?
            .options([("search_path", "p2pnas,public")]);
        let migration_pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(settings.database.connect_timeout)
            .connect_with(migration_opts)
            .await
            .context("Pool de migration")?;
        sqlx::migrate!("../../migrations")
            .run(&migration_pool)
            .await
            .context("Migrations")?;
    }

    // Storage layer: node identity (auto-generated key), SQLCipher manifest, shards.
    let data_dir = std::path::PathBuf::from(&settings.storage.data_dir);
    let identity = Arc::new(
        p2pnas_store::NodeIdentity::load_or_create(&data_dir.join("identity"))
            .context("Initialisation de l'identité du nœud")?,
    );
    let manifest = Arc::new(p2pnas_store::Manifest::new(
        data_dir.join("manifest.db"),
        identity.manifest_key_hex.clone(),
    ));
    let store = Arc::new(p2pnas_store::ChunkStore::new(data_dir.join("chunks")));

    let state = AppState {
        db:       pool,
        settings: Arc::new(settings.clone()),
        identity,
        manifest,
        store,
    };

    // Register with the core (infinite retry) + heartbeat every 30s.
    let http = Client::new();
    register_with_core(&http, &settings).await;
    {
        let http2 = http.clone();
        let settings2 = settings.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let url = format!("{}/internal/modules/{MODULE_ID}/heartbeat", settings2.core.url);
                match http2
                    .post(&url)
                    .header("X-Internal-Secret", settings2.core.internal_secret.as_str())
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => {}
                    Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                        tracing::info!("Heartbeat 404 — ré-enregistrement…");
                        register_with_core(&http2, &settings2).await;
                    }
                    Ok(r) if r.status() == reqwest::StatusCode::FORBIDDEN => {
                        tracing::info!("Heartbeat 403 — module désactivé, attente…");
                    }
                    Ok(r) => tracing::warn!(status = %r.status(), "Heartbeat réponse inattendue"),
                    Err(e) => tracing::warn!(error = %e, "Heartbeat erreur réseau"),
                }
            }
        });
    }

    let addr = format!("{}:{}", settings.server.host, settings.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Bind sur {addr}"))?;
    tracing::info!("Kubuno p2pnas démarré sur http://{addr}");

    // Record the node's stable peer id in the control plane — in the background, so
    // it never delays binding the port (avoids restart/bind races at startup).
    {
        let pool = state.db.clone();
        let peer_id = state.identity.peer_id.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE p2pnas.node_local SET peer_id = $1, updated_at = now() WHERE id = 1")
                .bind(peer_id)
                .execute(&pool)
                .await;
        });
    }

    axum::serve(
        listener,
        router::build(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .context("Erreur du serveur HTTP")?;

    Ok(())
}

fn backoff(attempt: u32) -> u64 {
    if attempt <= 10 {
        (attempt * 2) as u64
    } else {
        30
    }
}

async fn register_with_core(http: &Client, settings: &Settings) {
    let base_url = format!("http://{}:{}", settings.server.host, settings.server.port);
    let core_url = &settings.core.url;
    let secret = &settings.core.internal_secret;

    let manifest = load_manifest();
    let display_name = manifest.as_ref().map(|m| m.module.display_name.as_str()).unwrap_or("My Cloud").to_string();
    let description = manifest.as_ref().and_then(|m| m.module.description.clone());
    let settings_path = manifest.as_ref().and_then(|m| m.module.settings_path.clone());
    let sidebar_items: Vec<Value> = manifest
        .as_ref()
        .map(|m| {
            m.sidebar_items
                .iter()
                .map(|s| json!({ "id": s.id, "label": s.label, "icon": s.icon, "path": s.path, "position": s.position }))
                .collect()
        })
        .unwrap_or_else(|| vec![json!({ "id": "p2pnas", "label": "My Cloud", "icon": "Cloud", "path": "/p2pnas", "position": 12 })]);
    let subscribed_events: Vec<String> = manifest
        .as_ref()
        .and_then(|m| m.events.as_ref())
        .map(|e| e.subscribed.clone())
        .unwrap_or_else(|| vec!["UserDeleted".into()]);

    let payload = json!({
        "module_id":         MODULE_ID,
        "display_name":      display_name,
        "description":       description,
        "settings_path":     settings_path,
        "base_url":          base_url,
        "version":           env!("CARGO_PKG_VERSION"),
        "routes":            [{ "method": "*", "path": "/*" }],
        "sidebar_items":     sidebar_items,
        "subscribed_events": subscribed_events,
        "mcp_tools":         json!([]),
    });

    for attempt in 1u32.. {
        let url = format!("{core_url}/internal/modules/register");
        match http.post(&url).header("X-Internal-Secret", secret.as_str()).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("Module p2pnas enregistré auprès du core");
                return;
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                tracing::info!(attempt, "Module désactivé par l'admin, nouvel essai dans 30s…");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            Ok(resp) => {
                let wait = backoff(attempt);
                tracing::warn!(attempt, status = %resp.status(), "Enregistrement échoué, retry dans {wait}s…");
                tokio::time::sleep(Duration::from_secs(wait)).await;
            }
            Err(e) => {
                let wait = backoff(attempt);
                tracing::warn!(attempt, error = %e, "Core inaccessible, retry dans {wait}s…");
                tokio::time::sleep(Duration::from_secs(wait)).await;
            }
        }
    }
}
