use anyhow::{Context, Result};
use clap::Parser;
use kubuno_p2pnas::{config::Settings, router, state::AppState, SCHEMA};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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
    /// Pages the admin panel is split into (`[[setting_groups]]`).
    #[serde(default)]
    setting_groups: Vec<SettingGroupRaw>,
    /// Instance-wide knobs the admin console renders (`[[settings]]`).
    #[serde(default)]
    settings:       Vec<SettingDefRaw>,
}

/// One `[[setting_groups]]` entry of module.toml, forwarded verbatim so the core
/// renders the admin sub-menus. `id` is a STABLE, UNTRANSLATED slug: it travels
/// in the URL of the admin page.
#[derive(Deserialize, Serialize)]
struct SettingGroupRaw {
    id:          String,
    label:       String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    icon:        Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    position:    Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

/// One `[[settings]]` entry of module.toml, forwarded verbatim: the core stores
/// the schema and the admin console renders it, so every knob p2pnas exposes is
/// described HERE and nowhere in the console's code.
///
/// Presentation metadata (`min`/`max`, `unit`, `multiline`, `advanced`, `risk`)
/// is optional and only serialised when the manifest sets it — an omitted field
/// must not reach the core as `null` and overwrite a sane default.
#[derive(Deserialize, Serialize)]
struct SettingDefRaw {
    key:         String,
    scope:       String,
    #[serde(rename = "type")]
    value_type:  String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    values:      Option<Value>,
    default:     Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label:       Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    category:    Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group:       Option<String>,
    #[serde(default)]
    public:      bool,
    #[serde(default)]
    advanced:    bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    risk:        Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    min:         Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max:         Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unit:        Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    placeholder: Option<String>,
    #[serde(default)]
    multiline:   bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    depends_on:  Option<String>,
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

    // Database pool. The engine (PostgreSQL / MySQL / SQLite) is the
    // administrator's choice in `[database] engine`, read at run time; `connect`
    // also creates the module's namespace (PostgreSQL schema, MySQL database, or
    // the ATTACHed SQLite file). Only the control plane lives here — the local
    // SQLCipher manifest is opened separately below and is untouched.
    let pool = kubuno_db::connect(&settings.database, SCHEMA)
        .await
        .context("Connexion à la base de données")?;

    // Migrations: the set for the pool's engine, kept inside the module's own
    // namespace (the schema PostgreSQL already used through its search_path).
    if settings.database.run_migrations {
        kubuno_db::migrations!(
            "../../migrations/postgres",
            "../../migrations/mysql",
            "../../migrations/sqlite",
        )
        .run(&pool, SCHEMA)
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

    let http = Client::new();

    // Instance settings start at the compiled defaults; the first read from the
    // core happens just after registration (the core only knows the schema once
    // the module has declared it).
    let instance = Arc::new(std::sync::RwLock::new(
        kubuno_p2pnas::config::instance::InstanceConfig::default(),
    ));

    let state = AppState {
        db:       pool,
        settings: Arc::new(settings.clone()),
        identity,
        manifest,
        store,
        http:     http.clone(),
        instance: instance.clone(),
    };

    // Register with the core (infinite retry) + heartbeat every 30s.
    register_with_core(&http, &settings).await;

    // First read of the administrator's values, now that the core has the schema:
    // the first upload and the first repair pass must already see them rather
    // than the compiled defaults. A failed read simply leaves the defaults, which
    // the refresher below will correct within a minute.
    if let Some(cfg) = kubuno_p2pnas::config::instance::fetch(
        &http,
        &settings.core.url,
        &settings.core.internal_secret,
    )
    .await
    {
        if let Ok(mut w) = instance.write() {
            *w = cfg;
        }
    }

    // Instance-settings refresher: an admin edit takes effect within a minute,
    // no restart. A failed read keeps the last good values.
    {
        let http_refresh     = http.clone();
        let settings_refresh = settings.clone();
        let instance_refresh = instance.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                if let Some(cfg) = kubuno_p2pnas::config::instance::fetch(
                    &http_refresh,
                    &settings_refresh.core.url,
                    &settings_refresh.core.internal_secret,
                )
                .await
                {
                    if let Ok(mut w) = instance_refresh.write() {
                        *w = cfg;
                    }
                }
            }
        });
    }

    // Heartbeat every 30s.
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
            let now = pool.backend().now();
            let _ = pool
                .execute(
                    &format!("UPDATE p2pnas.node_local SET peer_id = $1, updated_at = {now} WHERE id = 1"),
                    kubuno_db::params![peer_id],
                )
                .await;
        });
    }

    // Embedded P2P listener (separate port). seccomp only blocks execve, so
    // sockets are allowed; this peer hosts/serves shards for the network.
    {
        let p2p_addr = format!("{}:{}", settings.p2p.host, settings.p2p.port);
        match tokio::net::TcpListener::bind(&p2p_addr).await {
            Ok(p2p_listener) => {
                tracing::info!("Listener P2P p2pnas sur {p2p_addr}");
                let handler = std::sync::Arc::new(kubuno_p2pnas::p2p::P2pShardHandler {
                    peer_id:  state.identity.peer_id.clone(),
                    api_port: settings.server.port,
                    store:    state.store.clone(),
                    db:       state.db.clone(),
                    // Lets this node answer a peer's identity challenge. Without it
                    // we would demand proof from others while offering none.
                    signer:   kubuno_p2pnas::p2p::node_signer(&state.identity),
                });
                tokio::spawn(p2pnas_p2p::serve(p2p_listener, handler));
            }
            Err(e) => tracing::error!(error = %e, addr = %p2p_addr, "bind P2P échoué — pair en mode dégradé"),
        }
    }

    // Zero-config LAN discovery: announce + auto-add peers found via mDNS.
    if settings.discovery.mdns {
        let db = state.db.clone();
        let id = state.identity.clone();
        let (api_port, p2p_port) = (settings.server.port, settings.p2p.port);
        tokio::spawn(async move {
            kubuno_p2pnas::discovery::mdns::run(db, id, api_port, p2p_port).await;
        });
    }

    // Wide-area discovery: join the Kademlia DHT overlay and auto-add the peers
    // it surfaces. Off unless configured (needs bootstrap nodes to be useful).
    if settings.discovery.dht {
        let db = state.db.clone();
        let id = state.identity.clone();
        let (api_port, p2p_port) = (settings.server.port, settings.p2p.port);
        let bind_addr = format!("0.0.0.0:{}", settings.discovery.dht_port);
        let bootstrap = settings.discovery.dht_bootstrap.clone();
        let state_file = std::path::PathBuf::from(&settings.storage.data_dir).join("dht_nodes.json");
        tokio::spawn(async move {
            kubuno_p2pnas::discovery::dht::run(db, id, api_port, p2p_port, bind_addr, bootstrap, state_file).await;
        });
    }

    // Background job worker: processes repair jobs claimed with SKIP LOCKED.
    {
        let st = state.clone();
        tokio::spawn(async move { kubuno_p2pnas::jobs::worker(st).await });
    }

    // Periodic self-healing: enqueue a repair job (the worker runs it). Admin can
    // also trigger a pass on demand via POST /admin/repair.
    //
    // The delay is re-read at every iteration rather than baked into a fixed
    // `interval`: shortening it in the console must speed the next pass up, not
    // the one after a restart. A change therefore applies from the pass that
    // follows the edit — the sleep already under way is not interrupted.
    {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(st.instance().repair_interval_secs)).await;
                kubuno_p2pnas::jobs::enqueue(&st.db, "repair", serde_json::json!({})).await;
            }
        });
    }

    // Retention / reciprocity sweep: reclaim space from long-absent owners, in
    // graduated and reversible stages (see `retention`). Once a day is ample —
    // the thresholds are in days — and it runs off the same worker queue.
    {
        let st = state.clone();
        tokio::spawn(async move {
            const DAY: u64 = 24 * 60 * 60;
            loop {
                tokio::time::sleep(Duration::from_secs(DAY)).await;
                kubuno_p2pnas::jobs::enqueue(&st.db, "retention", serde_json::json!({})).await;
            }
        });
    }

    // Small-file packing + container compaction, every 6 hours. Repack first
    // (regroup new tiny files), then compact (reclaim containers the retention
    // sweep has hollowed out) — jobs coalesce, so this never piles up.
    {
        let st = state.clone();
        tokio::spawn(async move {
            const SIX_HOURS: u64 = 6 * 60 * 60;
            tokio::time::sleep(Duration::from_secs(600)).await;
            loop {
                kubuno_p2pnas::jobs::enqueue(&st.db, "repack_small", serde_json::json!({})).await;
                kubuno_p2pnas::jobs::enqueue(&st.db, "compact_packs", serde_json::json!({})).await;
                tokio::time::sleep(Duration::from_secs(SIX_HOURS)).await;
            }
        });
    }

    // Distributed manifest backup: once a day. The version IS a day number, so a
    // second pass on the same day is a no-op — and enqueuing BEFORE the sleep means
    // a node restarted every day still gets backed up.
    {
        let st = state.clone();
        tokio::spawn(async move {
            const DAY: u64 = 24 * 60 * 60;
            // Let the node probe its peers before the first snapshot.
            tokio::time::sleep(Duration::from_secs(300)).await;
            loop {
                kubuno_p2pnas::jobs::enqueue(&st.db, "manifest_backup", serde_json::json!({})).await;
                tokio::time::sleep(Duration::from_secs(DAY)).await;
            }
        });
    }

    // Trash / version retention: reclaim what has passed its window. Hourly is
    // ample (the windows are in days) and the job coalesces, so a slow sweep can
    // never pile up behind itself.
    {
        let st = state.clone();
        tokio::spawn(async move {
            const HOUR: u64 = 60 * 60;
            loop {
                tokio::time::sleep(Duration::from_secs(HOUR)).await;
                kubuno_p2pnas::jobs::enqueue(&st.db, "gc_trash", serde_json::json!({})).await;
            }
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

    // Admin surface. `setting_groups` are the pages of the sub-menu; `settings`
    // are the instance-wide knobs the core renders inside them. Live DATA (quotas
    // per user, peers, contribution, repair reports) is NOT a setting and stays in
    // the module's own React sections, which the console shows above the form.
    let setting_groups: Vec<Value> = manifest
        .as_ref()
        .map(|m| m.setting_groups.iter().map(|g| serde_json::to_value(g).unwrap_or(Value::Null)).collect())
        .unwrap_or_default();
    let settings_schema: Vec<Value> = manifest
        .as_ref()
        .map(|m| m.settings.iter().map(|s| serde_json::to_value(s).unwrap_or(Value::Null)).collect())
        .unwrap_or_default();

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
        "setting_groups":    setting_groups,
        // The core's registration DTO names this field `settings_schema`; the
        // manifest names the array `[[settings]]`. Same thing, two names.
        "settings_schema":   settings_schema,
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
