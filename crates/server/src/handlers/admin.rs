use axum::{
    body::Bytes,
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use kubuno_db::dialect::Backend;
use kubuno_db::params;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    errors::{P2pError, Result},
    manifest_backup, repair,
    state::AppState,
};

#[derive(Deserialize)]
pub struct BackupParams {
    pub passphrase: String,
}

/// `GET /admin/backup?passphrase=…` — download an encrypted cold-storage bundle
/// {identity + manifest snapshot}. The admin keeps it OFF the node; it is the
/// only thing that can bring a dead node back, so the response is never cached.
pub async fn backup_export(
    State(st): State<AppState>,
    Query(p): Query<BackupParams>,
) -> Result<Response> {
    let data_dir = std::path::PathBuf::from(&st.settings.storage.data_dir);
    let (man, pass) = (st.manifest.clone(), p.passphrase);
    let blob = tokio::task::spawn_blocking(move || p2pnas_store::backup::export(&data_dir, &man, &pass))
        .await
        .map_err(|_| P2pError::BadRequest("backup task failed".into()))?
        .map_err(|e| P2pError::BadRequest(e.to_string()))?;

    let filename = format!("p2pnas-backup-{}.kbbak", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        blob,
    )
        .into_response())
}

/// `POST /admin/restore?passphrase=…` with the bundle as the raw request body —
/// recover onto a FRESH node. Refuses if this node already holds data. The module
/// must be restarted afterwards to load the restored identity and manifest.
pub async fn backup_restore(
    State(st): State<AppState>,
    Query(p): Query<BackupParams>,
    body: Bytes,
) -> Result<Json<Value>> {
    let data_dir = std::path::PathBuf::from(&st.settings.storage.data_dir);
    let (man, pass, blob) = (st.manifest.clone(), p.passphrase, body.to_vec());
    tokio::task::spawn_blocking(move || p2pnas_store::backup::import(&data_dir, &man, &pass, &blob))
        .await
        .map_err(|_| P2pError::BadRequest("restore task failed".into()))?
        .map_err(|e| P2pError::BadRequest(e.to_string()))?;

    Ok(Json(json!({
        "restored": true,
        "note": "restart the p2pnas module to load the restored identity and manifest, then run a repair"
    })))
}

/// `GET /admin/manifest-backup` — state of the AUTOMATIC distributed backup: the
/// versions this node believes it has pushed onto its peers, most recent first.
///
/// Informational only. The restore never trusts this list — it re-derives the
/// fragment ids and asks the peers — but it is what tells an administrator, at a
/// glance, whether the safety net is actually being woven.
pub async fn manifest_backup_status(State(st): State<AppState>) -> Result<Json<Value>> {
    Ok(Json(json!({
        "current_version": p2pnas_store::backup::manifest_backup_version_now(),
        "recent": manifest_backup::recorded_versions(&st, 20).await,
    })))
}

/// `POST /admin/manifest-backup` — run the distributed backup now instead of
/// waiting for the daily ticker. Enqueued rather than executed inline: vacuuming
/// and uploading a large manifest is not something to hold an HTTP request open
/// for, and the job kind coalesces so a double click costs nothing.
pub async fn manifest_backup_now(State(st): State<AppState>) -> Result<Json<Value>> {
    crate::jobs::enqueue(&st.db, "manifest_backup", json!({ "reason": "manual" })).await;
    Ok(Json(json!({ "enqueued": "manifest_backup" })))
}

#[derive(Deserialize, Default)]
pub struct ManifestRestoreBody {
    /// Peer addresses (`ip:port`) to interrogate, merged with `p2pnas.peers`.
    ///
    /// Required when the control-plane database went down with the node: without
    /// at least one peer there is nobody to ask, whatever the node key can
    /// compute. They are ordinary public addresses — nothing secret to keep.
    #[serde(default)]
    pub peers:         Vec<String>,
    /// Restore one specific day number instead of the most recent recoverable
    /// one (used to step back past a manifest that was already damaged).
    #[serde(default)]
    pub version:       Option<u64>,
    /// How many days back to scan when `version` is absent.
    #[serde(default)]
    pub lookback_days: Option<u64>,
}

/// `POST /admin/manifest-backup/restore` — rebuild `manifest.db` from the shards
/// held by the peers, on a fresh node that has `identity.key` back.
///
/// Refuses on a node that already holds files. Runs inline: the administrator is
/// waiting on the answer, and a restore happens once in a node's life.
pub async fn manifest_backup_restore(
    State(st): State<AppState>,
    body: Bytes,
) -> Result<Json<Value>> {
    // Taken as raw bytes rather than `Json<…>` so an EMPTY post is legitimate: on
    // a node whose control plane survived, the peer table alone is enough to find
    // the shards, and there is nothing for the administrator to type.
    let params: ManifestRestoreBody = if body.is_empty() {
        ManifestRestoreBody::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| P2pError::BadRequest(format!("corps JSON invalide: {e}")))?
    };
    let out = manifest_backup::restore(&st, &params.peers, params.version, params.lookback_days).await?;
    let out = serde_json::to_value(&out).unwrap_or_default();
    Ok(Json(json!({
        "restored": out,
        "note": "restart the p2pnas module to reopen the restored manifest, then run a repair"
    })))
}

/// List every user's quota (admin only).
pub async fn list_quotas(State(st): State<AppState>) -> Result<Json<Value>> {
    let rows: Vec<(Uuid, i64, i64)> = st
        .db
        .fetch_all_as(
            "SELECT user_id, quota_bytes, used_bytes FROM p2pnas.user_quota ORDER BY user_id",
            params![],
        )
        .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, quota, used)| {
            json!({
                "user_id": user_id,
                "quota_bytes": quota,
                "used_bytes": used,
                "available_bytes": (quota - used).max(0),
            })
        })
        .collect();
    Ok(Json(json!({ "quotas": items })))
}

#[derive(Deserialize)]
pub struct SetQuota {
    pub user_id:     Uuid,
    pub quota_bytes: i64,
}

/// Set a user's quota (admin only). Enforces that the sum of all user quotas
/// never exceeds the node's contributed capacity.
pub async fn set_quota(State(st): State<AppState>, Json(body): Json<SetQuota>) -> Result<Json<Value>> {
    if body.quota_bytes < 0 {
        return Err(P2pError::BadRequest("quota_bytes must be ≥ 0".into()));
    }

    let be = st.db.backend();
    let now = be.now();
    let contributed: i64 = st
        .db
        .fetch_scalar("SELECT contributed_bytes FROM p2pnas.node_local WHERE id = 1", params![])
        .await?;
    let others: i64 = st
        .db
        .fetch_scalar(
            &format!(
                "SELECT {} FROM p2pnas.user_quota WHERE user_id <> $1",
                be.sum_bigint("quota_bytes")
            ),
            params![body.user_id],
        )
        .await?;

    if others + body.quota_bytes > contributed {
        return Err(P2pError::BadRequest(format!(
            "allocation exceeds node capacity: {} + {} > {} bytes",
            others, body.quota_bytes, contributed
        )));
    }

    // `updated_at` is set both on insert and in the conflict branch; the upsert
    // helper's `Expr` splices the engine's now() there.
    let upsert = be.upsert(
        "p2pnas.user_quota",
        &["user_id"],
        &[
            kubuno_db::dialect::Assign::Incoming("quota_bytes"),
            kubuno_db::dialect::Assign::Expr { col: "updated_at", expr: now },
        ],
    );
    st.db
        .execute(
            &format!(
                "INSERT INTO p2pnas.user_quota (user_id, quota_bytes, updated_at)
                 VALUES ($1, $2, {now}){upsert}"
            ),
            params![body.user_id, body.quota_bytes],
        )
        .await?;

    Ok(Json(json!({ "user_id": body.user_id, "quota_bytes": body.quota_bytes })))
}

#[derive(Deserialize)]
pub struct SetContribution {
    pub bytes: i64,
}

/// Set the storage this node contributes to the network (admin only). Cannot drop
/// below what is already used or already allocated to users.
pub async fn set_contribution(State(st): State<AppState>, Json(body): Json<SetContribution>) -> Result<Json<Value>> {
    if body.bytes < 0 {
        return Err(P2pError::BadRequest("bytes must be ≥ 0".into()));
    }
    let be = st.db.backend();
    let now = be.now();
    let used: i64 = st
        .db
        .fetch_scalar("SELECT used_bytes FROM p2pnas.node_local WHERE id = 1", params![])
        .await?;
    let allocated: i64 = st
        .db
        .fetch_scalar(
            &format!("SELECT {} FROM p2pnas.user_quota", be.sum_bigint("quota_bytes")),
            params![],
        )
        .await?;
    if body.bytes < used || body.bytes < allocated {
        return Err(P2pError::BadRequest(format!(
            "contribution {} below used {} or allocated {} bytes",
            body.bytes, used, allocated
        )));
    }
    st.db
        .execute(
            &format!("UPDATE p2pnas.node_local SET contributed_bytes = $1, updated_at = {now} WHERE id = 1"),
            params![body.bytes],
        )
        .await?;
    Ok(Json(json!({ "contributed_bytes": body.bytes })))
}

#[derive(Deserialize)]
pub struct AddPeer {
    pub addr: String,
    /// Register a known peer that may be offline right now (no handshake): the
    /// admin supplies its peer_id. It starts `down` and is promoted to `active`
    /// once it answers a liveness probe.
    #[serde(default)]
    pub peer_id: Option<String>,
    /// Extra days of retention this node grants THIS peer on top of the instance
    /// policy — how generous we choose to be with someone we know (a machine we
    /// know is often powered off, say). Omitted leaves the current value; posting
    /// the same peer again is how an operator adjusts it.
    #[serde(default)]
    pub threshold_days: Option<i32>,
}

/// Add a trusted peer (admin only). By default it handshakes the peer over P2P
/// and records the id it reports; with an explicit `peer_id` it registers the
/// peer without requiring it to be online.
pub async fn add_peer(State(st): State<AppState>, Json(body): Json<AddPeer>) -> Result<Json<Value>> {
    let addr = body.addr.trim().to_string();
    if addr.is_empty() {
        return Err(P2pError::BadRequest("addr requis (ip:port)".into()));
    }

    // `handshake_verified` rather than `handshake`: a peer added by hand is exactly
    // the one whose key we most want pinned, and pinning only happens on a
    // handshake WE initiate. A peer too old to prove itself still registers, with
    // no key — it simply stays unpinned until it can.
    let (peer_id, api_port, status, public_key) =
        match body.peer_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            // Offline registration: no handshake, so nothing to prove yet.
            Some(pid) => (pid.to_string(), 0u16, "down", None),
            None => {
                let peer = p2pnas_p2p::handshake_verified(&addr, &st.identity.peer_id, st.settings.server.port)
                    .await
                    .map_err(|e| P2pError::BadRequest(format!("handshake échoué: {e}")))?;
                (peer.peer_id, peer.api_port, "active", peer.public_key)
            }
        };

    // Generosity is clamped to a sane range: it may only ever ADD retention time,
    // and a decade is well past any plausible intent.
    let generosity = body.threshold_days.map(|d| d.clamp(0, 3650));

    // Same hijack guard as discovery, done here as a portable read-modify-write
    // (the conditional upsert it replaces is PostgreSQL-only): an update is refused
    // if a different key is already pinned for this peer_id. `COALESCE` on the key
    // means a peer that could not prove itself never erases a key we already trust.
    let be = st.db.backend();
    let now = be.now();
    let lock = if be == Backend::Sqlite { "" } else { " FOR UPDATE" };
    let key = public_key.as_deref();

    let applied = async {
        let mut tx = st.db.begin().await?;
        let existing: Option<Option<String>> = tx
            .fetch_optional_row(
                &format!("SELECT public_key FROM p2pnas.peers WHERE peer_id = $1{lock}"),
                params![&peer_id],
            )
            .await?
            .map(|r| r.try_get::<Option<String>>("public_key"))
            .transpose()?;

        let applied = match existing {
            None => {
                tx.execute(
                    &format!(
                        "INSERT INTO p2pnas.peers
                             (peer_id, addr, status, last_seen, threshold_days, public_key, verified_at)
                         VALUES ($1, $2, $3, {now}, COALESCE($4, 7), $5,
                                 CASE WHEN $6 IS NULL THEN NULL ELSE {now} END)"
                    ),
                    params![&peer_id, &addr, status, generosity, key, key],
                )
                .await?;
                true
            }
            Some(pinned) => {
                let allowed = pinned.is_none() || pinned.as_deref() == key;
                if allowed {
                    tx.execute(
                        &format!(
                            "UPDATE p2pnas.peers SET
                                 addr = $1,
                                 last_seen = {now},
                                 threshold_days = COALESCE($2, threshold_days),
                                 public_key = COALESCE(public_key, $3),
                                 verified_at = CASE WHEN $4 IS NULL THEN verified_at ELSE {now} END
                             WHERE peer_id = $5"
                        ),
                        params![&addr, generosity, key, key, &peer_id],
                    )
                    .await?;
                }
                allowed
            }
        };
        tx.commit().await?;
        Ok::<bool, sqlx::Error>(applied)
    }
    .await?;

    if !applied {
        tracing::warn!(peer_id, addr, "add_peer refused: a different public key is pinned for this peer");
        return Err(P2pError::BadRequest(
            "ce pair est déjà enregistré avec une autre clé publique — vérifiez l'adresse".into(),
        ));
    }

    Ok(Json(json!({
        "peer_id": peer_id, "addr": addr, "api_port": api_port, "status": status,
        "threshold_days": generosity, "proven": public_key.is_some(),
    })))
}

/// Trigger a node-wide self-healing repair pass (admin only): probe peer
/// liveness, then re-replicate any shard whose host has gone unreachable.
pub async fn run_repair(State(st): State<AppState>) -> Result<Json<Value>> {
    let report = repair::repair_all(&st).await;
    let report = serde_json::to_value(&report).unwrap_or_default();
    Ok(Json(json!({ "repair": report })))
}

/// Enqueue a locality rebalance (admin only) — heals losses, then re-homes shards
/// toward the latency-optimal layout. Non-blocking; the worker runs it.
pub async fn rebalance(State(st): State<AppState>) -> Result<Json<Value>> {
    crate::jobs::enqueue(&st.db, "rebalance_locality", json!({ "reason": "manual" })).await;
    Ok(Json(json!({ "enqueued": "rebalance_locality" })))
}

/// Node metrics (admin only): storage, peers, jobs, discovery, data-loss risk.
pub async fn metrics(State(st): State<AppState>) -> Result<Json<Value>> {
    let be = st.db.backend();
    let (contributed, used, hosted): (i64, i64, i64) = st
        .db
        .fetch_one_as(
            "SELECT contributed_bytes, used_bytes, hosted_bytes FROM p2pnas.node_local WHERE id = 1",
            params![],
        )
        .await
        .unwrap_or((0, 0, 0));
    let (public_ip, country): (Option<String>, Option<String>) = st
        .db
        .fetch_one_as("SELECT public_ip, country FROM p2pnas.node_local WHERE id = 1", params![])
        .await
        .unwrap_or((None, None));
    // `COUNT(*) FILTER (WHERE …)` is PostgreSQL-only; the portable form counts a
    // conditional 1/0 with SUM, cast to bigint by `sum_bigint`.
    let (peers_total, peers_active, peers_down): (i64, i64, i64) = st
        .db
        .fetch_one_as(
            &format!(
                "SELECT {}, {}, {} FROM p2pnas.peers",
                be.count_bigint("*"),
                be.sum_bigint("CASE WHEN status = 'active' THEN 1 ELSE 0 END"),
                be.sum_bigint("CASE WHEN status = 'down' THEN 1 ELSE 0 END"),
            ),
            params![],
        )
        .await
        .unwrap_or((0, 0, 0));
    let hosted_shards: i64 = st
        .db
        .fetch_scalar(
            &format!("SELECT {} FROM p2pnas.hosted_shards", be.count_bigint("*")),
            params![],
        )
        .await
        .unwrap_or(0);
    let (jobs_pending, jobs_running): (i64, i64) = st
        .db
        .fetch_one_as(
            &format!(
                "SELECT {}, {} FROM p2pnas.jobs",
                be.sum_bigint("CASE WHEN state = 'pending' THEN 1 ELSE 0 END"),
                be.sum_bigint("CASE WHEN state = 'running' THEN 1 ELSE 0 END"),
            ),
            params![],
        )
        .await
        .unwrap_or((0, 0));
    let unrepairable: i64 = st
        .db
        .fetch_scalar(
            &format!(
                "SELECT {} FROM p2pnas.events WHERE kind = 'chunk_unrepairable'",
                be.count_bigint("*")
            ),
            params![],
        )
        .await
        .unwrap_or(0);

    let man = st.manifest.clone();
    let (files, chunks, stored) = tokio::task::spawn_blocking(move || p2pnas_store::service::node_stats(&man))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or((0, 0, 0));

    Ok(Json(json!({
        "node": {
            "contributed_bytes": contributed, "used_bytes": used, "hosted_bytes": hosted,
            "available_bytes": (contributed - used - hosted).max(0),
            "public_ip": public_ip, "country": country,
        },
        "storage": { "files": files, "chunks": chunks, "stored_bytes": stored, "hosted_shards": hosted_shards },
        "peers": { "total": peers_total, "active": peers_active, "down": peers_down },
        "jobs": { "pending": jobs_pending, "running": jobs_running },
        "discovery": { "mdns": st.settings.discovery.mdns, "dht": st.settings.discovery.dht },
        "risk": { "unrepairable_events": unrepairable },
    })))
}

/// Forget a peer (admin only). Shards currently hosted there stay referenced in
/// the manifest until a repair pass relocates them; removing an unreachable peer
/// lets the next pass treat its shards as lost and re-replicate them.
pub async fn remove_peer(
    State(st): State<AppState>,
    axum::extract::Path(peer_id): axum::extract::Path<String>,
) -> Result<Json<Value>> {
    let n = st
        .db
        .execute("DELETE FROM p2pnas.peers WHERE peer_id = $1", params![&peer_id])
        .await?;
    Ok(Json(json!({ "removed": peer_id, "found": n > 0 })))
}

/// List trusted peers (admin only).
pub async fn list_peers(State(st): State<AppState>) -> Result<Json<Value>> {
    type Row = (String, String, f64, i64, Option<chrono::DateTime<chrono::Utc>>, Option<f64>, Option<String>, i32);
    let rows: Vec<Row> = st
        .db
        .fetch_all_as(
            "SELECT peer_id, addr, reliability_score, contributed_bytes, last_seen, rtt_ms, country, threshold_days
             FROM p2pnas.peers ORDER BY reliability_score DESC, peer_id",
            params![],
        )
        .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|(peer_id, addr, score, contributed, last_seen, rtt_ms, country, threshold_days)| {
            json!({
                "peer_id": peer_id,
                "addr": addr,
                "reliability_score": score,
                "contributed_bytes": contributed,
                "last_seen": last_seen.map(|t| t.to_rfc3339()),
                "rtt_ms": rtt_ms,
                "country": country,
                // Extra retention days this node grants that peer (see `retention`).
                "threshold_days": threshold_days,
            })
        })
        .collect();
    Ok(Json(json!({ "peers": items })))
}

/// Recent control-plane events (admin only): repair / data-loss-risk notices.
pub async fn list_events(State(st): State<AppState>) -> Result<Json<Value>> {
    type Row = (i64, String, Value, chrono::DateTime<chrono::Utc>);
    let rows: Vec<Row> = st
        .db
        .fetch_all_as(
            "SELECT id, kind, payload, created_at FROM p2pnas.events ORDER BY id DESC LIMIT 50",
            params![],
        )
        .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|(id, kind, payload, created_at)| {
            json!({ "id": id, "kind": kind, "payload": payload, "created_at": created_at.to_rfc3339() })
        })
        .collect();
    Ok(Json(json!({ "events": items })))
}
