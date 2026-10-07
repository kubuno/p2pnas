//! Core → module event ingestion.
//!
//! `module.toml` has declared a subscription to `UserDeleted` since the module
//! existed, and the promise was never kept: there was no route to deliver it to,
//! so a removed account kept its `p2pnas.user_quota` row — and with it a slice of
//! the node's contributed capacity that `handlers::admin::set_quota` still
//! counted as allocated, forever. Deleting enough accounts would eventually make
//! the node refuse to allocate anything to anyone.
//!
//! The envelope is the core's `AppEvent`: `{"type": "...", "payload": {...}}`.
//! Only the events this module subscribes to are decoded; anything else is
//! ignored rather than refused, so the core may add event types without this
//! route starting to answer errors.

use kubuno_db::params;
use serde::Deserialize;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum P2pnasEvent {
    UserDeleted { user_id: Uuid },
}

pub async fn handle(event: P2pnasEvent, st: &AppState) {
    match event {
        P2pnasEvent::UserDeleted { user_id } => purge_user(st, user_id).await,
    }
}

/// Removes everything a deleted account still owns: its stored files (and the
/// local shards behind them), the node-level accounting they weighed on, and its
/// quota row.
///
/// Shards this node had pushed onto PEERS are not reclaimed here — a peer's store
/// is not ours to command, and the existing delete path has the same limit; they
/// become unreferenced fragments that the peer's own housekeeping collects.
///
/// Best effort throughout: one unreadable file must not leave the quota row
/// behind, since that row is what silently consumes the node's capacity.
async fn purge_user(st: &AppState, user_id: Uuid) {
    let (man, store, uid) = (st.manifest.clone(), st.store.clone(), user_id.to_string());

    // The manifest is SQLCipher (blocking), so the whole sweep runs off the
    // async runtime rather than one hop per file.
    let purge = tokio::task::spawn_blocking(move || {
        // `list_all_of_user`, not `list`: a deleted account must give back its
        // trash and superseded versions too, not only what is currently visible.
        let files = match p2pnas_store::service::list_all_of_user(&man, &uid) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, user_id = %uid, "purge p2pnas : lecture du manifeste impossible");
                return (0usize, 0i64, Vec::new());
            }
        };
        let (mut deleted, mut stored) = (0usize, 0i64);
        let mut remote: Vec<(String, String)> = Vec::new();
        for f in files {
            match p2pnas_store::service::purge_file(&man, &store, &uid, &f.file_id) {
                Ok((row, mut r)) => {
                    deleted += 1;
                    stored += row.stored_bytes;
                    remote.append(&mut r);
                }
                Err(e) => tracing::error!(
                    error = %e, user_id = %uid, file_id = %f.file_id,
                    "purge p2pnas : suppression de fichier impossible"
                ),
            }
        }
        (deleted, stored, remote)
    })
    .await;

    let (deleted, stored, remote) = match purge {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, %user_id, "purge p2pnas : tâche de suppression interrompue");
            (0, 0, Vec::new())
        }
    };

    // Free the deleted user's shards on the peers that host them too.
    if !remote.is_empty() {
        crate::jobs::enqueue(
            &st.db,
            "gc_remote",
            serde_json::json!({ "shards": remote, "attempt": 0 }),
        )
        .await;
    }

    let be = st.db.backend();
    let now = be.now();
    let greatest = crate::greatest(be);
    if stored > 0 {
        if let Err(e) = st
            .db
            .execute(
                &format!(
                    "UPDATE p2pnas.node_local
                        SET used_bytes = {greatest}(used_bytes - $1, 0), updated_at = {now}
                      WHERE id = 1"
                ),
                params![stored],
            )
            .await
        {
            tracing::error!(error = %e, %user_id, "purge p2pnas : décompte du stockage du nœud");
        }
    }

    // The point of the whole subscription: give the allocated capacity back.
    match st
        .db
        .execute("DELETE FROM p2pnas.user_quota WHERE user_id = $1", params![user_id])
        .await
    {
        Ok(rows) => tracing::info!(
            %user_id, deleted, stored, quota_row_removed = rows > 0,
            "p2pnas : données purgées après suppression du compte"
        ),
        Err(e) => tracing::error!(error = %e, %user_id, "purge p2pnas : suppression du quota"),
    }

    if let Err(e) = st
        .db
        .execute(
            "INSERT INTO p2pnas.events (kind, payload) VALUES ('user_purged', $1)",
            params![serde_json::json!({ "user_id": user_id, "files_deleted": deleted, "stored_bytes_freed": stored })],
        )
        .await
    {
        tracing::error!(error = %e, %user_id, "purge p2pnas : journalisation");
    }
}
