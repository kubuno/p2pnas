//! Background job queue (PostgreSQL `p2pnas.jobs`, claimed with `FOR UPDATE SKIP
//! LOCKED`). Repair runs are enqueued (by the periodic ticker, or on demand) and
//! processed by a worker, so concurrent triggers — or several module instances
//! sharing the database — never run the same repair twice.

use std::time::Duration;

use serde_json::Value;
use sqlx::PgPool;

use crate::{repair, state::AppState};

/// Add a job to the queue.
pub async fn enqueue(db: &PgPool, kind: &str, payload: Value) {
    if let Err(e) = sqlx::query("INSERT INTO p2pnas.jobs (kind, payload) VALUES ($1, $2)")
        .bind(kind)
        .bind(payload)
        .execute(db)
        .await
    {
        tracing::warn!(kind, error = %e, "failed to enqueue job");
    }
}

/// Atomically claim one runnable job (marks it `running`). `FOR UPDATE SKIP
/// LOCKED` lets multiple workers pull distinct jobs without blocking.
async fn claim(db: &PgPool) -> Option<(i64, String, Value)> {
    sqlx::query_as(
        "UPDATE p2pnas.jobs SET state = 'running', attempts = attempts + 1
         WHERE id = (
             SELECT id FROM p2pnas.jobs
             WHERE state = 'pending' AND run_after <= now()
             ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1
         )
         RETURNING id, kind, payload",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
}

async fn finish(db: &PgPool, id: i64, ok: bool) {
    let state = if ok { "done" } else { "failed" };
    let _ = sqlx::query("UPDATE p2pnas.jobs SET state = $2 WHERE id = $1")
        .bind(id)
        .bind(state)
        .execute(db)
        .await;
}

/// Worker loop: claim and run jobs; idle-poll when the queue is empty.
pub async fn worker(st: AppState) {
    loop {
        match claim(&st.db).await {
            Some((id, kind, _payload)) => {
                let ok = match kind.as_str() {
                    "repair" => {
                        let r = repair::repair_all(&st).await;
                        if r.shards_replaced > 0 || r.chunks_unrepairable > 0 {
                            tracing::info!(
                                replaced = r.shards_replaced,
                                unrepairable = r.chunks_unrepairable,
                                "repair job complete"
                            );
                        }
                        true // best-effort: unrepairable chunks aren't a job failure
                    }
                    other => {
                        tracing::warn!(kind = other, "unknown job kind");
                        false
                    }
                };
                finish(&st.db, id, ok).await;
            }
            None => tokio::time::sleep(Duration::from_secs(10)).await,
        }
    }
}
