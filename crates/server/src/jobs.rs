//! Background job queue (PostgreSQL `p2pnas.jobs`, claimed with `FOR UPDATE SKIP
//! LOCKED`). Repair runs are enqueued (by the periodic ticker, or on demand) and
//! processed by a worker, so concurrent triggers — or several module instances
//! sharing the database — never run the same repair twice.

use std::time::{Duration, Instant};

use p2pnas_p2p::P2pMessage;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::{rebalance, repair, state::AppState};

/// How many times a remote-GC job retries peers that were unreachable before
/// giving up, and the base back-off between tries (grows linearly).
const GC_MAX_ATTEMPTS: u64 = 5;
const GC_RETRY_BASE_SECS: u64 = 300;

/// Job kinds that are whole-node passes carrying no meaningful payload: a second
/// one queued while the first is still `pending` would repeat the exact same work.
/// The periodic ticker enqueues them blindly, so whenever a pass takes longer than
/// its interval the queue would otherwise grow without bound. Deliberately NOT
/// listed: `gc_remote` (its payload names specific shards) and `rebalance_locality`
/// (rare, and its payload records why it was triggered).
const COALESCED_KINDS: &[&str] = &["repair", "retention", "gc_trash", "manifest_backup"];

/// A job stuck in `running` for longer than this is assumed to be the debris of a
/// crashed worker and is put back in the queue. `claim` only ever looks at
/// `pending` rows, so without this a crash mid-job loses that job for good.
/// The window is generous because several module instances may share the database
/// and a repair pass over a large node is legitimately long; every job kind here
/// is idempotent, so re-running one is safe.
const STALE_RUNNING_HOURS: i32 = 1;

/// How long finished jobs and events are kept before the worker purges them.
/// Long enough to investigate an incident from the admin console's event list,
/// short enough that these two append-only tables stay bounded.
const RETAIN_DAYS: i32 = 30;

/// How often the worker runs its own housekeeping (requeue + purge).
const MAINTENANCE_EVERY: Duration = Duration::from_secs(3600);

/// Add a job to the queue.
///
/// For the kinds in [`COALESCED_KINDS`] this is a no-op when an identical job is
/// already waiting. The `WHERE NOT EXISTS` is not a hard lock (two concurrent
/// callers could still both insert), but it is enough to keep the periodic ticker
/// from piling up work it will never catch up with.
pub async fn enqueue(db: &PgPool, kind: &str, payload: Value) {
    // Both branches are string literals, so the statement text is fixed at compile
    // time: `kind` only selects between them and never reaches the SQL, it is bound
    // as a parameter below. The `&'static str` annotation makes that guarantee the
    // compiler's — a run-time-built `String` would no longer satisfy `SqlSafeStr`.
    let sql: &'static str = if COALESCED_KINDS.contains(&kind) {
        "INSERT INTO p2pnas.jobs (kind, payload)
         SELECT $1::text, $2::jsonb
         WHERE NOT EXISTS (
             SELECT 1 FROM p2pnas.jobs WHERE kind = $1::text AND state = 'pending'
         )"
    } else {
        "INSERT INTO p2pnas.jobs (kind, payload) VALUES ($1::text, $2::jsonb)"
    };
    match sqlx::query(sql).bind(kind).bind(payload).execute(db).await {
        Ok(res) if res.rows_affected() == 0 => {
            tracing::debug!(kind, "job already pending — not enqueued again");
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(kind, error = %e, "failed to enqueue job"),
    }
}

/// Add a job that only becomes runnable after `delay` (used to back off retries).
pub async fn enqueue_after(db: &PgPool, kind: &str, payload: Value, delay: Duration) {
    if let Err(e) = sqlx::query(
        "INSERT INTO p2pnas.jobs (kind, payload, run_after) VALUES ($1, $2, now() + make_interval(secs => $3))",
    )
    .bind(kind)
    .bind(payload)
    .bind(delay.as_secs() as i32)
    .execute(db)
    .await
    {
        tracing::warn!(kind, error = %e, "failed to enqueue delayed job");
    }
}

/// Tell the peers hosting a deleted file's remote shards to drop them.
///
/// Best-effort with bounded retry: a peer offline right now is retried a few
/// times with a growing back-off; one that never comes back is eventually given
/// up on (a host-side orphan sweep is the intended backstop for that case). The
/// hosts accept the deletion because we send our own peer id as `owner_peer_id`,
/// which matches what they recorded at StoreShard time.
async fn run_gc_remote(st: &AppState, payload: Value) -> bool {
    let shards: Vec<(String, String)> =
        serde_json::from_value(payload.get("shards").cloned().unwrap_or(Value::Null)).unwrap_or_default();
    let attempt = payload.get("attempt").and_then(|v| v.as_u64()).unwrap_or(0);
    if shards.is_empty() {
        return true;
    }

    let mut failed: Vec<(String, String)> = Vec::new();
    for (frag, peer_id) in shards {
        let addr: Option<(String,)> = sqlx::query_as("SELECT addr FROM p2pnas.peers WHERE peer_id = $1")
            .bind(&peer_id)
            .fetch_optional(&st.db)
            .await
            .ok()
            .flatten();
        let Some((addr,)) = addr else {
            // Peer no longer known: nothing to send it to. Not a retryable failure.
            continue;
        };
        let reply = crate::p2p::signed_request(
            &st.identity,
            st.settings.server.port,
            &addr,
            &P2pMessage::DeleteShard {
                fragment_id: frag.clone(),
                owner_peer_id: st.identity.peer_id.clone(),
            },
        )
        .await;
        if !matches!(reply, Ok(P2pMessage::Ack { .. })) {
            failed.push((frag, peer_id));
        }
    }

    if failed.is_empty() {
        return true;
    }
    if attempt + 1 < GC_MAX_ATTEMPTS {
        let delay = Duration::from_secs(GC_RETRY_BASE_SECS * (attempt + 1));
        enqueue_after(&st.db, "gc_remote", json!({ "shards": failed, "attempt": attempt + 1 }), delay).await;
    } else {
        tracing::warn!(count = failed.len(), "gc_remote: giving up on unreachable peers after retries");
    }
    true
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
    .inspect_err(|e| tracing::error!(error = %e, "failed to claim a job"))
    .ok()
    .flatten()
}

async fn finish(db: &PgPool, id: i64, ok: bool) {
    let state = if ok { "done" } else { "failed" };
    if let Err(e) = sqlx::query("UPDATE p2pnas.jobs SET state = $2 WHERE id = $1")
        .bind(id)
        .bind(state)
        .execute(db)
        .await
    {
        // The row stays `running`; the stale-job sweep below is what recovers it.
        tracing::error!(job_id = id, error = %e, "failed to mark job finished");
    }
}

/// Put jobs abandoned in `running` back into the queue.
///
/// `p2pnas.jobs` has no "claimed at" column, so age is measured from `created_at`:
/// a job still `running` long after it was created either crashed with its worker
/// or is pathologically slow, and re-running it is harmless in both cases.
async fn requeue_stale_jobs(db: &PgPool) {
    match sqlx::query(
        "UPDATE p2pnas.jobs SET state = 'pending', run_after = now()
         WHERE state = 'running' AND created_at < now() - make_interval(hours => $1)",
    )
    .bind(STALE_RUNNING_HOURS)
    .execute(db)
    .await
    {
        Ok(res) if res.rows_affected() > 0 => {
            tracing::warn!(count = res.rows_affected(), "requeued jobs left running by a crashed worker");
        }
        Ok(_) => {}
        Err(e) => tracing::error!(error = %e, "failed to requeue stale jobs"),
    }
}

/// Drop finished jobs and old events. Both tables are append-only otherwise and
/// would grow for the lifetime of the node. Jobs that are still `pending` or
/// `running` are never touched, whatever their age.
async fn purge_old_rows(db: &PgPool) {
    if let Err(e) = sqlx::query(
        "DELETE FROM p2pnas.jobs
         WHERE state IN ('done', 'failed') AND created_at < now() - make_interval(days => $1)",
    )
    .bind(RETAIN_DAYS)
    .execute(db)
    .await
    {
        tracing::error!(error = %e, "failed to purge finished jobs");
    }
    if let Err(e) = sqlx::query("DELETE FROM p2pnas.events WHERE created_at < now() - make_interval(days => $1)")
        .bind(RETAIN_DAYS)
        .execute(db)
        .await
    {
        tracing::error!(error = %e, "failed to purge old events");
    }
}

/// Worker loop: claim and run jobs; idle-poll when the queue is empty.
///
/// Housekeeping (recovering crashed jobs, purging finished ones) runs once at
/// start-up — the moment a previous crash is most likely to have left debris —
/// and then on a slow timer.
pub async fn worker(st: AppState) {
    requeue_stale_jobs(&st.db).await;
    purge_old_rows(&st.db).await;
    let mut last_maintenance = Instant::now();

    loop {
        if last_maintenance.elapsed() >= MAINTENANCE_EVERY {
            requeue_stale_jobs(&st.db).await;
            purge_old_rows(&st.db).await;
            last_maintenance = Instant::now();
        }
        match claim(&st.db).await {
            Some((id, kind, payload)) => {
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
                        true
                    }
                    // Full locality maintenance: first heal any losses (so we never
                    // move the last copy of a chunk that's already degraded), then
                    // re-home healthy shards toward the latency-optimal layout.
                    "rebalance_locality" => {
                        repair::repair_all(&st).await;
                        rebalance::rebalance_all(&st).await;
                        true
                    }
                    "gc_remote" => run_gc_remote(&st, payload).await,
                    "retention" => {
                        crate::retention::sweep(&st).await;
                        true
                    }
                    // Distributed backup of the manifest: snapshot, seal,
                    // erasure-code, push onto the peers, prune the aged-out
                    // versions. Always reports success — a failed pass is an
                    // event and a log line, not a job to retry in a loop, since
                    // the next daily run is the natural retry.
                    "manifest_backup" => {
                        let r = crate::manifest_backup::run_backup(&st).await;
                        if !r.skipped {
                            tracing::info!(
                                version = r.version,
                                placed = r.shards_placed,
                                recoverable = r.recoverable,
                                "manifest backup job complete"
                            );
                        }
                        true
                    }
                    // Reclaims trashed files and superseded versions past their
                    // retention window — locally and on the peers hosting them.
                    "gc_trash" => {
                        crate::handlers::files::purge_retired_now(&st).await;
                        true
                    }
                    "repack_small" => {
                        crate::handlers::files::repack_all_now(&st).await;
                        true
                    }
                    "compact_packs" => {
                        crate::handlers::files::compact_packs_now(&st).await;
                        true
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
