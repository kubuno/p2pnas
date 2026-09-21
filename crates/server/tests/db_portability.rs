//! Runs the p2pnas **control plane** against a real server of each engine, from a
//! single compiled binary — the proof that the engine is a run-time choice, not a
//! build-time one. Only the control plane goes through kubuno-db; the encrypted
//! SQLCipher manifest (crates/store) is a separate concern and is not exercised
//! here.
//!
//! It issues the very SQL the module issues for the portability-sensitive paths:
//!   * the guarded peer upsert (first-use key pinning, formerly a PostgreSQL-only
//!     conditional `ON CONFLICT ... WHERE`);
//!   * the job queue's claim-by-`rows_affected` (formerly `FOR UPDATE SKIP
//!     LOCKED` + `RETURNING`);
//!   * quota accounting with the portable `GREATEST`/`MAX` clamp and a `now()`
//!     that differs per engine;
//!   * the `COUNT(*) FILTER (WHERE …)` metrics rewritten as `SUM(CASE …)`;
//!   * JSON event payloads and a `payload->'version'` lookup.
//!
//! * SQLite always runs (a temp file, no server).
//! * PostgreSQL runs when `KUBUNO_PG_TEST_URL` points at a throwaway database.
//! * MySQL/MariaDB runs when `KUBUNO_MYSQL_TEST_URL` does.
//!
//! ```sh
//! KUBUNO_PG_TEST_URL=postgres://u:p@127.0.0.1:5432/kubuno_test \
//! KUBUNO_MYSQL_TEST_URL=mysql://u:p@127.0.0.1:3306/p2pnas \
//!   cargo test --test db_portability
//! ```

use kubuno_db::dialect::Backend;
use kubuno_db::{params, DbPool};
use kubuno_p2pnas::{greatest, SCHEMA};
use uuid::Uuid;

fn base_settings(engine: &str) -> kubuno_db::DbSettings {
    kubuno_db::DbSettings {
        engine: engine.to_string(),
        url: None,
        host: None,
        port: None,
        user: None,
        password: None,
        database: None,
        path: None,
        max_connections: 4,
        min_connections: 0,
        connect_timeout: std::time::Duration::from_secs(10),
        run_migrations: true,
    }
}

/// Migrations run one at a time: the PostgreSQL and MySQL suites may share a server.
static EXCLUSIVE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn migrated_pool(settings: kubuno_db::DbSettings) -> (DbPool, impl Sized) {
    let guard = EXCLUSIVE.lock().await;
    let pool = kubuno_db::connect(&settings, SCHEMA).await.expect("connect");
    kubuno_db::migrations!(
        "../../migrations/postgres",
        "../../migrations/mysql",
        "../../migrations/sqlite",
    )
    .run(&pool, SCHEMA)
    .await
    .expect("migrations");
    // A clean control plane for each run, whatever the engine kept from a prior one.
    for t in ["events", "jobs", "hosted_shards", "peers", "user_quota"] {
        pool.execute(&format!("DELETE FROM p2pnas.{t}"), params![])
            .await
            .expect("reset");
    }
    (pool, guard)
}

// ── the guarded peer upsert (first-use key pinning) ──────────────────────────

/// Mirrors `discovery::upsert_peer_guarded`: insert or refresh a peer under the
/// pin guard, returning whether the write was applied.
async fn upsert_peer(db: &DbPool, peer_id: &str, addr: &str, key: Option<&str>) -> bool {
    let be = db.backend();
    let now = be.now();
    let lock = if be == Backend::Sqlite { "" } else { " FOR UPDATE" };
    let mut tx = db.begin().await.expect("begin");
    let existing: Option<Option<String>> = tx
        .fetch_optional_row(
            &format!("SELECT public_key FROM p2pnas.peers WHERE peer_id = $1{lock}"),
            params![peer_id],
        )
        .await
        .expect("select")
        .map(|r| r.try_get::<Option<String>>("public_key").expect("decode"));
    let applied = match existing {
        None => {
            tx.execute(
                &format!(
                    "INSERT INTO p2pnas.peers (peer_id, addr, public_key, verified_at, last_seen)
                     VALUES ($1, $2, $3, CASE WHEN $4 IS NULL THEN NULL ELSE {now} END, {now})"
                ),
                params![peer_id, addr, key, key],
            )
            .await
            .expect("insert peer");
            true
        }
        Some(pinned) => {
            let allowed = pinned.is_none() || pinned.as_deref() == key;
            if allowed {
                tx.execute(
                    &format!(
                        "UPDATE p2pnas.peers SET addr = $1, last_seen = {now},
                             public_key = COALESCE(public_key, $2),
                             verified_at = CASE WHEN $3 IS NULL THEN verified_at ELSE {now} END
                         WHERE peer_id = $4"
                    ),
                    params![addr, key, key, peer_id],
                )
                .await
                .expect("update peer");
            }
            allowed
        }
    };
    tx.commit().await.expect("commit");
    applied
}

async fn peer_addr(db: &DbPool, peer_id: &str) -> Option<String> {
    db.fetch_optional_as::<(String,)>("SELECT addr FROM p2pnas.peers WHERE peer_id = $1", params![peer_id])
        .await
        .expect("peer addr")
        .map(|(a,)| a)
}

async fn peer_key(db: &DbPool, peer_id: &str) -> Option<String> {
    db.fetch_optional_scalar::<Option<String>>("SELECT public_key FROM p2pnas.peers WHERE peer_id = $1", params![peer_id])
        .await
        .expect("peer key")
        .flatten()
}

// ── the portable job claim ───────────────────────────────────────────────────

async fn enqueue(db: &DbPool, kind: &str, payload: serde_json::Value) {
    db.execute(
        "INSERT INTO p2pnas.jobs (kind, payload) VALUES ($1, $2)",
        params![kind, payload],
    )
    .await
    .expect("enqueue");
}

/// Mirrors `jobs::claim`: pick a candidate, claim it by `rows_affected == 1`.
async fn claim(db: &DbPool) -> Option<(i64, String)> {
    let now = db.backend().now();
    loop {
        let candidate: Option<(i64,)> = db
            .fetch_optional_as(
                &format!(
                    "SELECT id FROM p2pnas.jobs WHERE state = 'pending' AND run_after <= {now} ORDER BY id LIMIT 1"
                ),
                params![],
            )
            .await
            .expect("candidate");
        let (id,) = candidate?;
        let n = db
            .execute(
                "UPDATE p2pnas.jobs SET state = 'running', attempts = attempts + 1 WHERE id = $1 AND state = 'pending'",
                params![id],
            )
            .await
            .expect("claim");
        if n != 1 {
            continue;
        }
        let row: Option<(String,)> = db
            .fetch_optional_as("SELECT kind FROM p2pnas.jobs WHERE id = $1", params![id])
            .await
            .expect("reselect");
        if let Some((kind,)) = row {
            return Some((id, kind));
        }
    }
}

async fn full_suite(pool: &DbPool) {
    let be = pool.backend();
    let now = be.now();
    let g = greatest(be);

    // ── seeded singleton row ──
    let contributed: i64 = pool
        .fetch_scalar("SELECT contributed_bytes FROM p2pnas.node_local WHERE id = 1", params![])
        .await
        .expect("node_local row exists");
    assert_eq!(contributed, 0);

    // ── quota upsert + GREATEST/MAX clamp ──
    let user = Uuid::new_v4();
    let upsert = be.upsert(
        "p2pnas.user_quota",
        &["user_id"],
        &[
            kubuno_db::dialect::Assign::Incoming("quota_bytes"),
            kubuno_db::dialect::Assign::Expr { col: "updated_at", expr: now },
        ],
    );
    pool.execute(
        &format!("INSERT INTO p2pnas.user_quota (user_id, quota_bytes, updated_at) VALUES ($1, $2, {now}){upsert}"),
        params![user, 1000i64],
    )
    .await
    .expect("insert quota");
    // Upsert again: the row is updated, not duplicated.
    pool.execute(
        &format!("INSERT INTO p2pnas.user_quota (user_id, quota_bytes, updated_at) VALUES ($1, $2, {now}){upsert}"),
        params![user, 2000i64],
    )
    .await
    .expect("upsert quota");
    let quota: i64 = pool
        .fetch_scalar("SELECT quota_bytes FROM p2pnas.user_quota WHERE user_id = $1", params![user])
        .await
        .expect("quota");
    assert_eq!(quota, 2000, "upsert replaced, not duplicated");

    // Clamp: subtracting past zero floors at 0 on every engine.
    pool.execute(
        &format!("UPDATE p2pnas.user_quota SET used_bytes = {g}(used_bytes - $1, 0) WHERE user_id = $2"),
        params![500i64, user],
    )
    .await
    .expect("clamp");
    let used: i64 = pool
        .fetch_scalar("SELECT used_bytes FROM p2pnas.user_quota WHERE user_id = $1", params![user])
        .await
        .expect("used");
    assert_eq!(used, 0, "clamped at zero, never negative");

    // sum_bigint over the quota table.
    let allocated: i64 = pool
        .fetch_scalar(
            &format!("SELECT {} FROM p2pnas.user_quota", be.sum_bigint("quota_bytes")),
            params![],
        )
        .await
        .expect("sum");
    assert_eq!(allocated, 2000);

    // ── guarded peer upsert: first-use key pinning ──
    assert!(upsert_peer(pool, "peerA", "10.0.0.1:7474", None).await, "new peer accepted");
    // A legacy re-announce (no key) may still move the address while unpinned.
    assert!(upsert_peer(pool, "peerA", "10.0.0.2:7474", None).await);
    assert_eq!(peer_addr(pool, "peerA").await.as_deref(), Some("10.0.0.2:7474"));
    // Pin a key.
    assert!(upsert_peer(pool, "peerA", "10.0.0.2:7474", Some("KEY1")).await, "pinning accepted");
    assert_eq!(peer_key(pool, "peerA").await.as_deref(), Some("KEY1"));
    // A different key is refused and changes nothing (the hijack guard).
    assert!(!upsert_peer(pool, "peerA", "6.6.6.6:7474", Some("EVIL")).await, "different key refused");
    assert_eq!(peer_addr(pool, "peerA").await.as_deref(), Some("10.0.0.2:7474"), "address unchanged after refusal");
    assert_eq!(peer_key(pool, "peerA").await.as_deref(), Some("KEY1"), "pinned key intact");
    // A legacy (no key) handshake for a pinned peer is also refused (no downgrade).
    assert!(!upsert_peer(pool, "peerA", "7.7.7.7:7474", None).await, "legacy downgrade refused");
    assert_eq!(peer_addr(pool, "peerA").await.as_deref(), Some("10.0.0.2:7474"));
    // The same key re-announcing from a new address is allowed.
    assert!(upsert_peer(pool, "peerA", "10.0.0.9:7474", Some("KEY1")).await, "same key allowed");
    assert_eq!(peer_addr(pool, "peerA").await.as_deref(), Some("10.0.0.9:7474"));

    // A second peer, marked down, for the metrics below.
    upsert_peer(pool, "peerB", "10.0.0.3:7474", Some("KEY2")).await;
    pool.execute("UPDATE p2pnas.peers SET status = 'down' WHERE peer_id = $1", params!["peerB"])
        .await
        .expect("mark down");

    // ── COUNT(*) FILTER rewritten as SUM(CASE …) ──
    let (total, active, down): (i64, i64, i64) = pool
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
        .expect("metrics");
    assert_eq!((total, active, down), (2, 1, 1));

    // ── job queue: claim-by-rows_affected, exactly once each ──
    enqueue(pool, "repair", serde_json::json!({})).await;
    enqueue(pool, "retention", serde_json::json!({})).await;
    let c1 = claim(pool).await.expect("first claim");
    let c2 = claim(pool).await.expect("second claim");
    assert_ne!(c1.0, c2.0, "two claims take two distinct jobs");
    let mut kinds = [c1.1, c2.1];
    kinds.sort();
    assert_eq!(kinds, ["repair".to_owned(), "retention".to_owned()]);
    assert!(claim(pool).await.is_none(), "queue drained: nothing left to claim");
    // Both are 'running' now, none 'pending'.
    let pending: i64 = pool
        .fetch_scalar(
            &format!(
                "SELECT {} FROM p2pnas.jobs WHERE state = 'pending'",
                be.count_bigint("*")
            ),
            params![],
        )
        .await
        .expect("pending count");
    assert_eq!(pending, 0);

    // ── JSON event payload + payload->'version' lookup ──
    pool.execute(
        "INSERT INTO p2pnas.events (kind, payload) VALUES ('manifest_backup', $1)",
        params![serde_json::json!({ "version": 42, "shards_placed": 14 })],
    )
    .await
    .expect("insert event");
    let vexpr = be.json_text("payload", &["version"]);
    let vexpr = if be == Backend::Sqlite { format!("CAST({vexpr} AS TEXT)") } else { vexpr };
    let found: Option<i32> = pool
        .fetch_optional_scalar(
            &format!("SELECT 1 FROM p2pnas.events WHERE kind = 'manifest_backup' AND {vexpr} = $1 LIMIT 1"),
            params![42u64.to_string()],
        )
        .await
        .expect("version lookup");
    assert!(found.is_some(), "payload->>'version' matches the stored number as text");

    // The event round-trips as (id, kind, Value, timestamp).
    let events: Vec<(i64, String, serde_json::Value, chrono::DateTime<chrono::Utc>)> = pool
        .fetch_all_as(
            "SELECT id, kind, payload, created_at FROM p2pnas.events ORDER BY id DESC",
            params![],
        )
        .await
        .expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].2["shards_placed"], serde_json::json!(14));

    // ── hosted_shards: reclaim query (parity-first) ──
    for (i, frag) in ["f0", "f10", "f13"].iter().enumerate() {
        let idx = [0i32, 10, 13][i];
        pool.execute(
            "INSERT INTO p2pnas.hosted_shards (fragment_id, owner_peer_id, size_bytes, shard_index) VALUES ($1, $2, $3, $4)",
            params![*frag, "peerB", 100i64, idx],
        )
        .await
        .expect("insert shard");
    }
    // Parity shards are those with index >= the data-shard count (10 here).
    let parity: Vec<(String, i64)> = pool
        .fetch_all_as(
            "SELECT fragment_id, size_bytes FROM p2pnas.hosted_shards WHERE owner_peer_id = $1 AND shard_index >= $2 ORDER BY fragment_id",
            params!["peerB", 10i32],
        )
        .await
        .expect("parity shards");
    assert_eq!(parity.len(), 2, "two parity shards (index 10 and 13)");
}

#[tokio::test]
async fn sqlite_from_the_one_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut s = base_settings("sqlite");
    s.path = Some(dir.path().to_string_lossy().into_owned());
    let (pool, _keep) = migrated_pool(s).await;
    full_suite(&pool).await;
}

#[tokio::test]
async fn postgres_from_the_one_binary() {
    let Ok(url) = std::env::var("KUBUNO_PG_TEST_URL") else {
        eprintln!("skipping: KUBUNO_PG_TEST_URL not set");
        return;
    };
    let mut s = base_settings("postgres");
    s.url = Some(url);
    let (pool, _keep) = migrated_pool(s).await;
    full_suite(&pool).await;
}

#[tokio::test]
async fn mysql_from_the_one_binary() {
    let Ok(url) = std::env::var("KUBUNO_MYSQL_TEST_URL") else {
        eprintln!("skipping: KUBUNO_MYSQL_TEST_URL not set");
        return;
    };
    let mut s = base_settings("mysql");
    s.url = Some(url);
    let (pool, _keep) = migrated_pool(s).await;
    full_suite(&pool).await;
}
