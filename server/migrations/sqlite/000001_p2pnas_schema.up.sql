-- SQLite — `p2pnas` is an ATTACHed database file, attached on every pooled
-- connection by kubuno-db, so the qualified names below resolve as they do on the
-- other two engines. This single file declares the FINAL shape the PostgreSQL
-- side reached across its 000001..000007 migrations (control plane only; the
-- SQLCipher manifest is a separate file this migrator never touches).
--
-- Differences from PostgreSQL, and why:
--   * UUID -> BLOB, TIMESTAMPTZ -> TEXT (`%F %T%.f`, UTC), as sqlx encodes them.
--   * JSONB -> TEXT holding JSON; every insert binds the payload.
--   * BIGSERIAL -> INTEGER PRIMARY KEY AUTOINCREMENT (jobs/events ids).
--   * DOUBLE PRECISION -> REAL.
--   * The single-row node_local uses CHECK (id = 1) like PostgreSQL; the seed row
--     is inserted here.

CREATE TABLE p2pnas.node_local (
    id                INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    peer_id           TEXT,
    contributed_bytes INTEGER NOT NULL DEFAULT 0,
    used_bytes        INTEGER NOT NULL DEFAULT 0,
    hosted_bytes      INTEGER NOT NULL DEFAULT 0,
    public_ip         TEXT,
    country           TEXT,
    last_rebalance_at TEXT,
    updated_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
INSERT INTO p2pnas.node_local (id) VALUES (1);

CREATE TABLE p2pnas.user_quota (
    user_id     BLOB    NOT NULL PRIMARY KEY,
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    used_bytes  INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);

CREATE TABLE p2pnas.peers (
    peer_id              TEXT    NOT NULL PRIMARY KEY,
    addr                 TEXT    NOT NULL,
    reliability_score    REAL    NOT NULL DEFAULT 100.0,
    contributed_bytes    INTEGER NOT NULL DEFAULT 0,
    used_bytes           INTEGER NOT NULL DEFAULT 0,
    threshold_days       INTEGER NOT NULL DEFAULT 7,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    status               TEXT    NOT NULL DEFAULT 'active',
    rtt_ms               REAL,
    country              TEXT,
    zone                 TEXT,
    public_key           TEXT,
    verified_at          TEXT,
    last_seen            TEXT,
    created_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE INDEX p2pnas.peers_zone_idx ON peers (zone);

CREATE TABLE p2pnas.hosted_shards (
    fragment_id   TEXT    NOT NULL PRIMARY KEY,
    owner_peer_id TEXT    NOT NULL,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    shard_index   INTEGER NOT NULL DEFAULT -1,
    reclaimed_at  TEXT,
    stored_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE INDEX p2pnas.hosted_shards_owner_idx ON hosted_shards (owner_peer_id);

CREATE TABLE p2pnas.jobs (
    id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    kind       TEXT    NOT NULL,
    payload    TEXT    NOT NULL DEFAULT '{}',
    state      TEXT    NOT NULL DEFAULT 'pending',
    attempts   INTEGER NOT NULL DEFAULT 0,
    run_after  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE INDEX p2pnas.jobs_claim_idx   ON jobs (state, run_after);
CREATE INDEX p2pnas.jobs_pending_idx ON jobs (run_after);

CREATE TABLE p2pnas.events (
    id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    kind       TEXT    NOT NULL,
    payload    TEXT    NOT NULL DEFAULT '{}',
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
