-- MySQL / MariaDB — the `p2pnas` database is created by kubuno-db's schema setup
-- before the migrator runs, so there is no CREATE DATABASE here. This single file
-- declares the FINAL shape the PostgreSQL side reached across its 000001..000007
-- migrations (control plane only: the encrypted file/chunk/shard index stays in
-- the SQLCipher manifest, which is not a database this migrator touches).
--
-- Differences from PostgreSQL, and why:
--   * UUID -> BINARY(16): what sqlx encodes a `uuid::Uuid` as on MySQL.
--   * TIMESTAMPTZ -> DATETIME(6); every value written is UTC (the pool pins
--     `time_zone = '+00:00'`). The app sets updated_at explicitly on each write.
--   * JSONB -> JSON. Every insert binds the payload, so no column default is
--     needed (MySQL JSON columns cannot carry a literal default anyway).
--   * BIGSERIAL -> BIGINT AUTO_INCREMENT (jobs/events ids are DB-generated;
--     the code never needs them back before insert).
--   * DOUBLE PRECISION -> DOUBLE.
--   * TEXT keys -> VARCHAR so they can be primary/indexed.
--   * Partial indexes (WHERE ...) become plain indexes (MySQL has none).
--   * utf8mb4_bin so peer ids / fragment ids stay case- and byte-exact.

-- ── Node-level storage accounting (single row) ────────────────────────────────
CREATE TABLE node_local (
    id                SMALLINT     NOT NULL PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    peer_id           VARCHAR(255) NULL,
    contributed_bytes BIGINT       NOT NULL DEFAULT 0,
    used_bytes        BIGINT       NOT NULL DEFAULT 0,
    hosted_bytes      BIGINT       NOT NULL DEFAULT 0,
    public_ip         VARCHAR(64)  NULL,
    country           VARCHAR(8)   NULL,
    last_rebalance_at DATETIME(6)  NULL,
    updated_at        DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
INSERT INTO node_local (id) VALUES (1);

-- ── Per-user "My Cloud" quota (admin-managed) ─────────────────────────────────
CREATE TABLE user_quota (
    user_id     BINARY(16)  NOT NULL PRIMARY KEY,
    quota_bytes BIGINT      NOT NULL DEFAULT 0,
    used_bytes  BIGINT      NOT NULL DEFAULT 0,
    updated_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- ── Trusted peers (the "network of acquaintances") ────────────────────────────
CREATE TABLE peers (
    peer_id              VARCHAR(255) NOT NULL PRIMARY KEY,
    addr                 VARCHAR(255) NOT NULL,
    reliability_score    DOUBLE       NOT NULL DEFAULT 100.0,
    contributed_bytes    BIGINT       NOT NULL DEFAULT 0,
    used_bytes           BIGINT       NOT NULL DEFAULT 0,
    threshold_days       INT          NOT NULL DEFAULT 7,
    consecutive_failures INT          NOT NULL DEFAULT 0,
    status               VARCHAR(20)  NOT NULL DEFAULT 'active',
    rtt_ms               DOUBLE       NULL,
    country              VARCHAR(8)   NULL,
    zone                 VARCHAR(255) NULL,
    public_key           VARCHAR(128) NULL,
    verified_at          DATETIME(6)  NULL,
    last_seen            DATETIME(6)  NULL,
    created_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE INDEX peers_zone_idx ON peers (zone);

-- ── Shards this node hosts for other peers ────────────────────────────────────
CREATE TABLE hosted_shards (
    fragment_id   VARCHAR(255) NOT NULL PRIMARY KEY,
    owner_peer_id VARCHAR(255) NOT NULL,
    size_bytes    BIGINT       NOT NULL DEFAULT 0,
    shard_index   INT          NOT NULL DEFAULT -1,
    reclaimed_at  DATETIME(6)  NULL,
    stored_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE INDEX hosted_shards_owner_idx ON hosted_shards (owner_peer_id);

-- ── Background job queue (repair / re-replication / proof-of-storage) ──────────
CREATE TABLE jobs (
    id         BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    kind       VARCHAR(64)  NOT NULL,
    payload    JSON         NOT NULL,
    state      VARCHAR(20)  NOT NULL DEFAULT 'pending',
    attempts   INT          NOT NULL DEFAULT 0,
    run_after  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE INDEX jobs_claim_idx   ON jobs (state, run_after);
CREATE INDEX jobs_pending_idx ON jobs (run_after);

-- ── Event log (mirrored to LISTEN/NOTIFY for drive integration on PostgreSQL) ──
CREATE TABLE events (
    id         BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    kind       VARCHAR(64)  NOT NULL,
    payload    JSON         NOT NULL,
    created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
