-- 000001_p2pnas_schema.up.sql
-- PostgreSQL control plane for the p2pnas module. The encrypted file/chunk/shard
-- index lives separately in the SQLCipher manifest (see crates/core); PostgreSQL
-- owns quotas, peer state, the repair job queue and the cross-module event log.

CREATE SCHEMA IF NOT EXISTS p2pnas;

-- ── Node-level storage accounting (single row) ────────────────────────────────
-- available = contributed_bytes - used_bytes. The sum of every user_quota.quota
-- must never exceed `contributed_bytes` (enforced in the admin handler).
CREATE TABLE IF NOT EXISTS p2pnas.node_local (
    id                SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    peer_id           TEXT,
    contributed_bytes BIGINT NOT NULL DEFAULT 0,
    used_bytes        BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO p2pnas.node_local (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- ── Per-user "My Cloud" quota (admin-managed) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS p2pnas.user_quota (
    user_id     UUID PRIMARY KEY,
    quota_bytes BIGINT NOT NULL DEFAULT 0,
    used_bytes  BIGINT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Trusted peers (the "network of acquaintances") ────────────────────────────
CREATE TABLE IF NOT EXISTS p2pnas.peers (
    peer_id           TEXT PRIMARY KEY,
    addr              TEXT NOT NULL,
    reliability_score DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    contributed_bytes BIGINT NOT NULL DEFAULT 0,
    used_bytes        BIGINT NOT NULL DEFAULT 0,
    threshold_days    INTEGER NOT NULL DEFAULT 7,
    last_seen         TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Shards this node hosts for other peers ────────────────────────────────────
CREATE TABLE IF NOT EXISTS p2pnas.hosted_shards (
    fragment_id   TEXT PRIMARY KEY,
    owner_peer_id TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL DEFAULT 0,
    stored_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS hosted_shards_owner_idx ON p2pnas.hosted_shards (owner_peer_id);

-- ── Background job queue (repair / re-replication / proof-of-storage) ──────────
-- Workers claim rows with SELECT … FOR UPDATE SKIP LOCKED.
CREATE TABLE IF NOT EXISTS p2pnas.jobs (
    id         BIGSERIAL PRIMARY KEY,
    kind       TEXT NOT NULL,
    payload    JSONB NOT NULL DEFAULT '{}'::jsonb,
    state      TEXT NOT NULL DEFAULT 'pending',
    attempts   INTEGER NOT NULL DEFAULT 0,
    run_after  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS jobs_claim_idx ON p2pnas.jobs (state, run_after);

-- ── Event log (mirrored to LISTEN/NOTIFY for drive integration) ───────────────
CREATE TABLE IF NOT EXISTS p2pnas.events (
    id         BIGSERIAL PRIMARY KEY,
    kind       TEXT NOT NULL,
    payload    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
