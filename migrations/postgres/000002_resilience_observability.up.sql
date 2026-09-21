-- Resilience + observability columns (improvements batch).

-- Peer health: track consecutive probe failures so a flaky peer can be auto-
-- excluded from placement, and an explicit status flag.
ALTER TABLE p2pnas.peers ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE p2pnas.peers ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';

-- Bytes this node currently hosts on behalf of other peers (capped by what we
-- contribute). Kept alongside `used_bytes` (our own data) for accounting.
ALTER TABLE p2pnas.node_local ADD COLUMN IF NOT EXISTS hosted_bytes BIGINT NOT NULL DEFAULT 0;

-- Index for the jobs worker's claim query (state + run_after already indexed in
-- 000001; add a partial index for the common pending lookup).
CREATE INDEX IF NOT EXISTS jobs_pending_idx ON p2pnas.jobs (run_after) WHERE state = 'pending';
