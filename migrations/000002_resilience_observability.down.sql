DROP INDEX IF EXISTS p2pnas.jobs_pending_idx;
ALTER TABLE p2pnas.node_local DROP COLUMN IF EXISTS hosted_bytes;
ALTER TABLE p2pnas.peers DROP COLUMN IF EXISTS status;
ALTER TABLE p2pnas.peers DROP COLUMN IF EXISTS consecutive_failures;
