-- Retention / reciprocity policy support.
--
-- 1. Record which shard index a hosted shard is, so a host can shed PARITY
--    shards first (indices >= data count) when reclaiming space from an absent
--    owner — the data shards alone still reconstruct the file. -1 = unknown
--    (rows written before this column, or by a peer that predates it): such a
--    shard is only ever removed at full eviction, never in the parity-first step.
ALTER TABLE p2pnas.hosted_shards ADD COLUMN IF NOT EXISTS shard_index INTEGER NOT NULL DEFAULT -1;

-- 2. Per-owner retention bookkeeping, so the sweep is observable and idempotent:
--    which lifecycle stage we last applied for each owner we host for.
ALTER TABLE p2pnas.hosted_shards ADD COLUMN IF NOT EXISTS reclaimed_at TIMESTAMPTZ;
