-- Locality signals on peers: measured round-trip latency (EWMA, ms) and an
-- optional coarse geo hint (country code) used by latency/jurisdiction-aware
-- placement. Both are NULL until first measured / resolved.
ALTER TABLE p2pnas.peers ADD COLUMN IF NOT EXISTS rtt_ms DOUBLE PRECISION;
ALTER TABLE p2pnas.peers ADD COLUMN IF NOT EXISTS country TEXT;

-- This node's own last-observed public geo (country), so a move can be detected.
ALTER TABLE p2pnas.node_local ADD COLUMN IF NOT EXISTS country TEXT;
