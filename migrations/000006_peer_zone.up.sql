-- Correlated-failure zone of a peer, used by zone-aware shard placement.
--
-- Two peers sharing a zone are assumed to fail together (same site, same uplink,
-- same power feed), so a zone — not just a peer — may hold at most PARITY shards
-- of a chunk. NULL means "unknown": placement then derives a zone from the peer
-- address (IPv4 /24, IPv6 /64) and, failing that, treats the peer as its own zone.
--
-- The column is operator-editable on purpose: only a human knows that two peers
-- in different subnets sit in the same building, or that two addresses in one /24
-- are actually two independent sites.
ALTER TABLE p2pnas.peers ADD COLUMN IF NOT EXISTS zone TEXT;

CREATE INDEX IF NOT EXISTS peers_zone_idx ON p2pnas.peers (zone);
