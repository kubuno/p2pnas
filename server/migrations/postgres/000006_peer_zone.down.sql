DROP INDEX IF EXISTS p2pnas.peers_zone_idx;
ALTER TABLE p2pnas.peers DROP COLUMN IF EXISTS zone;
