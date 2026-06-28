-- Hysteresis for the locality rebalance: remember when we last re-homed, so an
-- automatic trigger (a flapping public IP) can't cause repeated churn.
ALTER TABLE p2pnas.node_local ADD COLUMN IF NOT EXISTS last_rebalance_at TIMESTAMPTZ;
