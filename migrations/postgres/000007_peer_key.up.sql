-- Cryptographic identity of a peer (trust on first use).
--
-- A peer_id is PUBLIC: it is announced over mDNS and stored in the DHT, so any
-- node can claim someone else's. Before this column, `register_peer` upserted on
-- peer_id and overwrote `addr`, which let an attacker announcing a victim's
-- peer_id repoint its address at itself and capture every StoreShard/GetShard/
-- DeleteShard meant for that victim.
--
-- `public_key` is the Ed25519 key (32 bytes, lowercase hex) the peer PROVED it
-- holds by signing a fresh challenge during the handshake. It is pinned the first
-- time we successfully challenge the peer; afterwards any handshake for that
-- peer_id presenting a different key — or no key at all — is refused and writes
-- nothing. NULL means "not pinned yet": a peer discovered before this node spoke
-- the authenticated handshake, or one still running an older build.
--
-- Recovery: a node that legitimately regenerates its identity.key gets a new
-- key pair, so its peers will refuse it. That is intentional — the fix is an
-- explicit operator action, `UPDATE p2pnas.peers SET public_key = NULL,
-- verified_at = NULL WHERE peer_id = '…'`, which re-arms the first-use pinning.
ALTER TABLE p2pnas.peers ADD COLUMN IF NOT EXISTS public_key TEXT;

-- When the key above was last proven against a fresh challenge. Lets an operator
-- (and the admin console) tell a peer authenticated minutes ago from one whose
-- identity has only ever been declared.
ALTER TABLE p2pnas.peers ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
