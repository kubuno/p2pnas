//! Peer discovery: turn a freshly-found network address into a trusted peer.
//! The transports (mDNS on the LAN, the Kademlia DHT for wide-area) all funnel
//! through [`register_peer`], which handshakes the address and upserts it.
//!
//! Trust model — trust on first use (TOFU). A `peer_id` is public: it travels in
//! mDNS announcements and in the DHT, so announcing someone else's is free. What
//! is not free is signing a fresh challenge with the key behind it. The first
//! time we successfully challenge a peer we PIN its public key
//! (`p2pnas.peers.public_key`); from then on, any handshake for that `peer_id`
//! presenting a different key — or no key at all — is refused and writes nothing.
//! That is what closes the address-hijack: an attacker announcing a victim's
//! `peer_id` can no longer repoint its `addr` at itself and collect every shard
//! operation meant for it.

pub mod dht;
pub mod mdns;

use sqlx::PgPool;

use p2pnas_store::NodeIdentity;

/// Handshake a discovered address and record it as a peer. Skips our own node
/// (same peer_id). Returns the peer_id on success. Idempotent: re-discovering a
/// known peer just refreshes its address + `last_seen`.
pub async fn register_peer(db: &PgPool, identity: &NodeIdentity, my_api_port: u16, addr: &str) -> Option<String> {
    // Dedup: if we already know a peer at this address that was seen recently,
    // skip the handshake (discovery transports re-surface the same addr often).
    if let Ok(Some((pid,))) = sqlx::query_as::<_, (String,)>(
        "SELECT peer_id FROM p2pnas.peers WHERE addr = $1 AND last_seen > now() - interval '2 minutes'",
    )
    .bind(addr)
    .fetch_optional(db)
    .await
    {
        return Some(pid);
    }

    // Challenge the address: the responder must SIGN a fresh nonce with the key
    // behind the peer_id it announces. `handshake_verified` falls back to the
    // legacy Ping for peers that predate this, and flags the result unproven.
    let peer = p2pnas_p2p::handshake_verified(addr, &identity.peer_id, my_api_port).await.ok()?;
    if peer.peer_id == identity.peer_id {
        return None; // discovered ourselves
    }
    if peer.public_key.is_none() {
        if crate::p2p::strict_peer_auth() {
            tracing::warn!(addr, peer_id = %peer.peer_id, "discovery: refusing a peer that cannot prove its identity (strict peer auth)");
            return None;
        }
        // Permissive mode: accepted, but only for a peer_id we have NOT pinned —
        // the SQL below refuses to move the address of an already-pinned peer.
        tracing::warn!(addr, peer_id = %peer.peer_id, "discovery: peer answered the legacy handshake; its identity is declared, not proven");
    }

    // Record the failure domain derived from the address (IPv4 /24, IPv6 /64) so
    // placement can avoid putting a chunk's shards behind one router. `COALESCE`
    // keeps an operator's explicit label: they know a topology no IP range shows
    // (two "distant" addresses on the same building's power, say).
    let zone = crate::placement::zone_of_addr(addr);
    // The `WHERE` on the conflict branch is the hijack guard: an update only
    // happens if we have no key pinned yet, or if the key just proven is exactly
    // the pinned one. Anything else leaves the row untouched (0 rows affected) —
    // in particular an attacker announcing a known peer_id from its own address,
    // and a legacy handshake for a peer whose key we already pinned (which would
    // otherwise be a trivial downgrade path to the same hijack).
    //
    // `public_key` uses COALESCE rather than EXCLUDED so a later legacy handshake
    // can never erase a pinned key.
    let r = sqlx::query(
        "INSERT INTO p2pnas.peers (peer_id, addr, zone, public_key, verified_at, last_seen)
         VALUES ($1, $2, $3, $4, CASE WHEN $4::text IS NULL THEN NULL ELSE now() END, now())
         ON CONFLICT (peer_id) DO UPDATE SET
             addr = EXCLUDED.addr,
             last_seen = now(),
             zone = COALESCE(peers.zone, EXCLUDED.zone),
             public_key = COALESCE(peers.public_key, EXCLUDED.public_key),
             verified_at = CASE WHEN EXCLUDED.public_key IS NULL THEN peers.verified_at ELSE now() END
         WHERE peers.public_key IS NULL OR peers.public_key IS NOT DISTINCT FROM EXCLUDED.public_key",
    )
    .bind(&peer.peer_id)
    .bind(addr)
    .bind(zone)
    .bind(peer.public_key.as_deref())
    .execute(db)
    .await;
    match r {
        Ok(res) if res.rows_affected() == 0 => {
            tracing::warn!(
                addr,
                peer_id = %peer.peer_id,
                proven = peer.public_key.is_some(),
                "discovery: refusing peer update — the presented public key is missing or differs from the pinned one"
            );
            None
        }
        Ok(_) => Some(peer.peer_id),
        Err(e) => {
            tracing::warn!(error = %e, addr, "discovery: peer upsert failed");
            None
        }
    }
}
