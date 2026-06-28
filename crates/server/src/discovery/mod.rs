//! Peer discovery: turn a freshly-found network address into a trusted peer.
//! The transports (mDNS on the LAN, the Kademlia DHT for wide-area) all funnel
//! through [`register_peer`], which handshakes the address and upserts it.

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

    let (peer_id, _api_port) = p2pnas_p2p::handshake(addr, &identity.peer_id, my_api_port).await.ok()?;
    if peer_id == identity.peer_id {
        return None; // discovered ourselves
    }
    let r = sqlx::query(
        "INSERT INTO p2pnas.peers (peer_id, addr, last_seen) VALUES ($1, $2, now())
         ON CONFLICT (peer_id) DO UPDATE SET addr = EXCLUDED.addr, last_seen = now()",
    )
    .bind(&peer_id)
    .bind(addr)
    .execute(db)
    .await;
    match r {
        Ok(_) => Some(peer_id),
        Err(e) => {
            tracing::warn!(error = %e, addr, "discovery: peer upsert failed");
            None
        }
    }
}
