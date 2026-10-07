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

use kubuno_db::{dialect::Backend, dialect::Unit, params, DbPool};

use p2pnas_store::NodeIdentity;

/// Handshake a discovered address and record it as a peer. Skips our own node
/// (same peer_id). Returns the peer_id on success. Idempotent: re-discovering a
/// known peer just refreshes its address + `last_seen`.
pub async fn register_peer(db: &DbPool, identity: &NodeIdentity, my_api_port: u16, addr: &str) -> Option<String> {
    // Dedup: if we already know a peer at this address that was seen recently,
    // skip the handshake (discovery transports re-surface the same addr often).
    let recent = db.backend().interval_before(2, Unit::Minute);
    if let Ok(Some((pid,))) = db
        .fetch_optional_as::<(String,)>(
            &format!("SELECT peer_id FROM p2pnas.peers WHERE addr = $1 AND last_seen > {recent}"),
            params![addr],
        )
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
    // The hijack guard, applied here in Rust because the conditional upsert it
    // replaces (`ON CONFLICT ... WHERE peers.public_key IS NOT DISTINCT FROM
    // EXCLUDED.public_key`) is PostgreSQL-only. The read-modify-write runs in one
    // transaction — row-locked on PostgreSQL/MySQL, single-writer on SQLite — so
    // the pin decision cannot race a concurrent handshake for the same peer_id.
    //
    // An update only happens if we have no key pinned yet, or if the key just
    // proven is exactly the pinned one. Anything else leaves the row untouched —
    // in particular an attacker announcing a known peer_id from its own address,
    // and a legacy handshake for a peer whose key we already pinned (a downgrade
    // path to the same hijack). `public_key`/`zone` use COALESCE so a later
    // legacy handshake can never erase a pinned key or an operator's zone label.
    match upsert_peer_guarded(db, &peer.peer_id, addr, zone.as_deref(), peer.public_key.as_deref()).await {
        Ok(true) => Some(peer.peer_id),
        Ok(false) => {
            tracing::warn!(
                addr,
                peer_id = %peer.peer_id,
                proven = peer.public_key.is_some(),
                "discovery: refusing peer update — the presented public key is missing or differs from the pinned one"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, addr, "discovery: peer upsert failed");
            None
        }
    }
}

/// Insert or refresh a peer row under the first-use key-pinning guard, portably.
///
/// Returns `Ok(true)` when the row was created or refreshed, `Ok(false)` when the
/// guard refused the write (a different key is pinned, or a legacy handshake for a
/// peer whose key is already pinned). `zone`/`public_key` are only ever filled in,
/// never overwritten, so a later unproven handshake cannot erase them.
pub(crate) async fn upsert_peer_guarded(
    db: &DbPool,
    peer_id: &str,
    addr: &str,
    zone: Option<&str>,
    public_key: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let be = db.backend();
    let now = be.now();
    let lock = if be == Backend::Sqlite { "" } else { " FOR UPDATE" };

    let mut tx = db.begin().await?;

    let existing: Option<Option<String>> = tx
        .fetch_optional_row(
            &format!("SELECT public_key FROM p2pnas.peers WHERE peer_id = $1{lock}"),
            params![peer_id],
        )
        .await?
        .map(|r| r.try_get::<Option<String>>("public_key"))
        .transpose()?;

    let applied = match existing {
        // Brand-new peer: record it (proven ones carry a verified_at).
        None => {
            tx.execute(
                &format!(
                    "INSERT INTO p2pnas.peers (peer_id, addr, zone, public_key, verified_at, last_seen)
                     VALUES ($1, $2, $3, $4, CASE WHEN $5 IS NULL THEN NULL ELSE {now} END, {now})"
                ),
                params![peer_id, addr, zone, public_key, public_key],
            )
            .await?;
            true
        }
        // Known peer: the guard. Refuse when a key is pinned and the caller did
        // not prove that exact key (a missing key counts as different).
        Some(pinned) => {
            let allowed = pinned.is_none() || pinned.as_deref() == public_key;
            if allowed {
                // Placeholders must appear once each, in ascending order (they map
                // to positional `?` on MySQL/SQLite), so `peer_id` is bound last.
                tx.execute(
                    &format!(
                        "UPDATE p2pnas.peers SET
                             addr = $1,
                             last_seen = {now},
                             zone = COALESCE(zone, $2),
                             public_key = COALESCE(public_key, $3),
                             verified_at = CASE WHEN $4 IS NULL THEN verified_at ELSE {now} END
                         WHERE peer_id = $5"
                    ),
                    params![addr, zone, public_key, public_key, peer_id],
                )
                .await?;
            }
            allowed
        }
    };

    tx.commit().await?;
    Ok(applied)
}
