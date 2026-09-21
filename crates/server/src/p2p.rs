//! Wires the embedded P2P listener to this node's shard store. Shards hosted FOR
//! other peers live in the same on-disk store, tracked in `p2pnas.hosted_shards`.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use kubuno_db::dialect::Assign;
use kubuno_db::{params, DbPool};
use p2pnas_p2p::{AuthenticatedPeer, P2pMessage, PeerSigner, ShardHandler};
use p2pnas_store::{ChunkStore, NodeIdentity};

/// Largest single shard we accept to host (a shard is ~chunk/DATA_SHARDS bytes;
/// 8 MiB is far above the default, and rejects an over-large/malicious frame).
const MAX_HOSTED_SHARD: i64 = 8 * 1024 * 1024;

/// HKDF label for the node's P2P signing key.
///
/// A dedicated domain so this key can never collide with the manifest key
/// (`p2pnas/manifest/v1`) or the peer id (`p2pnas/peer-id/v1`): all three come
/// out of the same master key and only the label separates them.
const P2P_KEY_INFO: &[u8] = b"p2pnas/p2p-ed25519/v1";

/// Environment switch: require a PROVEN peer identity for every shard write and
/// delete. Off by default so an existing network keeps working while nodes are
/// rolled out one at a time; every unauthenticated operation is logged as a
/// `warn!` so an operator can watch the last legacy peers disappear before
/// flipping it.
///
/// Enable with `P2PNAS_STRICT_PEER_AUTH=1` (also accepts `true`/`yes`) in the
/// module's systemd unit, then restart. Read once: a policy must not change
/// halfway through a run.
pub fn strict_peer_auth() -> bool {
    static STRICT: OnceLock<bool> = OnceLock::new();
    *STRICT.get_or_init(|| {
        let on = matches!(
            std::env::var("P2PNAS_STRICT_PEER_AUTH").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        );
        if on {
            tracing::info!("p2p: strict peer authentication enabled");
        }
        on
    })
}

/// The node's Ed25519 signing key, derived from the master key and built once
/// per process.
///
/// Derived on the fly rather than stored in `NodeIdentity`: the derivation is
/// deterministic, so it costs one HKDF plus one scalar multiplication at first
/// use and nothing afterwards, and no extra secret ends up in a struct that is
/// cloned throughout the module. Returns `None` only if the derivation fails,
/// in which case the node keeps serving but answers the legacy handshake and
/// cannot be pinned by its peers.
pub fn node_signer(identity: &NodeIdentity) -> Option<Arc<PeerSigner>> {
    static SIGNER: OnceLock<Option<Arc<PeerSigner>>> = OnceLock::new();
    SIGNER
        .get_or_init(|| {
            let seed = match identity.data_key.derive_raw(P2P_KEY_INFO) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "p2p signing key derivation failed");
                    return None;
                }
            };
            match PeerSigner::from_seed(&seed[..]) {
                Ok(s) => Some(Arc::new(s)),
                Err(e) => {
                    tracing::error!(error = %e, "p2p signing key initialisation failed");
                    None
                }
            }
        })
        .clone()
}

/// Send `msg` to `addr` over a connection where this node first PROVES its own
/// identity, so the remote can check the `owner_peer_id` we quote instead of
/// taking it on faith.
///
/// Use it for every `StoreShard` / `DeleteShard`. It degrades on its own: a
/// remote that does not speak the authenticated exchange gets a plain request
/// (its own policy then decides), and a node with no signing key never attempts
/// the exchange at all.
pub async fn signed_request(
    identity: &NodeIdentity,
    api_port: u16,
    addr: &str,
    msg: &P2pMessage,
) -> std::io::Result<P2pMessage> {
    match node_signer(identity) {
        Some(signer) => {
            p2pnas_p2p::authenticated_request(addr, &signer, &identity.peer_id, api_port, msg).await
        }
        None => p2pnas_p2p::request(addr, msg).await,
    }
}

pub struct P2pShardHandler {
    pub peer_id:  String,
    pub api_port: u16,
    pub store:    Arc<ChunkStore>,
    pub db:       DbPool,
    /// Key proving this node owns `peer_id` — see [`node_signer`]. `None`
    /// disables the authenticated handshake for this node.
    pub signer:   Option<Arc<PeerSigner>>,
}

impl P2pShardHandler {
    /// Bytes we already host for the given fragment (0 if none).
    async fn hosted_size(&self, fragment_id: &str) -> i64 {
        self.db
            .fetch_optional_scalar::<i64>(
                "SELECT size_bytes FROM p2pnas.hosted_shards WHERE fragment_id = $1",
                params![fragment_id],
            )
            .await
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    /// May the caller act on behalf of `owner_peer_id`?
    ///
    /// Two independent facts must hold, and the transport can only establish the
    /// first one:
    ///   1. the caller holds the private key behind the public key it presented
    ///      (proven by the connection handshake), and
    ///   2. that public key is the one WE pinned for `owner_peer_id` on first
    ///      encounter (`p2pnas.peers.public_key`).
    ///
    /// Without (2) anyone could mint a key pair and claim any peer id, which is
    /// exactly the impersonation this whole change exists to stop.
    async fn authorize_owner(&self, authenticated: Option<&AuthenticatedPeer>, owner_peer_id: &str) -> bool {
        let Some(caller) = authenticated else {
            // Legacy caller: nothing was proven. Refuse under strict auth,
            // otherwise accept and make the exposure visible in the logs.
            if strict_peer_auth() {
                tracing::warn!(owner_peer_id, "rejecting unauthenticated shard operation (strict peer auth)");
                return false;
            }
            tracing::warn!(
                owner_peer_id,
                "accepting an UNAUTHENTICATED shard operation — the peer id is only declared; \
                 set P2PNAS_STRICT_PEER_AUTH=1 once every peer has been upgraded"
            );
            return true;
        };

        if caller.peer_id != owner_peer_id {
            tracing::warn!(
                owner_peer_id,
                caller = %caller.peer_id,
                "rejecting shard operation: the authenticated peer is not the claimed owner"
            );
            return false;
        }

        let pinned: Option<(Option<String>,)> = self
            .db
            .fetch_optional_as("SELECT public_key FROM p2pnas.peers WHERE peer_id = $1", params![owner_peer_id])
            .await
            .unwrap_or_else(|e| {
                tracing::error!(owner_peer_id, error = %e, "peer key lookup failed");
                None
            });

        match pinned {
            // Unknown peer: unchanged from before, we only host for peers we know.
            None => {
                tracing::warn!(owner_peer_id, "rejecting shard operation from an unknown peer");
                false
            }
            // Known peer whose key we never pinned (discovered before this node
            // spoke the authenticated handshake). We deliberately do NOT pin it
            // here: an inbound connection is chosen by the caller, so pinning on
            // it would let whoever gets there first claim the identity. Pinning
            // only happens on a handshake WE initiated (`discovery::register_peer`).
            Some((None,)) => {
                if strict_peer_auth() {
                    tracing::warn!(owner_peer_id, "rejecting shard operation: no public key pinned for this peer (strict peer auth)");
                    return false;
                }
                tracing::warn!(owner_peer_id, "shard operation from a peer with no pinned public key — accepted in permissive mode");
                true
            }
            Some((Some(known),)) if known == caller.public_key => true,
            Some((Some(_),)) => {
                // The caller proved a key, but not the one we pinned: this is an
                // impersonation attempt (or a peer whose identity key was reset —
                // an operator then has to clear `p2pnas.peers.public_key` for it).
                tracing::warn!(owner_peer_id, "rejecting shard operation: public key does not match the pinned one");
                false
            }
        }
    }
}

#[async_trait]
impl ShardHandler for P2pShardHandler {
    fn peer_id(&self) -> String {
        self.peer_id.clone()
    }
    fn api_port(&self) -> u16 {
        self.api_port
    }
    fn signer(&self) -> Option<Arc<PeerSigner>> {
        self.signer.clone()
    }

    /// Authorization gate for hosting a shard: the caller must have PROVEN it is
    /// `owner_peer_id` (see [`P2pShardHandler::authorize_owner`]). Before this,
    /// `owner_peer_id` was a string the caller picked, so quoting any known peer
    /// id was enough to get past the "known peer" check below.
    async fn store_from(
        &self,
        authenticated: Option<&AuthenticatedPeer>,
        fragment_id: &str,
        owner_peer_id: &str,
        shard_index: i32,
        data: Vec<u8>,
    ) -> bool {
        if !self.authorize_owner(authenticated, owner_peer_id).await {
            return false;
        }
        self.store(fragment_id, owner_peer_id, shard_index, data).await
    }

    /// Same gate for dropping a shard — the destructive half. `delete` still
    /// checks the recorded owner; this makes the claimed owner unforgeable.
    async fn delete_from(
        &self,
        authenticated: Option<&AuthenticatedPeer>,
        fragment_id: &str,
        owner_peer_id: &str,
    ) -> bool {
        if !self.authorize_owner(authenticated, owner_peer_id).await {
            return false;
        }
        self.delete(fragment_id, owner_peer_id).await
    }

    async fn store(&self, fragment_id: &str, owner_peer_id: &str, shard_index: i32, data: Vec<u8>) -> bool {
        // Transport size (what arrived on the wire) guards the frame; the on-disk
        // COST (whole filesystem blocks, since each shard is its own file) is what
        // the capacity accounting must use — counting the raw length let this node
        // accept far more than it could actually hold.
        let size = data.len() as i64;
        let disk_cost = p2pnas_core::erasure::shard_disk_cost(data.len()) as i64;

        // (5) Size guard.
        if size > MAX_HOSTED_SHARD {
            tracing::warn!(fragment_id, size, "rejecting oversized hosted shard");
            return false;
        }

        // (3) Write authorization: only host for peers we know (trusted set /
        // discovered). Blocks a random internet host from filling our disk.
        let known: Option<(i32,)> = self
            .db
            .fetch_optional_as("SELECT 1 FROM p2pnas.peers WHERE peer_id = $1", params![owner_peer_id])
            .await
            .ok()
            .flatten();
        if known.is_none() {
            tracing::warn!(owner_peer_id, "rejecting StoreShard from unknown peer");
            return false;
        }

        // (4) Capacity: never host beyond what we contribute to the network.
        let (contributed, hosted): (i64, i64) = self
            .db
            .fetch_one_as("SELECT contributed_bytes, hosted_bytes FROM p2pnas.node_local WHERE id = 1", params![])
            .await
            .unwrap_or((0, 0));
        let old = self.hosted_size(fragment_id).await;
        if hosted - old + disk_cost > contributed {
            tracing::warn!(fragment_id, hosted, contributed, "rejecting hosted shard: contribution cap reached");
            return false;
        }

        if let Err(e) = self.store.write(fragment_id, &data) {
            tracing::warn!(fragment_id, error = %e, "hosted shard write failed");
            return false;
        }
        let be = self.db.backend();
        let upsert = be.upsert(
            "p2pnas.hosted_shards",
            &["fragment_id"],
            &[
                Assign::Incoming("owner_peer_id"),
                Assign::Incoming("size_bytes"),
                Assign::Incoming("shard_index"),
            ],
        );
        let r = self
            .db
            .execute(
                &format!(
                    "INSERT INTO p2pnas.hosted_shards (fragment_id, owner_peer_id, size_bytes, shard_index)
                     VALUES ($1, $2, $3, $4){upsert}"
                ),
                params![fragment_id, owner_peer_id, disk_cost, shard_index],
            )
            .await;
        if let Err(e) = r {
            tracing::warn!(fragment_id, error = %e, "hosted shard record failed");
            return false;
        }
        // (16) Accounting: net delta of hosted bytes.
        let (now, greatest) = (be.now(), crate::greatest(be));
        let _ = self
            .db
            .execute(
                &format!(
                    "UPDATE p2pnas.node_local
                        SET hosted_bytes = {greatest}(hosted_bytes + $1, 0), updated_at = {now}
                      WHERE id = 1"
                ),
                params![disk_cost - old],
            )
            .await;
        true
    }

    async fn get(&self, fragment_id: &str) -> Option<Vec<u8>> {
        // Only serve shards we actually host FOR a peer — never this node's own
        // shards. Together with fragment-id validation (which blocks reading
        // arbitrary files), this means a `GetShard` can only ever return a
        // ciphertext shard that was legitimately placed here.
        let hosted: Option<(i32,)> = self
            .db
            .fetch_optional_as("SELECT 1 FROM p2pnas.hosted_shards WHERE fragment_id = $1", params![fragment_id])
            .await
            .ok()
            .flatten();
        hosted?;
        self.store.read(fragment_id).ok()
    }

    async fn has(&self, fragment_id: &str) -> bool {
        self.store.exists(fragment_id)
    }

    async fn audit(&self, fragment_id: &str) -> String {
        match self.store.read(fragment_id) {
            Ok(b) => p2pnas_store::shard_hash(&b),
            Err(_) => String::new(),
        }
    }

    async fn delete(&self, fragment_id: &str, owner_peer_id: &str) -> bool {
        // Only the peer we host this shard FOR may delete it. Previously the
        // owner was ignored, so any node that learned a fragment_id could erase
        // it — destroying redundancy for free and, once enough copies were gone,
        // making the chunk permanently unrecoverable. We match the claimed owner
        // against the row we recorded at StoreShard time.
        //
        // `owner_peer_id` is trustworthy only when the caller came through
        // `delete_from`, which proves it owns that id. Reaching `delete` with an
        // unproven owner is the permissive transition mode (see
        // `strict_peer_auth`), and it is logged as such.
        let recorded: Option<(String,)> = self
            .db
            .fetch_optional_as(
                "SELECT owner_peer_id FROM p2pnas.hosted_shards WHERE fragment_id = $1",
                params![fragment_id],
            )
            .await
            .ok()
            .flatten();
        match recorded {
            // Nothing hosted under this id: idempotent success, delete nothing.
            None => return true,
            Some((owner,)) if owner == owner_peer_id => {}
            Some(_) => {
                tracing::warn!(fragment_id, owner_peer_id, "rejecting DeleteShard: owner mismatch");
                return false;
            }
        }

        let old = self.hosted_size(fragment_id).await;
        let _ = self.store.delete(fragment_id);
        let _ = self
            .db
            .execute("DELETE FROM p2pnas.hosted_shards WHERE fragment_id = $1", params![fragment_id])
            .await;
        let be = self.db.backend();
        let (now, greatest) = (be.now(), crate::greatest(be));
        let _ = self
            .db
            .execute(
                &format!(
                    "UPDATE p2pnas.node_local
                        SET hosted_bytes = {greatest}(hosted_bytes - $1, 0), updated_at = {now}
                      WHERE id = 1"
                ),
                params![old],
            )
            .await;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2pnas_core::crypto::{DataKey, KEY_LEN};

    /// Locks the P2P identity to the node master key. The public key is what
    /// every peer pins on first encounter, so a change here would make an
    /// upgraded node look like an impostor to the whole network — exactly the
    /// situation `authorize_owner` refuses.
    ///
    /// Vectors: HKDF-SHA256(salt = "p2pnas/file-subkey/v1", ikm = 0x00..0x1f,
    /// info = "p2pnas/p2p-ed25519/v1") → seed → Ed25519 public key.
    #[test]
    fn p2p_key_derivation_is_byte_stable() {
        let mut raw = [0u8; KEY_LEN];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key = DataKey::from_bytes(raw);

        let seed = key.derive_raw(P2P_KEY_INFO).unwrap();
        assert_eq!(
            hex_lower(&seed[..]),
            "e07a65cab85d39d3c3e23a41bc5e050876fc43e82d0b47ea6d2e1869a4b67d10"
        );

        let signer = PeerSigner::from_seed(&seed[..]).unwrap();
        assert_eq!(
            signer.public_key_hex(),
            "34a5ecb6e632ad296689ad41212f616e169f5df49d98a6c098e5130f39ff22b7"
        );

        // The signing key must never be one of the node's other derived secrets.
        assert_ne!(&seed[..], &key.derive_raw(b"p2pnas/manifest/v1").unwrap()[..]);
        assert_ne!(&seed[..], &key.as_bytes()[..]);
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
