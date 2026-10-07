//! p2pnas embedded P2P transport: length-prefixed JSON frames, a shard
//! store/fetch protocol, a listener (`serve`) driven by a host `ShardHandler`,
//! and client helpers (`request`, `handshake`). NAT relay / DHT come later.
//!
//! Peer identity is CHALLENGED, not declared. A `peer_id` is public, so
//! [`handshake_verified`] makes the responder sign a fresh nonce with the Ed25519
//! key behind it, and [`authenticated_request`] additionally proves the caller's
//! own identity on the same connection before the request travels. The host then
//! decides what a proven identity is worth (it pins the key on first use). The
//! legacy `Ping`/`Pong` and unauthenticated requests still work, so a network can
//! be upgraded node by node.

pub mod client;
pub mod dht;
pub mod protocol;
pub mod server;

pub use client::{
    audit_shard, authenticated_request, handshake, handshake_verified, has_shard, ping,
    ping_observed, ping_rtt, request, VerifiedPeer,
};
pub use dht::{DhtNode, PersistNode};
pub use protocol::{
    content_hash, proof_transcript, pong_transcript, random_nonce, verify_signature, AuthError,
    AuthenticatedPeer, P2pMessage, PeerAuthSession, PeerSigner, NONCE_LEN,
};
pub use server::{serve, ShardHandler};

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    struct MemHandler {
        id: String,
        port: u16,
        map: Mutex<HashMap<String, Vec<u8>>>,
        signer: Option<Arc<PeerSigner>>,
        /// Identity proven by the last `store` caller, so a test can assert what
        /// the listener actually attributed the write to.
        last_writer: Mutex<Option<AuthenticatedPeer>>,
    }

    impl MemHandler {
        fn new(id: &str, signer: Option<Arc<PeerSigner>>) -> Self {
            MemHandler {
                id: id.into(),
                port: 3119,
                map: Mutex::new(HashMap::new()),
                signer,
                last_writer: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl ShardHandler for MemHandler {
        fn peer_id(&self) -> String { self.id.clone() }
        fn api_port(&self) -> u16 { self.port }
        fn signer(&self) -> Option<Arc<PeerSigner>> { self.signer.clone() }
        async fn store(&self, fragment_id: &str, _owner: &str, _shard_index: i32, data: Vec<u8>) -> bool {
            self.map.lock().await.insert(fragment_id.to_string(), data);
            true
        }
        async fn store_from(
            &self,
            authenticated: Option<&AuthenticatedPeer>,
            fragment_id: &str,
            owner_peer_id: &str,
            shard_index: i32,
            data: Vec<u8>,
        ) -> bool {
            *self.last_writer.lock().await = authenticated.cloned();
            self.store(fragment_id, owner_peer_id, shard_index, data).await
        }
        async fn get(&self, fragment_id: &str) -> Option<Vec<u8>> {
            self.map.lock().await.get(fragment_id).cloned()
        }
        async fn delete(&self, fragment_id: &str, _owner: &str) -> bool {
            self.map.lock().await.remove(fragment_id).is_some()
        }
    }

    #[tokio::test]
    async fn ping_store_get_delete_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handler = Arc::new(MemHandler::new("node-b", None));
        tokio::spawn(serve(listener, handler));

        // Handshake.
        let (peer_id, api_port) = handshake(&addr, "node-a", 3119).await.unwrap();
        assert_eq!(peer_id, "node-b");
        assert_eq!(api_port, 3119);

        // Store a shard on the peer.
        let ack = request(&addr, &P2pMessage::StoreShard {
            fragment_id: "frag-1".into(), owner_peer_id: "node-a".into(), shard_index: 0, data: vec![9, 8, 7, 6],
        }).await.unwrap();
        assert_eq!(ack, P2pMessage::Ack { fragment_id: "frag-1".into() });

        // Fetch it back.
        let got = request(&addr, &P2pMessage::GetShard { fragment_id: "frag-1".into() }).await.unwrap();
        assert_eq!(got, P2pMessage::ShardData { fragment_id: "frag-1".into(), data: vec![9, 8, 7, 6] });

        // Existence probe: present vs absent.
        assert!(has_shard(&addr, "frag-1").await.unwrap());
        assert!(!has_shard(&addr, "nope").await.unwrap());

        // Missing shard.
        let miss = request(&addr, &P2pMessage::GetShard { fragment_id: "nope".into() }).await.unwrap();
        assert_eq!(miss, P2pMessage::ShardNotFound { fragment_id: "nope".into() });

        // Delete, then it's gone.
        request(&addr, &P2pMessage::DeleteShard { fragment_id: "frag-1".into(), owner_peer_id: "node-a".into() }).await.unwrap();
        let after = request(&addr, &P2pMessage::GetShard { fragment_id: "frag-1".into() }).await.unwrap();
        assert_eq!(after, P2pMessage::ShardNotFound { fragment_id: "frag-1".into() });
    }

    /// End-to-end: the listener proves its identity, the caller proves its own on
    /// the same connection, and the write is attributed to the proven peer.
    #[tokio::test]
    async fn authenticated_handshake_and_write() {
        let host_key = Arc::new(PeerSigner::from_seed(&[11u8; 32]).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handler = Arc::new(MemHandler::new("node-b", Some(host_key.clone())));
        tokio::spawn(serve(listener, handler.clone()));

        let peer = handshake_verified(&addr, "node-a", 3119).await.unwrap();
        assert!(peer.is_authenticated());
        assert_eq!(peer.peer_id, "node-b");
        assert_eq!(peer.public_key.as_deref(), Some(host_key.public_key_hex()));
        assert_eq!(peer.observed_addr.as_deref(), Some("127.0.0.1"));

        let caller = PeerSigner::from_seed(&[22u8; 32]).unwrap();
        let msg = P2pMessage::StoreShard {
            fragment_id: "frag-a".into(), owner_peer_id: "node-a".into(), shard_index: 0, data: vec![1, 2, 3],
        };
        let ack = authenticated_request(&addr, &caller, "node-a", 3119, &msg).await.unwrap();
        assert_eq!(ack, P2pMessage::Ack { fragment_id: "frag-a".into() });

        let writer = handler.last_writer.lock().await.clone().unwrap();
        assert_eq!(writer.peer_id, "node-a");
        assert_eq!(writer.public_key, caller.public_key_hex());
    }

    /// A peer with no signing key still answers the legacy handshake, and the
    /// result is explicitly flagged as unproven instead of failing the caller.
    #[tokio::test]
    async fn handshake_falls_back_when_the_peer_cannot_prove_itself() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(serve(listener, Arc::new(MemHandler::new("node-b", None))));

        let peer = handshake_verified(&addr, "node-a", 3119).await.unwrap();
        assert!(!peer.is_authenticated());
        assert_eq!(peer.peer_id, "node-b");

        // And a write still goes through, unattributed — the transition mode the
        // host decides to accept or refuse.
        let caller = PeerSigner::from_seed(&[33u8; 32]).unwrap();
        let msg = P2pMessage::StoreShard {
            fragment_id: "frag-b".into(), owner_peer_id: "node-a".into(), shard_index: 0, data: vec![4],
        };
        let ack = authenticated_request(&addr, &caller, "node-a", 3119, &msg).await.unwrap();
        assert_eq!(ack, P2pMessage::Ack { fragment_id: "frag-b".into() });
    }
}
