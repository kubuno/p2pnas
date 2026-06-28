//! p2pnas embedded P2P transport: length-prefixed JSON frames, a shard
//! store/fetch protocol, a listener (`serve`) driven by a host `ShardHandler`,
//! and client helpers (`request`, `handshake`). NAT relay / DHT come later.

pub mod client;
pub mod protocol;
pub mod server;

pub use client::{handshake, has_shard, ping, request};
pub use protocol::P2pMessage;
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
    }

    #[async_trait]
    impl ShardHandler for MemHandler {
        fn peer_id(&self) -> String { self.id.clone() }
        fn api_port(&self) -> u16 { self.port }
        async fn store(&self, fragment_id: &str, _owner: &str, data: Vec<u8>) -> bool {
            self.map.lock().await.insert(fragment_id.to_string(), data);
            true
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
        let handler = Arc::new(MemHandler { id: "node-b".into(), port: 3119, map: Mutex::new(HashMap::new()) });
        tokio::spawn(serve(listener, handler));

        // Handshake.
        let (peer_id, api_port) = handshake(&addr, "node-a", 3119).await.unwrap();
        assert_eq!(peer_id, "node-b");
        assert_eq!(api_port, 3119);

        // Store a shard on the peer.
        let ack = request(&addr, &P2pMessage::StoreShard {
            fragment_id: "frag-1".into(), owner_peer_id: "node-a".into(), data: vec![9, 8, 7, 6],
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
}
