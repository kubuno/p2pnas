//! P2P listener. Accepts connections and dispatches shard operations to a
//! `ShardHandler` provided by the host (the p2pnas module backs it with its
//! local shard store + the `hosted_shards` table).

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};

use crate::protocol::{read_message, write_message, P2pMessage};

/// What the listener needs from the host to answer peer requests.
#[async_trait]
pub trait ShardHandler: Send + Sync {
    fn peer_id(&self) -> String;
    fn api_port(&self) -> u16;
    /// Host a shard for another peer. Returns false on failure (e.g. quota).
    async fn store(&self, fragment_id: &str, owner_peer_id: &str, data: Vec<u8>) -> bool;
    /// Return a hosted shard's bytes, or None.
    async fn get(&self, fragment_id: &str) -> Option<Vec<u8>>;
    /// Drop a hosted shard.
    async fn delete(&self, fragment_id: &str, owner_peer_id: &str) -> bool;
    /// Cheap existence check (no payload). Default: derived from `get`, but hosts
    /// should override with a metadata-only lookup.
    async fn has(&self, fragment_id: &str) -> bool {
        self.get(fragment_id).await.is_some()
    }
    /// Proof-of-storage: content hash of the held shard (empty if not held).
    /// Default reads + hashes the bytes; correct for any honest host.
    async fn audit(&self, fragment_id: &str) -> String {
        match self.get(fragment_id).await {
            Some(b) => crate::protocol::content_hash(&b),
            None => String::new(),
        }
    }
}

/// Accept loop. Run as a background task for the lifetime of the node.
pub async fn serve(listener: TcpListener, handler: Arc<dyn ShardHandler>) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let _ = stream.set_nodelay(true);
                let h = handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, h, addr.ip()).await {
                        tracing::debug!(peer = %addr, error = %e, "p2p connection ended");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "p2p accept failed"),
        }
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    handler: Arc<dyn ShardHandler>,
    peer_ip: std::net::IpAddr,
) -> std::io::Result<()> {
    // Several request/response pairs may share one connection until it closes.
    loop {
        let msg = match read_message(&mut stream).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let resp = match msg {
            P2pMessage::Ping { .. } => P2pMessage::Pong {
                peer_id: handler.peer_id(),
                api_port: handler.api_port(),
                observed_addr: Some(peer_ip.to_string()),
            },
            P2pMessage::StoreShard { fragment_id, owner_peer_id, data } => {
                if handler.store(&fragment_id, &owner_peer_id, data).await {
                    P2pMessage::Ack { fragment_id }
                } else {
                    P2pMessage::Error { message: "store rejected".into() }
                }
            }
            P2pMessage::GetShard { fragment_id } => match handler.get(&fragment_id).await {
                Some(data) => P2pMessage::ShardData { fragment_id, data },
                None => P2pMessage::ShardNotFound { fragment_id },
            },
            P2pMessage::HasShard { fragment_id } => {
                let present = handler.has(&fragment_id).await;
                P2pMessage::HasShardResult { fragment_id, present }
            }
            P2pMessage::AuditShard { fragment_id } => {
                let hash = handler.audit(&fragment_id).await;
                P2pMessage::AuditResult { fragment_id, hash }
            }
            P2pMessage::DeleteShard { fragment_id, owner_peer_id } => {
                handler.delete(&fragment_id, &owner_peer_id).await;
                P2pMessage::Ack { fragment_id }
            }
            other => P2pMessage::Error { message: format!("unsupported request: {other:?}") },
        };
        write_message(&mut stream, &resp).await?;
    }
}
