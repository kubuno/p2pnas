//! P2P client helpers: one connection per request/response round-trip.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::protocol::{read_message, write_message, P2pMessage};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect to `addr`, send `msg`, return the single response.
pub async fn request(addr: &str, msg: &P2pMessage) -> std::io::Result<P2pMessage> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = stream.set_nodelay(true); // shard round-trips are latency-sensitive
    timeout(IO_TIMEOUT, async {
        write_message(&mut stream, msg).await?;
        read_message(&mut stream).await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "io timeout"))?
}

/// Probe whether a peer still holds a shard (no bytes transferred).
pub async fn has_shard(addr: &str, fragment_id: &str) -> std::io::Result<bool> {
    match request(addr, &P2pMessage::HasShard { fragment_id: fragment_id.to_string() }).await? {
        P2pMessage::HasShardResult { present, .. } => Ok(present),
        other => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("expected HasShardResult, got {other:?}"))),
    }
}

/// Proof-of-storage probe: returns the host's content hash for a shard (empty
/// string if the host doesn't hold it).
pub async fn audit_shard(addr: &str, fragment_id: &str) -> std::io::Result<String> {
    match request(addr, &P2pMessage::AuditShard { fragment_id: fragment_id.to_string() }).await? {
        P2pMessage::AuditResult { hash, .. } => Ok(hash),
        other => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("expected AuditResult, got {other:?}"))),
    }
}

/// Liveness probe: returns Ok if the peer answers a Ping with a Pong.
pub async fn ping(addr: &str, my_peer_id: &str, my_api_port: u16) -> std::io::Result<()> {
    handshake(addr, my_peer_id, my_api_port).await.map(|_| ())
}

/// Liveness + latency probe: returns the Ping→Pong round-trip time in
/// milliseconds (used to score peers for latency-aware placement).
pub async fn ping_rtt(addr: &str, my_peer_id: &str, my_api_port: u16) -> std::io::Result<f64> {
    let start = std::time::Instant::now();
    handshake(addr, my_peer_id, my_api_port).await?;
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

/// Handshake: Ping a peer and return its (peer_id, api_port) from the Pong.
pub async fn handshake(addr: &str, my_peer_id: &str, my_api_port: u16) -> std::io::Result<(String, u16)> {
    let resp = request(addr, &P2pMessage::Ping { peer_id: my_peer_id.to_string(), api_port: my_api_port }).await?;
    match resp {
        P2pMessage::Pong { peer_id, api_port } => Ok((peer_id, api_port)),
        other => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("expected Pong, got {other:?}"))),
    }
}
