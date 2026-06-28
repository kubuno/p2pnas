//! Wire protocol: length-prefixed (u32 LE) JSON frames, one request → one
//! response per round-trip. Mirrors ptopnas's framing. Shard payloads are small
//! (one RS shard ≈ ≤512 KiB) so JSON encoding of the byte array is acceptable
//! for now; a compact codec can replace it later without changing call sites.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Hard cap on a single frame (guards against a malicious length prefix).
pub const MAX_MESSAGE_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum P2pMessage {
    /// Liveness + identity handshake.
    Ping { peer_id: String, api_port: u16 },
    Pong { peer_id: String, api_port: u16 },

    /// Ask the remote to host `data` (a shard owned by `owner_peer_id`).
    StoreShard { fragment_id: String, owner_peer_id: String, data: Vec<u8> },
    Ack { fragment_id: String },

    /// Retrieve a previously stored shard.
    GetShard { fragment_id: String },
    ShardData { fragment_id: String, data: Vec<u8> },
    ShardNotFound { fragment_id: String },

    /// Cheap existence probe (no payload transfer) — used by the scrubber/repair
    /// pass to check a shard is still held without pulling its bytes.
    HasShard { fragment_id: String },
    HasShardResult { fragment_id: String, present: bool },

    /// Drop a shard the owner no longer needs.
    DeleteShard { fragment_id: String, owner_peer_id: String },

    Error { message: String },
}

pub async fn read_message(stream: &mut TcpStream) -> std::io::Result<P2pMessage> {
    let len = stream.read_u32_le().await?;
    if len > MAX_MESSAGE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("p2p frame too large: {len} bytes (max {MAX_MESSAGE_BYTES})"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

pub async fn write_message(stream: &mut TcpStream, msg: &P2pMessage) -> std::io::Result<()> {
    let data = serde_json::to_vec(msg).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    stream.write_u32_le(data.len() as u32).await?;
    stream.write_all(&data).await?;
    stream.flush().await?;
    Ok(())
}
