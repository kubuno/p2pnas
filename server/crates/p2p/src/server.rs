//! P2P listener. Accepts connections and dispatches shard operations to a
//! `ShardHandler` provided by the host (the p2pnas module backs it with its
//! local shard store + the `hosted_shards` table).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::protocol::{
    pong_transcript, read_message, write_message, AuthenticatedPeer, P2pMessage, PeerAuthSession,
    PeerSigner, NONCE_LEN,
};

/// Ceiling on simultaneously-open peer connections. One task per connection with
/// no bound lets an attacker open thousands of connections that each announce a
/// large frame then dribble bytes, pinning memory until the node OOMs. A permit
/// is held for the whole connection.
const MAX_CONNECTIONS: usize = 256;

/// Max time to wait for the next frame on an open connection. A peer that opens a
/// connection and then stalls (slow-loris) is dropped rather than holding a slot
/// and its read buffer indefinitely.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Pause after an `accept` error so a persistent failure (EMFILE once file
/// descriptors are exhausted) cannot spin the accept loop at 100% CPU and flood
/// the logs.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What the listener needs from the host to answer peer requests.
#[async_trait]
pub trait ShardHandler: Send + Sync {
    fn peer_id(&self) -> String;
    fn api_port(&self) -> u16;
    /// Host a shard for another peer. Returns false on failure (e.g. quota).
    /// `shard_index` is the shard's position in its chunk (data shards below the
    /// data count, parity above); -1 when the caller did not supply it.
    async fn store(&self, fragment_id: &str, owner_peer_id: &str, shard_index: i32, data: Vec<u8>) -> bool;
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

    /// The key proving this node owns [`peer_id`](ShardHandler::peer_id).
    ///
    /// `None` (the default) disables the authenticated handshake: callers fall
    /// back to the legacy `Ping`/`Pong` and cannot pin this node's key. A real
    /// node must override it; the in-tree examples deliberately do not.
    fn signer(&self) -> Option<Arc<PeerSigner>> {
        None
    }

    /// Authenticated variant of [`store`](ShardHandler::store).
    ///
    /// `authenticated` is the identity the caller PROVED on this connection (see
    /// [`AuthenticatedPeer`]), or `None` when it never authenticated — an older
    /// client, or one that chose not to. Hosts that care about authorization
    /// override this and decide what an unauthenticated write is worth; the
    /// default keeps the pre-authentication behaviour so existing implementors
    /// (and the examples) still compile and work.
    async fn store_from(
        &self,
        authenticated: Option<&AuthenticatedPeer>,
        fragment_id: &str,
        owner_peer_id: &str,
        shard_index: i32,
        data: Vec<u8>,
    ) -> bool {
        let _ = authenticated;
        self.store(fragment_id, owner_peer_id, shard_index, data).await
    }

    /// Authenticated variant of [`delete`](ShardHandler::delete). Same contract
    /// as [`store_from`](ShardHandler::store_from).
    async fn delete_from(
        &self,
        authenticated: Option<&AuthenticatedPeer>,
        fragment_id: &str,
        owner_peer_id: &str,
    ) -> bool {
        let _ = authenticated;
        self.delete(fragment_id, owner_peer_id).await
    }
}

/// Accept loop. Run as a background task for the lifetime of the node.
pub async fn serve(listener: TcpListener, handler: Arc<dyn ShardHandler>) {
    let conn_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                // Refuse rather than queue when at capacity: the stream is
                // dropped (closed) and the attacker gains no held resource.
                let permit = match conn_limit.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(peer = %addr, "p2p connection refused: at capacity");
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let h = handler.clone();
                tokio::spawn(async move {
                    let _permit = permit; // held for the connection's lifetime
                    if let Err(e) = handle_conn(stream, h, addr.ip()).await {
                        tracing::debug!(peer = %addr, error = %e, "p2p connection ended");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "p2p accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    handler: Arc<dyn ShardHandler>,
    peer_ip: std::net::IpAddr,
) -> std::io::Result<()> {
    // Peer authentication is scoped to the CONNECTION: the challenge we mint and
    // the identity it proves live exactly as long as this socket. That is what
    // lets `StoreShard`/`DeleteShard` be attributed to a proven peer without any
    // cross-connection state (and therefore without a replay window).
    let mut session = PeerAuthSession::new();

    // Several request/response pairs may share one connection until it closes.
    loop {
        let msg = match tokio::time::timeout(READ_TIMEOUT, read_message(&mut stream)).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e),
            // Idle past the read timeout (slow-loris): close quietly.
            Err(_) => return Ok(()),
        };
        let resp = match msg {
            P2pMessage::Ping { .. } => P2pMessage::Pong {
                peer_id: handler.peer_id(),
                api_port: handler.api_port(),
                observed_addr: Some(peer_ip.to_string()),
            },
            P2pMessage::AuthPing { nonce, .. } => auth_pong(&handler, &nonce, peer_ip, &mut session),
            P2pMessage::AuthProof { peer_id, public_key, signature } => {
                if session.accept_proof(&handler.peer_id(), &peer_id, &public_key, &signature) {
                    tracing::debug!(peer = %peer_ip, peer_id = %peer_id, "p2p peer authenticated");
                    P2pMessage::AuthOk { peer_id }
                } else {
                    // Either no challenge was outstanding (proof sent out of
                    // order / replayed) or the signature did not verify.
                    tracing::warn!(peer = %peer_ip, peer_id = %peer_id, "p2p identity proof rejected");
                    P2pMessage::Error { message: "auth proof rejected".into() }
                }
            }
            P2pMessage::StoreShard { fragment_id, owner_peer_id, shard_index, data } => {
                if handler
                    .store_from(session.authenticated_peer(), &fragment_id, &owner_peer_id, shard_index, data)
                    .await
                {
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
                // A refusal is now reported instead of being masked by a blanket
                // `Ack`: the handler only answers false when it actively declined
                // (wrong owner, or an unproven identity under strict auth), and
                // the caller must not record the shard as gone in that case.
                // "Nothing hosted under this id" still answers true (idempotent).
                if handler
                    .delete_from(session.authenticated_peer(), &fragment_id, &owner_peer_id)
                    .await
                {
                    P2pMessage::Ack { fragment_id }
                } else {
                    P2pMessage::Error { message: "delete rejected".into() }
                }
            }
            // Never echo the request back: `{other:?}` on a large inbound frame
            // (e.g. a `ShardData` of 16 MiB sent in request position) builds a
            // multi-megabyte Debug string and returns it — a ~5× amplification at
            // no cost to the attacker. A fixed string is the only safe reply.
            _ => P2pMessage::Error { message: "unsupported request".into() },
        };
        write_message(&mut stream, &resp).await?;
    }
}

/// Build the signed answer to an `AuthPing`, and mint the challenge that lets the
/// caller authenticate itself on the same connection.
///
/// Any failure answers a plain `Error`, which the caller treats as "this peer
/// does not do authenticated handshakes" and downgrades to the legacy `Ping` —
/// never a dropped connection.
fn auth_pong(
    handler: &Arc<dyn ShardHandler>,
    nonce: &[u8],
    peer_ip: std::net::IpAddr,
    session: &mut PeerAuthSession,
) -> P2pMessage {
    // Fixed-size challenge only: a caller must not be able to make us sign an
    // attacker-chosen 16 MiB blob (nor to choose the transcript's shape).
    if nonce.len() != NONCE_LEN {
        return P2pMessage::Error { message: "bad challenge length".into() };
    }
    let Some(signer) = handler.signer() else {
        return P2pMessage::Error { message: "peer authentication unavailable".into() };
    };

    let peer_id = handler.peer_id();
    let api_port = handler.api_port();
    let observed = peer_ip.to_string();
    let signature = match signer.sign_hex(&pong_transcript(&peer_id, api_port, nonce, Some(&observed))) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(peer = %peer_ip, error = %e, "p2p handshake signing failed");
            return P2pMessage::Error { message: "signing failed".into() };
        }
    };
    let challenge = match session.issue_challenge() {
        Ok(c) => c.to_vec(),
        Err(e) => {
            tracing::warn!(peer = %peer_ip, error = %e, "p2p challenge generation failed");
            return P2pMessage::Error { message: "challenge unavailable".into() };
        }
    };

    P2pMessage::AuthPong {
        peer_id,
        api_port,
        observed_addr: Some(observed),
        public_key: signer.public_key_hex().to_string(),
        signature,
        challenge,
    }
}
