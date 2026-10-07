//! P2P client helpers: one connection per request/response round-trip.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::protocol::{
    pong_transcript, proof_transcript, random_nonce, read_message, verify_signature, write_message,
    P2pMessage, PeerSigner,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect budget for the *read* path (shard retrieval during a download).
///
/// Deliberately much shorter than [`CONNECT_TIMEOUT`]: reconstructing a file walks
/// every chunk, and each chunk that still lists a shard on a host which has since
/// gone offline pays a connect timeout again — a 1 GiB file is ~256 chunks, so the
/// default budget would add ~256 × 5 s of pure waiting to a read the erasure code
/// can serve without that host at all. On the control plane the trade-off runs the
/// other way (wrongly declaring a slow-but-alive peer dead costs durability), which
/// is why this is a per-call override and not the global default.
pub const READ_CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Connect to `addr`, send `msg`, return the single response.
pub async fn request(addr: &str, msg: &P2pMessage) -> std::io::Result<P2pMessage> {
    request_with_timeout(addr, msg, CONNECT_TIMEOUT).await
}

/// Same as [`request`], with a caller-chosen budget for the CONNECT phase only.
/// Once the peer has answered, the transfer still gets the full `IO_TIMEOUT`: a
/// short budget is meant to detect an unreachable host quickly, never to cut off
/// a large shard that is legitimately still arriving.
pub async fn request_with_timeout(
    addr: &str,
    msg: &P2pMessage,
    connect_timeout: Duration,
) -> std::io::Result<P2pMessage> {
    let mut stream = timeout(connect_timeout, TcpStream::connect(addr))
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
        P2pMessage::Pong { peer_id, api_port, .. } => Ok((peer_id, api_port)),
        other => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("expected Pong, got {other:?}"))),
    }
}

/// The outcome of an authenticated handshake.
///
/// `public_key` is `Some` only when the peer actually PROVED, against a fresh
/// challenge, that it holds the key behind `peer_id`. It is `None` when the peer
/// answered the legacy handshake (older build, or no signing key): the identity
/// is then merely *declared* and must not be trusted to move an address around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeer {
    pub peer_id:       String,
    pub api_port:      u16,
    pub observed_addr: Option<String>,
    pub public_key:    Option<String>,
}

impl VerifiedPeer {
    pub fn is_authenticated(&self) -> bool {
        self.public_key.is_some()
    }
}

/// Handshake that CHALLENGES the peer: it must sign our nonce with the key
/// behind the `peer_id` it announces before we believe anything it says.
///
/// Compatibility: a peer that cannot answer an `AuthPing` (older build — the
/// frame does not even decode there — or one with no signing key) is retried with
/// the legacy `Ping`, and the result comes back with `public_key: None`. A peer
/// that answers with a signature that does NOT verify is an impostor and yields
/// an error; that case is never downgraded.
pub async fn handshake_verified(addr: &str, my_peer_id: &str, my_api_port: u16) -> std::io::Result<VerifiedPeer> {
    let nonce = random_nonce()?;
    let ping = P2pMessage::AuthPing {
        peer_id:  my_peer_id.to_string(),
        api_port: my_api_port,
        nonce:    nonce.to_vec(),
    };
    match request(addr, &ping).await {
        Ok(P2pMessage::AuthPong { peer_id, api_port, observed_addr, public_key, signature, .. }) => {
            let message = pong_transcript(&peer_id, api_port, &nonce, observed_addr.as_deref());
            if !verify_signature(&public_key, &message, &signature) {
                tracing::warn!(addr, peer_id, "p2p handshake signature rejected — refusing the peer");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "handshake signature rejected",
                ));
            }
            Ok(VerifiedPeer { peer_id, api_port, observed_addr, public_key: Some(public_key) })
        }
        // Anything else (an `Error` reply, or a transport failure because the
        // remote could not decode an unknown variant) means "no authenticated
        // handshake here" — fall back so a mixed-version network keeps working.
        other => {
            if let Err(e) = &other {
                tracing::debug!(addr, error = %e, "authenticated handshake unavailable; falling back to Ping");
            }
            let (peer_id, api_port, observed_addr) = legacy_handshake(addr, my_peer_id, my_api_port).await?;
            Ok(VerifiedPeer { peer_id, api_port, observed_addr, public_key: None })
        }
    }
}

/// Legacy (unauthenticated) Ping/Pong, kept for peers that predate the signed
/// handshake.
async fn legacy_handshake(
    addr: &str,
    my_peer_id: &str,
    my_api_port: u16,
) -> std::io::Result<(String, u16, Option<String>)> {
    let resp = request(addr, &P2pMessage::Ping { peer_id: my_peer_id.to_string(), api_port: my_api_port }).await?;
    match resp {
        P2pMessage::Pong { peer_id, api_port, observed_addr } => Ok((peer_id, api_port, observed_addr)),
        other => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("expected Pong, got {other:?}"))),
    }
}

/// Send `msg` over a connection on which we first PROVED our own identity, so the
/// remote can attribute the operation to a peer id we actually own. Use this for
/// every `StoreShard` / `DeleteShard`: those quote an `owner_peer_id` that the
/// remote must be able to check.
///
/// Transition behaviour: if the remote does not speak the authenticated exchange
/// (or refuses our proof), the message is retried as a plain request on a new
/// connection and the remote's own policy decides whether to honour it (see the
/// host's strict-auth switch). The one case never downgraded is the remote
/// failing to prove ITS identity — we do not hand shards to an impostor.
pub async fn authenticated_request(
    addr: &str,
    signer: &PeerSigner,
    my_peer_id: &str,
    my_api_port: u16,
    msg: &P2pMessage,
) -> std::io::Result<P2pMessage> {
    match authenticated_session(addr, signer, my_peer_id, my_api_port, msg).await {
        Ok(resp) => Ok(resp),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(e),
        Err(e) => {
            tracing::debug!(addr, error = %e, "authenticated request unavailable; falling back to a plain request");
            request(addr, msg).await
        }
    }
}

/// One connection carrying: our challenge → the peer's signed answer + its
/// challenge → our signed proof → the actual request.
async fn authenticated_session(
    addr: &str,
    signer: &PeerSigner,
    my_peer_id: &str,
    my_api_port: u16,
    msg: &P2pMessage,
) -> std::io::Result<P2pMessage> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = stream.set_nodelay(true);
    timeout(IO_TIMEOUT, async {
        let nonce = random_nonce()?;
        let ping = P2pMessage::AuthPing {
            peer_id:  my_peer_id.to_string(),
            api_port: my_api_port,
            nonce:    nonce.to_vec(),
        };
        write_message(&mut stream, &ping).await?;

        // Leg 1 — the peer proves who it is (we are about to hand it our data).
        let (remote_peer_id, challenge) = match read_message(&mut stream).await? {
            P2pMessage::AuthPong { peer_id, api_port, observed_addr, public_key, signature, challenge } => {
                let message = pong_transcript(&peer_id, api_port, &nonce, observed_addr.as_deref());
                if !verify_signature(&public_key, &message, &signature) {
                    tracing::warn!(addr, peer_id, "p2p peer failed to prove its identity");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "peer handshake signature rejected",
                    ));
                }
                (peer_id, challenge)
            }
            // Deliberately without `{:?}` of the frame: Debug-formatting an
            // inbound 16 MiB message just to build an error string is the same
            // amplification the listener refuses to do.
            _ => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected AuthPong"));
            }
        };

        // Leg 2 — we prove who we are, bound to the peer's challenge AND to its
        // identity, so this proof is worthless anywhere else.
        let proof = proof_transcript(&remote_peer_id, my_peer_id, &challenge);
        let signature = signer.sign_hex(&proof)?;
        write_message(&mut stream, &P2pMessage::AuthProof {
            peer_id:    my_peer_id.to_string(),
            public_key: signer.public_key_hex().to_string(),
            signature,
        })
        .await?;
        match read_message(&mut stream).await? {
            P2pMessage::AuthOk { .. } => {}
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "identity proof refused")),
        }

        // The request itself, on the now-authenticated connection.
        write_message(&mut stream, msg).await?;
        read_message(&mut stream).await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "io timeout"))?
}

/// Ping a peer and return (rtt_ms, the public IP the peer saw us at). Used to
/// discover our own public IP STUN-style and detect a location change.
pub async fn ping_observed(addr: &str, my_peer_id: &str, my_api_port: u16) -> std::io::Result<(f64, Option<String>)> {
    let start = std::time::Instant::now();
    let resp = request(addr, &P2pMessage::Ping { peer_id: my_peer_id.to_string(), api_port: my_api_port }).await?;
    let rtt = start.elapsed().as_secs_f64() * 1000.0;
    match resp {
        P2pMessage::Pong { observed_addr, .. } => Ok((rtt, observed_addr)),
        other => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("expected Pong, got {other:?}"))),
    }
}
