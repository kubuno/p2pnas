//! Wire protocol: length-prefixed (u32 LE) JSON frames, one request → one
//! response per round-trip. Mirrors ptopnas's framing. Shard payloads are small
//! (one RS shard ≈ ≤512 KiB) so JSON encoding of the byte array is acceptable
//! for now; a compact codec can replace it later without changing call sites.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Hard cap on a single frame (guards against a malicious length prefix).
pub const MAX_MESSAGE_BYTES: u32 = 16 * 1024 * 1024;

/// Length of a handshake challenge. 32 random bytes make a replay across
/// connections computationally impossible without any server-side state.
pub const NONCE_LEN: usize = 32;

/// Ed25519 sizes, restated here so a malformed hex string is rejected on length
/// before it ever reaches the verifier.
const ED25519_SEED_LEN: usize = 32;
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

/// Domain tag for the proof a responder returns in an `AuthPong`.
const HANDSHAKE_CONTEXT: &[u8] = b"p2pnas/handshake/v1";
/// Domain tag for the proof an initiator returns in an `AuthProof`. Distinct
/// from `HANDSHAKE_CONTEXT` so a signature produced for one leg of the exchange
/// can never be presented as the other.
const PROOF_CONTEXT: &[u8] = b"p2pnas/peer-proof/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum P2pMessage {
    /// Liveness + identity handshake. The Pong echoes the source IP the responder
    /// saw (`observed_addr`), giving the pinger a STUN-style view of its own public
    /// IP without any external service.
    Ping { peer_id: String, api_port: u16 },
    Pong { peer_id: String, api_port: u16, observed_addr: Option<String> },

    /// Ask the remote to host `data` (a shard owned by `owner_peer_id`).
    // `shard_index` lets the host know whether this is a data or a parity shard,
    // so it can shed parity first when reclaiming space from an absent owner.
    // (Adding a field renumbers no variant — bincode keys variants by order — so
    // this stays wire-compatible with peers as long as they are on the same build.)
    StoreShard { fragment_id: String, owner_peer_id: String, shard_index: i32, data: Vec<u8> },
    Ack { fragment_id: String },

    /// Retrieve a previously stored shard.
    GetShard { fragment_id: String },
    ShardData { fragment_id: String, data: Vec<u8> },
    ShardNotFound { fragment_id: String },

    /// Cheap existence probe (no payload transfer) — used by the scrubber/repair
    /// pass to check a shard is still held without pulling its bytes.
    HasShard { fragment_id: String },
    HasShardResult { fragment_id: String, present: bool },

    /// Lightweight proof-of-storage: ask the host to return the content hash of a
    /// shard it holds. The owner checks it against the hash recorded in its
    /// manifest, detecting silent corruption/loss a bare `HasShard` would miss.
    /// (Empty hash = not held.) Does not defeat a peer that retains only the hash.
    AuditShard { fragment_id: String },
    AuditResult { fragment_id: String, hash: String },

    /// Drop a shard the owner no longer needs.
    DeleteShard { fragment_id: String, owner_peer_id: String },

    Error { message: String },

    // ── Authenticated handshake (v2) ──────────────────────────────────────────
    // These variants are APPENDED after every pre-existing one on purpose:
    // bincode encodes an enum as its positional index, so appending leaves the
    // wire meaning of `Ping`..`Error` untouched. A peer running an older build
    // cannot decode them — it errors out and closes the connection — which the
    // client turns into a fallback to the legacy `Ping`, never into a crash.
    /// Authenticated liveness + identity handshake. `nonce` is a fresh random
    /// challenge (exactly [`NONCE_LEN`] bytes) that the responder must sign to
    /// prove it holds the key behind the `peer_id` it announces.
    AuthPing { peer_id: String, api_port: u16, nonce: Vec<u8> },
    /// Answer to an `AuthPing`. `signature` covers [`pong_transcript`], which
    /// binds the announced `peer_id`, the api port, the caller's challenge and
    /// the address the responder saw — so the proof cannot be replayed towards
    /// another node, for another identity, or from another address.
    ///
    /// `challenge` is the responder's own fresh nonce, letting the SAME
    /// connection authenticate the caller in the other direction (`AuthProof`).
    AuthPong {
        peer_id:       String,
        api_port:      u16,
        observed_addr: Option<String>,
        /// Ed25519 public key, hex-encoded (32 bytes → 64 hex chars).
        public_key:    String,
        /// Ed25519 signature, hex-encoded (64 bytes → 128 hex chars).
        signature:     String,
        challenge:     Vec<u8>,
    },
    /// Second leg: the initiator proves it owns the `peer_id` it will quote as
    /// `owner_peer_id` in the shard operations that follow on this connection.
    AuthProof { peer_id: String, public_key: String, signature: String },
    /// The proof was accepted; subsequent frames on this connection are
    /// attributed to `peer_id`.
    AuthOk { peer_id: String },
}

/// What went wrong in the signing/verification path. A local enum rather than a
/// new dependency: the p2p crate deliberately carries no error framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The seed or the public key was malformed / rejected by the backend.
    Key,
    /// The signing operation itself failed.
    Sign,
    /// The system RNG refused to produce a challenge.
    Rng,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthError::Key => "invalid peer signing key",
            AuthError::Sign => "peer signature failed",
            AuthError::Rng => "system rng failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AuthError {}

impl From<AuthError> for std::io::Error {
    fn from(e: AuthError) -> Self {
        std::io::Error::other(e)
    }
}

/// A peer identity that was actually PROVEN on a connection: the remote holds the
/// private key matching `public_key` and claims to be `peer_id`.
///
/// Binding `peer_id` → `public_key` is deliberately NOT done here: only the host
/// knows which key it pinned for that peer (trust on first use, in the control
/// plane). Without that second check a stranger can still generate a key pair and
/// claim any peer id, so a host MUST compare `public_key` against its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub peer_id:    String,
    pub public_key: String,
}

/// This node's Ed25519 signing key. Built from a 32-byte seed derived from the
/// node master key, so it is stable across restarts and never stored separately.
pub struct PeerSigner {
    key_pair:       Ed25519KeyPair,
    public_key_hex: String,
}

impl PeerSigner {
    /// Build the signer from a 32-byte seed (an HKDF output of the node key).
    pub fn from_seed(seed: &[u8]) -> Result<Self, AuthError> {
        // `from_seed_unchecked` only requires *at least* 32 bytes and would
        // silently ignore extra ones, so pin the length ourselves: two different
        // seeds sharing a 32-byte prefix must never yield the same identity.
        if seed.len() != ED25519_SEED_LEN {
            return Err(AuthError::Key);
        }
        let key_pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| AuthError::Key)?;
        let public_key_hex = to_hex(key_pair.public_key().as_ref());
        Ok(PeerSigner { key_pair, public_key_hex })
    }

    /// Hex-encoded public key, as it travels on the wire and is pinned in the
    /// control plane.
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Sign a transcript, returning the hex signature.
    pub fn sign_hex(&self, message: &[u8]) -> Result<String, AuthError> {
        let sig = self.key_pair.try_sign(message).map_err(|_| AuthError::Sign)?;
        Ok(to_hex(sig.as_ref()))
    }
}

/// Fresh challenge for a handshake.
pub fn random_nonce() -> Result<[u8; NONCE_LEN], AuthError> {
    let mut n = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut n).map_err(|_| AuthError::Rng)?;
    Ok(n)
}

/// Bytes signed by the responder of an `AuthPing`.
///
/// Everything the caller will act upon is inside the signature: the identity
/// (`peer_id`), where to reach it (`api_port`), the challenge that makes the
/// proof fresh, and the address the responder observed — so a signature captured
/// on one link cannot be replayed by a relay sitting on another.
pub fn pong_transcript(peer_id: &str, api_port: u16, nonce: &[u8], observed_addr: Option<&str>) -> Vec<u8> {
    transcript(
        HANDSHAKE_CONTEXT,
        &[peer_id.as_bytes(), &api_port.to_be_bytes(), nonce, observed_addr.unwrap_or("").as_bytes()],
    )
}

/// Bytes signed by the initiator in an `AuthProof`.
///
/// `verifier_peer_id` (the identity the responder just proved) is inside the
/// signature so the proof is useless anywhere else: a malicious node cannot
/// forward a proof it collected to a third peer and pass as its author.
pub fn proof_transcript(verifier_peer_id: &str, claimed_peer_id: &str, challenge: &[u8]) -> Vec<u8> {
    transcript(PROOF_CONTEXT, &[verifier_peer_id.as_bytes(), claimed_peer_id.as_bytes(), challenge])
}

/// Verify a hex signature over `message` with a hex Ed25519 public key.
/// Returns false — never an error — on any malformed input, so no call site can
/// accidentally treat "could not parse" as "verified".
pub fn verify_signature(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let (Some(key), Some(sig)) = (from_hex(public_key_hex), from_hex(signature_hex)) else {
        return false;
    };
    if key.len() != ED25519_PUBLIC_KEY_LEN || sig.len() != ED25519_SIGNATURE_LEN {
        return false;
    }
    UnparsedPublicKey::new(&ED25519, key).verify(message, &sig).is_ok()
}

/// Per-connection challenge/response state kept by the listener.
///
/// One instance lives for the lifetime of a connection: the challenge it mints is
/// consumed by the first `AuthProof` attempt (pass or fail), so a captured proof
/// can never be replayed — not on a later connection (fresh random challenge) nor
/// on the same one (the challenge is gone).
#[derive(Default)]
pub struct PeerAuthSession {
    challenge: Option<[u8; NONCE_LEN]>,
    peer:      Option<AuthenticatedPeer>,
}

impl PeerAuthSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint the challenge carried by an `AuthPong`. Any previous, unanswered
    /// challenge is dropped, so only the most recent one is ever accepted.
    pub fn issue_challenge(&mut self) -> Result<[u8; NONCE_LEN], AuthError> {
        let n = random_nonce()?;
        self.challenge = Some(n);
        Ok(n)
    }

    /// Check an `AuthProof` against the outstanding challenge. `local_peer_id` is
    /// this node's own id, which the proof must be bound to.
    ///
    /// The challenge is consumed unconditionally: a failed attempt does not leave
    /// a live challenge for the attacker to keep grinding against.
    pub fn accept_proof(
        &mut self,
        local_peer_id: &str,
        peer_id: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> bool {
        let Some(challenge) = self.challenge.take() else {
            return false; // no challenge outstanding — nothing to answer
        };
        let message = proof_transcript(local_peer_id, peer_id, &challenge);
        if !verify_signature(public_key_hex, &message, signature_hex) {
            return false;
        }
        self.peer = Some(AuthenticatedPeer {
            peer_id:    peer_id.to_string(),
            public_key: public_key_hex.to_string(),
        });
        true
    }

    /// The identity proven on this connection, if any.
    pub fn authenticated_peer(&self) -> Option<&AuthenticatedPeer> {
        self.peer.as_ref()
    }
}

/// Length-delimited concatenation of a domain tag and the signed fields.
///
/// Every part is prefixed with its length so no two different field tuples can
/// collide: without it, signing `("ab", "c")` and `("a", "bc")` would produce the
/// same bytes and a proof for one would verify for the other.
fn transcript(context: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = context.len() + parts.iter().map(|p| p.len() + 4).sum::<usize>() + 4;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(context.len() as u32).to_le_bytes());
    out.extend_from_slice(context);
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Lowercase hex — the on-the-wire form of keys and signatures.
fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Parse hex (either case). `None` on any non-hex or odd-length input, so a
/// malformed field can never be mistaken for a valid key or signature.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

/// Canonical shard content hash (hex of the first 16 bytes of blake3) — matches
/// `p2pnas_store::shard_hash` so an audit reply can be compared to the manifest.
pub fn content_hash(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    digest.as_bytes()[..16].iter().map(|b| format!("{b:02x}")).collect()
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
    bincode::deserialize(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

pub async fn write_message(stream: &mut TcpStream, msg: &P2pMessage) -> std::io::Result<()> {
    let data = bincode::serialize(msg).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    stream.write_u32_le(data.len() as u32).await?;
    stream.write_all(&data).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(byte: u8) -> PeerSigner {
        PeerSigner::from_seed(&[byte; ED25519_SEED_LEN]).unwrap()
    }

    /// RFC 8032 §7.1 TEST 1. Pins seed → public key → signature, so a change of
    /// backend, of seed handling or of encoding cannot silently produce a
    /// different identity for the same node key (every peer that pinned the old
    /// key would refuse the node).
    #[test]
    fn ed25519_matches_the_rfc8032_vector() {
        let seed = from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let s = PeerSigner::from_seed(&seed).unwrap();
        assert_eq!(s.public_key_hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(
            s.sign_hex(b"").unwrap(),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn seed_length_is_pinned() {
        assert!(PeerSigner::from_seed(&[0u8; 31]).is_err());
        // A longer seed must be refused, not silently truncated to 32 bytes.
        assert!(PeerSigner::from_seed(&[0u8; 33]).is_err());
        assert!(PeerSigner::from_seed(&[0u8; 32]).is_ok());
    }

    #[test]
    fn handshake_signature_verifies_and_tampering_does_not() {
        let s = signer(1);
        let nonce = random_nonce().unwrap();
        let msg = pong_transcript("peer-b", 3100, &nonce, Some("10.0.0.7"));
        let sig = s.sign_hex(&msg).unwrap();
        assert!(verify_signature(s.public_key_hex(), &msg, &sig));

        // A flipped bit anywhere in the signature.
        let mut bad = sig.clone().into_bytes();
        bad[0] ^= 0x01;
        assert!(!verify_signature(s.public_key_hex(), &msg, &String::from_utf8(bad).unwrap()));

        // Another key: the signature belongs to nobody else.
        assert!(!verify_signature(signer(2).public_key_hex(), &msg, &sig));

        // Malformed inputs are refused, never mistaken for a valid proof.
        assert!(!verify_signature("zz", &msg, &sig));
        assert!(!verify_signature(s.public_key_hex(), &msg, "abc"));
        assert!(!verify_signature(s.public_key_hex(), &msg, ""));
    }

    /// The proof is bound to the challenge, the identity and the address: a
    /// signature captured for one of them must not verify for another. This is
    /// what stops a replay towards a different node or for a different peer id.
    #[test]
    fn handshake_signature_is_bound_to_every_field() {
        let s = signer(3);
        let nonce = random_nonce().unwrap();
        let sig = s.sign_hex(&pong_transcript("peer-b", 3100, &nonce, Some("10.0.0.7"))).unwrap();

        let other_nonce = random_nonce().unwrap();
        for forged in [
            pong_transcript("peer-b", 3100, &other_nonce, Some("10.0.0.7")), // replayed challenge
            pong_transcript("peer-c", 3100, &nonce, Some("10.0.0.7")),       // stolen identity
            pong_transcript("peer-b", 3101, &nonce, Some("10.0.0.7")),       // moved port
            pong_transcript("peer-b", 3100, &nonce, Some("10.0.0.8")),       // relayed address
            pong_transcript("peer-b", 3100, &nonce, None),
        ] {
            assert!(!verify_signature(s.public_key_hex(), &forged, &sig));
        }
    }

    /// Length-delimited framing: two different field tuples can never produce the
    /// same transcript, and the two legs of the handshake never share one.
    #[test]
    fn transcripts_are_unambiguous_and_domain_separated() {
        assert_ne!(proof_transcript("ab", "c", b"n"), proof_transcript("a", "bc", b"n"));
        assert_ne!(pong_transcript("a", 1, b"n", Some("x")), proof_transcript("a", "x", b"n"));
    }

    #[test]
    fn session_accepts_a_valid_proof() {
        let s = signer(4);
        let mut session = PeerAuthSession::new();
        assert!(session.authenticated_peer().is_none());

        let challenge = session.issue_challenge().unwrap();
        let sig = s.sign_hex(&proof_transcript("me", "peer-a", &challenge)).unwrap();
        assert!(session.accept_proof("me", "peer-a", s.public_key_hex(), &sig));

        let peer = session.authenticated_peer().unwrap();
        assert_eq!(peer.peer_id, "peer-a");
        assert_eq!(peer.public_key, s.public_key_hex());
    }

    /// A challenge answers exactly once. Replaying a captured `AuthProof` on the
    /// same connection finds no outstanding challenge and fails.
    #[test]
    fn a_challenge_is_single_use() {
        let s = signer(5);
        let mut session = PeerAuthSession::new();
        let challenge = session.issue_challenge().unwrap();
        let sig = s.sign_hex(&proof_transcript("me", "peer-a", &challenge)).unwrap();

        assert!(session.accept_proof("me", "peer-a", s.public_key_hex(), &sig));
        assert!(!session.accept_proof("me", "peer-a", s.public_key_hex(), &sig));

        // And it stays refused against a freshly issued challenge.
        let _ = session.issue_challenge().unwrap();
        assert!(!session.accept_proof("me", "peer-a", s.public_key_hex(), &sig));
    }

    /// A failed attempt burns the challenge too: an attacker cannot keep grinding
    /// proofs against one nonce.
    #[test]
    fn a_failed_proof_burns_the_challenge() {
        let s = signer(6);
        let mut session = PeerAuthSession::new();
        let challenge = session.issue_challenge().unwrap();
        let good = s.sign_hex(&proof_transcript("me", "peer-a", &challenge)).unwrap();

        assert!(!session.accept_proof("me", "peer-a", s.public_key_hex(), "00"));
        assert!(!session.accept_proof("me", "peer-a", s.public_key_hex(), &good));
        assert!(session.authenticated_peer().is_none());
    }

    /// A proof collected by node X cannot be forwarded to node Y: the verifier's
    /// own id is inside the signed transcript.
    #[test]
    fn a_proof_cannot_be_relayed_to_another_node() {
        let s = signer(7);
        let mut session = PeerAuthSession::new();
        let challenge = session.issue_challenge().unwrap();
        let sig = s.sign_hex(&proof_transcript("node-x", "peer-a", &challenge)).unwrap();
        assert!(!session.accept_proof("node-y", "peer-a", s.public_key_hex(), &sig));
    }

    #[test]
    fn a_proof_without_a_challenge_is_refused() {
        let s = signer(8);
        let mut session = PeerAuthSession::new();
        let sig = s.sign_hex(&proof_transcript("me", "peer-a", &[0u8; NONCE_LEN])).unwrap();
        assert!(!session.accept_proof("me", "peer-a", s.public_key_hex(), &sig));
    }

    #[test]
    fn hex_roundtrips_and_rejects_garbage() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
        assert_eq!(to_hex(&[0x0a, 0xff]), "0aff");
        // Uppercase is accepted on the way in (some peers may emit it).
        assert_eq!(from_hex("0AFF").unwrap(), vec![0x0a, 0xff]);
        assert!(from_hex("abc").is_none()); // odd length
        assert!(from_hex("zz").is_none()); // not hex
    }
}
