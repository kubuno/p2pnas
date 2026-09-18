//! A compact Kademlia DHT over UDP, used for **wide-area peer discovery**.
//!
//! Each node has a 160-bit id derived from its `peer_id`, a routing table of
//! k-buckets keyed by XOR distance, and answers two RPCs: `Ping` and `FindNode`.
//! Every message carries the sender's id + TCP P2P port, so a node learns the
//! sender of any packet it receives — that, plus `FindNode` propagation, is what
//! spreads knowledge of the "network of acquaintances" across the overlay.
//!
//! The discovery sink lives in the server: it periodically harvests
//! [`DhtNode::peer_addrs_verified`] and handshakes each over the existing TCP
//! transport. This module is purely the overlay (no value storage / republish —
//! discovery only). UDP sockets are allowed under the seccomp execve ban.
//!
//! # Hardening
//!
//! Everything in a DHT datagram is attacker-controlled, and the discovery sink
//! turns what we learn into outbound **TCP connections**. Three abuses are
//! defended against here:
//!
//! - **SSRF / internal scanning** — addresses in node records are arbitrary, so
//!   an attacker could have us probe `127.0.0.1:22` or a RFC1918 admin panel and
//!   read the answer through timing. Every address is therefore checked against
//!   [`is_routable_ip`] / [`is_contactable_port`] before it is learned, contacted,
//!   persisted or handed to the discovery sink.
//! - **UDP amplification** — a ~110-byte `FindNode` used to return K full records
//!   with a forgeable source IP (×6-7 reflector). An unverified source now gets
//!   [`K_UNVERIFIED`] records and a challenge `Ping`; only a source that has
//!   proved it really lives at its address (it answered a query *we* sent) gets a
//!   full K-record answer.
//! - **Poisoning / eclipse** — buckets used to drop newcomers and never expire
//!   the dead, so whoever filled them first owned our view forever. Buckets now
//!   evict stale (preferably unverified) entries for a newcomer, and a single
//!   source IP may only create [`LEARN_PER_WINDOW`] new entries per minute.
//!
//! Cryptographic peer authentication (a signed id) is a separate piece of work;
//! nothing here assumes ids are trustworthy, and the `verified` flag is exactly
//! the place such a proof would later plug into.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const ID_LEN: usize = 20; // 160-bit
const K: usize = 8; // bucket size / fan-out
const MAX_DATAGRAM: usize = 16 * 1024;

/// Records returned to a source that has not proved its address yet. Keeping the
/// answer this small caps the reflection ratio at roughly 2-3× (vs 6-7× before)
/// while still letting an honest newcomer make progress: it also receives a
/// challenge `Ping`, so one round-trip later it is verified and gets the full K.
const K_UNVERIFIED: usize = 2;

/// Records absorbed from a single `Nodes` message — a peer cannot flood us with
/// a thousand records in one datagram.
const MAX_NODES_PER_MSG: usize = K;

/// A routing-table entry is a candidate for eviction after this long without a
/// packet from it. Long enough that a peer rebooting is not forgotten, short
/// enough that a bucket filled by an attacker does not stay frozen for days.
const STALE_AFTER: Duration = Duration::from_secs(15 * 60);

/// New routing-table entries a single source IP may create per [`LEARN_WINDOW`].
/// Caps how fast one host can rewrite our view of the overlay.
const LEARN_PER_WINDOW: usize = 16;
const LEARN_WINDOW: Duration = Duration::from_secs(60);

/// A query we sent counts as an invitation for this long: an answer arriving from
/// that exact address within the window proves the address is reachable (not a
/// spoofed source), which is what promotes a node to `verified`.
const PENDING_TTL: Duration = Duration::from_secs(120);

/// Minimum interval between two challenge pings to the same address, so the
/// challenge itself cannot be turned into a reflector.
const PING_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// Unverified entries probed per refresh round (bounded, so a table full of
/// unverified junk cannot turn a refresh into a packet storm).
const VERIFY_BATCH: usize = 8;

/// Upper bound on the per-source bookkeeping maps.
const MAX_TRACKED_SOURCES: usize = 4096;

/// Upper bound on entries read from / written to the on-disk snapshot, so a
/// tampered state file cannot make us load an unbounded table at boot.
pub const MAX_PERSIST_NODES: usize = 512;

pub type NodeId = [u8; ID_LEN];

/// Which peer addresses this node is willing to talk to.
///
/// The DHT is the *wide-area* transport (the LAN is mDNS's job), so the default
/// refuses everything that is not globally routable — that is what closes the
/// SSRF / internal-scan hole. [`AddrPolicy::AllowPrivate`] exists for test rigs
/// and single-LAN deployments and must be an explicit opt-in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AddrPolicy {
    #[default]
    PublicOnly,
    AllowPrivate,
}

impl AddrPolicy {
    /// Escape hatch for LAN/dev rigs: `P2PNAS_DHT_ALLOW_PRIVATE=1`. Strict
    /// otherwise — a missing or unparsable value never weakens the policy.
    pub fn from_env() -> Self {
        match std::env::var("P2PNAS_DHT_ALLOW_PRIVATE").as_deref() {
            Ok("1") | Ok("true") | Ok("yes") => AddrPolicy::AllowPrivate,
            _ => AddrPolicy::PublicOnly,
        }
    }

    /// Is this IP acceptable as a peer address under the policy?
    pub fn accepts_ip(self, ip: IpAddr) -> bool {
        match self {
            AddrPolicy::PublicOnly => is_routable_ip(ip),
            // Even the permissive mode refuses the addresses that are never a
            // peer and are pure scan targets (0.0.0.0, multicast, broadcast).
            AddrPolicy::AllowPrivate => !(ip.is_unspecified() || ip.is_multicast() || is_broadcast(ip)),
        }
    }

    /// Is this full contact address (IP + port) acceptable?
    pub fn accepts(self, ip: IpAddr, port: u16) -> bool {
        is_contactable_port(port) && self.accepts_ip(ip)
    }
}

/// Ports we are willing to *contact*. Port 0 is not an endpoint, and a
/// privileged port is never a p2pnas peer but is exactly what an attacker wants
/// us to knock on (22, 25, 445, 631…).
pub fn is_contactable_port(port: u16) -> bool {
    port >= 1024
}

fn is_broadcast(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
}

/// Is this address globally routable — i.e. plausibly a real peer on the
/// Internet rather than something inside our own trust perimeter?
pub fn is_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_routable_v4(v4),
        IpAddr::V6(v6) => is_routable_v6(v6),
    }
}

fn is_routable_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let this_network = o[0] == 0; // 0.0.0.0/8
    let cgnat = o[0] == 100 && (64..128).contains(&o[1]); // 100.64.0.0/10
    let benchmarking = o[0] == 198 && (o[1] == 18 || o[1] == 19); // 198.18.0.0/15
    let reserved = o[0] >= 240; // 240.0.0.0/4 (255.255.255.255 included)
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || this_network
        || cgnat
        || benchmarking
        || reserved)
}

fn is_routable_v6(ip: Ipv6Addr) -> bool {
    // An IPv4-mapped address is really IPv4 — judge it as such, otherwise
    // `::ffff:127.0.0.1` would walk straight past the v6 checks.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_routable_v4(v4);
    }
    let s = ip.segments();
    let unique_local = (s[0] & 0xfe00) == 0xfc00; // fc00::/7
    let link_local = (s[0] & 0xffc0) == 0xfe80; // fe80::/10
    let documentation = s[0] == 0x2001 && s[1] == 0x0db8; // 2001:db8::/32
    let discard = s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0; // 100::/64
    // ::/96 also covers ::1 and the deprecated IPv4-compatible form ::a.b.c.d,
    // which is another way of spelling a v4 address we already refuse.
    let embedded_v4_or_special = s[..6].iter().all(|&x| x == 0);
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || unique_local
        || link_local
        || documentation
        || discard
        || embedded_v4_or_special)
}

/// Routability check for an `ip:port` string (the form the discovery sink hands
/// to the TCP transport). A hostname has no verifiable address here, so it is
/// refused: everything the DHT produces is numeric.
pub fn is_routable_peer_addr(addr: &str) -> bool {
    match addr.parse::<SocketAddr>() {
        Ok(sa) => is_contactable_port(sa.port()) && is_routable_ip(sa.ip()),
        Err(_) => false,
    }
}

/// 160-bit id = first 20 bytes of blake3(peer_id).
pub fn id_from_peer(peer_id: &str) -> NodeId {
    let h = blake3::hash(peer_id.as_bytes());
    let mut id = [0u8; ID_LEN];
    id.copy_from_slice(&h.as_bytes()[..ID_LEN]);
    id
}

fn xor(a: &NodeId, b: &NodeId) -> NodeId {
    let mut o = [0u8; ID_LEN];
    for i in 0..ID_LEN {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// Bucket index = position of the most-significant differing bit (0 = closest).
/// None when the distance is zero (the node itself).
fn bucket_index(distance: &NodeId) -> Option<usize> {
    for (i, &b) in distance.iter().enumerate() {
        if b != 0 {
            return Some(i * 8 + b.leading_zeros() as usize);
        }
    }
    None
}

fn hex(id: &NodeId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<NodeId> {
    if s.len() != ID_LEN * 2 {
        return None;
    }
    let mut id = [0u8; ID_LEN];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(id)
}

#[derive(Clone)]
struct Node {
    id:        NodeId,
    udp:       SocketAddr,
    p2p_port:  u16,
    /// True once the node answered a query *we* sent to this exact address —
    /// proof the source address is not forged. Unverified entries are second-class:
    /// they are evicted first, get short answers, and are never persisted or
    /// handed to the discovery sink.
    verified:  bool,
    last_seen: Instant,
}

/// Routing table of 160 k-buckets, LRU-ish: a re-seen node moves to the back of
/// its bucket. A full bucket no longer refuses newcomers outright (that is what
/// let an early attacker freeze our view) — it evicts the least-recently-seen
/// entry that has gone silent past [`STALE_AFTER`], unverified ones first, and
/// only keeps the newcomer out when every incumbent still looks alive.
struct RoutingTable {
    self_id: NodeId,
    buckets: Vec<Vec<Node>>,
}

impl RoutingTable {
    fn new(self_id: NodeId) -> Self {
        RoutingTable { self_id, buckets: (0..ID_LEN * 8).map(|_| Vec::new()).collect() }
    }

    fn contains(&self, id: &NodeId) -> bool {
        match bucket_index(&xor(&self.self_id, id)) {
            Some(idx) => self.buckets[idx].iter().any(|n| n.id == *id),
            None => false,
        }
    }

    /// Insert or refresh `node`. Returns true when a *new* id entered the table
    /// (the caller charges that to the source's learning budget).
    fn add(&mut self, node: Node) -> bool {
        let Some(idx) = bucket_index(&xor(&self.self_id, &node.id)) else { return false };
        let b = &mut self.buckets[idx];

        if let Some(pos) = b.iter().position(|n| n.id == node.id) {
            let mut existing = b.remove(pos); // refresh recency
            existing.last_seen = node.last_seen;
            // An unverified sighting never rewrites the contact address of a node
            // we have already verified: otherwise anyone could re-point a known
            // id at an address of their choosing (and at a victim we would then
            // hammer). Only a proved address wins.
            if node.verified {
                existing.udp = node.udp;
                existing.p2p_port = node.p2p_port;
                existing.verified = true;
            }
            b.push(existing);
            return false;
        }

        if b.len() < K {
            b.push(node);
            return true;
        }

        // Bucket full: replace the oldest dead entry (unverified before verified);
        // a bucket of live nodes still refuses the newcomer, as Kademlia intends.
        let now = node.last_seen;
        let victim = b
            .iter()
            .enumerate()
            .filter(|(_, n)| now.saturating_duration_since(n.last_seen) > STALE_AFTER)
            .min_by_key(|(_, n)| (n.verified, n.last_seen))
            .map(|(i, _)| i);
        match victim {
            Some(i) => {
                b[i] = node;
                true
            }
            None => false,
        }
    }

    fn mark_verified(&mut self, addr: SocketAddr) {
        for b in &mut self.buckets {
            for n in b.iter_mut() {
                if n.udp == addr {
                    n.verified = true;
                    n.last_seen = Instant::now();
                }
            }
        }
    }

    fn is_verified_source(&self, addr: SocketAddr) -> bool {
        self.buckets.iter().flatten().any(|n| n.udp == addr && n.verified)
    }

    fn all(&self) -> Vec<Node> {
        self.buckets.iter().flatten().cloned().collect()
    }

    /// The `count` nodes closest (XOR) to `target`.
    fn closest(&self, target: &NodeId, count: usize) -> Vec<Node> {
        let mut all = self.all();
        all.sort_by_key(|n| xor(&n.id, target));
        all.truncate(count);
        all
    }
}

/// Per-source bookkeeping: learning budget, outstanding queries (what promotes a
/// node to `verified`) and challenge-ping throttling. All three are bounded maps.
#[derive(Default)]
struct SourceState {
    /// source IP → (window start, new entries created in the window)
    learn:   HashMap<IpAddr, (Instant, usize)>,
    /// address we queried → when (an answer within [`PENDING_TTL`] proves it)
    pending: HashMap<SocketAddr, Instant>,
    /// address we last challenged → when (see [`PING_MIN_INTERVAL`])
    pinged:  HashMap<SocketAddr, Instant>,
}

impl SourceState {
    fn allow_learn(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.prune(now);
        let slot = self.learn.entry(ip).or_insert((now, 0));
        if now.saturating_duration_since(slot.0) > LEARN_WINDOW {
            *slot = (now, 0);
        }
        if slot.1 >= LEARN_PER_WINDOW {
            return false;
        }
        slot.1 += 1;
        true
    }

    fn note_query(&mut self, addr: SocketAddr, now: Instant) {
        self.prune(now);
        self.pending.insert(addr, now);
    }

    /// Consume the outstanding query for `addr`: true when we did ask it something
    /// recently, i.e. its answer proves it really is at that address.
    fn take_pending(&mut self, addr: SocketAddr, now: Instant) -> bool {
        match self.pending.remove(&addr) {
            Some(t) => now.saturating_duration_since(t) <= PENDING_TTL,
            None => false,
        }
    }

    fn allow_ping(&mut self, addr: SocketAddr, now: Instant) -> bool {
        self.prune(now);
        match self.pinged.get(&addr) {
            Some(t) if now.saturating_duration_since(*t) < PING_MIN_INTERVAL => false,
            _ => {
                self.pinged.insert(addr, now);
                true
            }
        }
    }

    /// Keep the maps bounded whatever the traffic: expired entries go first, and
    /// a flood that still overflows the cap resets the map rather than growing
    /// (losing verification state degrades service, never safety).
    fn prune(&mut self, now: Instant) {
        if self.learn.len() >= MAX_TRACKED_SOURCES {
            self.learn.retain(|_, (start, _)| now.saturating_duration_since(*start) <= LEARN_WINDOW);
            if self.learn.len() >= MAX_TRACKED_SOURCES {
                self.learn.clear();
            }
        }
        if self.pending.len() >= MAX_TRACKED_SOURCES {
            self.pending.retain(|_, t| now.saturating_duration_since(*t) <= PENDING_TTL);
            if self.pending.len() >= MAX_TRACKED_SOURCES {
                self.pending.clear();
            }
        }
        if self.pinged.len() >= MAX_TRACKED_SOURCES {
            self.pinged.retain(|_, t| now.saturating_duration_since(*t) <= PING_MIN_INTERVAL);
            if self.pinged.len() >= MAX_TRACKED_SOURCES {
                self.pinged.clear();
            }
        }
    }
}

/// A routing-table entry persisted across restarts (for faster overlay rejoin).
#[derive(Serialize, Deserialize)]
pub struct PersistNode {
    pub id:       String,
    pub ip:       String,
    pub udp_port: u16,
    pub p2p_port: u16,
}

#[derive(Serialize, Deserialize)]
struct NodeRec {
    id:       String,
    ip:       String,
    udp_port: u16,
    p2p_port: u16,
}

#[derive(Serialize, Deserialize)]
enum DhtMsg {
    Ping { from: String, p2p: u16 },
    Pong { from: String, p2p: u16 },
    FindNode { from: String, p2p: u16, target: String },
    Nodes { from: String, p2p: u16, nodes: Vec<NodeRec> },
}

impl DhtMsg {
    fn sender(&self) -> (&str, u16) {
        match self {
            DhtMsg::Ping { from, p2p } | DhtMsg::Pong { from, p2p } => (from, *p2p),
            DhtMsg::FindNode { from, p2p, .. } | DhtMsg::Nodes { from, p2p, .. } => (from, *p2p),
        }
    }

    /// Does this message answer something we asked? Only an answer can prove that
    /// its source address is real (an unsolicited packet proves nothing).
    fn is_answer(&self) -> bool {
        matches!(self, DhtMsg::Pong { .. } | DhtMsg::Nodes { .. })
    }
}

/// A live DHT node: owns the UDP socket and the routing table.
pub struct DhtNode {
    socket:   Arc<UdpSocket>,
    self_id:  NodeId,
    p2p_port: u16,
    policy:   AddrPolicy,
    table:    Arc<Mutex<RoutingTable>>,
    sources:  Arc<Mutex<SourceState>>,
}

impl DhtNode {
    /// Bind the UDP socket and create the (empty) routing table, with the address
    /// policy taken from the environment (strict unless explicitly relaxed).
    pub async fn bind(bind_addr: &str, peer_id: &str, p2p_port: u16) -> std::io::Result<Arc<Self>> {
        Self::bind_with_policy(bind_addr, peer_id, p2p_port, AddrPolicy::from_env()).await
    }

    /// Same, with an explicit address policy (LAN rigs and tests).
    pub async fn bind_with_policy(
        bind_addr: &str,
        peer_id: &str,
        p2p_port: u16,
        policy: AddrPolicy,
    ) -> std::io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let self_id = id_from_peer(peer_id);
        Ok(Arc::new(DhtNode {
            socket,
            self_id,
            p2p_port,
            policy,
            table: Arc::new(Mutex::new(RoutingTable::new(self_id))),
            sources: Arc::new(Mutex::new(SourceState::default())),
        }))
    }

    /// A persistable view of the nodes worth keeping: only entries that proved
    /// their address and still pass the routability filter, so a poisoned or
    /// internal address can never survive a restart in the state file.
    pub async fn export_nodes(&self) -> Vec<PersistNode> {
        self.table
            .lock()
            .await
            .all()
            .into_iter()
            .filter(|n| n.verified && self.policy.accepts(n.udp.ip(), n.p2p_port))
            .take(MAX_PERSIST_NODES)
            .map(|n| PersistNode {
                id:       hex(&n.id),
                ip:       n.udp.ip().to_string(),
                udp_port: n.udp.port(),
                p2p_port: n.p2p_port,
            })
            .collect()
    }

    /// Seed the routing table from a previously exported snapshot. Restored
    /// entries are *unverified* — the file could have been tampered with, so they
    /// must prove themselves again before they are trusted or re-persisted.
    pub async fn import_nodes(&self, nodes: Vec<PersistNode>) {
        let now = Instant::now();
        let mut table = self.table.lock().await;
        for r in nodes.into_iter().take(MAX_PERSIST_NODES) {
            let (Some(id), Ok(ip)) = (unhex(&r.id), r.ip.parse::<IpAddr>()) else { continue };
            if id == self.self_id || !self.policy.accepts(ip, r.udp_port) || !is_contactable_port(r.p2p_port) {
                continue;
            }
            table.add(Node {
                id,
                udp: SocketAddr::new(ip, r.udp_port),
                p2p_port: r.p2p_port,
                verified: false,
                last_seen: now,
            });
        }
    }

    /// TCP P2P addresses (`ip:p2p_port`) of every node we currently know.
    pub async fn peer_addrs(&self) -> Vec<String> {
        self.collect_addrs(false).await
    }

    /// TCP P2P addresses of the nodes that proved their address — what the
    /// discovery sink should hand to the TCP transport. An unverified entry may
    /// carry any address a stranger felt like announcing, and connecting to it is
    /// precisely the SSRF primitive we refuse to offer.
    pub async fn peer_addrs_verified(&self) -> Vec<String> {
        self.collect_addrs(true).await
    }

    async fn collect_addrs(&self, verified_only: bool) -> Vec<String> {
        self.table
            .lock()
            .await
            .all()
            .into_iter()
            .filter(|n| !verified_only || n.verified)
            .filter(|n| self.policy.accepts(n.udp.ip(), n.p2p_port))
            .map(|n| format!("{}:{}", n.udp.ip(), n.p2p_port))
            .collect()
    }

    /// Send `msg` to `to`, refusing addresses the policy rejects. Queries are
    /// remembered so that the answer can promote the peer to `verified`.
    async fn send(&self, msg: &DhtMsg, to: SocketAddr) -> bool {
        if !self.policy.accepts_ip(to.ip()) {
            tracing::debug!(%to, "DHT: refusing to contact a non-routable address");
            return false;
        }
        let Ok(bytes) = serde_json::to_vec(msg) else { return false };
        if !msg.is_answer() {
            self.sources.lock().await.note_query(to, Instant::now());
        }
        match self.socket.send_to(&bytes, to).await {
            Ok(_) => true,
            Err(e) => {
                tracing::debug!(error = %e, %to, "DHT: send failed");
                false
            }
        }
    }

    fn my_find(&self, target: &NodeId) -> DhtMsg {
        DhtMsg::FindNode { from: hex(&self.self_id), p2p: self.p2p_port, target: hex(target) }
    }

    fn my_ping(&self) -> DhtMsg {
        DhtMsg::Ping { from: hex(&self.self_id), p2p: self.p2p_port }
    }

    /// Join the overlay: ask each bootstrap node for the nodes closest to us.
    pub async fn bootstrap(&self, addrs: &[String]) {
        let find = self.my_find(&self.self_id);
        for a in addrs {
            let target = match a.parse::<SocketAddr>() {
                Ok(sa) => Some(sa),
                Err(_) => match tokio::net::lookup_host(a).await {
                    Ok(mut it) => it.next(),
                    Err(e) => {
                        tracing::warn!(error = %e, bootstrap = %a, "DHT: bootstrap host lookup failed");
                        None
                    }
                },
            };
            let Some(sa) = target else { continue };
            if !self.send(&find, sa).await {
                // Most likely a LAN bootstrap under the strict policy — say so,
                // silence here would look like a network problem.
                tracing::warn!(bootstrap = %a, "DHT: bootstrap address rejected by the address policy");
            }
        }
    }

    /// One refresh round: `FindNode(self)` to the K closest known nodes, plus a
    /// few perturbed targets so coverage isn't limited to our own neighbourhood.
    /// Ends by challenging a bounded batch of unverified entries, which is how
    /// they earn the right to be persisted and handshaked.
    pub async fn refresh(&self) {
        let targets = self.refresh_targets();
        let (closest, unverified) = {
            let table = self.table.lock().await;
            let unverified: Vec<SocketAddr> =
                table.all().iter().filter(|n| !n.verified).map(|n| n.udp).take(VERIFY_BATCH).collect();
            (table.closest(&self.self_id, K), unverified)
        };
        for t in &targets {
            let msg = self.my_find(t);
            for n in &closest {
                self.send(&msg, n.udp).await;
            }
        }
        let ping = self.my_ping();
        for addr in unverified {
            let allowed = { self.sources.lock().await.allow_ping(addr, Instant::now()) };
            if allowed {
                self.send(&ping, addr).await;
            }
        }
    }

    /// Self + a handful of deterministically perturbed ids (flip a high bit each)
    /// to probe different parts of the keyspace without an RNG dependency.
    fn refresh_targets(&self) -> Vec<NodeId> {
        let mut out = vec![self.self_id];
        for bit in [0usize, 1, 2, 4] {
            let mut t = self.self_id;
            t[bit / 8] ^= 0x80 >> (bit % 8);
            out.push(t);
        }
        out
    }

    /// Receive loop: learn the sender of every packet and answer RPCs.
    pub async fn run(self: Arc<Self>) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, src) = match self.socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!(error = %e, "DHT recv error");
                    continue;
                }
            };
            let Ok(msg) = serde_json::from_slice::<DhtMsg>(&buf[..n]) else { continue };
            self.handle(msg, src).await;
        }
    }

    /// Insert/refresh a node, charging new entries to the source's budget.
    /// Returns true when the table gained an entry.
    async fn learn(&self, node: Node) -> bool {
        if node.id == self.self_id || !self.policy.accepts(node.udp.ip(), node.p2p_port) {
            return false;
        }
        // Lock order everywhere: sources → table.
        let mut sources = self.sources.lock().await;
        let mut table = self.table.lock().await;
        if !table.contains(&node.id) && !sources.allow_learn(node.udp.ip(), node.last_seen) {
            tracing::debug!(src = %node.udp, "DHT: learning budget exhausted for this source");
            return false;
        }
        table.add(node)
    }

    async fn handle(&self, msg: DhtMsg, src: SocketAddr) {
        // 0. A datagram whose source we would never contact teaches us nothing and
        //    gets no answer — that also stops us from reflecting toward it.
        if !self.policy.accepts_ip(src.ip()) {
            tracing::trace!(%src, "DHT: datagram from a non-routable source ignored");
            return;
        }
        let now = Instant::now();

        // 1. Did we ask this address something? Only then is its answer a proof
        //    that it really lives there (an unsolicited packet proves nothing).
        let solicited = msg.is_answer() && { self.sources.lock().await.take_pending(src, now) };
        if solicited {
            self.table.lock().await.mark_verified(src);
        }

        // 2. Learn the sender (rate-limited, routability-filtered).
        let (from, p2p) = msg.sender();
        if let Some(id) = unhex(from) {
            self.learn(Node { id, udp: src, p2p_port: p2p, verified: solicited, last_seen: now }).await;
        }

        // 3. Answer / absorb.
        match msg {
            DhtMsg::Ping { .. } => {
                // A Pong is the same size as the Ping: no amplification, and it is
                // how the other side proves *us*.
                self.send(&DhtMsg::Pong { from: hex(&self.self_id), p2p: self.p2p_port }, src).await;
            }
            DhtMsg::FindNode { target, .. } => {
                let verified_src = { self.table.lock().await.is_verified_source(src) };
                let want = if verified_src { K } else { K_UNVERIFIED };
                let target = unhex(&target).unwrap_or(self.self_id);
                let nodes = { self.table.lock().await.closest(&target, want) };
                let recs = nodes
                    .into_iter()
                    .map(|n| NodeRec {
                        id:       hex(&n.id),
                        ip:       n.udp.ip().to_string(),
                        udp_port: n.udp.port(),
                        p2p_port: n.p2p_port,
                    })
                    .collect();
                self.send(&DhtMsg::Nodes { from: hex(&self.self_id), p2p: self.p2p_port, nodes: recs }, src)
                    .await;
                // Challenge an unverified questioner (throttled): if the source
                // address was forged, nobody answers and it stays second-class.
                if !verified_src {
                    let allowed = { self.sources.lock().await.allow_ping(src, now) };
                    if allowed {
                        self.send(&self.my_ping(), src).await;
                    }
                }
            }
            DhtMsg::Nodes { nodes, .. } => {
                for r in nodes.into_iter().take(MAX_NODES_PER_MSG) {
                    let (Some(id), Ok(ip)) = (unhex(&r.id), r.ip.parse::<IpAddr>()) else { continue };
                    // Third-party hearsay: unverified by construction, and subject
                    // to the same routability filter as everything else.
                    self.learn(Node {
                        id,
                        udp: SocketAddr::new(ip, r.udp_port),
                        p2p_port: r.p2p_port,
                        verified: false,
                        last_seen: now,
                    })
                    .await;
                }
            }
            DhtMsg::Pong { .. } => {} // sender already learned above
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address literal")
    }

    #[test]
    fn bucket_and_distance() {
        let a = id_from_peer("node-a");
        let b = id_from_peer("node-b");
        assert_ne!(a, b);
        // Distance to self is zero → no bucket.
        assert_eq!(bucket_index(&xor(&a, &a)), None);
        // hex round-trips.
        assert_eq!(unhex(&hex(&a)), Some(a));
    }

    #[test]
    fn non_routable_addresses_are_refused() {
        // Everything inside our own trust perimeter — the SSRF targets.
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.10",
            "169.254.10.10",
            "100.64.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "2001:db8::1",
            // Two ways of smuggling a loopback/private v4 through a v6 field.
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
        ] {
            assert!(!is_routable_ip(ip(s)), "{s} must be refused");
        }
        for s in ["1.1.1.1", "57.129.12.127", "2001:4860:4860::8888", "2a01:e0a::1"] {
            assert!(is_routable_ip(ip(s)), "{s} must be accepted");
        }
    }

    #[test]
    fn privileged_and_zero_ports_are_refused() {
        assert!(!is_contactable_port(0));
        assert!(!is_contactable_port(22));
        assert!(!is_contactable_port(1023));
        assert!(is_contactable_port(1024));
        assert!(is_contactable_port(7490));
    }

    #[test]
    fn peer_addr_filter() {
        assert!(is_routable_peer_addr("57.129.12.127:7490"));
        assert!(is_routable_peer_addr("[2001:4860::1]:7490"));
        // Private target, privileged port, port 0, hostname: all refused.
        assert!(!is_routable_peer_addr("192.168.1.10:7490"));
        assert!(!is_routable_peer_addr("57.129.12.127:22"));
        assert!(!is_routable_peer_addr("57.129.12.127:0"));
        assert!(!is_routable_peer_addr("peer.example.org:7490"));
        assert!(!is_routable_peer_addr("not-an-address"));
    }

    #[test]
    fn permissive_policy_still_refuses_the_absurd() {
        let p = AddrPolicy::AllowPrivate;
        assert!(p.accepts(ip("192.168.1.10"), 7490)); // the point of the mode
        assert!(p.accepts(ip("127.0.0.1"), 7490)); // test rigs live here
        assert!(!p.accepts(ip("192.168.1.10"), 22)); // never a peer port
        assert!(!p.accepts(ip("0.0.0.0"), 7490));
        assert!(!p.accepts(ip("224.0.0.1"), 7490));
        assert!(!p.accepts(ip("255.255.255.255"), 7490));
    }

    /// An id whose first byte is `0x01`: with a zero `self_id` every such id has
    /// the same most-significant differing bit, so they all land in ONE bucket —
    /// which is what makes the eviction rule testable.
    fn same_bucket_id(n: u8) -> NodeId {
        let mut id = [0u8; ID_LEN];
        id[0] = 0x01;
        id[1] = n;
        id
    }

    fn node(id: NodeId, addr: &str, verified: bool, last_seen: Instant) -> Node {
        Node { id, udp: addr.parse().expect("test socket address"), p2p_port: 7490, verified, last_seen }
    }

    fn ago(d: Duration) -> Instant {
        Instant::now().checked_sub(d).unwrap_or_else(Instant::now)
    }

    #[test]
    fn full_bucket_evicts_the_dead_not_the_newcomer() {
        let mut table = RoutingTable::new([0u8; ID_LEN]);
        let dead = ago(STALE_AFTER * 2);
        for i in 0..K as u8 {
            assert!(table.add(node(same_bucket_id(i), &format!("203.0.113.{i}:7000"), false, dead)));
        }
        assert_eq!(table.all().len(), K, "the bucket is full");

        // A newcomer must displace a silent entry rather than be thrown away.
        let fresh = same_bucket_id(200);
        assert!(table.add(node(fresh, "198.51.100.9:7000", true, Instant::now())));
        assert!(table.contains(&fresh), "a newcomer must displace a dead entry");
        assert_eq!(table.all().len(), K, "eviction replaces, it never grows the bucket");

        // Live incumbents, on the other hand, are never sacrificed: this is what
        // keeps a healthy table from being churned by a stranger.
        let mut live = RoutingTable::new([0u8; ID_LEN]);
        let now = Instant::now();
        for i in 0..K as u8 {
            live.add(node(same_bucket_id(i), &format!("203.0.113.{i}:7000"), true, now));
        }
        let intruder = same_bucket_id(201);
        assert!(!live.add(node(intruder, "198.51.100.9:7000", false, now)));
        assert!(!live.contains(&intruder), "a bucket of live nodes must keep its incumbents");
    }

    #[test]
    fn stale_unverified_entries_are_evicted_before_stale_verified_ones() {
        let mut table = RoutingTable::new([0u8; ID_LEN]);
        let older = ago(STALE_AFTER * 3);
        let old = ago(STALE_AFTER * 2);
        // Slot 0 is the oldest but verified; slot 1 is younger but unverified.
        table.add(node(same_bucket_id(0), "203.0.113.1:7000", true, older));
        table.add(node(same_bucket_id(1), "203.0.113.2:7000", false, old));
        for i in 2..K as u8 {
            table.add(node(same_bucket_id(i), &format!("203.0.113.{i}:7000"), true, Instant::now()));
        }
        table.add(node(same_bucket_id(202), "198.51.100.9:7000", true, Instant::now()));
        assert!(table.contains(&same_bucket_id(0)), "the verified entry must be kept");
        assert!(!table.contains(&same_bucket_id(1)), "the unverified entry must go first");
    }

    #[test]
    fn unverified_sighting_cannot_move_a_verified_node() {
        let mut table = RoutingTable::new([0u8; ID_LEN]);
        let now = Instant::now();
        let victim = same_bucket_id(1);
        table.add(node(victim, "203.0.113.7:7000", true, now));
        // Same id, attacker-chosen address, no proof: the address must not move.
        table.add(node(victim, "198.51.100.66:7000", false, now));
        let addr = table.all().into_iter().find(|n| n.id == victim).map(|n| n.udp.to_string());
        assert_eq!(addr.as_deref(), Some("203.0.113.7:7000"));
    }

    #[test]
    fn learning_budget_is_bounded_per_source() {
        let mut st = SourceState::default();
        let now = Instant::now();
        let src = ip("203.0.113.7");
        for _ in 0..LEARN_PER_WINDOW {
            assert!(st.allow_learn(src, now));
        }
        assert!(!st.allow_learn(src, now), "budget must run out inside the window");
        // Another source has its own budget…
        assert!(st.allow_learn(ip("198.51.100.7"), now));
        // …and the window eventually resets.
        assert!(st.allow_learn(src, now + LEARN_WINDOW + Duration::from_secs(1)));
    }

    #[test]
    fn only_a_solicited_answer_proves_an_address() {
        let mut st = SourceState::default();
        let now = Instant::now();
        let addr: SocketAddr = "203.0.113.7:7000".parse().expect("test socket address");
        assert!(!st.take_pending(addr, now), "an unsolicited answer proves nothing");
        st.note_query(addr, now);
        assert!(st.take_pending(addr, now));
        assert!(!st.take_pending(addr, now), "a proof is consumed once");
        // A very late answer is not a proof either.
        st.note_query(addr, now);
        assert!(!st.take_pending(addr, now + PENDING_TTL + Duration::from_secs(1)));
    }

    #[test]
    fn challenge_pings_are_throttled() {
        let mut st = SourceState::default();
        let now = Instant::now();
        let addr: SocketAddr = "203.0.113.7:7000".parse().expect("test socket address");
        assert!(st.allow_ping(addr, now));
        assert!(!st.allow_ping(addr, now));
        assert!(st.allow_ping(addr, now + PING_MIN_INTERVAL + Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn two_nodes_discover_each_other() {
        // A binds; B bootstraps off A. Both should learn each other's TCP port.
        // Loopback needs the permissive policy — the strict default is exactly
        // what forbids talking to 127.0.0.1.
        let p = AddrPolicy::AllowPrivate;
        let a = DhtNode::bind_with_policy("127.0.0.1:0", "dht-node-a", 7001, p).await.unwrap();
        let b = DhtNode::bind_with_policy("127.0.0.1:0", "dht-node-b", 7002, p).await.unwrap();
        let a_addr = a.socket.local_addr().unwrap().to_string();

        tokio::spawn(a.clone().run());
        tokio::spawn(b.clone().run());

        b.bootstrap(&[a_addr]).await;
        // Give the exchange a couple of round-trips.
        for _ in 0..10 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if !a.peer_addrs().await.is_empty() && !b.peer_addrs().await.is_empty() {
                break;
            }
        }
        let a_knows = a.peer_addrs().await;
        let b_knows = b.peer_addrs().await;
        assert!(a_knows.iter().any(|s| s.ends_with(":7002")), "A should know B's p2p port: {a_knows:?}");
        assert!(b_knows.iter().any(|s| s.ends_with(":7001")), "B should know A's p2p port: {b_knows:?}");

        // B asked A a question, so A's answer proves A's address: A must end up
        // verified in B's table (and thus be harvestable by discovery).
        for _ in 0..10 {
            if !b.peer_addrs_verified().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let verified = b.peer_addrs_verified().await;
        assert!(verified.iter().any(|s| s.ends_with(":7001")), "A should be verified for B: {verified:?}");
    }

    #[tokio::test]
    async fn strict_policy_ignores_loopback_traffic() {
        // Same setup under the default policy: nothing is learned, because the
        // whole conversation happens inside the trust perimeter.
        let a = DhtNode::bind_with_policy("127.0.0.1:0", "strict-a", 7001, AddrPolicy::PublicOnly)
            .await
            .unwrap();
        let b = DhtNode::bind_with_policy("127.0.0.1:0", "strict-b", 7002, AddrPolicy::PublicOnly)
            .await
            .unwrap();
        let a_addr = a.socket.local_addr().unwrap().to_string();
        tokio::spawn(a.clone().run());
        tokio::spawn(b.clone().run());
        b.bootstrap(&[a_addr]).await;
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        assert!(a.peer_addrs().await.is_empty());
        assert!(b.peer_addrs().await.is_empty());
    }
}
