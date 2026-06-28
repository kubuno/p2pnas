//! A compact Kademlia DHT over UDP, used for **wide-area peer discovery**.
//!
//! Each node has a 160-bit id derived from its `peer_id`, a routing table of
//! k-buckets keyed by XOR distance, and answers two RPCs: `Ping` and `FindNode`.
//! Every message carries the sender's id + TCP P2P port, so a node learns the
//! sender of any packet it receives — that, plus `FindNode` propagation, is what
//! spreads knowledge of the "network of acquaintances" across the overlay.
//!
//! The discovery sink lives in the server: it periodically harvests
//! [`DhtNode::peer_addrs`] and handshakes each over the existing TCP transport.
//! This module is purely the overlay (no value storage / republish — discovery
//! only). UDP sockets are allowed under the seccomp execve ban.

use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const ID_LEN: usize = 20; // 160-bit
const K: usize = 8; // bucket size / fan-out
const MAX_DATAGRAM: usize = 16 * 1024;

pub type NodeId = [u8; ID_LEN];

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
    id:       NodeId,
    udp:      SocketAddr,
    p2p_port: u16,
}

/// Routing table of 160 k-buckets. Simple LRU-ish: a re-seen node moves to the
/// back of its bucket; a full bucket drops the newcomer (good enough for
/// discovery — we never evict a live node we still talk to).
struct RoutingTable {
    self_id: NodeId,
    buckets: Vec<Vec<Node>>,
}

impl RoutingTable {
    fn new(self_id: NodeId) -> Self {
        RoutingTable { self_id, buckets: (0..ID_LEN * 8).map(|_| Vec::new()).collect() }
    }

    fn add(&mut self, node: Node) {
        let Some(idx) = bucket_index(&xor(&self.self_id, &node.id)) else { return };
        let b = &mut self.buckets[idx];
        if let Some(pos) = b.iter().position(|n| n.id == node.id) {
            b.remove(pos); // refresh recency
            b.push(node);
        } else if b.len() < K {
            b.push(node);
        }
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
}

/// A live DHT node: owns the UDP socket and the routing table.
pub struct DhtNode {
    socket:   Arc<UdpSocket>,
    self_id:  NodeId,
    p2p_port: u16,
    table:    Arc<Mutex<RoutingTable>>,
}

impl DhtNode {
    /// Bind the UDP socket and create the (empty) routing table.
    pub async fn bind(bind_addr: &str, peer_id: &str, p2p_port: u16) -> std::io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let self_id = id_from_peer(peer_id);
        Ok(Arc::new(DhtNode {
            socket,
            self_id,
            p2p_port,
            table: Arc::new(Mutex::new(RoutingTable::new(self_id))),
        }))
    }

    /// A persistable view of a known node (so the routing table survives restart).
    pub async fn export_nodes(&self) -> Vec<PersistNode> {
        self.table
            .lock()
            .await
            .all()
            .into_iter()
            .map(|n| PersistNode {
                id:       hex(&n.id),
                ip:       n.udp.ip().to_string(),
                udp_port: n.udp.port(),
                p2p_port: n.p2p_port,
            })
            .collect()
    }

    /// Seed the routing table from a previously exported snapshot.
    pub async fn import_nodes(&self, nodes: Vec<PersistNode>) {
        let mut table = self.table.lock().await;
        for r in nodes {
            let (Some(id), Ok(ip)) = (unhex(&r.id), r.ip.parse()) else { continue };
            if id == self.self_id {
                continue;
            }
            table.add(Node { id, udp: SocketAddr::new(ip, r.udp_port), p2p_port: r.p2p_port });
        }
    }

    /// TCP P2P addresses (`ip:p2p_port`) of every node we currently know — the
    /// discovery harvest handshakes these.
    pub async fn peer_addrs(&self) -> Vec<String> {
        self.table
            .lock()
            .await
            .all()
            .into_iter()
            .map(|n| format!("{}:{}", n.udp.ip(), n.p2p_port))
            .collect()
    }

    async fn send(&self, msg: &DhtMsg, to: SocketAddr) {
        if let Ok(bytes) = serde_json::to_vec(msg) {
            let _ = self.socket.send_to(&bytes, to).await;
        }
    }

    fn my_find(&self, target: &NodeId) -> DhtMsg {
        DhtMsg::FindNode { from: hex(&self.self_id), p2p: self.p2p_port, target: hex(target) }
    }

    /// Join the overlay: ask each bootstrap node for the nodes closest to us.
    pub async fn bootstrap(&self, addrs: &[String]) {
        let find = self.my_find(&self.self_id);
        for a in addrs {
            if let Ok(sa) = a.parse::<SocketAddr>() {
                self.send(&find, sa).await;
            } else if let Ok(mut it) = tokio::net::lookup_host(a).await {
                if let Some(sa) = it.next() {
                    self.send(&find, sa).await;
                }
            }
        }
    }

    /// One refresh round: `FindNode(self)` to the K closest known nodes, plus a
    /// few perturbed targets so coverage isn't limited to our own neighbourhood.
    pub async fn refresh(&self) {
        let targets = self.refresh_targets();
        let closest = { self.table.lock().await.closest(&self.self_id, K) };
        for t in &targets {
            let msg = self.my_find(t);
            for n in &closest {
                self.send(&msg, n.udp).await;
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

    async fn handle(&self, msg: DhtMsg, src: SocketAddr) {
        // 1. Learn the sender (every packet teaches us a node).
        let (from, p2p) = msg.sender();
        if let Some(id) = unhex(from) {
            if id != self.self_id {
                self.table.lock().await.add(Node { id, udp: src, p2p_port: p2p });
            }
        }

        // 2. Answer / absorb.
        match msg {
            DhtMsg::Ping { .. } => {
                self.send(&DhtMsg::Pong { from: hex(&self.self_id), p2p: self.p2p_port }, src).await;
            }
            DhtMsg::FindNode { target, .. } => {
                let target = unhex(&target).unwrap_or(self.self_id);
                let nodes = { self.table.lock().await.closest(&target, K) };
                let recs = nodes
                    .into_iter()
                    .map(|n| NodeRec {
                        id:       hex(&n.id),
                        ip:       n.udp.ip().to_string(),
                        udp_port: n.udp.port(),
                        p2p_port: n.p2p_port,
                    })
                    .collect();
                self.send(&DhtMsg::Nodes { from: hex(&self.self_id), p2p: self.p2p_port, nodes: recs }, src).await;
            }
            DhtMsg::Nodes { nodes, .. } => {
                let mut table = self.table.lock().await;
                for r in nodes {
                    let (Some(id), Ok(ip)) = (unhex(&r.id), r.ip.parse()) else { continue };
                    if id == self.self_id {
                        continue;
                    }
                    table.add(Node { id, udp: SocketAddr::new(ip, r.udp_port), p2p_port: r.p2p_port });
                }
            }
            DhtMsg::Pong { .. } => {} // sender already learned above
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn two_nodes_discover_each_other() {
        // A binds; B bootstraps off A. Both should learn each other's TCP port.
        let a = DhtNode::bind("127.0.0.1:0", "dht-node-a", 7001).await.unwrap();
        let b = DhtNode::bind("127.0.0.1:0", "dht-node-b", 7002).await.unwrap();
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
    }
}
