//! Wide-area discovery driver: runs the embedded Kademlia [`DhtNode`], joins the
//! overlay via the configured bootstrap nodes, and periodically refreshes the
//! routing table and harvests every known node into a trusted peer (handshaking
//! it over the existing TCP transport via [`super::register_peer`]).
//!
//! Everything the DHT reports is attacker-influenced, and harvesting turns it
//! into outbound TCP connections — so the harvest is filtered twice: the overlay
//! only surfaces nodes that proved their address (`peer_addrs_verified`), and the
//! address is re-checked against the [`AddrPolicy`] here before anything is
//! contacted or written to the state file.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

use p2pnas_p2p::dht::{AddrPolicy, MAX_PERSIST_NODES};
use p2pnas_store::NodeIdentity;

pub async fn run(
    db: PgPool,
    identity: Arc<NodeIdentity>,
    api_port: u16,
    p2p_port: u16,
    bind_addr: String,
    bootstrap: Vec<String>,
    state_file: PathBuf,
) {
    // Same source of truth as the DhtNode itself, so the harvest filter and the
    // overlay filter can never disagree.
    let policy = AddrPolicy::from_env();
    let node = match p2pnas_p2p::DhtNode::bind(&bind_addr, &identity.peer_id, p2p_port).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, %bind_addr, "DHT: bind failed — wide-area discovery disabled");
            return;
        }
    };
    tracing::info!(%bind_addr, bootstrap = bootstrap.len(), ?policy, "DHT: node online");
    tokio::spawn(node.clone().run());

    // (12) Seed the routing table from the last run so we rejoin the overlay fast.
    // The file is local but not trustworthy (it is written from network data, and
    // anything with disk access can edit it): `import_nodes` re-applies the
    // address filter and restores every entry as *unverified*.
    if let Ok(bytes) = std::fs::read(&state_file) {
        match serde_json::from_slice::<Vec<p2pnas_p2p::PersistNode>>(&bytes) {
            Ok(mut nodes) => {
                nodes.truncate(MAX_PERSIST_NODES);
                let n = nodes.len();
                node.import_nodes(nodes).await;
                tracing::info!(restored = n, "DHT: routing table restored from disk");
            }
            Err(e) => tracing::warn!(error = %e, "DHT: unreadable routing-table snapshot ignored"),
        }
    }

    if !bootstrap.is_empty() {
        node.bootstrap(&bootstrap).await;
    }

    // Refresh the overlay, let responses settle, then register everything we know.
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        node.refresh().await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        // Verified nodes only: an unverified entry carries an address a stranger
        // simply declared, and handshaking it would make this node a scanner for
        // whoever asked.
        for addr in node.peer_addrs_verified().await {
            if !contactable(&addr, policy) {
                tracing::debug!(%addr, "DHT: harvest target rejected by the address policy");
                continue;
            }
            if let Some(pid) = super::register_peer(&db, &identity, api_port, &addr).await {
                tracing::info!(peer_id = %pid, %addr, "DHT: discovered peer");
            }
        }
        // Persist the routing table for the next restart (verified entries only —
        // see `DhtNode::export_nodes`).
        match serde_json::to_vec(&node.export_nodes().await) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&state_file, bytes) {
                    tracing::warn!(error = %e, file = %state_file.display(), "DHT: routing-table snapshot write failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "DHT: routing-table snapshot encode failed"),
        }
    }
}

/// Is this `ip:port` something we are willing to open a TCP connection to?
/// A hostname never reaches here (the DHT only carries numeric addresses), and a
/// name would defeat the check anyway since it can resolve anywhere.
fn contactable(addr: &str, policy: AddrPolicy) -> bool {
    match addr.parse::<SocketAddr>() {
        Ok(sa) => policy.accepts(sa.ip(), sa.port()),
        Err(_) => false,
    }
}
