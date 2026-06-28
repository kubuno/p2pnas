//! Wide-area discovery driver: runs the embedded Kademlia [`DhtNode`], joins the
//! overlay via the configured bootstrap nodes, and periodically refreshes the
//! routing table and harvests every known node into a trusted peer (handshaking
//! it over the existing TCP transport via [`super::register_peer`]).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

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
    let node = match p2pnas_p2p::DhtNode::bind(&bind_addr, &identity.peer_id, p2p_port).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, %bind_addr, "DHT: bind failed — wide-area discovery disabled");
            return;
        }
    };
    tracing::info!(%bind_addr, bootstrap = bootstrap.len(), "DHT: node online");
    tokio::spawn(node.clone().run());

    // (12) Seed the routing table from the last run so we rejoin the overlay fast.
    if let Ok(bytes) = std::fs::read(&state_file) {
        if let Ok(nodes) = serde_json::from_slice::<Vec<p2pnas_p2p::PersistNode>>(&bytes) {
            let n = nodes.len();
            node.import_nodes(nodes).await;
            tracing::info!(restored = n, "DHT: routing table restored from disk");
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
        for addr in node.peer_addrs().await {
            if let Some(pid) = super::register_peer(&db, &identity, api_port, &addr).await {
                tracing::info!(peer_id = %pid, %addr, "DHT: discovered peer");
            }
        }
        // Persist the routing table for the next restart.
        if let Ok(bytes) = serde_json::to_vec(&node.export_nodes().await) {
            let _ = std::fs::write(&state_file, bytes);
        }
    }
}
