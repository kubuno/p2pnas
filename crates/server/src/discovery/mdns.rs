//! Zero-config LAN discovery over mDNS/DNS-SD. The node announces a
//! `_p2pnas._tcp` service carrying its P2P port + peer_id, and browses for the
//! same service; every resolved instance is handshaked and added as a peer.
//!
//! `mdns-sd` runs its own background thread and never spawns a subprocess, so it
//! stays within the seccomp execve ban.

use std::sync::Arc;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use sqlx::PgPool;

use p2pnas_store::NodeIdentity;

const SERVICE_TYPE: &str = "_p2pnas._tcp.local.";

/// Announce this node and continuously register peers found on the LAN.
pub async fn run(db: PgPool, identity: Arc<NodeIdentity>, api_port: u16, p2p_port: u16) {
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "mDNS: daemon init failed — LAN discovery disabled");
            return;
        }
    };

    announce(&daemon, &identity.peer_id, p2p_port);

    let receiver = match daemon.browse(SERVICE_TYPE) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "mDNS: browse failed — LAN discovery disabled");
            return;
        }
    };
    tracing::info!("mDNS: browsing {SERVICE_TYPE} for peers");

    loop {
        match receiver.recv_async().await {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                // Ignore our own announcement early (instance name == peer_id).
                if info.get_fullname().contains(&*identity.peer_id) {
                    continue;
                }
                // A service can advertise several interface addresses (LAN, docker,
                // VPN…). Handshake them in turn and keep the first that answers —
                // that's the one actually routable from here.
                let port = info.get_port();
                for ip in info.get_addresses() {
                    let addr = format!("{ip}:{port}");
                    if let Some(pid) = super::register_peer(&db, &identity, api_port, &addr).await {
                        tracing::info!(peer_id = %pid, %addr, "mDNS: discovered peer");
                        break;
                    }
                }
            }
            Ok(_) => {} // SearchStarted / ServiceFound / *Removed — nothing to do
            Err(_) => {
                // Channel closed/errored: back off, then keep trying.
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Register our `_p2pnas._tcp` service (auto-detecting local addresses).
fn announce(daemon: &ServiceDaemon, peer_id: &str, p2p_port: u16) {
    let host = format!("{peer_id}.local.");
    let props = [("peer_id", peer_id)];
    match ServiceInfo::new(SERVICE_TYPE, peer_id, &host, "", p2p_port, &props[..]) {
        Ok(info) => {
            let info = info.enable_addr_auto();
            match daemon.register(info) {
                Ok(()) => tracing::info!(port = p2p_port, "mDNS: announced _p2pnas._tcp"),
                Err(e) => tracing::warn!(error = %e, "mDNS: register failed"),
            }
        }
        Err(e) => tracing::warn!(error = %e, "mDNS: ServiceInfo build failed"),
    }
}
