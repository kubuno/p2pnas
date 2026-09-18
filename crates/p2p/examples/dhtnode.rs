//! A standalone p2pnas-ish node for DHT discovery tests: serves shards over TCP
//! (so a real node can handshake it) AND runs a Kademlia DHT node that bootstraps
//! off a given address.
//!   cargo run -p p2pnas-p2p --example dhtnode -- \
//!       <tcp_addr> <dir> <peer_id> <dht_udp_bind> [bootstrap_udp]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use p2pnas_p2p::{serve, DhtNode, ShardHandler};
use tokio::net::TcpListener;

struct FileHost {
    id:  String,
    dir: PathBuf,
}

#[async_trait]
impl ShardHandler for FileHost {
    fn peer_id(&self) -> String { self.id.clone() }
    fn api_port(&self) -> u16 { 0 }
    async fn store(&self, fragment_id: &str, _o: &str, _shard_index: i32, data: Vec<u8>) -> bool {
        let _ = std::fs::create_dir_all(&self.dir);
        std::fs::write(self.dir.join(fragment_id), data).is_ok()
    }
    async fn get(&self, fragment_id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.dir.join(fragment_id)).ok()
    }
    async fn has(&self, fragment_id: &str) -> bool { self.dir.join(fragment_id).exists() }
    async fn delete(&self, fragment_id: &str, _o: &str) -> bool {
        std::fs::remove_file(self.dir.join(fragment_id)).is_ok()
    }
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let tcp = a.get(1).cloned().unwrap_or_else(|| "0.0.0.0:7491".into());
    let dir = a.get(2).cloned().unwrap_or_else(|| "/tmp/dhtnode".into());
    let peer_id = a.get(3).cloned().unwrap_or_else(|| "dhtnode00000000000000000000000aaa".into());
    let dht_bind = a.get(4).cloned().unwrap_or_else(|| "0.0.0.0:7476".into());
    let bootstrap = a.get(5).cloned();

    let tcp_port: u16 = tcp.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(7491);

    // DHT node.
    let dht = DhtNode::bind(&dht_bind, &peer_id, tcp_port).await.expect("dht bind");
    tokio::spawn(dht.clone().run());
    if let Some(b) = bootstrap.clone() {
        dht.bootstrap(&[b]).await;
    }
    // Periodically refresh so transitive discovery propagates.
    {
        let dht = dht.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                dht.refresh().await;
            }
        });
    }

    println!("dhtnode peer_id={peer_id} tcp={tcp} dht={dht_bind} bootstrap={bootstrap:?}");
    let listener = TcpListener::bind(&tcp).await.expect("tcp bind");
    serve(listener, Arc::new(FileHost { id: peer_id, dir: dir.into() })).await;
}
