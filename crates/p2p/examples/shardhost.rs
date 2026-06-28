//! A minimal standalone peer that hosts shards on disk — for testing the
//! distribution path against a running p2pnas node.
//!   cargo run -p p2pnas-p2p --example shardhost -- 127.0.0.1:7475 /tmp/p2p-peer <peer_id>
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use p2pnas_p2p::{serve, ShardHandler};
use tokio::net::TcpListener;

struct FileHost {
    id: String,
    dir: PathBuf,
}

#[async_trait]
impl ShardHandler for FileHost {
    fn peer_id(&self) -> String { self.id.clone() }
    fn api_port(&self) -> u16 { 0 }
    async fn store(&self, fragment_id: &str, _owner: &str, data: Vec<u8>) -> bool {
        let _ = std::fs::create_dir_all(&self.dir);
        std::fs::write(self.dir.join(fragment_id), data).is_ok()
    }
    async fn get(&self, fragment_id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.dir.join(fragment_id)).ok()
    }
    async fn has(&self, fragment_id: &str) -> bool {
        self.dir.join(fragment_id).exists()
    }
    async fn delete(&self, fragment_id: &str, _owner: &str) -> bool {
        std::fs::remove_file(self.dir.join(fragment_id)).is_ok()
    }
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a.get(1).cloned().unwrap_or_else(|| "127.0.0.1:7475".into());
    let dir = a.get(2).cloned().unwrap_or_else(|| "/tmp/p2p-peer".into());
    let peer_id = a.get(3).cloned().unwrap_or_else(|| "testpeerhost00000000000000000aaa".into());
    let listener = TcpListener::bind(&addr).await.expect("bind shardhost");
    println!("shardhost peer_id={peer_id} addr={addr} dir={dir}");
    serve(listener, Arc::new(FileHost { id: peer_id, dir: dir.into() })).await;
}
