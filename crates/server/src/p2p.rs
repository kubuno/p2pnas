//! Wires the embedded P2P listener to this node's shard store. Shards hosted FOR
//! other peers live in the same on-disk store, tracked in `p2pnas.hosted_shards`.

use std::sync::Arc;

use async_trait::async_trait;
use p2pnas_p2p::ShardHandler;
use p2pnas_store::ChunkStore;
use sqlx::PgPool;

pub struct P2pShardHandler {
    pub peer_id:  String,
    pub api_port: u16,
    pub store:    Arc<ChunkStore>,
    pub db:       PgPool,
}

#[async_trait]
impl ShardHandler for P2pShardHandler {
    fn peer_id(&self) -> String {
        self.peer_id.clone()
    }
    fn api_port(&self) -> u16 {
        self.api_port
    }

    async fn store(&self, fragment_id: &str, owner_peer_id: &str, data: Vec<u8>) -> bool {
        let size = data.len() as i64;
        if let Err(e) = self.store.write(fragment_id, &data) {
            tracing::warn!(fragment_id, error = %e, "hosted shard write failed");
            return false;
        }
        let r = sqlx::query(
            "INSERT INTO p2pnas.hosted_shards (fragment_id, owner_peer_id, size_bytes)
             VALUES ($1, $2, $3)
             ON CONFLICT (fragment_id) DO UPDATE SET owner_peer_id = EXCLUDED.owner_peer_id, size_bytes = EXCLUDED.size_bytes",
        )
        .bind(fragment_id)
        .bind(owner_peer_id)
        .bind(size)
        .execute(&self.db)
        .await;
        if let Err(e) = r {
            tracing::warn!(fragment_id, error = %e, "hosted shard record failed");
        }
        true
    }

    async fn get(&self, fragment_id: &str) -> Option<Vec<u8>> {
        self.store.read(fragment_id).ok()
    }

    async fn delete(&self, fragment_id: &str, _owner_peer_id: &str) -> bool {
        let _ = self.store.delete(fragment_id);
        let _ = sqlx::query("DELETE FROM p2pnas.hosted_shards WHERE fragment_id = $1")
            .bind(fragment_id)
            .execute(&self.db)
            .await;
        true
    }
}
