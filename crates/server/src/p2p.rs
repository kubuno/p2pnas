//! Wires the embedded P2P listener to this node's shard store. Shards hosted FOR
//! other peers live in the same on-disk store, tracked in `p2pnas.hosted_shards`.

use std::sync::Arc;

use async_trait::async_trait;
use p2pnas_p2p::ShardHandler;
use p2pnas_store::ChunkStore;
use sqlx::PgPool;

/// Largest single shard we accept to host (a shard is ~chunk/DATA_SHARDS bytes;
/// 8 MiB is far above the default, and rejects an over-large/malicious frame).
const MAX_HOSTED_SHARD: i64 = 8 * 1024 * 1024;

pub struct P2pShardHandler {
    pub peer_id:  String,
    pub api_port: u16,
    pub store:    Arc<ChunkStore>,
    pub db:       PgPool,
}

impl P2pShardHandler {
    /// Bytes we already host for the given fragment (0 if none).
    async fn hosted_size(&self, fragment_id: &str) -> i64 {
        sqlx::query_scalar("SELECT size_bytes FROM p2pnas.hosted_shards WHERE fragment_id = $1")
            .bind(fragment_id)
            .fetch_optional(&self.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(0)
    }
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

        // (5) Size guard.
        if size > MAX_HOSTED_SHARD {
            tracing::warn!(fragment_id, size, "rejecting oversized hosted shard");
            return false;
        }

        // (3) Write authorization: only host for peers we know (trusted set /
        // discovered). Blocks a random internet host from filling our disk.
        let known: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM p2pnas.peers WHERE peer_id = $1")
            .bind(owner_peer_id)
            .fetch_optional(&self.db)
            .await
            .ok()
            .flatten();
        if known.is_none() {
            tracing::warn!(owner_peer_id, "rejecting StoreShard from unknown peer");
            return false;
        }

        // (4) Capacity: never host beyond what we contribute to the network.
        let (contributed, hosted): (i64, i64) =
            sqlx::query_as("SELECT contributed_bytes, hosted_bytes FROM p2pnas.node_local WHERE id = 1")
                .fetch_one(&self.db)
                .await
                .unwrap_or((0, 0));
        let old = self.hosted_size(fragment_id).await;
        if hosted - old + size > contributed {
            tracing::warn!(fragment_id, hosted, contributed, "rejecting hosted shard: contribution cap reached");
            return false;
        }

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
            return false;
        }
        // (16) Accounting: net delta of hosted bytes.
        let _ = sqlx::query("UPDATE p2pnas.node_local SET hosted_bytes = GREATEST(hosted_bytes + $1, 0), updated_at = now() WHERE id = 1")
            .bind(size - old)
            .execute(&self.db)
            .await;
        true
    }

    async fn get(&self, fragment_id: &str) -> Option<Vec<u8>> {
        self.store.read(fragment_id).ok()
    }

    async fn has(&self, fragment_id: &str) -> bool {
        self.store.exists(fragment_id)
    }

    async fn audit(&self, fragment_id: &str) -> String {
        match self.store.read(fragment_id) {
            Ok(b) => p2pnas_store::shard_hash(&b),
            Err(_) => String::new(),
        }
    }

    async fn delete(&self, fragment_id: &str, _owner_peer_id: &str) -> bool {
        let old = self.hosted_size(fragment_id).await;
        let _ = self.store.delete(fragment_id);
        let _ = sqlx::query("DELETE FROM p2pnas.hosted_shards WHERE fragment_id = $1")
            .bind(fragment_id)
            .execute(&self.db)
            .await;
        let _ = sqlx::query("UPDATE p2pnas.node_local SET hosted_bytes = GREATEST(hosted_bytes - $1, 0), updated_at = now() WHERE id = 1")
            .bind(old)
            .execute(&self.db)
            .await;
        true
    }
}
