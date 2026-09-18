//! p2pnas storage layer: node identity, the SQLCipher manifest, the local shard
//! store, and the push/pull orchestration that ties them to the core pipeline.

pub mod backup;
pub mod chunkstore;
pub mod error;
pub mod identity;
pub mod manifest;
pub mod service;

pub use chunkstore::ChunkStore;
pub use error::{Result, StoreError};
pub use identity::NodeIdentity;
pub use manifest::{shard_hash, ChunkRow, FileRow, Manifest, ShardRow};
