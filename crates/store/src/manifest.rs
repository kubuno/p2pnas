//! Encrypted manifest (SQLCipher) — the source of truth for the file/chunk/shard
//! index. Namespaced per user (decision 2A: logical isolation). Opened on demand;
//! callers run operations inside a single connection (and a transaction for push).

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::Result;

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS files (
    file_id      TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    path         TEXT NOT NULL,
    size         INTEGER NOT NULL,
    stored_bytes INTEGER NOT NULL DEFAULT 0,
    chunk_count  INTEGER NOT NULL,
    created_at   TEXT NOT NULL,
    UNIQUE (user_id, path)
);
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id      TEXT PRIMARY KEY,
    file_id       TEXT NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    idx           INTEGER NOT NULL,
    nonce         BLOB NOT NULL,
    is_compressed INTEGER NOT NULL,
    plaintext_len INTEGER NOT NULL,
    cipher_len    INTEGER NOT NULL,
    shard_len     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS shards (
    fragment_id TEXT PRIMARY KEY,
    chunk_id    TEXT NOT NULL REFERENCES chunks(chunk_id) ON DELETE CASCADE,
    shard_index INTEGER NOT NULL,
    -- Where this shard lives: 'local' (this node's store) or a peer_id (hosted remotely).
    location    TEXT NOT NULL DEFAULT 'local'
);
CREATE INDEX IF NOT EXISTS chunks_file_idx ON chunks(file_id);
CREATE INDEX IF NOT EXISTS shards_chunk_idx ON shards(chunk_id);
"#;

#[derive(Debug, Clone, Serialize)]
pub struct FileRow {
    pub file_id:      String,
    pub user_id:      String,
    pub path:         String,
    pub size:         i64,
    pub stored_bytes: i64,
    pub chunk_count:  i64,
    pub created_at:   String,
}

#[derive(Debug, Clone)]
pub struct ChunkRow {
    pub chunk_id:      String,
    pub file_id:       String,
    pub idx:           i64,
    pub nonce:         Vec<u8>,
    pub is_compressed: bool,
    pub plaintext_len: i64,
    pub cipher_len:    i64,
    pub shard_len:     i64,
}

#[derive(Debug, Clone)]
pub struct ShardRow {
    pub fragment_id: String,
    pub chunk_id:    String,
    pub shard_index: i64,
    /// 'local' or a peer_id.
    pub location:    String,
}

/// Handle to the manifest DB (path + SQLCipher key). Open a fresh connection per
/// unit of work via [`Manifest::connect`].
#[derive(Clone)]
pub struct Manifest {
    path:    PathBuf,
    key_hex: String,
}

impl Manifest {
    pub fn new(path: impl Into<PathBuf>, key_hex: impl Into<String>) -> Self {
        Manifest { path: path.into(), key_hex: key_hex.into() }
    }

    /// Open the (encrypted) database and ensure the schema exists.
    pub fn connect(&self) -> Result<Connection> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&self.path)?;
        // Raw key form `x'HEX'` (64 hex chars = 32-byte key) — no KDF over our key.
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", self.key_hex))?;
        conn.execute_batch(SCHEMA)?;
        // Additive migration for manifests created before the `location` column.
        let _ = conn.execute_batch("ALTER TABLE shards ADD COLUMN location TEXT NOT NULL DEFAULT 'local';");
        Ok(conn)
    }
}

pub fn insert_file(conn: &Connection, f: &FileRow) -> Result<()> {
    conn.execute(
        "INSERT INTO files (file_id, user_id, path, size, stored_bytes, chunk_count, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![f.file_id, f.user_id, f.path, f.size, f.stored_bytes, f.chunk_count, f.created_at],
    )?;
    Ok(())
}

pub fn insert_chunk(conn: &Connection, c: &ChunkRow) -> Result<()> {
    conn.execute(
        "INSERT INTO chunks (chunk_id, file_id, idx, nonce, is_compressed, plaintext_len, cipher_len, shard_len)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![c.chunk_id, c.file_id, c.idx, c.nonce, c.is_compressed as i64, c.plaintext_len, c.cipher_len, c.shard_len],
    )?;
    Ok(())
}

pub fn insert_shard(conn: &Connection, s: &ShardRow) -> Result<()> {
    conn.execute(
        "INSERT INTO shards (fragment_id, chunk_id, shard_index, location) VALUES (?1, ?2, ?3, ?4)",
        params![s.fragment_id, s.chunk_id, s.shard_index, s.location],
    )?;
    Ok(())
}

/// Record where a shard now lives ('local' or a peer_id) after (re)placement.
pub fn set_shard_location(conn: &Connection, fragment_id: &str, location: &str) -> Result<()> {
    conn.execute(
        "UPDATE shards SET location = ?2 WHERE fragment_id = ?1",
        params![fragment_id, location],
    )?;
    Ok(())
}

pub fn list_files(conn: &Connection, user_id: &str) -> Result<Vec<FileRow>> {
    let mut stmt = conn.prepare(
        "SELECT file_id, user_id, path, size, stored_bytes, chunk_count, created_at
         FROM files WHERE user_id = ?1 ORDER BY path",
    )?;
    let rows = stmt
        .query_map(params![user_id], map_file)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_file(conn: &Connection, user_id: &str, file_id: &str) -> Result<Option<FileRow>> {
    let mut stmt = conn.prepare(
        "SELECT file_id, user_id, path, size, stored_bytes, chunk_count, created_at
         FROM files WHERE user_id = ?1 AND file_id = ?2",
    )?;
    let row = stmt.query_row(params![user_id, file_id], map_file).ok();
    Ok(row)
}

pub fn get_file_by_path(conn: &Connection, user_id: &str, path: &str) -> Result<Option<FileRow>> {
    let mut stmt = conn.prepare(
        "SELECT file_id, user_id, path, size, stored_bytes, chunk_count, created_at
         FROM files WHERE user_id = ?1 AND path = ?2",
    )?;
    Ok(stmt.query_row(params![user_id, path], map_file).ok())
}

pub fn get_chunks(conn: &Connection, file_id: &str) -> Result<Vec<ChunkRow>> {
    let mut stmt = conn.prepare(
        "SELECT chunk_id, file_id, idx, nonce, is_compressed, plaintext_len, cipher_len, shard_len
         FROM chunks WHERE file_id = ?1 ORDER BY idx",
    )?;
    let rows = stmt
        .query_map(params![file_id], |r| {
            Ok(ChunkRow {
                chunk_id:      r.get(0)?,
                file_id:       r.get(1)?,
                idx:           r.get(2)?,
                nonce:         r.get(3)?,
                is_compressed: r.get::<_, i64>(4)? != 0,
                plaintext_len: r.get(5)?,
                cipher_len:    r.get(6)?,
                shard_len:     r.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_shards(conn: &Connection, chunk_id: &str) -> Result<Vec<ShardRow>> {
    let mut stmt = conn.prepare(
        "SELECT fragment_id, chunk_id, shard_index, location FROM shards WHERE chunk_id = ?1 ORDER BY shard_index",
    )?;
    let rows = stmt
        .query_map(params![chunk_id], |r| {
            Ok(ShardRow { fragment_id: r.get(0)?, chunk_id: r.get(1)?, shard_index: r.get(2)?, location: r.get(3)? })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Delete a file (chunks + shards cascade). Returns the fragment ids that were
/// referenced, so the caller can remove them from the shard store.
pub fn delete_file(conn: &Connection, user_id: &str, file_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT s.fragment_id FROM shards s
         JOIN chunks c ON c.chunk_id = s.chunk_id
         WHERE c.file_id = ?1",
    )?;
    let frags = stmt
        .query_map(params![file_id], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    conn.execute("DELETE FROM files WHERE user_id = ?1 AND file_id = ?2", params![user_id, file_id])?;
    Ok(frags)
}

fn map_file(r: &rusqlite::Row) -> rusqlite::Result<FileRow> {
    Ok(FileRow {
        file_id:      r.get(0)?,
        user_id:      r.get(1)?,
        path:         r.get(2)?,
        size:         r.get(3)?,
        stored_bytes: r.get(4)?,
        chunk_count:  r.get(5)?,
        created_at:   r.get(6)?,
    })
}

/// Helper used by both reader and writer paths for stable fragment addressing.
pub fn fragment_id(chunk_id: &str, shard_index: usize) -> String {
    let mut h = blake3::Hasher::new();
    h.update(chunk_id.as_bytes());
    h.update(b":");
    h.update(&(shard_index as u32).to_be_bytes());
    hex::encode(&h.finalize().as_bytes()[..16])
}

/// Stable per-chunk id.
pub fn chunk_id(file_id: &str, idx: usize) -> String {
    format!("{file_id}:{idx}")
}

#[allow(dead_code)]
fn _unused(_: &Path) {}
