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
    -- Soft delete + versioning. A row is "retired" once it is in the trash
    -- (`deleted_at`) or has been replaced by a newer upload at the same path
    -- (`superseded_at`). Retiring a row moves its user-visible path into
    -- `retired_path` and rewrites `path` to a tombstone key derived from the
    -- file_id (see `RETIRED_PATH_PREFIX`), so `UNIQUE (user_id, path)` below keeps
    -- guarding exactly one namespace: the live one.
    retired_path  TEXT,
    deleted_at    TEXT,
    superseded_at TEXT,
    -- Every version of the same logical file shares a lineage id (the file_id of
    -- the first version stored at that path). NULL on rows written before
    -- versioning existed — read everywhere as COALESCE(lineage, file_id).
    lineage       TEXT,
    -- Which key-derivation / authentication scheme this file was written with
    -- (see `p2pnas_core::crypto::KeyScheme`). The read path MUST reproduce the
    -- scheme used at write time, so it is stored per file rather than assumed.
    -- 1 = legacy (node key + file id, empty AAD); 2 = owner-bound key + per-chunk
    -- authenticated metadata. Rows written before this column read back as 1.
    key_scheme    INTEGER NOT NULL DEFAULT 1,
    -- BLAKE3 of the plaintext, so re-uploading identical bytes can be recognised
    -- and skipped instead of storing a whole new version (a sync client that
    -- re-pushes unchanged files would otherwise multiply the parc by the version
    -- cap). NULL on rows written before this column: they simply never match.
    content_hash  TEXT,
    -- Small-file packing (see `service::pack_files`). A "member" row's bytes live
    -- inside a container ("pack") that is itself an ordinary `files` row — one
    -- whose `path` is a hidden `PACK_PATH_PREFIX` key, exactly like retired rows
    -- park theirs on a tombstone. Reusing `files` (rather than a new table) keeps
    -- the `chunks → files` cascade, purge, repair, placement and remote GC working
    -- unchanged for packs. A member has `chunk_count = 0`, no chunk/shard rows of
    -- its own, and reads back as the plaintext range
    -- [pack_offset, pack_offset + pack_len) of its pack. NULL = self-contained.
    pack_id       TEXT,
    pack_offset   INTEGER,
    pack_len      INTEGER,
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
    location    TEXT NOT NULL DEFAULT 'local',
    -- blake3 of the shard bytes (hex), to detect corruption/tampering on read and
    -- to verify proof-of-storage challenges from peers.
    hash        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS chunks_file_idx ON chunks(file_id);
CREATE INDEX IF NOT EXISTS shards_chunk_idx ON shards(chunk_id);
-- Explicit folders (so empty / freshly-created directories persist; non-empty
-- folders are also implied by file paths). `parent` is the dirname of `path`.
CREATE TABLE IF NOT EXISTS folders (
    user_id TEXT NOT NULL,
    path    TEXT NOT NULL,
    parent  TEXT NOT NULL,
    PRIMARY KEY (user_id, path)
);
CREATE INDEX IF NOT EXISTS folders_parent_idx ON folders(user_id, parent);
"#;

/// Indexes over the soft-delete / versioning / packing columns.
///
/// Kept out of [`SCHEMA`] on purpose: on a manifest created before those columns
/// existed the `CREATE TABLE IF NOT EXISTS` above is a no-op, so the columns only
/// appear once `add_column_if_missing` has run. Indexing them has to happen after.
const SCHEMA_RETIRED_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS files_trash_idx ON files(user_id, deleted_at);
-- Indexed on the same expression the version lookup selects on (COALESCE is
-- deterministic, so SQLite accepts it in an index and can actually use it here);
-- indexing the bare column would never be consulted.
CREATE INDEX IF NOT EXISTS files_lineage_idx ON files(user_id, COALESCE(lineage, file_id));
CREATE INDEX IF NOT EXISTS files_superseded_idx ON files(superseded_at);
-- Member → pack lookups (compaction, occupancy). Partial: almost every row has
-- NULL here, and NULL rows are the ones the index would otherwise be full of.
CREATE INDEX IF NOT EXISTS files_pack_idx ON files(pack_id) WHERE pack_id IS NOT NULL;
"#;

/// Prefix of the tombstone key a retired row's `path` is rewritten to.
///
/// It exists only to keep `UNIQUE (user_id, path)` — baked into the table since
/// the first release, and not relaxable without rebuilding a table other tables
/// hold foreign keys into — from treating a trashed file or an old version as
/// still occupying its path. U+0001 is a control character no real path carries,
/// and the file_id appended to it is the table's primary key, so the rewritten
/// value is unique by construction and can never collide with a live path.
/// Callers never see it: every read goes through `COALESCE(retired_path, path)`.
const RETIRED_PATH_PREFIX: &str = "\u{1}retired/";

/// The tombstone key a retired row parks its `path` on. Deriving it from the
/// file_id makes retiring idempotent: applying it twice is a no-op.
fn retired_key(file_id: &str) -> String {
    format!("{RETIRED_PATH_PREFIX}{file_id}")
}

/// Prefix of the hidden key a pack container row uses as its `path`.
///
/// Same construction — and same rationale — as [`RETIRED_PATH_PREFIX`]: U+0001
/// never occurs in a real path, and the pack's file_id appended to it makes the
/// value unique under `UNIQUE (user_id, path)` by construction. A pack row is a
/// LIVE row (never trashed or superseded), so the listing queries exclude this
/// prefix explicitly; everything keyed by file_id (chunks, shards, cascade,
/// purge, repair, placement) treats a pack like any other file.
pub const PACK_PATH_PREFIX: &str = "\u{1}pack/";

/// The hidden `path` key of the pack container row with id `pack_id`.
pub fn pack_key(pack_id: &str) -> String {
    format!("{PACK_PATH_PREFIX}{pack_id}")
}

/// SQL predicate keeping hidden pack container rows out of user-facing reads.
///
/// `%` / `_` cannot occur in the prefix, so a plain LIKE is exact here. Interpolated
/// (not bound) because every query that uses it is already built with `format!`.
fn not_pack() -> String {
    format!("path NOT LIKE '{PACK_PATH_PREFIX}%'")
}

/// Columns every `FileRow` read selects, in `map_file` order.
///
/// `path` is always the user-visible one and `lineage` always a usable id, so no
/// caller has to know that retired rows park their path elsewhere.
const FILE_COLS: &str = "file_id, user_id, COALESCE(retired_path, path) AS path, size, stored_bytes, \
                         chunk_count, created_at, deleted_at, superseded_at, COALESCE(lineage, file_id) AS lineage, \
                         key_scheme, content_hash, pack_id, pack_offset, pack_len";

/// SQL predicate for a row the user currently sees: not in the trash, not replaced.
const LIVE: &str = "deleted_at IS NULL AND superseded_at IS NULL";

/// Directory part of a "/"-separated path ("" for a top-level entry).
pub fn dirname(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..i],
        None => "",
    }
}

/// Last segment of a "/"-separated path.
pub fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRow {
    pub file_id:      String,
    pub user_id:      String,
    /// User-visible path — the one it occupies, or occupied before being retired.
    pub path:         String,
    pub size:         i64,
    pub stored_bytes: i64,
    pub chunk_count:  i64,
    pub created_at:   String,
    /// RFC3339 instant this file was moved to the trash (None = not deleted).
    /// The bytes are still stored and still counted: the trash is a delay, not a
    /// discount.
    pub deleted_at:    Option<String>,
    /// RFC3339 instant a newer upload took this path over (None = current version).
    pub superseded_at: Option<String>,
    /// Id shared by every version of the same logical file (see `SCHEMA`).
    pub lineage:       String,
    /// Key scheme this file was written with (`p2pnas_core::crypto::KeyScheme`).
    pub key_scheme:    i64,
    /// BLAKE3 of the plaintext (None on rows written before it was recorded).
    pub content_hash:  Option<String>,
    /// file_id of the pack this row's bytes live in (None = self-contained file).
    pub pack_id:       Option<String>,
    /// Byte offset of this member in the pack's PLAINTEXT (None when `pack_id` is).
    pub pack_offset:   Option<i64>,
    /// Byte length of this member in the pack's plaintext.
    pub pack_len:      Option<i64>,
}

impl FileRow {
    /// True while the user still sees this row in listings.
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none() && self.superseded_at.is_none()
    }

    /// True for a hidden pack container row (recognised by its `path` key, the
    /// same way retired rows are recognised by theirs).
    pub fn is_pack(&self) -> bool {
        self.path.starts_with(PACK_PATH_PREFIX)
    }
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
    /// blake3(shard bytes) in hex (empty for pre-hash rows).
    pub hash:        String,
}

/// blake3 of shard bytes, hex — the canonical content hash stored in `hash`.
pub fn shard_hash(bytes: &[u8]) -> String {
    hex::encode(&blake3::hash(bytes).as_bytes()[..16])
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

    /// Write a consistent, self-contained snapshot of the manifest to `dest`
    /// using `VACUUM INTO`. The snapshot inherits the connection's SQLCipher key,
    /// so it is encrypted with the node's manifest key exactly like the live DB —
    /// readable again only once the matching `identity.key` is restored.
    ///
    /// `VACUUM INTO` takes a whole-database read lock and produces a coherent copy
    /// even while the manifest is in use, so this is safe to run from a background
    /// job. `dest` comes from the node's own configuration, never from user input.
    pub fn snapshot_to(&self, dest: &Path) -> Result<()> {
        if dest.exists() {
            std::fs::remove_file(dest)?;
        }
        let conn = self.connect()?;
        // `dest` is a trusted local path (data_dir); the single quotes are SQL
        // string delimiters and the path cannot contain one here.
        conn.execute_batch(&format!("VACUUM INTO '{}';", dest.display()))?;
        Ok(())
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
        // Additive migrations for manifests created before these columns existed.
        //
        // These used to be fire-and-forget (`let _ = ALTER TABLE …`), which made the
        // expected "duplicate column name" indistinguishable from a real failure.
        // That is not a cosmetic difference for `hash`: `verify_hash` treats an empty
        // hash as a legacy row and passes it, so a manifest that silently never got
        // the column would have every row at `hash = ''` and every integrity check
        // would succeed unconditionally. We therefore look the column up first and
        // propagate anything that goes wrong.
        add_column_if_missing(&conn, "shards", "location", "TEXT NOT NULL DEFAULT 'local'")?;
        add_column_if_missing(&conn, "shards", "hash", "TEXT NOT NULL DEFAULT ''")?;
        // Trash + versioning. All four are nullable with no default, so every row
        // already in the manifest reads back as "live, current, first of its
        // lineage" — exactly what it was before these columns existed.
        add_column_if_missing(&conn, "files", "retired_path", "TEXT")?;
        add_column_if_missing(&conn, "files", "deleted_at", "TEXT")?;
        add_column_if_missing(&conn, "files", "superseded_at", "TEXT")?;
        add_column_if_missing(&conn, "files", "lineage", "TEXT")?;
        add_column_if_missing(&conn, "files", "key_scheme", "INTEGER NOT NULL DEFAULT 1")?;
        add_column_if_missing(&conn, "files", "content_hash", "TEXT")?;
        // Small-file packing. All three nullable with no default: every existing
        // row reads back as a self-contained file, exactly what it was.
        add_column_if_missing(&conn, "files", "pack_id", "TEXT")?;
        add_column_if_missing(&conn, "files", "pack_offset", "INTEGER")?;
        add_column_if_missing(&conn, "files", "pack_len", "INTEGER")?;
        conn.execute_batch(SCHEMA_RETIRED_INDEXES).inspect_err(|e| {
            tracing::error!(error = %e, "manifest migration failed: could not index the trash columns");
        })?;
        Ok(conn)
    }
}

/// True if `table` already has a column named `column`.
///
/// `PRAGMA table_info` accepts no bound parameter, but `table` is always a literal
/// written in this module — never user input — so interpolating it is safe here.
fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        // Column 1 of `table_info` is the column name.
        if row.get::<_, String>(1)? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Add `column` to `table` if it is not there yet. Unlike a blind `ALTER TABLE`,
/// a genuine failure (I/O error, wrong key, corruption) is logged and propagated
/// instead of being mistaken for "the column already exists".
fn add_column_if_missing(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<()> {
    if column_exists(conn, table, column)? {
        return Ok(());
    }
    // Same rationale as above: table/column/decl are literals from this module.
    conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl};"))
        .inspect_err(|e| {
            tracing::error!(table, column, error = %e, "manifest migration failed: could not add column");
        })?;
    Ok(())
}

/// Insert a brand-new, live file row. `f.deleted_at` / `f.superseded_at` are
/// ignored: a freshly pushed version is always the current one.
pub fn insert_file(conn: &Connection, f: &FileRow) -> Result<()> {
    conn.execute(
        "INSERT INTO files (file_id, user_id, path, size, stored_bytes, chunk_count, created_at, lineage, key_scheme,
                            content_hash, pack_id, pack_offset, pack_len)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![f.file_id, f.user_id, f.path, f.size, f.stored_bytes, f.chunk_count, f.created_at, f.lineage,
                f.key_scheme, f.content_hash, f.pack_id, f.pack_offset, f.pack_len],
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
        "INSERT INTO shards (fragment_id, chunk_id, shard_index, location, hash) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![s.fragment_id, s.chunk_id, s.shard_index, s.location, s.hash],
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

/// The files a user currently sees: neither in the trash nor replaced by a newer
/// version — and never a pack container, which is storage plumbing, not a file
/// the user ever uploaded under that name. This is what every listing/browsing
/// path goes through.
pub fn list_files(conn: &Connection, user_id: &str) -> Result<Vec<FileRow>> {
    let np = not_pack();
    let mut stmt = conn.prepare(&format!(
        "SELECT {FILE_COLS} FROM files WHERE user_id = ?1 AND {LIVE} AND {np} ORDER BY path"
    ))?;
    let rows = stmt
        .query_map(params![user_id], map_file)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// The user's trash: files they deleted, still restorable until purged. Most
/// recently deleted first — that is the order a trash view reads in.
pub fn list_trashed(conn: &Connection, user_id: &str) -> Result<Vec<FileRow>> {
    // A pack is never trashed (it has no user-visible path to delete from), but
    // the exclusion is kept here too so no future caller can surface one.
    let np = not_pack();
    let mut stmt = conn.prepare(&format!(
        "SELECT {FILE_COLS} FROM files WHERE user_id = ?1 AND deleted_at IS NOT NULL AND {np}
          ORDER BY deleted_at DESC, path"
    ))?;
    let rows = stmt
        .query_map(params![user_id], map_file)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every stored version of one logical file — the current one included — newest
/// first. `lineage` is the value carried by [`FileRow::lineage`].
pub fn list_lineage(conn: &Connection, user_id: &str, lineage: &str) -> Result<Vec<FileRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {FILE_COLS} FROM files
          WHERE user_id = ?1 AND COALESCE(lineage, file_id) = ?2
          ORDER BY created_at DESC, file_id DESC"
    ))?;
    let rows = stmt
        .query_map(params![user_id, lineage], map_file)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every row a user owns, whatever its state (live, trashed, superseded). Used
/// when the account itself goes away and nothing may be left behind.
pub fn list_user_rows(conn: &Connection, user_id: &str) -> Result<Vec<FileRow>> {
    let mut stmt =
        conn.prepare(&format!("SELECT {FILE_COLS} FROM files WHERE user_id = ?1 ORDER BY path"))?;
    let rows = stmt
        .query_map(params![user_id], map_file)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every file across all users (for the node-wide repair/scrub pass).
///
/// Deliberately unfiltered: a trashed file and an old version still have shards
/// on peers and still have to survive until they are purged, otherwise a restore
/// would hand back an unrecoverable file. Their bytes are also what
/// `node_stats` must keep counting for the node's accounting to match reality.
pub fn list_all_files(conn: &Connection) -> Result<Vec<FileRow>> {
    let mut stmt = conn.prepare(&format!("SELECT {FILE_COLS} FROM files ORDER BY user_id, path"))?;
    let rows = stmt
        .query_map([], map_file)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Turn a single-row lookup into `Option`, but ONLY for "no such row".
///
/// `query_row(..).ok()` used to be the idiom here, which reported an unreadable
/// manifest (I/O error, corruption, wrong SQLCipher key) as "file not found":
/// a broken account looked like an empty one, and callers would happily go on to
/// re-create or delete data on that basis. Anything other than
/// `QueryReturnedNoRows` is logged and propagated.
fn optional_row<T>(res: rusqlite::Result<T>, what: &str) -> Result<Option<T>> {
    match res {
        Ok(row) => Ok(Some(row)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => {
            tracing::error!(query = what, error = %e, "manifest lookup failed");
            Err(e.into())
        }
    }
}

/// Look a file up by id, **whatever its state**. Reading a trashed file or an old
/// version is legitimate (previewing before restoring it, repairing its shards);
/// what the state gates is whether it shows up in a listing, not whether it can
/// be read. Callers that need a live row check [`FileRow::is_live`].
pub fn get_file(conn: &Connection, user_id: &str, file_id: &str) -> Result<Option<FileRow>> {
    let mut stmt =
        conn.prepare(&format!("SELECT {FILE_COLS} FROM files WHERE user_id = ?1 AND file_id = ?2"))?;
    optional_row(stmt.query_row(params![user_id, file_id], map_file), "get_file")
}

/// The file **currently** at `path` (retired rows park their path elsewhere, and
/// the state predicate says so explicitly rather than relying on that). Pack
/// container rows are excluded so no crafted path can address one by name —
/// they are reachable by file_id only.
pub fn get_file_by_path(conn: &Connection, user_id: &str, path: &str) -> Result<Option<FileRow>> {
    let np = not_pack();
    let mut stmt = conn.prepare(&format!(
        "SELECT {FILE_COLS} FROM files WHERE user_id = ?1 AND path = ?2 AND {LIVE} AND {np}"
    ))?;
    optional_row(stmt.query_row(params![user_id, path], map_file), "get_file_by_path")
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
        "SELECT fragment_id, chunk_id, shard_index, location, hash FROM shards WHERE chunk_id = ?1 ORDER BY shard_index",
    )?;
    let rows = stmt
        .query_map(params![chunk_id], |r| {
            Ok(ShardRow {
                fragment_id: r.get(0)?,
                chunk_id:    r.get(1)?,
                shard_index: r.get(2)?,
                location:    r.get(3)?,
                hash:        r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// ── Trash / versions ─────────────────────────────────────────────────────────

/// Retire a row: stamp `column` (`deleted_at` or `superseded_at`) and vacate the
/// live namespace by parking the path in `retired_path` and the path itself on a
/// tombstone key. Returns false when the row did not exist or was already retired
/// this way, which makes both callers idempotent.
///
/// `retired_path = COALESCE(retired_path, path)` keeps the FIRST path recorded: a
/// version that was superseded and later has its whole lineage trashed must still
/// remember where the user last saw it. `path = ?4` is unconditional because the
/// key is derived from the primary key — re-applying it changes nothing.
///
/// `column` is a literal written in this module (never user input), so
/// interpolating it is safe; SQLite has no way to bind a column name.
fn retire_row(conn: &Connection, user_id: &str, file_id: &str, column: &str, at: &str) -> Result<bool> {
    let n = conn
        .execute(
            &format!(
                "UPDATE files
                    SET {column} = ?3,
                        retired_path = COALESCE(retired_path, path),
                        path = ?4
                  WHERE user_id = ?1 AND file_id = ?2 AND {column} IS NULL"
            ),
            params![user_id, file_id, at, retired_key(file_id)],
        )
        .inspect_err(|e| {
            tracing::error!(column, file_id, error = %e, "manifest: could not retire a file row");
        })?;
    Ok(n > 0)
}

/// Move a file to the trash (`at` = RFC3339 instant). Nothing is freed: the shards
/// stay exactly where they are until the row is purged.
pub fn trash_file(conn: &Connection, user_id: &str, file_id: &str, at: &str) -> Result<bool> {
    retire_row(conn, user_id, file_id, "deleted_at", at)
}

/// Mark a file as replaced by a newer upload at the same path — it becomes a
/// version, not a deletion, so it is absent from the trash and listed only among
/// its lineage's versions.
pub fn supersede_file(conn: &Connection, user_id: &str, file_id: &str, at: &str) -> Result<bool> {
    retire_row(conn, user_id, file_id, "superseded_at", at)
}

/// Bring a retired row back as the live file at `path`: both state stamps cleared
/// and the path taken back from the tombstone key.
///
/// The caller must have freed `path` first (nothing here breaks the tie), which is
/// what `service::restore` does by superseding whatever occupies it.
pub fn restore_file(conn: &Connection, user_id: &str, file_id: &str, path: &str) -> Result<bool> {
    let n = conn
        .execute(
            "UPDATE files
                SET deleted_at = NULL, superseded_at = NULL, retired_path = NULL, path = ?3
              WHERE user_id = ?1 AND file_id = ?2",
            params![user_id, file_id, path],
        )
        .inspect_err(|e| {
            tracing::error!(file_id, error = %e, "manifest: could not restore a file row");
        })?;
    Ok(n > 0)
}

/// A row the retention sweep may reclaim: `(user_id, file_id, size, stored_bytes)`.
/// The sizes ride along so the caller can give the bytes back to the right
/// account without a second lookup per row.
pub type PurgeCandidate = (String, String, i64, i64);

fn purge_candidates(
    stmt: &mut rusqlite::Statement<'_>,
    args: &[&dyn rusqlite::ToSql],
) -> Result<Vec<PurgeCandidate>> {
    let rows = stmt
        .query_map(args, |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Trashed rows deleted strictly before `cutoff` (RFC3339).
///
/// String comparison is safe here because every stamp is written by
/// `chrono::DateTime<Utc>::to_rfc3339`: fixed-width date and time, always the
/// `+00:00` offset, and an optional fraction introduced by `.` — which sorts
/// after the `+` of a fraction-less stamp in the same second, i.e. exactly the
/// chronological order.
pub fn trashed_before(conn: &Connection, cutoff: &str) -> Result<Vec<PurgeCandidate>> {
    let mut stmt = conn.prepare(
        "SELECT user_id, file_id, size, stored_bytes FROM files
          WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
    )?;
    purge_candidates(&mut stmt, params![cutoff])
}

/// Old versions replaced strictly before `cutoff` (RFC3339).
pub fn superseded_before(conn: &Connection, cutoff: &str) -> Result<Vec<PurgeCandidate>> {
    let mut stmt = conn.prepare(
        "SELECT user_id, file_id, size, stored_bytes FROM files
          WHERE superseded_at IS NOT NULL AND superseded_at < ?1",
    )?;
    purge_candidates(&mut stmt, params![cutoff])
}

/// Old versions past the `keep` most recent of their lineage, whatever their age —
/// the ceiling that keeps a file rewritten every minute from filling the node.
/// `keep` counts PREVIOUS versions only; the current one is not ranked here.
pub fn superseded_beyond(conn: &Connection, keep: i64) -> Result<Vec<PurgeCandidate>> {
    let mut stmt = conn.prepare(
        "SELECT user_id, file_id, size, stored_bytes FROM (
             SELECT user_id, file_id, size, stored_bytes,
                    ROW_NUMBER() OVER (
                        PARTITION BY user_id, COALESCE(lineage, file_id)
                        ORDER BY created_at DESC, file_id DESC
                    ) AS rn
               FROM files WHERE superseded_at IS NOT NULL
         ) WHERE rn > ?1",
    )?;
    purge_candidates(&mut stmt, params![keep])
}

/// Superseded versions whose lineage has nothing left to restore — no current
/// file and nothing in the trash either.
///
/// Without this, purging the last live file of a lineage strands its history: the
/// old versions stop appearing in listings AND in the trash, yet keep occupying
/// space and counting against the quota until they age out months later. Nothing
/// can bring them back, since restoring is only ever offered for a live or trashed
/// row — so they are dead weight, and reclaimed at once.
///
/// The guard is `superseded_at IS NULL` on the sibling: such a row is either live
/// or in the trash, and both are restorable, so the history behind it must stay.
pub fn superseded_orphans(conn: &Connection) -> Result<Vec<PurgeCandidate>> {
    let mut stmt = conn.prepare(
        "SELECT f.user_id, f.file_id, f.size, f.stored_bytes
           FROM files f
          WHERE f.superseded_at IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM files l
                 WHERE l.user_id = f.user_id
                   AND COALESCE(l.lineage, l.file_id) = COALESCE(f.lineage, f.file_id)
                   AND l.superseded_at IS NULL
            )",
    )?;
    purge_candidates(&mut stmt, params![])
}

/// Permanently delete a file row (chunks + shards cascade). Returns the
/// `(fragment_id, location)` of every shard that was referenced, so the caller can
/// remove local shards from the store AND send `DeleteShard` to the peers hosting
/// the remote ones.
///
/// This is the only path that actually destroys data — the user-facing delete goes
/// through [`trash_file`] and reaches this one only via the retention sweep or an
/// explicit "delete permanently".
///
/// The `JOIN files … WHERE f.user_id = ?2` is a safety filter, not just a match
/// helper: without it this listed the shards of ANY file with this id, so a caller
/// invoked with a mismatched `(user_id, file_id)` pair would delete another user's
/// shards from the store while that user's manifest row survived — silent data
/// destruction. The `DELETE` was already scoped to the user; the SELECT now is too.
pub fn purge_file_row(conn: &Connection, user_id: &str, file_id: &str) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT s.fragment_id, s.location FROM shards s
         JOIN chunks c ON c.chunk_id = s.chunk_id
         JOIN files f ON f.file_id = c.file_id
         WHERE c.file_id = ?1 AND f.user_id = ?2",
    )?;
    let frags = stmt
        .query_map(params![file_id, user_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    conn.execute("DELETE FROM files WHERE user_id = ?1 AND file_id = ?2", params![user_id, file_id])?;
    Ok(frags)
}

// ── Small-file packing ───────────────────────────────────────────────────────

/// Point a member row at `(pack_id, offset, len)` and zero its own storage
/// figures: from now on its bytes live in the pack, so counting `stored_bytes`
/// on the member too would double-charge the node's accounting, and a non-zero
/// `chunk_count` would make the crypto context of a read expect chunks the row
/// no longer has. Returns false when no such row exists.
pub fn assign_to_pack(
    conn: &Connection,
    user_id: &str,
    file_id: &str,
    pack_id: &str,
    offset: i64,
    len: i64,
) -> Result<bool> {
    let n = conn
        .execute(
            "UPDATE files
                SET pack_id = ?3, pack_offset = ?4, pack_len = ?5, chunk_count = 0, stored_bytes = 0
              WHERE user_id = ?1 AND file_id = ?2",
            params![user_id, file_id, pack_id, offset, len],
        )
        .inspect_err(|e| {
            tracing::error!(file_id, pack_id, error = %e, "manifest: could not point a member row at its pack");
        })?;
    Ok(n > 0)
}

/// Drop a file's own chunk rows (shards cascade) WITHOUT touching the file row,
/// returning the `(fragment_id, location)` of every shard that was referenced —
/// the same shape [`purge_file_row`] returns, for the same reason: the caller
/// frees local shards and hands remote ones to the GC only after its transaction
/// commits. Used when a file's bytes move into a pack: the row survives (id,
/// path, lineage, history), only its private storage goes.
///
/// The `JOIN files … user_id` guard mirrors `purge_file_row`: a mismatched
/// `(user_id, file_id)` pair must select — and delete — nothing.
pub fn strip_file_chunks(conn: &Connection, user_id: &str, file_id: &str) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT s.fragment_id, s.location FROM shards s
         JOIN chunks c ON c.chunk_id = s.chunk_id
         JOIN files f ON f.file_id = c.file_id
         WHERE c.file_id = ?1 AND f.user_id = ?2",
    )?;
    let frags = stmt
        .query_map(params![file_id, user_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    conn.execute(
        "DELETE FROM chunks
          WHERE file_id IN (SELECT file_id FROM files WHERE file_id = ?1 AND user_id = ?2)",
        params![file_id, user_id],
    )?;
    Ok(frags)
}

/// Live, self-contained files of `user_id` no larger than `max_size` — the
/// candidates the small-file repack considers. Path order on purpose: files from
/// the same folder tend to be fetched together, so packing neighbours together
/// makes the "read one member = fetch the whole pack" cost more often amortised.
///
/// `chunk_count > 0` keeps out rows that store nothing of their own (members are
/// already excluded by `pack_id IS NULL`), and pack rows themselves are excluded
/// by prefix — a partially-filled pack can be smaller than `max_size`.
pub fn packable_files(conn: &Connection, user_id: &str, max_size: i64) -> Result<Vec<FileRow>> {
    let np = not_pack();
    let mut stmt = conn.prepare(&format!(
        "SELECT {FILE_COLS} FROM files
          WHERE user_id = ?1 AND {LIVE} AND pack_id IS NULL AND chunk_count > 0
            AND size <= ?2 AND {np}
          ORDER BY path"
    ))?;
    let rows = stmt
        .query_map(params![user_id, max_size], map_file)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// The users who currently have at least one packable file (same predicate as
/// [`packable_files`]), so a node-wide repack pass knows whom to visit.
pub fn packable_user_ids(conn: &Connection, max_size: i64) -> Result<Vec<String>> {
    let np = not_pack();
    let mut stmt = conn.prepare(&format!(
        "SELECT DISTINCT user_id FROM files
          WHERE {LIVE} AND pack_id IS NULL AND chunk_count > 0 AND size <= ?1 AND {np}
          ORDER BY user_id"
    ))?;
    let rows = stmt
        .query_map(params![max_size], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every row whose bytes live in `pack_id`, WHATEVER its state. Trashed and
/// superseded members are still restorable, so their ranges are still live bytes
/// of the pack; only a row that has been purged (deleted outright) stops holding
/// its range.
pub fn pack_members(conn: &Connection, user_id: &str, pack_id: &str) -> Result<Vec<FileRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {FILE_COLS} FROM files WHERE user_id = ?1 AND pack_id = ?2 ORDER BY pack_offset"
    ))?;
    let rows = stmt
        .query_map(params![user_id, pack_id], map_file)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// One pack's occupancy: the container row, the plaintext bytes still referenced
/// by member rows, and how many member rows reference it.
pub type PackOccupancy = (FileRow, i64, i64);

/// Every pack on the node with its referenced bytes and member count — what the
/// compaction pass decides from. A pack referenced by no row at all is pure dead
/// weight; one whose referenced bytes fall low enough is worth rewriting.
pub fn pack_occupancy(conn: &Connection) -> Result<Vec<PackOccupancy>> {
    // The derived table's grouping column is renamed (`member_of`) so the
    // unqualified `pack_id` in FILE_COLS stays unambiguous and resolves against
    // `p` (the pack row) — the aggregate join only appends two columns.
    let mut stmt = conn.prepare(&format!(
        "SELECT {FILE_COLS}, COALESCE(m.bytes, 0), COALESCE(m.members, 0)
           FROM files p
           LEFT JOIN (SELECT pack_id AS member_of, SUM(pack_len) AS bytes, COUNT(*) AS members
                        FROM files WHERE pack_id IS NOT NULL GROUP BY pack_id) m
             ON m.member_of = p.file_id
          WHERE p.path LIKE '{PACK_PATH_PREFIX}%'
          ORDER BY p.user_id, p.file_id"
    ))?;
    let rows = stmt
        .query_map([], |r| Ok((map_file(r)?, r.get(15)?, r.get(16)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// ── Folders ──────────────────────────────────────────────────────────────────

/// Create a folder and every missing ancestor (idempotent). No-op for "".
pub fn insert_folder(conn: &Connection, user_id: &str, path: &str) -> Result<()> {
    let path = path.trim_matches('/');
    if path.is_empty() {
        return Ok(());
    }
    // Build each ancestor prefix ("a", "a/b", "a/b/c") and insert if absent.
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut acc = String::new();
    for seg in segs {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        let parent = dirname(&acc).to_string();
        conn.execute(
            "INSERT OR IGNORE INTO folders (user_id, path, parent) VALUES (?1, ?2, ?3)",
            params![user_id, acc, parent],
        )?;
    }
    Ok(())
}

/// Explicit folder paths directly under `parent`.
pub fn folders_in(conn: &Connection, user_id: &str, parent: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT path FROM folders WHERE user_id = ?1 AND parent = ?2 ORDER BY path")?;
    let rows = stmt
        .query_map(params![user_id, parent], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// True if an explicit folder exists at `path`.
pub fn folder_exists(conn: &Connection, user_id: &str, path: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM folders WHERE user_id = ?1 AND path = ?2",
        params![user_id, path],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Delete a folder row (single path).
pub fn delete_folder_row(conn: &Connection, user_id: &str, path: &str) -> Result<()> {
    conn.execute("DELETE FROM folders WHERE user_id = ?1 AND path = ?2", params![user_id, path])?;
    Ok(())
}

/// Delete every folder row at or under `path` (the subtree). Files are handled by
/// the caller (which needs the fragment ids to free shards).
pub fn delete_folder_subtree(conn: &Connection, user_id: &str, path: &str) -> Result<()> {
    let prefix = format!("{path}/");
    conn.execute(
        "DELETE FROM folders WHERE user_id = ?1 AND (path = ?2 OR path LIKE ?3)",
        params![user_id, path, format!("{prefix}%")],
    )?;
    Ok(())
}

/// Live files at or under `path` (the file itself, or every file inside a folder).
/// Returns (file_id, path) pairs so the caller can free shards + re-key.
///
/// Retired rows are excluded twice over — their `path` is a tombstone key that no
/// user prefix matches, and the state predicate says so out loud — because both
/// callers (rename, trash) must only ever act on what the user can see.
pub fn files_under(conn: &Connection, user_id: &str, path: &str) -> Result<Vec<(String, String)>> {
    let prefix = format!("{path}/");
    let mut stmt = conn.prepare(&format!(
        "SELECT file_id, path FROM files
          WHERE user_id = ?1 AND (path = ?2 OR path LIKE ?3) AND {LIVE} ORDER BY path"
    ))?;
    let rows = stmt
        .query_map(params![user_id, path, format!("{prefix}%")], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every explicit folder row at or under `path`.
pub fn folders_under(conn: &Connection, user_id: &str, path: &str) -> Result<Vec<String>> {
    let prefix = format!("{path}/");
    let mut stmt = conn.prepare(
        "SELECT path FROM folders WHERE user_id = ?1 AND (path = ?2 OR path LIKE ?3) ORDER BY path",
    )?;
    let rows = stmt
        .query_map(params![user_id, path, format!("{prefix}%")], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Rewrite a single file's path (rename/move). Keeps file_id (and thus its
/// subkey/shards) intact.
pub fn update_file_path(conn: &Connection, user_id: &str, file_id: &str, new_path: &str) -> Result<()> {
    conn.execute(
        "UPDATE files SET path = ?3 WHERE user_id = ?1 AND file_id = ?2",
        params![user_id, file_id, new_path],
    )?;
    Ok(())
}

/// Rewrite a folder row's path + parent (used when moving/renaming a subtree).
pub fn update_folder_path(conn: &Connection, user_id: &str, old: &str, new: &str) -> Result<()> {
    conn.execute(
        "UPDATE folders SET path = ?3, parent = ?4 WHERE user_id = ?1 AND path = ?2",
        params![user_id, old, new, dirname(new)],
    )?;
    Ok(())
}

/// Row → [`FileRow`], in [`FILE_COLS`] order (keep the two in step).
fn map_file(r: &rusqlite::Row) -> rusqlite::Result<FileRow> {
    Ok(FileRow {
        file_id:       r.get(0)?,
        user_id:       r.get(1)?,
        path:          r.get(2)?,
        size:          r.get(3)?,
        stored_bytes:  r.get(4)?,
        chunk_count:   r.get(5)?,
        created_at:    r.get(6)?,
        deleted_at:    r.get(7)?,
        superseded_at: r.get(8)?,
        lineage:       r.get(9)?,
        key_scheme:    r.get(10)?,
        content_hash:  r.get(11)?,
        pack_id:       r.get(12)?,
        pack_offset:   r.get(13)?,
        pack_len:      r.get(14)?,
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// Fresh empty directory, unique per test (tests share a process, so the pid
    /// alone is not enough).
    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("p2pnas-manifest-{}-{name}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A minimal live row; `lineage` starts at the file's own id, as `push` does.
    fn file_row(file_id: &str, user_id: &str, path: &str) -> FileRow {
        FileRow {
            file_id:       file_id.into(),
            user_id:       user_id.into(),
            path:          path.into(),
            size:          3,
            stored_bytes:  3,
            chunk_count:   1,
            created_at:    "2026-01-01T00:00:00+00:00".into(),
            deleted_at:    None,
            superseded_at: None,
            lineage:       file_id.into(),
            key_scheme:    2,
            content_hash:  None,
            pack_id:       None,
            pack_offset:   None,
            pack_len:      None,
        }
    }

    #[test]
    fn adds_missing_columns_to_a_legacy_manifest() {
        let dir = tmp_dir("legacy");
        let db = dir.join("manifest.db");

        // A manifest as it existed before `location`/`hash` were introduced.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(&format!("PRAGMA key = \"x'{KEY}'\";")).unwrap();
            conn.execute_batch(
                "CREATE TABLE shards (
                     fragment_id TEXT PRIMARY KEY,
                     chunk_id    TEXT NOT NULL,
                     shard_index INTEGER NOT NULL
                 );",
            )
            .unwrap();
        }

        let manifest = Manifest::new(&db, KEY);
        let conn = manifest.connect().unwrap();
        assert!(column_exists(&conn, "shards", "location").unwrap());
        assert!(column_exists(&conn, "shards", "hash").unwrap());
        drop(conn);

        // Re-opening must stay a no-op rather than fail on the now-duplicate column.
        let conn = manifest.connect().unwrap();
        assert!(column_exists(&conn, "shards", "hash").unwrap());
        drop(conn);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_none_but_stored_file_is_found() {
        let dir = tmp_dir("lookup");
        let manifest = Manifest::new(dir.join("manifest.db"), KEY);
        let conn = manifest.connect().unwrap();

        assert!(get_file(&conn, "user-a", "nope").unwrap().is_none());
        assert!(get_file_by_path(&conn, "user-a", "nope.txt").unwrap().is_none());

        let row = file_row("f1", "user-a", "docs/a.txt");
        insert_file(&conn, &row).unwrap();
        assert_eq!(get_file(&conn, "user-a", "f1").unwrap().unwrap().path, "docs/a.txt");
        assert_eq!(get_file_by_path(&conn, "user-a", "docs/a.txt").unwrap().unwrap().file_id, "f1");
        // Another user must not see it (isolation is by user_id in every query).
        assert!(get_file(&conn, "user-b", "f1").unwrap().is_none());

        drop(conn);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn trashing_frees_the_path_and_hides_the_row() {
        let dir = tmp_dir("trash");
        let manifest = Manifest::new(dir.join("manifest.db"), KEY);
        let conn = manifest.connect().unwrap();

        insert_file(&conn, &file_row("f1", "u", "notes.txt")).unwrap();
        assert!(trash_file(&conn, "u", "f1", "2026-02-01T00:00:00+00:00").unwrap());
        // Trashing twice is a no-op rather than a second stamp.
        assert!(!trash_file(&conn, "u", "f1", "2026-03-01T00:00:00+00:00").unwrap());

        // Invisible in listings, visible in the trash, still readable by id.
        assert!(list_files(&conn, "u").unwrap().is_empty());
        assert_eq!(list_trashed(&conn, "u").unwrap().len(), 1);
        let row = get_file(&conn, "u", "f1").unwrap().unwrap();
        assert_eq!(row.deleted_at.as_deref(), Some("2026-02-01T00:00:00+00:00"));
        // The user-visible path survives the tombstone key.
        assert_eq!(row.path, "notes.txt");

        // And the path is free again: the UNIQUE constraint must not fire.
        insert_file(&conn, &file_row("f2", "u", "notes.txt")).unwrap();
        assert_eq!(get_file_by_path(&conn, "u", "notes.txt").unwrap().unwrap().file_id, "f2");

        // Restoring the old one supersedes nothing on its own — the caller frees the
        // path first — but it does take its own path back.
        supersede_file(&conn, "u", "f2", "2026-04-01T00:00:00+00:00").unwrap();
        assert!(restore_file(&conn, "u", "f1", "notes.txt").unwrap());
        let row = get_file(&conn, "u", "f1").unwrap().unwrap();
        assert!(row.is_live());
        assert_eq!(list_files(&conn, "u").unwrap().len(), 1);
        assert!(list_trashed(&conn, "u").unwrap().is_empty());

        drop(conn);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// History whose lineage has nothing restorable left is reclaimed at once;
    /// history still backing a live — or merely trashed — file is not.
    #[test]
    fn orphaned_history_is_reclaimable_but_restorable_history_is_not() {
        let dir = tmp_dir("orphans");
        let manifest = Manifest::new(dir.join("manifest.db"), KEY);
        let conn = manifest.connect().unwrap();

        // Lineage A: one superseded version behind a LIVE file.
        let mut a1 = file_row("a1", "u", "a.txt");
        a1.lineage = "a1".into();
        insert_file(&conn, &a1).unwrap();
        supersede_file(&conn, "u", "a1", "2026-01-02T00:00:00+00:00").unwrap();
        let mut a2 = file_row("a2", "u", "a.txt");
        a2.lineage = "a1".into();
        insert_file(&conn, &a2).unwrap();

        // Nothing is orphaned yet: a2 is live, so a1 still backs a restorable file.
        assert!(superseded_orphans(&conn).unwrap().is_empty());

        // Trashing a2 must NOT strand a1 — a trashed file can still be restored.
        trash_file(&conn, "u", "a2", "2026-01-03T00:00:00+00:00").unwrap();
        assert!(
            superseded_orphans(&conn).unwrap().is_empty(),
            "history behind a trashed file is still needed"
        );

        // Purging a2 for good leaves a1 unreachable: now it is reclaimable.
        purge_file_row(&conn, "u", "a2").unwrap();
        let orphans = superseded_orphans(&conn).unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].1, "a1");
    }

    #[test]
    fn retention_queries_pick_the_right_rows() {
        let dir = tmp_dir("retention");
        let manifest = Manifest::new(dir.join("manifest.db"), KEY);
        let conn = manifest.connect().unwrap();

        // One lineage with four versions: v4 current, v1..v3 superseded at
        // increasing dates (v1 oldest).
        for (i, id) in ["v1", "v2", "v3", "v4"].iter().enumerate() {
            let mut row = file_row(id, "u", "doc.txt");
            row.created_at = format!("2026-01-0{}T00:00:00+00:00", i + 1);
            row.lineage = "v1".into();
            // Only the current version may hold the path; retire the others first.
            if i > 0 {
                supersede_file(&conn, "u", ["v1", "v2", "v3"][i - 1], &format!("2026-01-0{}T00:00:00+00:00", i + 1))
                    .unwrap();
            }
            insert_file(&conn, &row).unwrap();
        }
        assert_eq!(list_lineage(&conn, "u", "v1").unwrap().len(), 4);
        assert_eq!(list_files(&conn, "u").unwrap().len(), 1);

        // Age cutoff: v1 (superseded on the 2nd) and v2 (on the 3rd) are older than
        // the 4th; v3 (on the 4th) is not.
        let old = superseded_before(&conn, "2026-01-04T00:00:00+00:00").unwrap();
        let mut ids: Vec<String> = old.iter().map(|c| c.1.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["v1", "v2"]);

        // Count cap: keep the 2 most recent PREVIOUS versions (v3, v2) → v1 goes.
        let beyond = superseded_beyond(&conn, 2).unwrap();
        assert_eq!(beyond.len(), 1);
        assert_eq!(beyond[0].1, "v1");
        // Keeping more than there are leaves nothing to purge.
        assert!(superseded_beyond(&conn, 10).unwrap().is_empty());

        drop(conn);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A pack container row is invisible everywhere a user looks, while its
    /// members list normally; occupancy tracks the referenced ranges as member
    /// rows come and go.
    #[test]
    fn pack_rows_are_hidden_and_occupancy_follows_the_members() {
        let dir = tmp_dir("packs");
        let manifest = Manifest::new(dir.join("manifest.db"), KEY);
        let conn = manifest.connect().unwrap();

        // The pack: a live row parked on the hidden key, holding the shards.
        let mut pack = file_row("p1", "u", &pack_key("p1"));
        pack.size = 100;
        pack.chunk_count = 1;
        insert_file(&conn, &pack).unwrap();
        // Two members pointing into it.
        for (fid, path, off, len) in [("m1", "a.txt", 0i64, 40i64), ("m2", "b.txt", 40, 30)] {
            insert_file(&conn, &file_row(fid, "u", path)).unwrap();
            assert!(assign_to_pack(&conn, "u", fid, "p1", off, len).unwrap());
        }

        // Members visible, the container not — by listing, by path, anywhere.
        let listed = list_files(&conn, "u").unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|f| !f.is_pack()));
        assert!(get_file_by_path(&conn, "u", &pack_key("p1")).unwrap().is_none());
        // A member reads back with its range, and zeroed private storage.
        let m1 = get_file(&conn, "u", "m1").unwrap().unwrap();
        assert_eq!(m1.pack_id.as_deref(), Some("p1"));
        assert_eq!((m1.pack_offset, m1.pack_len), (Some(0), Some(40)));
        assert_eq!((m1.chunk_count, m1.stored_bytes), (0, 0));

        let occ = pack_occupancy(&conn).unwrap();
        assert_eq!(occ.len(), 1);
        assert_eq!((occ[0].1, occ[0].2), (70, 2));
        // A trashed member still holds its range; a purged one no longer does.
        trash_file(&conn, "u", "m1", "2026-02-01T00:00:00+00:00").unwrap();
        assert_eq!(pack_occupancy(&conn).unwrap()[0].1, 70);
        purge_file_row(&conn, "u", "m2").unwrap();
        let occ = pack_occupancy(&conn).unwrap();
        assert_eq!((occ[0].1, occ[0].2), (40, 1));

        drop(conn);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_missing_rows_become_none() {
        let none: Result<Option<i64>> = optional_row(Err(rusqlite::Error::QueryReturnedNoRows), "t");
        assert!(matches!(none, Ok(None)));
        // Any other SQLite failure must surface, not masquerade as "not found".
        let err: Result<Option<i64>> = optional_row(Err(rusqlite::Error::InvalidQuery), "t");
        assert!(err.is_err());
    }
}
