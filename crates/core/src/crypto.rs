//! Content encryption for the p2pnas pipeline.
//!
//! Design goals (perf without weakening security):
//!   * AES-256-GCM via **aws-lc-rs** (assembly AES-NI / VAES, constant-time).
//!   * **In-place** sealing/opening — no per-chunk allocation or copy.
//!   * A fresh **per-file subkey** derived by HKDF-SHA256(data_key, file_id). Each
//!     subkey therefore only ever protects the chunks of a single file, so the
//!     number of (key, random-nonce) pairs stays far below GCM's birthday bound
//!     (~2^32) — we keep GCM's speed without GCM-SIV's overhead.
//!   * **Deterministic counter nonce** = chunk index, under the per-file subkey.
//!     Because each file (version) gets its own subkey and chunk indices are unique
//!     within a file, no (subkey, nonce) pair ever repeats — so we get GCM's full
//!     speed with no RNG on the hot path (no lock contention across threads) AND no
//!     birthday bound. Invariant the caller MUST keep: never re-encrypt different
//!     content at the same (file_id, chunk index) — rotate `file_id` per version.
//!
//! Two schemes coexist, selected per file by [`KeyScheme`] (persisted in the
//! manifest, defaulting to v1 for rows written before it existed):
//!   * **v1** — what every already-stored file uses: subkey = HKDF(data_key,
//!     file_id), empty AAD. Read-only from now on; its bytes must never move.
//!   * **v2** — used for new writes: the subkey is bound to `(user_id, file_id)`
//!     with explicit, length-prefixed domain separation, and each chunk's GCM tag
//!     authenticates a canonical AAD over (scheme, user, file, chunk_count,
//!     chunk_index). Decrypting therefore requires knowing the owner, and a chunk
//!     replayed into another file, reordered, or a file whose tail was cut off is
//!     rejected instead of silently yielding a valid-looking result.

use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
    hkdf::{KeyType, Salt, HKDF_SHA256},
};
use rand::RngCore;

use crate::error::CoreError;

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub use aws_lc_rs::aead::NONCE_LEN as NONCE_BYTES;
// Re-exported so the crates that handle key material (store: node identity,
// manifest key) get the same wiping primitives without each declaring `zeroize`.
pub use zeroize::{Zeroize, Zeroizing};

/// HKDF info string — versioned so the derivation scheme can evolve safely.
const SUBKEY_INFO: &[u8] = b"p2pnas/file-subkey/v1";

/// HKDF salt of every **v2** derivation. Distinct from [`SUBKEY_INFO`] so that a
/// v2 derivation can never reproduce a v1 one even if the two `info` strings
/// happened to coincide: the extract step already yields a different PRK.
const HKDF_SALT_V2: &[u8] = b"p2pnas/hkdf-salt/v2";

/// Domain tag of the v2 per-file content subkey.
const FILE_SUBKEY_DOMAIN_V2: &[u8] = b"p2pnas/file-subkey/v2";

/// Domain tag of the v2 per-chunk additional authenticated data.
const CHUNK_AAD_DOMAIN_V2: &[u8] = b"p2pnas/chunk-aad/v2";

/// Highest chunk index accepted by [`ChunkSealer::seal`]. GCM's safety analysis
/// bounds the number of encryptions under one key at 2^32; the counter nonce also
/// has to stay injective. Refusing above this keeps both properties provable
/// instead of merely conventional.
const MAX_CHUNK_INDEX: u64 = u32::MAX as u64;

/// Output length of every HKDF expansion here (one AES-256 key).
///
/// Hoisted out of `derive_raw` so the v1 and v2 derivations provably share the
/// same output length; the derived bytes are unaffected.
struct OkmLen;

impl KeyType for OkmLen {
    fn len(&self) -> usize {
        KEY_LEN
    }
}

/// Append `part` to `out` as `len(part) as u64 big-endian || part`.
///
/// Length prefixing is what makes a concatenation *injective*: without it,
/// `("ab", "c")` and `("a", "bc")` produce the same byte string and therefore the
/// same derived key. Every v2 derivation input and every v2 AAD is built only
/// from this, so two different tuples can never collide.
fn push_lp(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u64).to_be_bytes());
    out.extend_from_slice(part);
}

/// Canonical (unambiguous) encoding of `parts`: the length-prefixed
/// concatenation of each part, in order. See [`push_lp`].
fn lp_concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 8).sum());
    for p in parts {
        push_lp(&mut out, p);
    }
    out
}

/// Which key-derivation / authentication scheme a given file was written with.
///
/// Persisted per file (manifest column `key_scheme`) because the read path must
/// always reproduce the exact scheme used at write time. Files written before the
/// column existed are [`KeyScheme::V1`], which is why V1 is the `Default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyScheme {
    /// Legacy scheme: subkey = HKDF(data_key, file_id), empty AAD.
    ///
    /// The owner is not bound into the key material, so any caller holding the
    /// node key and a file id can decrypt — isolation between users rests
    /// entirely on the manifest's `WHERE user_id = ?`. Kept forever so already
    /// stored data stays readable; never used for new writes.
    #[default]
    V1,
    /// Owner-bound scheme: subkey = HKDF(data_key, domain ‖ user_id ‖ file_id)
    /// with length-prefixed domain separation, and every chunk sealed under a
    /// canonical AAD covering (scheme, user, file, chunk_count, chunk_index).
    ///
    /// Consequences: a file id alone no longer decrypts anything (the owner is
    /// needed), a chunk cannot be replayed into another file, at another index,
    /// or under a different chunk count — so truncation is detected.
    V2,
}

impl KeyScheme {
    /// Wire/AAD encoding: 1 for v1, 2 for v2. Never renumber these.
    pub fn as_u8(self) -> u8 {
        match self {
            KeyScheme::V1 => 1,
            KeyScheme::V2 => 2,
        }
    }

    /// Value stored in the manifest (`key_scheme` column).
    pub fn as_i64(self) -> i64 {
        i64::from(self.as_u8())
    }

    /// Parse a manifest value back. An unknown scheme is an error rather than a
    /// silent fallback: guessing v1 for a v2 file would surface as an opaque GCM
    /// failure, and guessing v2 for a v1 file would make old data look corrupt.
    pub fn from_i64(v: i64) -> Result<Self, CoreError> {
        match v {
            1 => Ok(KeyScheme::V1),
            2 => Ok(KeyScheme::V2),
            _ => Err(CoreError::Crypto("unknown key scheme")),
        }
    }
}

/// The master content key (node-level under decision 2A). Zeroized on drop.
pub struct DataKey([u8; KEY_LEN]);

impl Drop for DataKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl DataKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        DataKey(bytes)
    }

    /// Generate a fresh random data key (used once at node init).
    pub fn random() -> Self {
        let mut b = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut b);
        DataKey(b)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive a raw 32-byte subkey: HKDF-SHA256(self, info). Used for the per-file
    /// content subkey and for non-AEAD secrets (manifest SQLCipher key, peer id).
    ///
    /// INVARIANT (domain separation): the three uses share one HKDF namespace —
    /// `info` is either a caller-supplied file id or one of the fixed strings
    /// `p2pnas/manifest/v1` / `p2pnas/peer-id/v1`. Nothing here stops a file id
    /// from *being* one of those strings, which would hand the caller the manifest
    /// SQLCipher key. What neutralises it today is that every file id reaching
    /// `file_subkey` is a 32-character hex string minted by the store (never user
    /// text), so it can never collide with a fixed label. Keep it that way: a file
    /// id must stay machine-generated and hex. The structural fix — prefixing each
    /// use with a length-delimited domain tag — is deliberately NOT applied here
    /// because it would change every derived byte and make already-stored data
    /// unreadable; it lives in [`DataKey::derive_v2`] instead, which new files use
    /// via [`KeyScheme::V2`]. This function stays frozen for the legacy path (and
    /// for the manifest / peer-id secrets, which are derived once per node).
    ///
    /// The two HKDF steps below cannot fail for a fixed 32-byte output, but the
    /// release profile is `panic = "abort"`: a panic here would tear the process
    /// down without running any `Drop`, leaving key material in memory. So the
    /// impossible case is returned as an error rather than asserted.
    pub fn derive_raw(&self, info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, CoreError> {
        let prk = Salt::new(HKDF_SHA256, SUBKEY_INFO).extract(&self.0);
        let info = [info];
        let okm = prk
            .expand(&info, OkmLen)
            .map_err(|_| CoreError::Crypto("hkdf expand"))?;
        let mut sk = Zeroizing::new([0u8; KEY_LEN]);
        okm.fill(&mut sk[..]).map_err(|_| CoreError::Crypto("hkdf fill"))?;
        Ok(sk)
    }

    /// Derive the per-file content subkey: HKDF-SHA256(self, file_id).
    pub fn file_subkey(&self, file_id: &[u8]) -> Result<FileSubkey, CoreError> {
        Ok(FileSubkey(*self.derive_raw(file_id)?))
    }

    /// v2 derivation: HKDF-SHA256 with the fixed v2 salt (`p2pnas/hkdf-salt/v2`)
    /// and `info = lp(domain) ‖ lp(parts[0]) ‖ … ‖ lp(parts[n])`, where `lp(x)` is
    /// `x` prefixed by its length as a big-endian `u64`.
    ///
    /// This is the structural fix `derive_raw` documents but cannot apply: each
    /// use is tagged by an explicit domain and every component is length-
    /// delimited, so no caller-supplied value can ever be mistaken for another
    /// use's input (a file id equal to `p2pnas/manifest/v1` is now just a 20-byte
    /// component of the file-subkey domain, not the manifest key). It is a *new*
    /// path: v1 bytes are untouched, so stored data keeps decrypting.
    ///
    /// Fails (rather than panics) for the same reason as `derive_raw`: the
    /// release profile aborts on panic without running `Drop`, which would leave
    /// key material in memory.
    pub fn derive_v2(
        &self,
        domain: &[u8],
        parts: &[&[u8]],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, CoreError> {
        let sized: usize = parts.iter().map(|p| p.len() + 8).sum();
        let mut info = Vec::with_capacity(8 + domain.len() + sized);
        push_lp(&mut info, domain);
        for p in parts {
            push_lp(&mut info, p);
        }
        let prk = Salt::new(HKDF_SHA256, HKDF_SALT_V2).extract(&self.0);
        // Bound to a named local: `expand` borrows the slice-of-slices for as long
        // as the returned `Okm` lives, so a temporary would not outlive the call.
        let info_parts = [info.as_slice()];
        let okm = prk
            .expand(&info_parts, OkmLen)
            .map_err(|_| CoreError::Crypto("hkdf expand"))?;
        let mut sk = Zeroizing::new([0u8; KEY_LEN]);
        okm.fill(&mut sk[..]).map_err(|_| CoreError::Crypto("hkdf fill"))?;
        Ok(sk)
    }

    /// Derive the v2 per-file content subkey, bound to the **owner**.
    ///
    /// Decrypting a file now requires knowing who owns it, so an application-level
    /// identifier mix-up (the class of bug that a `WHERE user_id = ?` alone cannot
    /// stop) yields a failed GCM tag instead of somebody else's plaintext.
    pub fn file_subkey_v2(&self, user_id: &[u8], file_id: &[u8]) -> Result<FileSubkey, CoreError> {
        Ok(FileSubkey(*self.derive_v2(FILE_SUBKEY_DOMAIN_V2, &[user_id, file_id])?))
    }

    /// Derive the content subkey for `scheme` — the single entry point callers
    /// should use once a file's scheme is read from the manifest. `user_id` is
    /// ignored under [`KeyScheme::V1`] (which predates owner binding).
    pub fn file_subkey_for(
        &self,
        scheme: KeyScheme,
        user_id: &[u8],
        file_id: &[u8],
    ) -> Result<FileSubkey, CoreError> {
        match scheme {
            KeyScheme::V1 => self.file_subkey(file_id),
            KeyScheme::V2 => self.file_subkey_v2(user_id, file_id),
        }
    }
}

/// A per-file derived key. Zeroized on drop.
pub struct FileSubkey([u8; KEY_LEN]);

impl Drop for FileSubkey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl FileSubkey {
    /// Build a reusable sealer (the AES key schedule is computed once here, then
    /// reused for every chunk of the file across all threads).
    pub fn sealer(&self) -> Result<ChunkSealer, CoreError> {
        let ub = UnboundKey::new(&AES_256_GCM, &self.0)
            .map_err(|_| CoreError::Crypto("aead key init"))?;
        Ok(ChunkSealer(LessSafeKey::new(ub)))
    }
}

/// 96-bit nonce = big-endian chunk index (left-zero-padded). Unique per subkey.
fn nonce_for(index: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[NONCE_LEN - 8..].copy_from_slice(&index.to_be_bytes());
    n
}

/// Seals/opens individual chunks under one file subkey. `Send + Sync` and
/// RNG-free, so it is shared read-only across rayon worker threads with no lock.
pub struct ChunkSealer(LessSafeKey);

impl ChunkSealer {
    /// Encrypt chunk `index` in place: the 16-byte tag is appended to `buf`.
    /// Returns the (deterministic) nonce for storage/clarity.
    ///
    /// INVARIANT (nonce uniqueness) — GCM breaks catastrophically on a repeated
    /// (key, nonce): forging becomes possible and both plaintexts leak via their
    /// XOR. The nonce here is `index` alone, so the caller owns the whole
    /// guarantee and MUST satisfy both halves:
    ///   1. within one sealer (i.e. one `file_id`), never seal two different
    ///      plaintexts at the same `index` — indices come from the chunk position
    ///      in a single pass over one file version, never from client input;
    ///   2. across versions, mint a fresh `file_id` for every re-upload, so
    ///      rewriting chunk 0 happens under a different subkey.
    ///
    /// Re-sealing a *byte-identical* chunk at the same index is harmless (it
    /// reproduces the same ciphertext), which is what makes deduplication safe.
    /// The bound check below only enforces the counter's range; it cannot detect a
    /// violation of (1) or (2) — an internal counter would, but that is a caller-
    /// visible API change left for a follow-up.
    pub fn seal(&self, buf: &mut Vec<u8>, index: u64) -> Result<[u8; NONCE_LEN], CoreError> {
        // `Aad::empty()` is kept literally on this path: it is what every already
        // stored chunk was sealed with.
        self.seal_inner(buf, index, Aad::empty())
    }

    /// Same as [`ChunkSealer::seal`] but binds `aad` into the GCM tag.
    ///
    /// The tag then covers the chunk's *place* (which file, which owner, which
    /// index, out of how many chunks) and not just its bytes, so a chunk lifted
    /// into another file, reordered, or a file whose trailing chunks were dropped
    /// no longer opens. Callers should pass [`ChunkAad::encode`] rather than an
    /// ad-hoc byte string, so the encoding stays canonical on both sides.
    pub fn seal_with_aad(
        &self,
        buf: &mut Vec<u8>,
        index: u64,
        aad: &[u8],
    ) -> Result<[u8; NONCE_LEN], CoreError> {
        self.seal_inner(buf, index, Aad::from(aad))
    }

    fn seal_inner<A: AsRef<[u8]>>(
        &self,
        buf: &mut Vec<u8>,
        index: u64,
        aad: Aad<A>,
    ) -> Result<[u8; NONCE_LEN], CoreError> {
        if index > MAX_CHUNK_INDEX {
            return Err(CoreError::Crypto("chunk index above the GCM per-key bound"));
        }
        let nonce = nonce_for(index);
        self.0
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), aad, buf)
            .map_err(|_| CoreError::Crypto("seal"))?;
        Ok(nonce)
    }

    /// Decrypt chunk `index` (ciphertext||tag) in place; returns the plaintext.
    ///
    /// Intentionally not bounded like `seal`: the read path must stay able to open
    /// anything the write path ever produced, and a wrong index simply fails the
    /// GCM tag check.
    pub fn open<'a>(&self, index: u64, buf: &'a mut [u8]) -> Result<&'a mut [u8], CoreError> {
        // Literal `Aad::empty()`, as above: this is the legacy read path.
        self.0
            .open_in_place(Nonce::assume_unique_for_key(nonce_for(index)), Aad::empty(), buf)
            .map_err(|_| CoreError::Crypto("open"))
    }

    /// Decrypt chunk `index` requiring `aad` to match the one used at seal time.
    /// Any mismatch (wrong file, wrong owner, wrong index, wrong chunk count)
    /// fails the tag check and returns an error — never partial plaintext.
    pub fn open_with_aad<'a>(
        &self,
        index: u64,
        buf: &'a mut [u8],
        aad: &[u8],
    ) -> Result<&'a mut [u8], CoreError> {
        self.0
            .open_in_place(Nonce::assume_unique_for_key(nonce_for(index)), Aad::from(aad), buf)
            .map_err(|_| CoreError::Crypto("open"))
    }
}

/// The metadata bound into a v2 chunk's GCM tag.
///
/// Canonical encoding — every component is prefixed by its length as a
/// big-endian `u64` (written `lp(x)` below), so no two different tuples can
/// produce the same byte string:
///
/// ```text
/// lp("p2pnas/chunk-aad/v2") ‖ lp([scheme_u8]) ‖ lp(user_id) ‖ lp(file_id)
///     ‖ lp(chunk_count as u64 BE) ‖ lp(chunk_index as u64 BE)
/// ```
///
/// `chunk_count` is what makes truncation detectable: with an empty AAD nothing
/// marks the last chunk, so dropping the trailing chunks yields a shorter file
/// that decrypts perfectly. Here every chunk of a 12-chunk file asserts "I am
/// chunk i of 12", so a file cut down to 8 chunks fails to open.
#[derive(Debug, Clone, Copy)]
pub struct ChunkAad<'a> {
    pub scheme: KeyScheme,
    pub user_id: &'a [u8],
    pub file_id: &'a [u8],
    pub chunk_count: u64,
    pub chunk_index: u64,
}

impl ChunkAad<'_> {
    /// Serialize to the canonical byte string documented on the type.
    pub fn encode(&self) -> Vec<u8> {
        lp_concat(&[
            CHUNK_AAD_DOMAIN_V2,
            &[self.scheme.as_u8()],
            self.user_id,
            self.file_id,
            &self.chunk_count.to_be_bytes(),
            &self.chunk_index.to_be_bytes(),
        ])
    }
}

/// Everything needed to seal/open the chunks of **one file** under **one
/// scheme** — the type call sites should hold instead of a bare [`ChunkSealer`].
///
/// It owns the subkey's AES schedule (computed once, shared read-only across
/// rayon workers) and, for v2, the constant part of the per-chunk AAD, so the
/// caller can never forget to bind the owner or the chunk count. Under v1 it is
/// exactly the legacy behaviour (subkey over the file id, empty AAD), which is
/// how existing files keep opening byte for byte.
pub struct FileCipher {
    scheme: KeyScheme,
    sealer: ChunkSealer,
    /// v2 only: the AAD minus its trailing `lp(chunk_index)`, precomputed so a
    /// 4 MiB chunk does not pay for re-encoding constant metadata. Empty in v1.
    aad_prefix: Vec<u8>,
    chunk_count: u64,
}

impl FileCipher {
    /// Build the cipher for one file. `chunk_count` is the file's total number of
    /// chunks; it is bound into every v2 tag and ignored under v1 (pass the real
    /// count anyway — it costs nothing and keeps call sites uniform).
    pub fn new(
        key: &DataKey,
        scheme: KeyScheme,
        user_id: &[u8],
        file_id: &[u8],
        chunk_count: u64,
    ) -> Result<Self, CoreError> {
        let sealer = key.file_subkey_for(scheme, user_id, file_id)?.sealer()?;
        let aad_prefix = match scheme {
            KeyScheme::V1 => Vec::new(),
            KeyScheme::V2 => lp_concat(&[
                CHUNK_AAD_DOMAIN_V2,
                &[scheme.as_u8()],
                user_id,
                file_id,
                &chunk_count.to_be_bytes(),
            ]),
        };
        Ok(FileCipher { scheme, sealer, aad_prefix, chunk_count })
    }

    pub fn scheme(&self) -> KeyScheme {
        self.scheme
    }

    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// The underlying sealer, for the paths that still need the raw primitive.
    pub fn sealer(&self) -> &ChunkSealer {
        &self.sealer
    }

    /// The AAD for chunk `index` — empty under v1, [`ChunkAad::encode`] under v2.
    pub fn aad_for(&self, index: u64) -> Vec<u8> {
        match self.scheme {
            KeyScheme::V1 => Vec::new(),
            KeyScheme::V2 => {
                let mut aad = Vec::with_capacity(self.aad_prefix.len() + 16);
                aad.extend_from_slice(&self.aad_prefix);
                push_lp(&mut aad, &index.to_be_bytes());
                aad
            }
        }
    }

    /// Seal chunk `index` in place (tag appended), binding the scheme's AAD.
    pub fn seal_chunk(&self, buf: &mut Vec<u8>, index: u64) -> Result<[u8; NONCE_LEN], CoreError> {
        match self.scheme {
            KeyScheme::V1 => self.sealer.seal(buf, index),
            KeyScheme::V2 => self.sealer.seal_with_aad(buf, index, &self.aad_for(index)),
        }
    }

    /// Open chunk `index` in place.
    ///
    /// Under v2 an index at or beyond `chunk_count` is refused up front: the tag
    /// would fail anyway, but rejecting here names the actual problem (a chunk
    /// presented outside the file it belongs to) instead of a generic AEAD error.
    pub fn open_chunk<'a>(&self, index: u64, buf: &'a mut [u8]) -> Result<&'a mut [u8], CoreError> {
        match self.scheme {
            KeyScheme::V1 => self.sealer.open(index, buf),
            KeyScheme::V2 => {
                if index >= self.chunk_count {
                    return Err(CoreError::Crypto("chunk index outside the file's chunk count"));
                }
                self.sealer.open_with_aad(index, buf, &self.aad_for(index))
            }
        }
    }
}

/// BLAKE3 content hash (hex). Fast, used for content addressing / integrity.
pub fn blake3_hex(data: &[u8]) -> String {
    hex::encode(blake3::hash(data).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed key used by the derivation regression vectors below.
    fn fixed_key() -> DataKey {
        let mut b = [0u8; KEY_LEN];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        DataKey::from_bytes(b)
    }

    #[test]
    fn seal_open_roundtrip_inplace() {
        let key = DataKey::random();
        let sub = key.file_subkey(b"file-42").unwrap();
        let sealer = sub.sealer().unwrap();

        let plain = b"the quick brown fox jumps over the lazy dog".to_vec();
        let mut buf = plain.clone();
        sealer.seal(&mut buf, 7).unwrap();
        assert_eq!(buf.len(), plain.len() + TAG_LEN);
        assert_ne!(&buf[..plain.len()], &plain[..]);

        let opened = sealer.open(7, &mut buf).unwrap();
        assert_eq!(opened, &plain[..]);
    }

    #[test]
    fn distinct_files_get_distinct_subkeys() {
        let key = DataKey::random();
        let a = key.file_subkey(b"a").unwrap();
        let b = key.file_subkey(b"b").unwrap();
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn wrong_subkey_fails_to_open() {
        let key = DataKey::random();
        let mut buf = b"secret".to_vec();
        key.file_subkey(b"f1").unwrap().sealer().unwrap().seal(&mut buf, 0).unwrap();
        let res = key.file_subkey(b"f2").unwrap().sealer().unwrap().open(0, &mut buf);
        assert!(res.is_err());
    }

    /// Locks the derived bytes to their on-disk meaning: any change here makes
    /// every already-stored file and every existing manifest unreadable. Vectors
    /// are plain RFC 5869 HKDF-SHA256(salt = SUBKEY_INFO, ikm = key, info).
    #[test]
    fn derivation_is_byte_stable() {
        let key = fixed_key();
        assert_eq!(
            hex::encode(*key.derive_raw(b"p2pnas/manifest/v1").unwrap()),
            "0d91afe47cff0836493ab080e79cdbe62d7f39ddb36c32ea12a94b3d84d97b14"
        );
        assert_eq!(
            hex::encode(*key.derive_raw(b"file-42").unwrap()),
            "afad83700b04fa84d7996a2ac3c8567c864d65d39b31b6e502ace100ec669d6e"
        );
        // `file_subkey` must stay exactly `derive_raw` over the file id.
        assert_eq!(key.file_subkey(b"file-42").unwrap().0, *key.derive_raw(b"file-42").unwrap());
    }

    /// The v2 derivation must stay exactly HKDF-SHA256(salt = HKDF_SALT_V2,
    /// ikm = key, info = lp(domain) ‖ lp(user) ‖ lp(file)). The reference input is
    /// rebuilt here by hand — deliberately *not* through `push_lp`/`lp_concat` —
    /// so that changing the encoding helpers breaks this test instead of silently
    /// orphaning every v2 file.
    #[test]
    fn v2_derivation_uses_the_documented_encoding() {
        let key = fixed_key();
        let (user, file) = (b"user-a".as_slice(), b"file-42".as_slice());

        let mut info = Vec::new();
        for part in [FILE_SUBKEY_DOMAIN_V2, user, file] {
            info.extend_from_slice(&(part.len() as u64).to_be_bytes());
            info.extend_from_slice(part);
        }
        let prk = Salt::new(HKDF_SHA256, HKDF_SALT_V2).extract(key.as_bytes());
        let info_parts = [info.as_slice()];
        let okm = prk.expand(&info_parts, OkmLen).unwrap();
        let mut expected = [0u8; KEY_LEN];
        okm.fill(&mut expected[..]).unwrap();

        assert_eq!(key.file_subkey_v2(user, file).unwrap().0, expected);
        // …and it must differ from the v1 subkey for the same file id.
        assert_ne!(key.file_subkey(file).unwrap().0, expected);
    }

    /// Length prefixing is the whole point: no two different component tuples may
    /// encode to the same HKDF input. Without it, ("ab","c") and ("a","bc") — and
    /// a file id that literally spells another use's label — would collide.
    #[test]
    fn v2_components_cannot_be_confused() {
        let key = fixed_key();
        let ab_c = key.file_subkey_v2(b"ab", b"c").unwrap();
        let a_bc = key.file_subkey_v2(b"a", b"bc").unwrap();
        assert_ne!(ab_c.0, a_bc.0);

        // A file id spelling a fixed label of another use is now harmless: the
        // domain tag is a separate, length-delimited component.
        let looks_like_manifest = key.file_subkey_v2(b"", b"p2pnas/manifest/v1").unwrap();
        assert_ne!(looks_like_manifest.0, *key.derive_raw(b"p2pnas/manifest/v1").unwrap());
        // Different domains over identical components must diverge too.
        let components: [&[u8]; 2] = [b"u", b"f"];
        assert_ne!(
            *key.derive_v2(FILE_SUBKEY_DOMAIN_V2, &components).unwrap(),
            *key.derive_v2(CHUNK_AAD_DOMAIN_V2, &components).unwrap()
        );
    }

    /// The precomputed prefix in `FileCipher` must agree with the standalone
    /// `ChunkAad` encoding — otherwise sealing and opening would drift apart.
    #[test]
    fn file_cipher_aad_matches_the_canonical_encoding() {
        let key = DataKey::random();
        let cipher = FileCipher::new(&key, KeyScheme::V2, b"user-a", b"file-1", 12).unwrap();
        for index in [0u64, 1, 11] {
            let expected = ChunkAad {
                scheme: KeyScheme::V2,
                user_id: b"user-a",
                file_id: b"file-1",
                chunk_count: 12,
                chunk_index: index,
            }
            .encode();
            assert_eq!(cipher.aad_for(index), expected);
        }
        // v1 keeps an empty AAD, byte-identical to what stored chunks used.
        let v1 = FileCipher::new(&key, KeyScheme::V1, b"user-a", b"file-1", 12).unwrap();
        assert!(v1.aad_for(3).is_empty());
    }

    /// v1 through `FileCipher` must be the legacy path, ciphertext included.
    #[test]
    fn file_cipher_v1_is_byte_identical_to_the_legacy_path() {
        let key = DataKey::random();
        let plain = b"payload that must keep decrypting after the upgrade".to_vec();

        let mut legacy = plain.clone();
        key.file_subkey(b"file-1").unwrap().sealer().unwrap().seal(&mut legacy, 5).unwrap();

        let mut via_cipher = plain.clone();
        let cipher = FileCipher::new(&key, KeyScheme::V1, b"user-a", b"file-1", 9).unwrap();
        cipher.seal_chunk(&mut via_cipher, 5).unwrap();
        assert_eq!(legacy, via_cipher);

        // And a v1 file still opens with a different (or absent) user identity —
        // v1 never bound the owner, and we must not pretend otherwise.
        let other = FileCipher::new(&key, KeyScheme::V1, b"user-b", b"file-1", 9).unwrap();
        assert_eq!(other.open_chunk(5, &mut via_cipher).unwrap(), &plain[..]);
    }

    #[test]
    fn v2_chunk_does_not_open_for_another_user() {
        let key = DataKey::random();
        let a = FileCipher::new(&key, KeyScheme::V2, b"user-a", b"file-1", 4).unwrap();
        let b = FileCipher::new(&key, KeyScheme::V2, b"user-b", b"file-1", 4).unwrap();

        let mut buf = b"top secret".to_vec();
        a.seal_chunk(&mut buf, 2).unwrap();
        // A failed open may scribble over its buffer (the AEAD writes before the
        // tag check), so the rejected attempt runs on a copy.
        assert!(b.open_chunk(2, &mut buf.clone()).is_err());
        assert_eq!(a.open_chunk(2, &mut buf).unwrap(), &b"top secret"[..]);
    }

    #[test]
    fn v2_chunk_is_pinned_to_its_index_file_and_chunk_count() {
        let key = DataKey::random();
        let sealed_under = FileCipher::new(&key, KeyScheme::V2, b"user-a", b"file-1", 4).unwrap();
        let mut buf = b"chunk two of four".to_vec();
        sealed_under.seal_chunk(&mut buf, 2).unwrap();

        // Wrong index within the same file: reordering is rejected.
        assert!(sealed_under.open_chunk(1, &mut buf.clone()).is_err());
        // Wrong chunk count: this is the anti-truncation guarantee. A file cut to
        // 3 chunks presents chunk 2 as "2 of 3", which no longer authenticates.
        let truncated = FileCipher::new(&key, KeyScheme::V2, b"user-a", b"file-1", 3).unwrap();
        assert!(truncated.open_chunk(2, &mut buf.clone()).is_err());
        // Wrong file: a chunk cannot be grafted onto another file.
        let other_file = FileCipher::new(&key, KeyScheme::V2, b"user-a", b"file-2", 4).unwrap();
        assert!(other_file.open_chunk(2, &mut buf.clone()).is_err());
        // An index outside the declared count is refused before the AEAD call.
        assert!(sealed_under.open_chunk(4, &mut buf.clone()).is_err());

        assert_eq!(sealed_under.open_chunk(2, &mut buf).unwrap(), &b"chunk two of four"[..]);
    }

    #[test]
    fn key_scheme_round_trips_through_the_manifest_encoding() {
        assert_eq!(KeyScheme::default(), KeyScheme::V1);
        assert_eq!(KeyScheme::from_i64(KeyScheme::V1.as_i64()).unwrap(), KeyScheme::V1);
        assert_eq!(KeyScheme::from_i64(KeyScheme::V2.as_i64()).unwrap(), KeyScheme::V2);
        assert!(KeyScheme::from_i64(0).is_err());
        assert!(KeyScheme::from_i64(3).is_err());
    }

    #[test]
    fn seal_rejects_index_beyond_the_gcm_bound() {
        let key = DataKey::random();
        let sealer = key.file_subkey(b"f").unwrap().sealer().unwrap();

        let mut ok = b"payload".to_vec();
        assert!(sealer.seal(&mut ok, MAX_CHUNK_INDEX).is_ok());

        let mut too_far = b"payload".to_vec();
        assert!(sealer.seal(&mut too_far, MAX_CHUNK_INDEX + 1).is_err());
        // The buffer must be left untouched when the index is refused.
        assert_eq!(too_far, b"payload".to_vec());
    }
}
