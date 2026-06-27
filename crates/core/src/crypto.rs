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

use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
    hkdf::{KeyType, Salt, HKDF_SHA256},
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::CoreError;

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub use aws_lc_rs::aead::NONCE_LEN as NONCE_BYTES;

/// HKDF info string — versioned so the derivation scheme can evolve safely.
const SUBKEY_INFO: &[u8] = b"p2pnas/file-subkey/v1";

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
    pub fn derive_raw(&self, info: &[u8]) -> [u8; KEY_LEN] {
        struct OkmLen;
        impl KeyType for OkmLen {
            fn len(&self) -> usize {
                KEY_LEN
            }
        }
        let prk = Salt::new(HKDF_SHA256, SUBKEY_INFO).extract(&self.0);
        let info = [info];
        let okm = prk
            .expand(&info, OkmLen)
            .expect("hkdf expand (fixed-length output cannot fail)");
        let mut sk = [0u8; KEY_LEN];
        okm.fill(&mut sk).expect("hkdf fill (length matches OkmLen)");
        sk
    }

    /// Derive the per-file content subkey: HKDF-SHA256(self, file_id).
    pub fn file_subkey(&self, file_id: &[u8]) -> FileSubkey {
        FileSubkey(self.derive_raw(file_id))
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
    pub fn seal(&self, buf: &mut Vec<u8>, index: u64) -> Result<[u8; NONCE_LEN], CoreError> {
        let nonce = nonce_for(index);
        self.0
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), buf)
            .map_err(|_| CoreError::Crypto("seal"))?;
        Ok(nonce)
    }

    /// Decrypt chunk `index` (ciphertext||tag) in place; returns the plaintext.
    pub fn open<'a>(&self, index: u64, buf: &'a mut [u8]) -> Result<&'a mut [u8], CoreError> {
        self.0
            .open_in_place(Nonce::assume_unique_for_key(nonce_for(index)), Aad::empty(), buf)
            .map_err(|_| CoreError::Crypto("open"))
    }
}

/// BLAKE3 content hash (hex). Fast, used for content addressing / integrity.
pub fn blake3_hex(data: &[u8]) -> String {
    hex::encode(blake3::hash(data).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_inplace() {
        let key = DataKey::random();
        let sub = key.file_subkey(b"file-42");
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
        let a = key.file_subkey(b"a");
        let b = key.file_subkey(b"b");
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn wrong_subkey_fails_to_open() {
        let key = DataKey::random();
        let mut buf = b"secret".to_vec();
        key.file_subkey(b"f1").sealer().unwrap().seal(&mut buf, 0).unwrap();
        let res = key.file_subkey(b"f2").sealer().unwrap().open(0, &mut buf);
        assert!(res.is_err());
    }
}
