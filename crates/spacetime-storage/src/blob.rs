//! Content-addressed streaming blob seam.
//!
//! A blob is addressed by the SHA-256 of its bytes and is immutable by content: the store computes
//! the id itself as bytes are written (`put`/[`BlobWriter::finish`]), so a stored blob is always
//! addressed by its real hash and there is no "put with a caller-supplied id". A `finish()` whose
//! digest already exists in the store is a successful no-op — the incoming bytes are discarded and
//! the existing blob wins.
//!
//! The seam is class-agnostic: an id is exactly a 32-byte SHA-256, nothing more. A consumer that
//! wants classes (a `blobs/<class>/` layout, say) partitions by constructing one store
//! per class directory, e.g. `FsBlobStore::new(root.join("blobs").join(class), backend)`.
//!
//! The id is the digest of whichever `H: spacetime_crypto::Sha256` backend the consumer injects,
//! and the `sha256/` component of the filesystem layout asserts that this backend really is
//! SHA-256. Nothing in this crate can check that — picking the backend is the consumer's security
//! decision, exactly as it is for every other `spacetime-crypto` facade.
//!
//! `list` order is unspecified (an in-memory store may iterate one way, a filesystem store another);
//! callers that need a stable order sort the collected ids themselves.
//!
//! # Object safety
//!
//! [`BlobStore`] and [`BlobWriter`] are **not** object-safe: `BlobStore` uses GATs (`Reader<'a>`,
//! `Writer<'a>`) exactly like [`crate::KvScan`]/[`crate::TxnStore`], and `BlobWriter::finish`/`abort`
//! take `self` by value. Program against them generically, not as `dyn BlobStore`.

use crate::{StorageError, StorageResult};
use spacetime_crypto::{CryptoError, Sha256State};
use spacetime_io::{IoError, Read, Write};

/// Length of a blob id in bytes (SHA-256).
pub const BLOB_ID_LEN: usize = spacetime_crypto::SHA256_LEN;
/// Length of a blob id in lowercase hex characters.
pub const BLOB_ID_HEX_LEN: usize = 2 * BLOB_ID_LEN;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// SHA-256 of a blob's bytes — the only way to address a blob.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId([u8; BLOB_ID_LEN]);

impl BlobId {
    /// Wrap a raw 32-byte SHA-256 digest.
    pub const fn new(bytes: [u8; BLOB_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32-byte digest.
    pub const fn as_bytes(&self) -> &[u8; BLOB_ID_LEN] {
        &self.0
    }

    /// Consume `self`, returning the raw 32-byte digest.
    pub const fn into_bytes(self) -> [u8; BLOB_ID_LEN] {
        self.0
    }

    /// The two lowercase hex characters of the first byte — the `<aa>` shard directory name used by
    /// `crate::blob_fs::FsBlobStore`'s `<root>/sha256/<aa>/<hex64>` layout.
    pub const fn shard(&self) -> [u8; 2] {
        let b = self.0[0];
        [HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]]
    }

    /// Render as 64 lowercase hex characters into a caller-provided buffer; returns the `&str` view
    /// of `out`. Never fails.
    pub fn to_hex<'o>(&self, out: &'o mut [u8; BLOB_ID_HEX_LEN]) -> &'o str {
        for (i, b) in self.0.iter().enumerate() {
            out[2 * i] = HEX[(b >> 4) as usize];
            out[2 * i + 1] = HEX[(b & 0x0f) as usize];
        }
        // SAFETY / correctness: every byte written above is one of the ASCII hex digits in `HEX`.
        core::str::from_utf8(out).expect("hex encoding is always valid UTF-8")
    }

    /// Strict parse: exactly 64 characters, each in `0-9a-f`. Anything else (uppercase, whitespace,
    /// a `0x` prefix, 63 or 65 characters, non-ASCII) is `Err(StorageError::Invalid)`.
    pub fn from_hex(s: &str) -> StorageResult<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != BLOB_ID_HEX_LEN {
            return Err(StorageError::Invalid);
        }
        let mut out = [0u8; BLOB_ID_LEN];
        for i in 0..BLOB_ID_LEN {
            let hi = nibble(bytes[2 * i]).ok_or(StorageError::Invalid)?;
            let lo = nibble(bytes[2 * i + 1]).ok_or(StorageError::Invalid)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    /// Lowercase hex encoding as an owned [`alloc::string::String`].
    #[cfg(feature = "alloc")]
    pub fn to_hex_string(&self) -> alloc::string::String {
        let mut buf = [0u8; BLOB_ID_HEX_LEN];
        alloc::string::String::from(self.to_hex(&mut buf))
    }
}

/// Decode one ASCII hex digit; `None` for anything outside `0-9a-f` (uppercase is rejected).
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl From<[u8; BLOB_ID_LEN]> for BlobId {
    fn from(bytes: [u8; BLOB_ID_LEN]) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for BlobId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::str::FromStr for BlobId {
    type Err = StorageError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl core::fmt::Display for BlobId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; BLOB_ID_HEX_LEN];
        f.write_str(self.to_hex(&mut buf))
    }
}

impl core::fmt::Debug for BlobId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; BLOB_ID_HEX_LEN];
        f.write_str("BlobId(")?;
        f.write_str(self.to_hex(&mut buf))?;
        f.write_str(")")
    }
}

/// A writer returned by [`BlobStore::put`]. Bytes are hashed as they arrive.
///
/// Dropping a writer without calling `finish` is equivalent to `abort` (nothing becomes visible).
pub trait BlobWriter: Write {
    /// Seal the blob: durably store it (the filesystem backend `fsync`s then renames into place) and
    /// return its id. If a blob with this id already exists the incoming bytes are discarded and the
    /// existing blob wins — `finish` still returns `Ok(id)`.
    ///
    /// After an earlier `write` error the writer is poisoned: every later `write` and `finish`
    /// return an error (`finish`: `Err(StorageError::Io)`; the filesystem backend first removes its
    /// temp file).
    ///
    /// An `Err` does not always mean nothing landed: `crate::blob_fs::FsBlobWriter` returns
    /// `Err(StorageError::Io)` when the directory `fsync` after an otherwise successful rename
    /// fails. Retrying the put is the safe response — see that type's `# Errors` section.
    fn finish(self) -> StorageResult<BlobId>;

    /// Discard everything written so far. Never fails (cleanup errors are swallowed).
    fn abort(self);
}

/// Content-addressed blob store. See the module docs for the semantics.
pub trait BlobStore {
    /// Raw streaming reader over a stored blob.
    type Reader<'a>: Read
    where
        Self: 'a;
    /// Writer that hashes on the way in.
    type Writer<'a>: BlobWriter
    where
        Self: 'a;
    /// Streaming SHA-256 state of the store's hash backend.
    type Digest: Sha256State;

    /// Open `id` for reading. Missing → `Err(StorageError::NotFound)`.
    fn open(&self, id: &BlobId) -> StorageResult<Self::Reader<'_>>;

    /// A fresh SHA-256 state from the store's backend. `Err(StorageError::Digest(kind))` on backend
    /// failure.
    fn digest_init(&self) -> StorageResult<Self::Digest>;

    /// `open` wrapped in a [`crate::blob_verify::VerifiedReader`]: bytes stream through unchanged and
    /// the read that hits EOF fails with `IoError::InvalidInput` if the recomputed digest differs
    /// from `id`. Provided in terms of `open` and `digest_init`.
    fn open_verified(
        &self,
        id: &BlobId,
    ) -> StorageResult<crate::blob_verify::VerifiedReader<Self::Reader<'_>, Self::Digest>> {
        let inner = self.open(id)?;
        let state = self.digest_init()?;
        Ok(crate::blob_verify::VerifiedReader::new(inner, state, *id))
    }

    /// Start a new blob. The returned writer borrows the store mutably until `finish`/`abort`/drop.
    fn put(&mut self) -> StorageResult<Self::Writer<'_>>;

    /// Length in bytes of the stored blob. Missing → `Err(StorageError::NotFound)`.
    fn len(&self, id: &BlobId) -> StorageResult<u64>;

    /// Provided: `self.len(id).is_ok()` (mirrors [`crate::KvStore::contains`]).
    fn contains(&self, id: &BlobId) -> bool {
        self.len(id).is_ok()
    }

    /// Unlink the blob. Missing → `Err(StorageError::NotFound)`.
    fn remove(&mut self, id: &BlobId) -> StorageResult<()>;

    /// Visit every stored id in unspecified order; return `false` from `f` to stop early (the call
    /// still returns `Ok(())`).
    fn list(&self, f: &mut dyn FnMut(&BlobId) -> bool) -> StorageResult<()>;
}

// ---------------------------------------------------------------------------
// Error mapping — used by blob_verify / blob_mem / blob_fs / alloc_helpers
// ---------------------------------------------------------------------------

/// `IoError::NotFound → StorageError::NotFound`; every other variant → `StorageError::Io`.
///
/// Used by the `alloc`/`std` blob stores and helpers; conditionally compiled so a pure `no_std`
/// (no `alloc`) build — which has no caller for it — does not carry it as dead code.
#[cfg(any(feature = "alloc", test))]
pub(crate) fn storage_err_from_io(e: IoError) -> StorageError {
    match e {
        IoError::NotFound => StorageError::NotFound,
        _ => StorageError::Io,
    }
}

/// `StorageError::Digest(e.kind())`. See [`storage_err_from_io`] for why this is conditionally
/// compiled.
#[cfg(any(feature = "alloc", test))]
pub(crate) fn storage_err_from_crypto(e: CryptoError) -> StorageError {
    StorageError::Digest(e.kind())
}

/// Inside `Write::write`/`Read::read` a digest failure can only surface as `IoError::Other` — the
/// `spacetime_io` error model has no digest-specific variant.
pub(crate) fn io_err_from_crypto(_e: CryptoError) -> IoError {
    IoError::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny `core::fmt::Write` sink over a fixed buffer, so `Display` can be checked without
    /// `alloc`/`format!`.
    struct FixedWriter {
        buf: [u8; BLOB_ID_HEX_LEN],
        len: usize,
    }

    impl FixedWriter {
        fn new() -> Self {
            Self {
                buf: [0u8; BLOB_ID_HEX_LEN],
                len: 0,
            }
        }

        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    impl core::fmt::Write for FixedWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
            Ok(())
        }
    }

    fn fixed_id() -> ([u8; BLOB_ID_LEN], &'static str) {
        let mut bytes = [0u8; BLOB_ID_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        (
            bytes,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
    }

    #[test]
    fn hex_round_trip() {
        let (bytes, hex) = fixed_id();
        let id = BlobId::new(bytes);
        let mut buf = [0u8; BLOB_ID_HEX_LEN];
        assert_eq!(id.to_hex(&mut buf), hex);
        assert_eq!(BlobId::from_hex(hex).unwrap(), id);
    }

    #[test]
    fn display_equals_to_hex() {
        use core::fmt::Write as _;
        let (bytes, _) = fixed_id();
        let id = BlobId::new(bytes);
        let mut expected = [0u8; BLOB_ID_HEX_LEN];
        let expected = id.to_hex(&mut expected);

        let mut w = FixedWriter::new();
        write!(w, "{id}").unwrap();
        assert_eq!(w.as_str(), expected);
    }

    #[test]
    fn debug_starts_with_blob_id() {
        use core::fmt::Write as _;
        let (bytes, hex) = fixed_id();
        let id = BlobId::new(bytes);
        // "BlobId(" + 64 hex + ")" = 72 bytes.
        let mut buf = DebugBuf {
            buf: [0u8; BLOB_ID_HEX_LEN + 8],
            len: 0,
        };
        write!(buf, "{id:?}").unwrap();
        let s = buf.as_str();
        assert!(s.starts_with("BlobId("));
        assert!(s.ends_with(')'));
        assert!(s.contains(hex));
    }

    struct DebugBuf {
        buf: [u8; BLOB_ID_HEX_LEN + 8],
        len: usize,
    }

    impl DebugBuf {
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    impl core::fmt::Write for DebugBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
            Ok(())
        }
    }

    #[test]
    fn shard_is_first_byte_hex() {
        let mut bytes = [0u8; BLOB_ID_LEN];
        bytes[0] = 0xab;
        let id = BlobId::new(bytes);
        assert_eq!(id.shard(), *b"ab");
    }

    #[test]
    fn from_hex_rejects_malformed() {
        let (_, hex) = fixed_id();
        // 63 chars
        assert_eq!(BlobId::from_hex(&hex[..63]), Err(StorageError::Invalid));
        // 65 chars
        let too_long = alloc_string_concat(hex, "0");
        assert_eq!(
            BlobId::from_hex(too_long.as_str()),
            Err(StorageError::Invalid)
        );
        // one uppercase char
        let upper = alloc_string_replace_first(hex, b'A');
        assert_eq!(BlobId::from_hex(upper.as_str()), Err(StorageError::Invalid));
        // a 'g'
        let g = alloc_string_replace_first(hex, b'g');
        assert_eq!(BlobId::from_hex(g.as_str()), Err(StorageError::Invalid));
        // leading 0x
        assert_eq!(
            BlobId::from_hex("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            Err(StorageError::Invalid)
        );
        // trailing newline
        let with_nl = alloc_string_concat(hex, "\n");
        assert_eq!(
            BlobId::from_hex(with_nl.as_str()),
            Err(StorageError::Invalid)
        );
        // empty
        assert_eq!(BlobId::from_hex(""), Err(StorageError::Invalid));
    }

    /// Small no-`alloc` fixed-buffer helpers for the malformed-input test above.
    struct SmallBuf {
        buf: [u8; BLOB_ID_HEX_LEN + 1],
        len: usize,
    }
    impl SmallBuf {
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }
    fn alloc_string_concat(base: &str, suffix: &str) -> SmallBuf {
        let mut buf = SmallBuf {
            buf: [0u8; BLOB_ID_HEX_LEN + 1],
            len: 0,
        };
        buf.buf[..base.len()].copy_from_slice(base.as_bytes());
        buf.buf[base.len()..base.len() + suffix.len()].copy_from_slice(suffix.as_bytes());
        buf.len = base.len() + suffix.len();
        buf
    }
    fn alloc_string_replace_first(base: &str, c: u8) -> SmallBuf {
        let mut buf = SmallBuf {
            buf: [0u8; BLOB_ID_HEX_LEN + 1],
            len: base.len(),
        };
        buf.buf[..base.len()].copy_from_slice(base.as_bytes());
        buf.buf[0] = c;
        buf
    }

    #[test]
    fn from_str_agrees_with_from_hex() {
        let (_, hex) = fixed_id();
        let via_from_hex = BlobId::from_hex(hex);
        let via_from_str: Result<BlobId, StorageError> = hex.parse();
        assert_eq!(via_from_hex, via_from_str);
    }

    #[test]
    fn ord_orders_by_bytes() {
        let low = BlobId::new([0u8; BLOB_ID_LEN]);
        let high = BlobId::new([1u8; BLOB_ID_LEN]);
        assert!(low < high);
    }

    #[test]
    fn storage_err_from_io_maps_not_found() {
        assert_eq!(
            storage_err_from_io(IoError::NotFound),
            StorageError::NotFound
        );
        assert_eq!(storage_err_from_io(IoError::Other), StorageError::Io);
    }

    #[test]
    fn storage_err_from_crypto_wraps_kind() {
        use spacetime_crypto::CryptoErrorKind;
        let e = CryptoError::new(CryptoErrorKind::Failed);
        assert_eq!(
            storage_err_from_crypto(e),
            StorageError::Digest(CryptoErrorKind::Failed)
        );
    }

    #[test]
    fn io_err_from_crypto_is_other() {
        use spacetime_crypto::CryptoErrorKind;
        let e = CryptoError::new(CryptoErrorKind::Failed);
        assert_eq!(io_err_from_crypto(e), IoError::Other);
    }
}
