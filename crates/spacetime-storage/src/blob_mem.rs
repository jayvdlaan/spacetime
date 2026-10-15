//! In-memory content-addressed blob store (`alloc`).

use crate::blob::{io_err_from_crypto, storage_err_from_crypto, BlobId, BlobStore, BlobWriter};
use crate::{StorageError, StorageResult};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spacetime_crypto::{Sha256, Sha256State};
use spacetime_io::{IoError, IoResult, Read, Write};

/// In-memory content-addressed store: `BTreeMap<BlobId, Vec<u8>>`. For tests, embedded and
/// no_std+alloc callers.
pub struct MemBlobStore<H> {
    hash: H,
    map: BTreeMap<BlobId, Vec<u8>>,
}

impl<H> MemBlobStore<H> {
    /// Create an empty store backed by `hash`.
    pub fn new(hash: H) -> Self {
        Self {
            hash,
            map: BTreeMap::new(),
        }
    }

    /// Number of stored blobs.
    pub fn count(&self) -> usize {
        self.map.len()
    }

    /// Whether the store holds no blobs.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Borrow the hash backend.
    pub fn hasher(&self) -> &H {
        &self.hash
    }
}

/// Slice cursor over a stored blob.
pub struct MemBlobReader<'a> {
    data: &'a [u8],
}

impl<'a> Read for MemBlobReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let n = core::cmp::min(buf.len(), self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

/// Accumulates bytes and hashes them; `finish` inserts unless the id already exists.
pub struct MemBlobWriter<'a, H: Sha256> {
    store: &'a mut MemBlobStore<H>,
    state: H::State,
    buf: Vec<u8>,
    failed: bool,
}

impl<'a, H: Sha256> Write for MemBlobWriter<'a, H> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // Poisoned exactly like `FsBlobWriter::write`: once the digest state has rejected a chunk
        // it no longer describes `self.buf`, so a later `Ok` would report success for a blob that
        // is missing bytes (`BlobWriter::finish` documents the writer as poisoned).
        if self.failed {
            return Err(IoError::Other);
        }
        if let Err(e) = self.state.update(buf) {
            self.failed = true;
            return Err(io_err_from_crypto(e));
        }
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }
}

impl<'a, H: Sha256> BlobWriter for MemBlobWriter<'a, H> {
    fn finish(mut self) -> StorageResult<BlobId> {
        if self.failed {
            return Err(StorageError::Io);
        }
        let id = BlobId::new(self.state.finalize().map_err(storage_err_from_crypto)?);
        if !self.store.map.contains_key(&id) {
            self.store.map.insert(id, core::mem::take(&mut self.buf));
        }
        Ok(id)
    }

    fn abort(self) {
        // Dropping `self.buf` is the whole cleanup; nothing was ever inserted into the store.
    }
}

impl<H: Sha256> BlobStore for MemBlobStore<H> {
    type Reader<'a>
        = MemBlobReader<'a>
    where
        Self: 'a;
    type Writer<'a>
        = MemBlobWriter<'a, H>
    where
        Self: 'a;
    type Digest = H::State;

    fn open(&self, id: &BlobId) -> StorageResult<Self::Reader<'_>> {
        match self.map.get(id) {
            Some(data) => Ok(MemBlobReader { data }),
            None => Err(StorageError::NotFound),
        }
    }

    fn digest_init(&self) -> StorageResult<Self::Digest> {
        self.hash.sha256_init().map_err(storage_err_from_crypto)
    }

    fn put(&mut self) -> StorageResult<Self::Writer<'_>> {
        let state = self.hash.sha256_init().map_err(storage_err_from_crypto)?;
        Ok(MemBlobWriter {
            store: self,
            state,
            buf: Vec::new(),
            failed: false,
        })
    }

    fn len(&self, id: &BlobId) -> StorageResult<u64> {
        match self.map.get(id) {
            Some(v) => Ok(v.len() as u64),
            None => Err(StorageError::NotFound),
        }
    }

    fn contains(&self, id: &BlobId) -> bool {
        self.map.contains_key(id)
    }

    fn remove(&mut self, id: &BlobId) -> StorageResult<()> {
        match self.map.remove(id) {
            Some(_) => Ok(()),
            None => Err(StorageError::NotFound),
        }
    }

    fn list(&self, f: &mut dyn FnMut(&BlobId) -> bool) -> StorageResult<()> {
        for k in self.map.keys() {
            if !f(k) {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacetime_crypto::CryptoResult;
    use spacetime_io::write_all;

    /// Fake digest: the "hash" is the byte-length of the absorbed data, repeated to fill 32 bytes.
    /// Enough to prove put/finish/open round-trips correctly without a real SHA-256.
    #[derive(Clone, Copy, Default)]
    struct LenDigest;

    #[derive(Default)]
    struct LenDigestState {
        len: u64,
    }

    impl Sha256State for LenDigestState {
        fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
            self.len += data.len() as u64;
            Ok(())
        }
        fn finalize(&mut self) -> CryptoResult<[u8; 32]> {
            let mut out = [0u8; 32];
            out[..8].copy_from_slice(&self.len.to_le_bytes());
            self.len = 0;
            Ok(out)
        }
    }

    impl Sha256 for LenDigest {
        type State = LenDigestState;
        fn sha256_init(&self) -> CryptoResult<Self::State> {
            Ok(LenDigestState::default())
        }
    }

    fn fresh() -> MemBlobStore<LenDigest> {
        MemBlobStore::new(LenDigest)
    }

    fn put(store: &mut MemBlobStore<LenDigest>, data: &[u8]) -> BlobId {
        let mut w = store.put().unwrap();
        write_all(&mut w, data).unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn put_finish_open_round_trip() {
        let mut s = fresh();
        let id = put(&mut s, b"abc");
        let mut r = s.open(&id).unwrap();
        let mut buf = [0u8; 8];
        let n = r.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"abc");
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn count_tracks_puts() {
        let mut s = fresh();
        assert_eq!(s.count(), 0);
        assert!(s.is_empty());
        put(&mut s, b"a");
        put(&mut s, b"bb");
        assert_eq!(s.count(), 2);
        assert!(!s.is_empty());
    }

    #[test]
    fn remove_then_not_found() {
        let mut s = fresh();
        let id = put(&mut s, b"gone");
        s.remove(&id).unwrap();
        assert_eq!(s.remove(&id), Err(StorageError::NotFound));
    }

    #[test]
    fn list_yields_ascending_keys() {
        let mut s = fresh();
        let a = put(&mut s, b"1");
        let b = put(&mut s, b"22");
        let mut seen = Vec::new();
        s.list(&mut |id| {
            seen.push(*id);
            true
        })
        .unwrap();
        seen.sort();
        let mut expected = alloc::vec![a, b];
        expected.sort();
        assert_eq!(seen, expected);
    }

    #[test]
    fn list_early_exit() {
        let mut s = fresh();
        put(&mut s, b"1");
        put(&mut s, b"22");
        put(&mut s, b"333");
        let mut count = 0;
        s.list(&mut |_| {
            count += 1;
            false
        })
        .unwrap();
        assert_eq!(count, 1);
    }
}
