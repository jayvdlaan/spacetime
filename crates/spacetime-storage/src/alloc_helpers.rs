//! Convenience helpers enabled with `alloc`.

use crate::blob::{storage_err_from_io, BlobId, BlobStore, BlobWriter};
use crate::blob_verify::Verification;
use crate::{KvStore, StorageError, StorageResult};
use alloc::vec::Vec;
use spacetime_io::{write_all, Read};

/// Fetch into a newly allocated Vec.
pub fn get_alloc<S: KvStore>(store: &S, key: &[u8]) -> StorageResult<Vec<u8>> {
    // Start with a small buffer and grow exponentially until it fits or NotFound.
    let mut cap = 32usize;
    let max_cap = 1 << 20; // 1 MiB safety cap for this helper
    loop {
        let mut buf = alloc::vec![0u8; cap];
        match store.get(key, &mut buf[..]) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(StorageError::BufferTooSmall) => {
                if cap >= max_cap {
                    return Err(StorageError::BufferTooSmall);
                }
                cap = core::cmp::min(cap * 2, max_cap);
            }
            Err(e) => return Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Blob seam alloc helpers
// ---------------------------------------------------------------------------

/// Largest capacity `get_blob` will reserve up front. The hint comes from unverified on-disk
/// metadata, so it is only a hint: the `Vec` still grows to the blob's true size.
const MAX_CAPACITY_HINT: usize = 1 << 20;

/// Collect every id a store holds, in the order [`BlobStore::list`] yields it.
///
/// Memory is O(number of blobs) (32 bytes each): on a large store or a constrained target use
/// [`BlobStore::list`]'s callback form, which streams and can stop early.
pub fn list_blobs<S: BlobStore + ?Sized>(store: &S) -> StorageResult<Vec<BlobId>> {
    let mut ids = Vec::new();
    store.list(&mut |id| {
        ids.push(*id);
        true
    })?;
    Ok(ids)
}

/// `put` + `write_all` + `finish`. On a write error the writer is dropped (aborted) and the mapped
/// error is returned.
pub fn put_blob<S: BlobStore>(store: &mut S, data: &[u8]) -> StorageResult<BlobId> {
    let mut w = store.put()?;
    if let Err(e) = write_all(&mut w, data) {
        w.abort();
        return Err(storage_err_from_io(e));
    }
    w.finish()
}

/// Read the whole blob through [`BlobStore::open_verified`]; returns bytes only if the digest
/// matched — this is the "buffer to the end" pattern for a consumer that must not release unverified
/// bytes.
///
/// A read-time digest failure maps to `StorageError::Digest(CryptoErrorKind::Failed)`, never to
/// `StorageError::Io` — a digest failure must not look like a disk error.
pub fn get_blob<S: BlobStore>(store: &S, id: &BlobId) -> StorageResult<Vec<u8>> {
    let mut reader = store.open_verified(id)?;
    // Clamped: `len` is whatever the (not yet verified) store claims, and a blob file that says it
    // is a terabyte must not turn into an allocation abort before a single byte has been hashed.
    let hint = usize::try_from(store.len(id).unwrap_or(0)).unwrap_or(0);
    let mut buf = Vec::with_capacity(core::cmp::min(hint, MAX_CAPACITY_HINT));
    // On the heap, not the stack: this module is gated on `alloc`, not `std`, so it is compiled for
    // embedded targets whose task stacks are smaller than this chunk.
    let mut chunk = alloc::vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                return Err(match reader.verification() {
                    Verification::Mismatch => StorageError::HashMismatch,
                    Verification::Failed => {
                        StorageError::Digest(spacetime_crypto::CryptoErrorKind::Failed)
                    }
                    Verification::Pending | Verification::Verified => storage_err_from_io(e),
                });
            }
        }
    }
    // `Ok(0)` is EOF only by the readers' convention; make the "no unverified bytes leave this
    // helper" guarantee a local check rather than an invariant of whichever store was passed in.
    if reader.verification() != Verification::Verified {
        return Err(StorageError::HashMismatch);
    }
    Ok(buf)
}
