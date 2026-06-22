//! Async equivalents of the storage traits from `spacetime-storage`.
//!
//! These traits mirror the sync `KvStore`, `KvScan`, `TxnStore`, and `Txn`
//! traits but use associated future types for no_std compatibility. They are
//! intentionally independent of `spacetime-storage` — no dependency is added.
//!
//! Enable the `async-trait` feature for ergonomic `async fn` versions under
//! `storage::easy`.

use core::future::Future;

// ---------------------------------------------------------------------------
// Error types (parallel to spacetime-storage, kept independent)
// ---------------------------------------------------------------------------

/// Compact error codes for async storage operations.
///
/// This mirrors `spacetime_storage::StorageError` but is defined independently
/// to avoid coupling the two crates.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum StorageError {
    /// The provided key does not exist.
    NotFound,
    /// Provided buffer is too small to hold the value.
    BufferTooSmall,
    /// The key or value is invalid (length, encoding, etc.).
    Invalid,
    /// Unspecified I/O error.
    Io,
}

pub type StorageResult<T> = core::result::Result<T, StorageError>;

// ---------------------------------------------------------------------------
// AsyncKvStore
// ---------------------------------------------------------------------------

/// Async key-value store trait (no allocations, no_std-first).
///
/// Uses associated future types so implementations can provide concrete,
/// non-boxed futures — identical to the pattern used by `AsyncModule`.
pub trait AsyncKvStore {
    /// Future returned by [`get`](AsyncKvStore::get).
    type GetFut<'a>: Future<Output = StorageResult<usize>> + 'a
    where
        Self: 'a;

    /// Asynchronously get the value for `key` into `out`.
    /// Returns the number of bytes written.
    fn get<'a>(&'a self, key: &'a [u8], out: &'a mut [u8]) -> Self::GetFut<'a>;

    /// Future returned by [`put`](AsyncKvStore::put).
    type PutFut<'a>: Future<Output = StorageResult<()>> + 'a
    where
        Self: 'a;

    /// Asynchronously put the given key/value pair.
    fn put<'a>(&'a mut self, key: &'a [u8], value: &'a [u8]) -> Self::PutFut<'a>;

    /// Future returned by [`delete`](AsyncKvStore::delete).
    type DeleteFut<'a>: Future<Output = StorageResult<()>> + 'a
    where
        Self: 'a;

    /// Asynchronously delete the key if present.
    fn delete<'a>(&'a mut self, key: &'a [u8]) -> Self::DeleteFut<'a>;

    /// Future returned by [`len`](AsyncKvStore::len).
    type LenFut<'a>: Future<Output = StorageResult<usize>> + 'a
    where
        Self: 'a;

    /// Asynchronously return the length of the value stored at `key`.
    fn len<'a>(&'a self, key: &'a [u8]) -> Self::LenFut<'a>;

    /// Future returned by [`contains`](AsyncKvStore::contains).
    type ContainsFut<'a>: Future<Output = bool> + 'a
    where
        Self: 'a;

    /// Asynchronously return whether the key exists.
    fn contains<'a>(&'a self, key: &'a [u8]) -> Self::ContainsFut<'a>;
}

// ---------------------------------------------------------------------------
// AsyncPrefixScanIter + AsyncKvScan
// ---------------------------------------------------------------------------

/// Async equivalent of `PrefixScanIter`.
///
/// Each call to `next` returns a future that resolves to the next entry or
/// `None` when the scan is exhausted.
pub trait AsyncPrefixScanIter {
    /// Future returned by [`next`](AsyncPrefixScanIter::next).
    type NextFut<'a>: Future<Output = Option<StorageResult<(usize, usize)>>> + 'a
    where
        Self: 'a;

    /// Asynchronously yield the next key/value pair, writing into the provided
    /// buffers. Returns `Some(Ok((key_len, val_len)))` on success,
    /// `Some(Err(StorageError::BufferTooSmall))` if buffers are too small, or
    /// `None` when the scan has finished.
    fn next<'a>(&'a mut self, out_key: &'a mut [u8], out_val: &'a mut [u8]) -> Self::NextFut<'a>;
}

/// Async equivalent of `KvScan`.
pub trait AsyncKvScan {
    type Iter<'a>: AsyncPrefixScanIter
    where
        Self: 'a;

    /// Future returned by [`scan_prefix`](AsyncKvScan::scan_prefix).
    type ScanPrefixFut<'a>: Future<Output = Self::Iter<'a>> + 'a
    where
        Self: 'a;

    /// Asynchronously begin a prefix scan.
    fn scan_prefix<'a>(&'a self, prefix: &'a [u8]) -> Self::ScanPrefixFut<'a>;
}

// ---------------------------------------------------------------------------
// AsyncTxnStore + AsyncTxn
// ---------------------------------------------------------------------------

/// Async equivalent of `Txn`.
pub trait AsyncTxn {
    /// Future returned by [`get`](AsyncTxn::get).
    type GetFut<'a>: Future<Output = StorageResult<usize>> + 'a
    where
        Self: 'a;

    /// Asynchronously get a value within the transaction.
    fn get<'a>(&'a self, key: &'a [u8], out: &'a mut [u8]) -> Self::GetFut<'a>;

    /// Future returned by [`put`](AsyncTxn::put).
    type PutFut<'a>: Future<Output = StorageResult<()>> + 'a
    where
        Self: 'a;

    /// Asynchronously put a key/value pair within the transaction.
    fn put<'a>(&'a mut self, key: &'a [u8], value: &'a [u8]) -> Self::PutFut<'a>;

    /// Future returned by [`delete`](AsyncTxn::delete).
    type DeleteFut<'a>: Future<Output = StorageResult<()>> + 'a
    where
        Self: 'a;

    /// Asynchronously delete a key within the transaction.
    fn delete<'a>(&'a mut self, key: &'a [u8]) -> Self::DeleteFut<'a>;

    /// Future returned by [`commit`](AsyncTxn::commit).
    type CommitFut: Future<Output = StorageResult<()>>;

    /// Asynchronously commit the transaction, consuming it.
    fn commit(self) -> Self::CommitFut;

    /// Future returned by [`rollback`](AsyncTxn::rollback).
    type RollbackFut: Future<Output = StorageResult<()>>;

    /// Asynchronously rollback the transaction, consuming it.
    fn rollback(self) -> Self::RollbackFut;
}

/// Async equivalent of `TxnStore`.
pub trait AsyncTxnStore {
    type Txn<'a>: AsyncTxn
    where
        Self: 'a;

    /// Future returned by [`begin`](AsyncTxnStore::begin).
    type BeginFut<'a>: Future<Output = Self::Txn<'a>> + 'a
    where
        Self: 'a;

    /// Asynchronously begin a new transaction.
    fn begin<'a>(&'a mut self) -> Self::BeginFut<'a>;
}

// ---------------------------------------------------------------------------
// Ergonomic async-trait versions
// ---------------------------------------------------------------------------

/// Ergonomic `async fn` versions of the storage traits using the `async-trait`
/// macro. Requires the `async-trait` feature (implies `std`).
#[cfg(feature = "async-trait")]
pub mod easy {
    use super::StorageResult;
    use async_trait::async_trait;
    // Bring Box into scope for async-trait generated code.
    use std::boxed::Box;

    /// Ergonomic async key-value store trait.
    #[async_trait]
    pub trait AsyncKvStore {
        async fn get(&self, key: &[u8], out: &mut [u8]) -> StorageResult<usize>;
        async fn put(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()>;
        async fn delete(&mut self, key: &[u8]) -> StorageResult<()>;
        async fn len(&self, key: &[u8]) -> StorageResult<usize>;
        async fn contains(&self, key: &[u8]) -> bool {
            self.len(key).await.is_ok()
        }
    }

    /// Ergonomic async prefix scan iterator.
    #[async_trait]
    pub trait AsyncPrefixScanIter {
        async fn next(
            &mut self,
            out_key: &mut [u8],
            out_val: &mut [u8],
        ) -> Option<StorageResult<(usize, usize)>>;
    }

    /// Ergonomic async key-value scan trait.
    #[async_trait]
    pub trait AsyncKvScan {
        type Iter: AsyncPrefixScanIter + Send;
        async fn scan_prefix(&self, prefix: &[u8]) -> Self::Iter;
    }

    /// Ergonomic async transaction trait.
    #[async_trait]
    pub trait AsyncTxn {
        async fn get(&self, key: &[u8], out: &mut [u8]) -> StorageResult<usize>;
        async fn put(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()>;
        async fn delete(&mut self, key: &[u8]) -> StorageResult<()>;
        async fn commit(self) -> StorageResult<()>;
        async fn rollback(self) -> StorageResult<()>;
    }

    /// Ergonomic async transaction store trait.
    #[async_trait]
    pub trait AsyncTxnStore {
        type Txn: AsyncTxn + Send;
        async fn begin(&mut self) -> Self::Txn;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    // ------------------------------------------------------------------
    // Immediate-ready future helpers (mirror the pattern in the crate root)
    // ------------------------------------------------------------------

    struct Ready<T>(Option<T>);
    impl<T> Ready<T> {
        fn new(val: T) -> Self {
            Self(Some(val))
        }
    }
    impl<T> Future for Ready<T> {
        type Output = T;
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = unsafe { self.get_unchecked_mut() };
            Poll::Ready(this.0.take().expect("polled after completion"))
        }
    }

    fn noop_waker() -> Waker {
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    /// Poll a future that must resolve immediately.
    fn poll_ready<F: Future>(f: &mut F) -> F::Output {
        let w = noop_waker();
        let mut cx = Context::from_waker(&w);
        let pinned = unsafe { Pin::new_unchecked(f) };
        match Future::poll(pinned, &mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("expected Ready, got Pending"),
        }
    }

    // ------------------------------------------------------------------
    // Stub in-memory store implementing AsyncKvStore
    // ------------------------------------------------------------------

    use std::collections::HashMap;
    use std::vec::Vec;

    struct MemAsyncKv {
        data: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl MemAsyncKv {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
            }
        }
    }

    impl AsyncKvStore for MemAsyncKv {
        type GetFut<'a> = Ready<StorageResult<usize>>;
        fn get<'a>(&'a self, key: &'a [u8], out: &'a mut [u8]) -> Self::GetFut<'a> {
            match self.data.get(key) {
                Some(v) => {
                    if out.len() < v.len() {
                        Ready::new(Err(StorageError::BufferTooSmall))
                    } else {
                        out[..v.len()].copy_from_slice(v);
                        Ready::new(Ok(v.len()))
                    }
                }
                None => Ready::new(Err(StorageError::NotFound)),
            }
        }

        type PutFut<'a> = Ready<StorageResult<()>>;
        fn put<'a>(&'a mut self, key: &'a [u8], value: &'a [u8]) -> Self::PutFut<'a> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ready::new(Ok(()))
        }

        type DeleteFut<'a> = Ready<StorageResult<()>>;
        fn delete<'a>(&'a mut self, key: &'a [u8]) -> Self::DeleteFut<'a> {
            self.data.remove(key);
            Ready::new(Ok(()))
        }

        type LenFut<'a> = Ready<StorageResult<usize>>;
        fn len<'a>(&'a self, key: &'a [u8]) -> Self::LenFut<'a> {
            match self.data.get(key) {
                Some(v) => Ready::new(Ok(v.len())),
                None => Ready::new(Err(StorageError::NotFound)),
            }
        }

        type ContainsFut<'a> = Ready<bool>;
        fn contains<'a>(&'a self, key: &'a [u8]) -> Self::ContainsFut<'a> {
            Ready::new(self.data.contains_key(key))
        }
    }

    #[test]
    fn async_kv_put_get() {
        let mut store = MemAsyncKv::new();
        let res = poll_ready(&mut store.put(b"hello", b"world"));
        assert_eq!(res, Ok(()));

        let mut buf = [0u8; 64];
        let n = poll_ready(&mut store.get(b"hello", &mut buf)).unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[test]
    fn async_kv_contains_and_len() {
        let mut store = MemAsyncKv::new();
        assert!(!poll_ready(&mut store.contains(b"x")));
        poll_ready(&mut store.put(b"x", b"abc")).unwrap();
        assert!(poll_ready(&mut store.contains(b"x")));
        assert_eq!(poll_ready(&mut store.len(b"x")), Ok(3));
    }

    #[test]
    fn async_kv_delete() {
        let mut store = MemAsyncKv::new();
        poll_ready(&mut store.put(b"k", b"v")).unwrap();
        assert!(poll_ready(&mut store.contains(b"k")));
        poll_ready(&mut store.delete(b"k")).unwrap();
        assert!(!poll_ready(&mut store.contains(b"k")));
    }

    #[test]
    fn async_kv_not_found() {
        let store = MemAsyncKv::new();
        let mut buf = [0u8; 16];
        assert_eq!(
            poll_ready(&mut store.get(b"missing", &mut buf)),
            Err(StorageError::NotFound)
        );
    }

    #[test]
    fn async_kv_buffer_too_small() {
        let mut store = MemAsyncKv::new();
        poll_ready(&mut store.put(b"k", b"long_value")).unwrap();
        let mut tiny = [0u8; 2];
        assert_eq!(
            poll_ready(&mut store.get(b"k", &mut tiny)),
            Err(StorageError::BufferTooSmall)
        );
    }

    // ------------------------------------------------------------------
    // Easy trait tests (async-trait feature)
    // ------------------------------------------------------------------

    #[cfg(feature = "async-trait")]
    mod easy_tests {
        use super::*;
        use crate::storage::easy::AsyncKvStore as EasyAsyncKvStore;
        use std::boxed::Box;

        struct EasyMemKv {
            data: HashMap<Vec<u8>, Vec<u8>>,
        }
        impl EasyMemKv {
            fn new() -> Self {
                Self {
                    data: HashMap::new(),
                }
            }
        }

        #[async_trait::async_trait]
        impl EasyAsyncKvStore for EasyMemKv {
            async fn get(&self, key: &[u8], out: &mut [u8]) -> StorageResult<usize> {
                match self.data.get(key) {
                    Some(v) => {
                        if out.len() < v.len() {
                            Err(StorageError::BufferTooSmall)
                        } else {
                            out[..v.len()].copy_from_slice(v);
                            Ok(v.len())
                        }
                    }
                    None => Err(StorageError::NotFound),
                }
            }
            async fn put(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()> {
                self.data.insert(key.to_vec(), value.to_vec());
                Ok(())
            }
            async fn delete(&mut self, key: &[u8]) -> StorageResult<()> {
                self.data.remove(key);
                Ok(())
            }
            async fn len(&self, key: &[u8]) -> StorageResult<usize> {
                match self.data.get(key) {
                    Some(v) => Ok(v.len()),
                    None => Err(StorageError::NotFound),
                }
            }
        }

        #[tokio::test]
        async fn easy_async_kv_put_get() {
            let mut store = EasyMemKv::new();
            store.put(b"hello", b"world").await.unwrap();
            let mut buf = [0u8; 64];
            let n = store.get(b"hello", &mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"world");
        }
    }
}
