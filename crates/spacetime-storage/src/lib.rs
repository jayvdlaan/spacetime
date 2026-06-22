#![no_std]

//! Spacetime storage facades: minimal key/value store traits.
//!
//! Goals:
//! - no_std by default; no allocations in core traits.
//! - Caller-provided buffers for reads; iterators for writes when needed.
//! - `alloc` feature enables convenience APIs returning Vec.
//!
//! Examples (std feature):
//! - Basic MemStore usage: `cargo run -p spacetime-storage --example memstore_basic --features std,alloc`
//! - Prefix scan: `cargo run -p spacetime-storage --example prefix_scan --features std`

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Compact error codes for storage operations.
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
// Core traits
// ---------------------------------------------------------------------------

/// A minimal key-value store interface (no allocations).
pub trait KvStore {
    /// Get the value for `key` into `out`. Returns the number of bytes written.
    fn get(&self, key: &[u8], out: &mut [u8]) -> StorageResult<usize>;

    /// Put the given key/value pair. Implementations may persist or cache.
    fn put(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()>;

    /// Delete the key if present. Returns Ok whether or not the key existed.
    fn delete(&mut self, key: &[u8]) -> StorageResult<()>;

    /// Returns true if the key exists. Default implementation uses `len`.
    fn contains(&self, key: &[u8]) -> bool {
        self.len(key).is_ok()
    }

    /// Returns the length of the value stored at `key` without reading it.
    fn len(&self, key: &[u8]) -> StorageResult<usize>;
}

/// Optional range/iterator API for stores that support prefix scans.
///
/// This avoids allocations by letting the caller provide output buffers; the
/// iterator returns the number of bytes written for key and value.
pub trait PrefixScanIter {
    /// Returns Some(Ok((key_len, val_len))) and writes into `out_key`/`out_val` when an entry
    /// is available, Some(Err(StorageError::BufferTooSmall)) if the provided buffers are too small,
    /// or None when the scan has finished.
    fn next(
        &mut self,
        out_key: &mut [u8],
        out_val: &mut [u8],
    ) -> Option<StorageResult<(usize, usize)>>;
}

pub trait KvScan {
    type Iter<'a>: PrefixScanIter
    where
        Self: 'a;
    fn scan_prefix<'a>(&'a self, prefix: &'a [u8]) -> Self::Iter<'a>;
}

// ---------------------------------------------------------------------------
// Transaction traits
// ---------------------------------------------------------------------------

/// Transactions: traits for stores that support begin/commit/rollback.
pub trait TxnStore {
    type Txn<'a>: Txn
    where
        Self: 'a;
    fn begin<'a>(&'a mut self) -> Self::Txn<'a>;
}

/// A transaction handle supporting read/write operations with commit/rollback.
pub trait Txn {
    fn get(&self, key: &[u8], out: &mut [u8]) -> StorageResult<usize>;
    fn put(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()>;
    fn delete(&mut self, key: &[u8]) -> StorageResult<()>;
    fn commit(self) -> StorageResult<()>;
    fn rollback(self) -> StorageResult<()>;
}

// ---------------------------------------------------------------------------
// Feature-gated modules
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
extern crate alloc;

// When the `std` feature is enabled, link the standard library so we can use
// std types in std-gated modules and tests.
#[cfg(feature = "std")]
extern crate std;

/// A simple in-memory HashMap-backed KvStore for std environments.
#[cfg(feature = "std")]
pub mod std_impl;

/// Convenience helpers enabled with `alloc`.
#[cfg(feature = "alloc")]
pub mod alloc_helpers;

// ---------------------------------------------------------------------------
// Namespaced wrapper (no_std compatible)
// ---------------------------------------------------------------------------

mod namespaced;
pub use namespaced::Namespaced;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "std"))]
mod tests;
