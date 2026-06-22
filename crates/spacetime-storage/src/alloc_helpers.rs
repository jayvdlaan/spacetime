//! Convenience helpers enabled with `alloc`.

use crate::{KvStore, StorageError, StorageResult};
use alloc::vec::Vec;

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
