//! Lightweight namespacing/buckets using key prefixing without allocation.

use crate::{KvStore, StorageError, StorageResult};

/// Lightweight namespacing/buckets using key prefixing without allocation.
///
/// Methods take a caller-provided temporary buffer `tmp` that must be large
/// enough to hold `ns.len() + key.len()`.
pub struct Namespaced<'a, S> {
    pub ns: &'a [u8],
    pub store: S,
}

impl<'a, S> Namespaced<'a, S> {
    pub fn new(ns: &'a [u8], store: S) -> Self {
        Self { ns, store }
    }

    #[inline]
    fn build_key<'b>(&self, key: &[u8], tmp: &'b mut [u8]) -> StorageResult<&'b [u8]> {
        let need = self.ns.len().saturating_add(key.len());
        if tmp.len() < need {
            return Err(StorageError::BufferTooSmall);
        }
        let (pfx, rest) = tmp.split_at_mut(self.ns.len());
        pfx.copy_from_slice(self.ns);
        let (kdst, _) = rest.split_at_mut(key.len());
        kdst.copy_from_slice(key);
        Ok(&tmp[..need])
    }
}

impl<'a, S: KvStore> Namespaced<'a, S> {
    pub fn get_ns(&self, key: &[u8], out: &mut [u8], tmp: &mut [u8]) -> StorageResult<usize> {
        let full = self.build_key(key, tmp)?;
        self.store.get(full, out)
    }

    pub fn put_ns(&mut self, key: &[u8], value: &[u8], tmp: &mut [u8]) -> StorageResult<()> {
        let full = self.build_key(key, tmp)?;
        self.store.put(full, value)
    }

    pub fn delete_ns(&mut self, key: &[u8], tmp: &mut [u8]) -> StorageResult<()> {
        let full = self.build_key(key, tmp)?;
        self.store.delete(full)
    }

    pub fn len_ns(&self, key: &[u8], tmp: &mut [u8]) -> StorageResult<usize> {
        let full = self.build_key(key, tmp)?;
        self.store.len(full)
    }

    pub fn contains_ns(&self, key: &[u8], tmp: &mut [u8]) -> bool {
        self.len_ns(key, tmp).is_ok()
    }
}
