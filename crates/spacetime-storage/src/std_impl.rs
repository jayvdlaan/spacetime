//! In-memory HashMap-backed KvStore for std environments.

use crate::{KvScan, KvStore, PrefixScanIter, StorageError, StorageResult, Txn, TxnStore};
use alloc::vec::Vec;
use std::collections::HashMap;

/// An in-memory key/value store using a HashMap.
/// Keys and values are stored as owned Vec<u8>.
pub struct MemStore {
    pub(crate) map: HashMap<Vec<u8>, Vec<u8>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            map: HashMap::with_capacity(cap),
        }
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KvStore for MemStore {
    fn get(&self, key: &[u8], out: &mut [u8]) -> StorageResult<usize> {
        match self.map.get(key) {
            Some(val) => {
                if out.len() < val.len() {
                    return Err(StorageError::BufferTooSmall);
                }
                let n = val.len();
                out[..n].copy_from_slice(val);
                Ok(n)
            }
            None => Err(StorageError::NotFound),
        }
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        self.map.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> StorageResult<()> {
        self.map.remove(key);
        Ok(())
    }

    fn len(&self, key: &[u8]) -> StorageResult<usize> {
        match self.map.get(key) {
            Some(val) => Ok(val.len()),
            None => Err(StorageError::NotFound),
        }
    }
}

/// Iterator over entries with a given prefix; no allocation is required from the caller.
pub struct MemPrefixIter<'a> {
    inner: std::collections::hash_map::Iter<'a, Vec<u8>, Vec<u8>>,
    prefix: &'a [u8],
}

impl<'a> PrefixScanIter for MemPrefixIter<'a> {
    fn next(
        &mut self,
        out_key: &mut [u8],
        out_val: &mut [u8],
    ) -> Option<StorageResult<(usize, usize)>> {
        for (k, v) in self.inner.by_ref() {
            if k.starts_with(self.prefix) {
                if out_key.len() < k.len() {
                    return Some(Err(StorageError::BufferTooSmall));
                }
                if out_val.len() < v.len() {
                    return Some(Err(StorageError::BufferTooSmall));
                }
                out_key[..k.len()].copy_from_slice(k);
                out_val[..v.len()].copy_from_slice(v);
                return Some(Ok((k.len(), v.len())));
            }
        }
        None
    }
}

impl KvScan for MemStore {
    type Iter<'a>
        = MemPrefixIter<'a>
    where
        Self: 'a;
    fn scan_prefix<'a>(&'a self, prefix: &'a [u8]) -> Self::Iter<'a> {
        MemPrefixIter {
            inner: self.map.iter(),
            prefix,
        }
    }
}

/// Journal entry representing a put or delete within a transaction.
enum JournalEntry {
    Put(Vec<u8>),
    Delete,
}

/// A simple single-writer transaction over MemStore using a private journal.
pub struct MemTxn<'a> {
    store: &'a mut MemStore,
    journal: HashMap<Vec<u8>, JournalEntry>,
    finished: bool,
}

impl<'a> MemTxn<'a> {
    fn new(store: &'a mut MemStore) -> Self {
        Self {
            store,
            journal: HashMap::new(),
            finished: false,
        }
    }

    #[inline]
    fn read_from_views(&self, key: &[u8], out: &mut [u8]) -> StorageResult<usize> {
        if let Some(entry) = self.journal.get(key) {
            match entry {
                JournalEntry::Put(val) => {
                    if out.len() < val.len() {
                        return Err(StorageError::BufferTooSmall);
                    }
                    out[..val.len()].copy_from_slice(val);
                    return Ok(val.len());
                }
                JournalEntry::Delete => {
                    return Err(StorageError::NotFound);
                }
            }
        }
        self.store.get(key, out)
    }
}

impl<'a> Txn for MemTxn<'a> {
    fn get(&self, key: &[u8], out: &mut [u8]) -> StorageResult<usize> {
        self.read_from_views(key, out)
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        self.journal
            .insert(key.to_vec(), JournalEntry::Put(value.to_vec()));
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> StorageResult<()> {
        self.journal.insert(key.to_vec(), JournalEntry::Delete);
        Ok(())
    }

    fn commit(mut self) -> StorageResult<()> {
        if self.finished {
            return Ok(());
        }
        for (k, entry) in self.journal.drain() {
            match entry {
                JournalEntry::Put(v) => {
                    self.store.map.insert(k, v);
                }
                JournalEntry::Delete => {
                    self.store.map.remove(&k);
                }
            }
        }
        self.finished = true;
        Ok(())
    }

    fn rollback(mut self) -> StorageResult<()> {
        if self.finished {
            return Ok(());
        }
        self.journal.clear();
        self.finished = true;
        Ok(())
    }
}

impl TxnStore for MemStore {
    type Txn<'a>
        = MemTxn<'a>
    where
        Self: 'a;
    fn begin<'a>(&'a mut self) -> Self::Txn<'a> {
        MemTxn::new(self)
    }
}
