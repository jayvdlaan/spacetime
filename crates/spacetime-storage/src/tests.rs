use super::std_impl::MemStore;
use super::TxnStore;
use super::*;
use std::vec; // bring vec! macro into scope for this no_std crate under std tests

#[test]
fn memstore_basic_put_get_delete() {
    let mut s = MemStore::new();
    s.put(b"k", b"v").unwrap();
    let mut buf = [0u8; 8];
    let n = s.get(b"k", &mut buf).unwrap();
    assert_eq!(n, 1);
    assert_eq!(&buf[..n], b"v");
    s.delete(b"k").unwrap();
    assert_eq!(s.get(b"k", &mut buf).unwrap_err(), StorageError::NotFound);
}

#[test]
fn memstore_get_buffer_too_small() {
    let mut s = MemStore::new();
    s.put(b"k", b"hello").unwrap();
    let mut buf = [0u8; 3];
    let err = s.get(b"k", &mut buf).unwrap_err();
    assert!(matches!(err, StorageError::BufferTooSmall));
}

#[test]
fn contains_and_len() {
    let mut s = MemStore::new();
    s.put(b"a", b"123").unwrap();
    assert!(s.contains(b"a"));
    assert!(!s.contains(b"missing"));
    assert_eq!(s.len(b"a").unwrap(), 3);
    assert!(matches!(s.len(b"missing"), Err(StorageError::NotFound)));
}

#[test]
fn prefix_scan_basic() {
    use super::{KvScan, PrefixScanIter};
    let mut s = MemStore::new();
    s.put(b"ns:1", b"one").unwrap();
    s.put(b"ns:2", b"two").unwrap();
    s.put(b"other", b"zzz").unwrap();
    let mut it = KvScan::scan_prefix(&s, b"ns:");
    let mut k = [0u8; 16];
    let mut v = [0u8; 8];
    let mut seen = 0;
    while let Some(res) = it.next(&mut k, &mut v) {
        let (kl, vl) = res.unwrap();
        let key = &k[..kl];
        let val = &v[..vl];
        assert!(key.starts_with(b"ns:"));
        assert!(val == b"one" || val == b"two");
        seen += 1;
    }
    assert_eq!(seen, 2);
}

#[test]
fn namespaced_wrapper_works() {
    let mut s = Namespaced::new(b"user/", MemStore::new());
    let mut tmp = [0u8; 32];
    s.put_ns(b"k", b"v", &mut tmp).unwrap();
    let mut out = [0u8; 8];
    let n = s.get_ns(b"k", &mut out, &mut tmp).unwrap();
    assert_eq!(&out[..n], b"v");
    assert!(s.contains_ns(b"k", &mut tmp));
    s.delete_ns(b"k", &mut tmp).unwrap();
    assert!(!s.contains_ns(b"k", &mut tmp));
}

#[test]
fn large_values_len_and_get() {
    let mut s = MemStore::new();
    let large = vec![0xABu8; 4096];
    s.put(b"large", &large).unwrap();
    assert_eq!(s.len(b"large").unwrap(), 4096);
    let mut small = [0u8; 1024];
    assert!(matches!(
        s.get(b"large", &mut small),
        Err(StorageError::BufferTooSmall)
    ));
    let mut buf = vec![0u8; 4096];
    let n = s.get(b"large", &mut buf).unwrap();
    assert_eq!(n, 4096);
    assert_eq!(&buf[..n], &large[..]);
}

#[cfg(feature = "alloc")]
#[test]
fn alloc_helper_get_alloc() {
    let mut s = MemStore::new();
    s.put(b"k", b"world").unwrap();
    let v = crate::alloc_helpers::get_alloc(&s, b"k").unwrap();
    assert_eq!(v, b"world");
}

#[test]
fn txn_commit_persists_changes() {
    let mut s = MemStore::new();
    s.put(b"pre", b"x").unwrap();
    {
        let mut tx = TxnStore::begin(&mut s);
        tx.put(b"a", b"1").unwrap();
        tx.put(b"b", b"22").unwrap();
        tx.delete(b"pre").unwrap();
        // read-your-writes inside txn
        let mut out = [0u8; 8];
        let n = tx.get(b"a", &mut out).unwrap();
        assert_eq!(&out[..n], b"1");
        assert!(matches!(
            tx.get(b"pre", &mut out),
            Err(StorageError::NotFound)
        ));
        tx.commit().unwrap();
    }
    // After commit, base store sees changes
    let mut out = [0u8; 8];
    let n = s.get(b"b", &mut out).unwrap();
    assert_eq!(&out[..n], b"22");
    assert!(matches!(
        s.get(b"pre", &mut out),
        Err(StorageError::NotFound)
    ));
}

#[test]
fn txn_rollback_discards_changes() {
    let mut s = MemStore::new();
    s.put(b"stay", b"ok").unwrap();
    {
        let mut tx = TxnStore::begin(&mut s);
        tx.put(b"temp", b"zzz").unwrap();
        tx.delete(b"stay").unwrap();
        tx.rollback().unwrap();
    }
    // After rollback, temp key not present and stay still present
    let mut out = [0u8; 8];
    assert!(matches!(
        s.get(b"temp", &mut out),
        Err(StorageError::NotFound)
    ));
    let n = s.get(b"stay", &mut out).unwrap();
    assert_eq!(&out[..n], b"ok");
}

#[test]
fn txn_isolation_read_your_writes() {
    let mut s = MemStore::new();
    {
        let mut tx = TxnStore::begin(&mut s);
        tx.put(b"k", b"v1").unwrap();
        let mut out = [0u8; 8];
        let n = tx.get(b"k", &mut out).unwrap();
        assert_eq!(&out[..n], b"v1");
        tx.commit().unwrap();
    }
    let mut out = [0u8; 8];
    let n = s.get(b"k", &mut out).unwrap();
    assert_eq!(&out[..n], b"v1");
}

#[test]
fn storage_error_variants() {
    let variants = [
        StorageError::NotFound,
        StorageError::BufferTooSmall,
        StorageError::Invalid,
        StorageError::Io,
    ];
    for v in &variants {
        let cloned = *v;
        assert_eq!(*v, cloned);
    }
    assert_ne!(StorageError::NotFound, StorageError::Io);
}

#[test]
fn memstore_with_capacity() {
    let s = MemStore::with_capacity(16);
    assert!(!s.contains(b"any"));
}

#[test]
fn memstore_default() {
    let s = MemStore::default();
    assert!(!s.contains(b"any"));
}

#[test]
fn memstore_overwrite() {
    let mut s = MemStore::new();
    s.put(b"k", b"v1").unwrap();
    s.put(b"k", b"v2").unwrap();
    let mut out = [0u8; 8];
    let n = s.get(b"k", &mut out).unwrap();
    assert_eq!(&out[..n], b"v2");
}

#[test]
fn memstore_delete_nonexistent() {
    let mut s = MemStore::new();
    // Deleting a non-existent key should succeed silently
    s.delete(b"nope").unwrap();
}

#[test]
fn prefix_scan_no_matches() {
    use super::{KvScan, PrefixScanIter};
    let mut s = MemStore::new();
    s.put(b"other", b"val").unwrap();
    let mut it = KvScan::scan_prefix(&s, b"prefix:");
    let mut k = [0u8; 16];
    let mut v = [0u8; 8];
    assert!(it.next(&mut k, &mut v).is_none());
}

#[cfg(feature = "alloc")]
#[test]
fn alloc_helper_not_found() {
    let s = MemStore::new();
    let result = crate::alloc_helpers::get_alloc(&s, b"missing");
    assert!(matches!(result, Err(StorageError::NotFound)));
}
