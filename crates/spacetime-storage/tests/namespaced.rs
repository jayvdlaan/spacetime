//! Additional tests for the Namespaced wrapper in integration tests.
//!
//! The main test coverage is in lib.rs. These tests provide additional edge case coverage.

#![cfg(all(feature = "std", feature = "alloc"))]

use spacetime_storage::std_impl::MemStore;
use spacetime_storage::{KvStore, Namespaced, StorageError};

#[test]
fn get_ns_with_existing_key() {
    let mut store = MemStore::new();
    // Pre-populate with prefixed key
    store.put(b"ns:mykey", b"myvalue").unwrap();

    let ns = Namespaced::new(b"ns:", store);
    let mut out = [0u8; 16];
    let mut tmp = [0u8; 32];

    let n = ns.get_ns(b"mykey", &mut out, &mut tmp).unwrap();
    assert_eq!(&out[..n], b"myvalue");
}

#[test]
fn get_ns_missing_key_returns_not_found() {
    let store = MemStore::new();
    let ns = Namespaced::new(b"ns:", store);
    let mut out = [0u8; 16];
    let mut tmp = [0u8; 32];

    let err = ns.get_ns(b"missing", &mut out, &mut tmp).unwrap_err();
    assert_eq!(err, StorageError::NotFound);
}

#[test]
fn get_ns_buffer_too_small() {
    let mut store = MemStore::new();
    store.put(b"ns:key", b"longvalue123").unwrap();

    let ns = Namespaced::new(b"ns:", store);
    let mut out = [0u8; 4]; // Too small for "longvalue123"
    let mut tmp = [0u8; 32];

    let err = ns.get_ns(b"key", &mut out, &mut tmp).unwrap_err();
    assert_eq!(err, StorageError::BufferTooSmall);
}

#[test]
fn get_ns_tmp_buffer_too_small() {
    let mut store = MemStore::new();
    store.put(b"ns:longkey", b"value").unwrap();

    let ns = Namespaced::new(b"ns:", store);
    let mut out = [0u8; 16];
    let mut tmp = [0u8; 4]; // Too small for "ns:" + "longkey"

    let err = ns.get_ns(b"longkey", &mut out, &mut tmp).unwrap_err();
    assert_eq!(err, StorageError::BufferTooSmall);
}

#[test]
fn put_ns_stores_with_prefix() {
    let store = MemStore::new();
    let mut ns = Namespaced::new(b"pfx:", store);
    let mut tmp = [0u8; 32];

    ns.put_ns(b"key", b"value", &mut tmp).unwrap();

    // Verify via underlying store that the prefixed key exists
    let mut out = [0u8; 16];
    let n = ns.store.get(b"pfx:key", &mut out).unwrap();
    assert_eq!(&out[..n], b"value");
}

#[test]
fn put_ns_overwrites_existing() {
    let store = MemStore::new();
    let mut ns = Namespaced::new(b"ns:", store);
    let mut tmp = [0u8; 32];

    ns.put_ns(b"key", b"first", &mut tmp).unwrap();
    ns.put_ns(b"key", b"second", &mut tmp).unwrap();

    let mut out = [0u8; 16];
    let n = ns.get_ns(b"key", &mut out, &mut tmp).unwrap();
    assert_eq!(&out[..n], b"second");
}

#[test]
fn delete_ns_removes_correctly() {
    let store = MemStore::new();
    let mut ns = Namespaced::new(b"ns:", store);
    let mut tmp = [0u8; 32];

    ns.put_ns(b"key", b"value", &mut tmp).unwrap();
    ns.delete_ns(b"key", &mut tmp).unwrap();

    let mut out = [0u8; 16];
    let err = ns.get_ns(b"key", &mut out, &mut tmp).unwrap_err();
    assert_eq!(err, StorageError::NotFound);
}

#[test]
fn delete_ns_nonexistent_succeeds() {
    let store = MemStore::new();
    let mut ns = Namespaced::new(b"ns:", store);
    let mut tmp = [0u8; 32];

    // Deleting a key that doesn't exist should succeed
    ns.delete_ns(b"nonexistent", &mut tmp).unwrap();
}

#[test]
fn len_ns_returns_correct_size() {
    let store = MemStore::new();
    let mut ns = Namespaced::new(b"ns:", store);
    let mut tmp = [0u8; 32];

    ns.put_ns(b"key", b"12345", &mut tmp).unwrap();

    let len = ns.len_ns(b"key", &mut tmp).unwrap();
    assert_eq!(len, 5);
}

#[test]
fn len_ns_not_found() {
    let store = MemStore::new();
    let ns = Namespaced::new(b"ns:", store);
    let mut tmp = [0u8; 32];

    let err = ns.len_ns(b"missing", &mut tmp).unwrap_err();
    assert_eq!(err, StorageError::NotFound);
}

#[test]
fn contains_ns_finds_existing() {
    let store = MemStore::new();
    let mut ns = Namespaced::new(b"ns:", store);
    let mut tmp = [0u8; 32];

    ns.put_ns(b"exists", b"yes", &mut tmp).unwrap();

    assert!(ns.contains_ns(b"exists", &mut tmp));
    assert!(!ns.contains_ns(b"missing", &mut tmp));
}

#[test]
fn empty_namespace_works() {
    let store = MemStore::new();
    let mut ns = Namespaced::new(b"", store);
    let mut tmp = [0u8; 32];

    ns.put_ns(b"key", b"value", &mut tmp).unwrap();

    let mut out = [0u8; 16];
    let n = ns.get_ns(b"key", &mut out, &mut tmp).unwrap();
    assert_eq!(&out[..n], b"value");

    // The underlying key should be exactly "key" (no prefix)
    let n2 = ns.store.get(b"key", &mut out).unwrap();
    assert_eq!(&out[..n2], b"value");
}

#[test]
fn large_value_round_trip() {
    let store = MemStore::new();
    let mut ns = Namespaced::new(b"ns:", store);
    let mut tmp = [0u8; 64];

    let large_value = vec![0xABu8; 1024];
    ns.put_ns(b"large", &large_value, &mut tmp).unwrap();

    let len = ns.len_ns(b"large", &mut tmp).unwrap();
    assert_eq!(len, 1024);

    let mut out = vec![0u8; 2048];
    let n = ns.get_ns(b"large", &mut out, &mut tmp).unwrap();
    assert_eq!(&out[..n], &large_value[..]);
}
