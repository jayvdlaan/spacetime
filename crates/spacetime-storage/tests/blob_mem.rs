//! Conformance tests for `MemBlobStore`.

mod common;

use common::*;
use spacetime_storage::{BlobStore, MemBlobStore};

fn fresh() -> MemBlobStore<DevSha256> {
    MemBlobStore::new(DevSha256)
}

#[test]
fn mem_round_trip_empty() {
    round_trip_empty(&mut fresh());
}

#[test]
fn mem_round_trip_one_byte() {
    round_trip_one_byte(&mut fresh());
}

#[test]
fn mem_round_trip_1mib() {
    round_trip_1mib(&mut fresh());
}

#[test]
fn mem_round_trip_70_000_001() {
    round_trip_70_000_001(&mut fresh());
}

#[test]
fn mem_id_is_sha256_of_bytes() {
    id_is_sha256_of_bytes(&mut fresh());
}

#[test]
fn mem_duplicate_put_is_noop() {
    duplicate_put_is_noop(&mut fresh());
}

#[test]
fn mem_contains_len_remove() {
    contains_len_remove(&mut fresh());
}

#[test]
fn mem_open_missing_is_not_found() {
    open_missing_is_not_found(&mut fresh());
}

#[test]
fn mem_list_semantics() {
    list_semantics(&mut fresh());
}

#[test]
fn mem_abort_leaves_nothing() {
    abort_leaves_nothing(&mut fresh());
}

#[test]
fn mem_drop_leaves_nothing() {
    drop_leaves_nothing(&mut fresh());
}

#[test]
fn mem_alloc_helpers_round_trip() {
    alloc_helpers_round_trip(&mut fresh());
}

#[test]
fn mem_list_is_ascending() {
    let mut s = fresh();
    let mut ids: Vec<_> = (0u8..8).map(|i| put_chunked(&mut s, &[i; 4], 4)).collect();
    ids.sort();

    let mut seen = Vec::new();
    s.list(&mut |id| {
        seen.push(*id);
        true
    })
    .unwrap();
    // BTreeMap iterates in ascending key order.
    let mut sorted_seen = seen.clone();
    sorted_seen.sort();
    assert_eq!(seen, sorted_seen);
    assert_eq!(seen, ids);
}

#[test]
fn mem_count() {
    let mut s = fresh();
    assert_eq!(s.count(), 0);
    assert!(s.is_empty());
    let id = put_chunked(&mut s, b"one", 4);
    assert_eq!(s.count(), 1);
    assert!(!s.is_empty());
    s.remove(&id).unwrap();
    assert_eq!(s.count(), 0);
    assert!(s.is_empty());
}

#[test]
fn mem_write_error_poisons_writer() {
    write_error_poisons_writer(&mut MemBlobStore::new(FailingSha256));
}
