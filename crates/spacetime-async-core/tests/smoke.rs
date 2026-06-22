//! Smoke tests for spacetime-async-core.

use spacetime_async_core::storage::{StorageError, StorageResult};

#[test]
fn storage_error_variants_exist() {
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
}

#[test]
fn storage_error_debug() {
    let e = StorageError::NotFound;
    let s = format!("{:?}", e);
    assert!(s.contains("NotFound"));
}

#[test]
fn storage_result_type_alias() {
    let ok: StorageResult<usize> = Ok(42);
    assert!(ok.is_ok());

    let err: StorageResult<usize> = Err(StorageError::Io);
    assert!(err.is_err());
}
