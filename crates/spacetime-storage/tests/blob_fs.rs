//! Conformance and filesystem-specific tests for `FsBlobStore`.

mod common;

use common::*;
use spacetime_io::{write_all, IoError, Read};
use spacetime_storage::{
    alloc_helpers, BlobId, BlobStore, BlobWriter, FsBlobStore, StorageError, Verification,
};
use std::io::{Read as _, Seek, SeekFrom, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `std::env::temp_dir()/spacetime-storage-blob-<pid>-<name>-<counter>`, removed on drop (best
/// effort).
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "spacetime-storage-blob-{}-{name}-{n}",
            std::process::id()
        ));
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fresh(name: &str) -> (TempDir, FsBlobStore<DevSha256>) {
    let dir = TempDir::new(name);
    let store = FsBlobStore::new(dir.path().join("blobs"), DevSha256).unwrap();
    (dir, store)
}

fn tmp_entries<H>(store: &FsBlobStore<H>) -> usize {
    // `expect`, not `unwrap_or(0)`: a missing `tmp/` would make every "puts leak no staging file"
    // assertion in the suite pass vacuously.
    std::fs::read_dir(store.root().join("tmp"))
        .expect("tmp dir exists")
        .count()
}

macro_rules! fs_suite_test {
    ($fn_name:ident, $suite_fn:ident) => {
        #[test]
        fn $fn_name() {
            let (_dir, mut s) = fresh(stringify!($fn_name));
            $suite_fn(&mut s);
            assert_eq!(tmp_entries(&s), 0);
        }
    };
}

fs_suite_test!(fs_round_trip_empty, round_trip_empty);
fs_suite_test!(fs_round_trip_one_byte, round_trip_one_byte);
fs_suite_test!(fs_round_trip_1mib, round_trip_1mib);
fs_suite_test!(fs_round_trip_70_000_001, round_trip_70_000_001);
fs_suite_test!(fs_id_is_sha256_of_bytes, id_is_sha256_of_bytes);
fs_suite_test!(fs_duplicate_put_is_noop, duplicate_put_is_noop);
fs_suite_test!(fs_contains_len_remove, contains_len_remove);
fs_suite_test!(fs_open_missing_is_not_found, open_missing_is_not_found);
fs_suite_test!(fs_list_semantics, list_semantics);
fs_suite_test!(fs_abort_leaves_nothing, abort_leaves_nothing);
fs_suite_test!(fs_drop_leaves_nothing, drop_leaves_nothing);
fs_suite_test!(fs_alloc_helpers_round_trip, alloc_helpers_round_trip);

#[test]
fn fs_layout() {
    let (_dir, mut s) = fresh("fs_layout_case");
    let id = put_chunked(&mut s, b"layout", 4);
    let path = s.blob_path(&id);
    assert!(path.is_file());
    assert_eq!(std::fs::read(&path).unwrap(), b"layout");

    let shard = id.shard();
    let shard_str = std::str::from_utf8(&shard).unwrap();
    assert_eq!(
        path.parent().unwrap().file_name().unwrap().to_str(),
        Some(shard_str)
    );

    let sha_dir = s.root().join("sha256");
    let shard_dirs: Vec<_> = std::fs::read_dir(&sha_dir).unwrap().collect();
    assert_eq!(shard_dirs.len(), 1, "exactly one shard directory");
    let files: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().collect();
    assert_eq!(files.len(), 1, "exactly one file in the shard directory");
}

#[test]
fn fs_new_creates_dirs_and_is_idempotent() {
    let dir = TempDir::new("fs_new_idem");
    let root = dir.path().join("blobs");
    let mut s1 = FsBlobStore::new(&root, DevSha256).unwrap();
    let id = put_chunked(&mut s1, b"first handle", 4);
    assert!(root.join("sha256").is_dir());
    assert!(root.join("tmp").is_dir());

    // A second `new` on the same root is idempotent and sees the first handle's blobs.
    let s2 = FsBlobStore::new(&root, DevSha256).unwrap();
    assert!(s2.contains(&id));
}

#[test]
fn fs_tamper_flip_byte_fails_verified_read_at_eof() {
    let (_dir, mut s) = fresh("fs_tamper_flip");
    let data = pattern(100_000);
    let id = put_chunked(&mut s, &data, 4096);
    let path = s.blob_path(&id);
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(50_000)).unwrap();
        f.write_all(&[data[50_000] ^ 0xff]).unwrap();
    }

    // Raw open still returns all 100,000 bytes.
    let mut r = s.open(&id).unwrap();
    assert_eq!(read_all(&mut r).unwrap().len(), 100_000);

    let mut vr = s.open_verified(&id).unwrap();
    let mut buf = [0u8; 4096];
    loop {
        match vr.read(&mut buf) {
            Ok(0) => panic!("expected a mismatch at EOF, got clean Ok(0)"),
            Ok(_) => continue,
            Err(IoError::InvalidInput) => break,
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
    assert_eq!(vr.verification(), Verification::Mismatch);
    assert_eq!(vr.read(&mut buf), Err(IoError::InvalidInput));

    assert_eq!(
        alloc_helpers::get_blob(&s, &id).unwrap_err(),
        StorageError::HashMismatch
    );
    assert_eq!(s.len(&id).unwrap(), 100_000);
}

#[test]
fn fs_tamper_truncate_fails_verified_read() {
    let (_dir, mut s) = fresh("fs_tamper_truncate");
    let data = pattern(100_000);
    let id = put_chunked(&mut s, &data, 4096);
    let path = s.blob_path(&id);
    {
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(99_999).unwrap();
    }
    assert_eq!(s.len(&id).unwrap(), 99_999);

    let mut vr = s.open_verified(&id).unwrap();
    let mut buf = [0u8; 4096];
    loop {
        match vr.read(&mut buf) {
            Ok(0) => panic!("expected a mismatch at EOF"),
            Ok(_) => continue,
            Err(IoError::InvalidInput) => break,
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
    assert_eq!(vr.verification(), Verification::Mismatch);
    assert_eq!(
        alloc_helpers::get_blob(&s, &id).unwrap_err(),
        StorageError::HashMismatch
    );
}

#[test]
fn fs_stray_files_are_ignored_by_list() {
    let (_dir, mut s) = fresh("fs_stray");
    let real_id = put_chunked(&mut s, b"real blob", 4);

    let sha_dir = s.root().join("sha256");
    std::fs::create_dir_all(sha_dir.join("zz")).unwrap();
    std::fs::create_dir_all(sha_dir.join("ab")).unwrap();
    std::fs::write(sha_dir.join("ab").join("notahash"), b"x").unwrap();
    let upper_hex = "AB".to_owned() + &"0".repeat(62);
    std::fs::write(sha_dir.join("ab").join(&upper_hex), b"y").unwrap();
    let cd_prefixed_under_ab = "cd".to_owned() + &"0".repeat(62);
    std::fs::write(sha_dir.join("ab").join(&cd_prefixed_under_ab), b"z").unwrap();
    std::fs::write(sha_dir.join("README"), b"docs").unwrap();
    // A plain file whose name *is* a valid shard: `read_dir` on it fails, and `list` has to fall
    // back to `metadata` and skip it rather than error.
    std::fs::write(sha_dir.join("cd"), b"not a shard dir").unwrap();
    std::fs::write(s.root().join("tmp").join("123-4"), b"leftover").unwrap();

    let mut ids = alloc_helpers::list_blobs(&s).unwrap();
    ids.sort();
    assert_eq!(ids, vec![real_id]);

    let lower_id: BlobId = upper_hex.to_lowercase().parse().unwrap();
    assert!(!s.contains(&lower_id));
}

#[test]
fn fs_leftover_tmp_is_invisible_and_swept() {
    let (_dir, s) = fresh("fs_leftover_tmp");
    let fake = b"fake bytes";
    std::fs::write(s.root().join("tmp").join("9999-0"), fake).unwrap();

    assert!(alloc_helpers::list_blobs(&s).unwrap().is_empty());
    assert!(!s.contains(&oracle_id(fake)));

    assert_eq!(s.sweep_tmp().unwrap(), 1);
    assert_eq!(tmp_entries(&s), 0);
    assert_eq!(s.sweep_tmp().unwrap(), 0);
}

#[test]
fn fs_drop_removes_tmp() {
    let (_dir, mut s) = fresh("fs_drop_removes_tmp");
    let tmp_dir = s.root().join("tmp");
    let mut w = s.put().unwrap();
    write_all(&mut w, &[0u8; 10]).unwrap();
    assert_eq!(std::fs::read_dir(&tmp_dir).unwrap().count(), 1);
    drop(w);
    assert_eq!(std::fs::read_dir(&tmp_dir).unwrap().count(), 0);
}

#[test]
fn fs_abort_removes_tmp() {
    let (_dir, mut s) = fresh("fs_abort_removes_tmp");
    let tmp_dir = s.root().join("tmp");
    let mut w = s.put().unwrap();
    write_all(&mut w, &[0u8; 10]).unwrap();
    assert_eq!(std::fs::read_dir(&tmp_dir).unwrap().count(), 1);
    w.abort();
    assert_eq!(std::fs::read_dir(&tmp_dir).unwrap().count(), 0);
}

#[test]
fn fs_concurrent_same_content_converges() {
    let dir = TempDir::new("fs_concurrent");
    let root = dir.path().join("blobs");
    // Pre-create so all four threads share exactly one root from the start.
    let _ = FsBlobStore::new(&root, DevSha256).unwrap();

    let data = pattern(1 << 20);
    let ids: Vec<BlobId> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let root = &root;
                let data = &data;
                scope.spawn(move || {
                    let mut store = FsBlobStore::new(root, DevSha256).unwrap();
                    put_chunked(&mut store, data, 8192)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let expected = oracle_id(&data);
    for id in &ids {
        assert_eq!(*id, expected);
    }

    let store = FsBlobStore::new(&root, DevSha256).unwrap();
    assert_eq!(alloc_helpers::list_blobs(&store).unwrap(), vec![expected]);
    assert_eq!(tmp_entries(&store), 0);
    assert_eq!(std::fs::read(store.blob_path(&expected)).unwrap(), data);
}

#[test]
fn fs_remove_leaves_shard_dir() {
    let (_dir, mut s) = fresh("fs_remove_leaves_shard");
    let id = put_chunked(&mut s, b"removable", 4);
    let shard_dir = s.blob_path(&id).parent().unwrap().to_path_buf();
    s.remove(&id).unwrap();
    assert!(shard_dir.is_dir());
    assert!(alloc_helpers::list_blobs(&s).unwrap().is_empty());
}

#[test]
fn fs_reader_std_io_read() {
    let (_dir, mut s) = fresh("fs_reader_std_io_read");
    let id = put_chunked(&mut s, b"std io read", 4);
    let mut r = s.open(&id).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out, b"std io read");
}

#[test]
fn fs_bad_hex_is_refused() {
    let upper = "AB".to_owned() + &"0".repeat(62);
    assert_eq!(BlobId::from_hex(&upper), Err(StorageError::Invalid));
    let parsed: Result<BlobId, StorageError> = upper.parse();
    assert_eq!(parsed, Err(StorageError::Invalid));
}

#[test]
fn fs_len_of_directory_is_invalid() {
    let (_dir, s) = fresh("fs_len_of_dir");
    let id = oracle_id(b"dir");
    let path = s.blob_path(&id);
    std::fs::create_dir_all(&path).unwrap();

    assert_eq!(s.len(&id), Err(StorageError::Invalid));
    assert!(!s.contains(&id));
    assert_eq!(s.open(&id).err(), Some(StorageError::Invalid));
    assert_eq!(s.open_verified(&id).err(), Some(StorageError::Invalid));

    // `list` is name-only (D11): it still yields this id even though a directory sits at the path.
    let ids = alloc_helpers::list_blobs(&s).unwrap();
    assert!(ids.contains(&id));
}

#[test]
fn fs_put_over_a_directory_fails_and_keeps_the_bytes_out() {
    let (_dir, mut s) = fresh("fs_put_over_dir");
    let data = b"a directory is in the way";
    let id = oracle_id(data);
    std::fs::create_dir_all(s.blob_path(&id)).unwrap();

    // Never `Ok(id)`: that would discard the caller's only copy while nothing readable is stored.
    assert_eq!(alloc_helpers::put_blob(&mut s, data), Err(StorageError::Io));
    assert!(!s.contains(&id));
    assert_eq!(s.open(&id).err(), Some(StorageError::Invalid));
    assert_eq!(tmp_entries(&s), 0);
}

#[test]
fn fs_reput_heals_a_truncated_blob() {
    let (_dir, mut s) = fresh("fs_reput_heals");
    let data = pattern(100_000);
    let id = put_chunked(&mut s, &data, 4096);
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(s.blob_path(&id))
            .unwrap();
        f.set_len(99_999).unwrap();
    }
    assert_eq!(
        alloc_helpers::get_blob(&s, &id).unwrap_err(),
        StorageError::HashMismatch
    );

    // The operator's repair: re-put the correct bytes. They must replace the damaged object, not
    // be thrown away because "something already exists at that path".
    assert_eq!(alloc_helpers::put_blob(&mut s, &data).unwrap(), id);
    assert_eq!(alloc_helpers::get_blob(&s, &id).unwrap(), data);
    assert_eq!(s.len(&id).unwrap(), 100_000);
    assert_eq!(tmp_entries(&s), 0);
}

#[cfg(unix)]
#[test]
fn fs_put_replaces_a_symlink_at_the_blob_path() {
    let (_dir, mut s) = fresh("fs_put_symlink");
    let data = b"a symlink is in the way";
    let id = oracle_id(data);
    let path = s.blob_path(&id);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let decoy = s.root().join("decoy");
    std::fs::write(&decoy, b"attacker bytes").unwrap();
    std::os::unix::fs::symlink(&decoy, &path).unwrap();

    assert_eq!(alloc_helpers::put_blob(&mut s, data).unwrap(), id);
    assert_eq!(alloc_helpers::get_blob(&s, &id).unwrap(), data);
    assert!(!std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    // The symlink target is untouched: the rename replaced the link, not what it pointed at.
    assert_eq!(std::fs::read(&decoy).unwrap(), b"attacker bytes");
}

#[test]
fn fs_write_error_poisons_writer_and_leaves_no_tmp() {
    let dir = TempDir::new("fs_write_error_poisons");
    let mut s = FsBlobStore::new(dir.path().join("blobs"), FailingSha256).unwrap();
    write_error_poisons_writer(&mut s);
    assert_eq!(tmp_entries(&s), 0);
}

#[test]
fn fs_digest_backend_failure_is_a_digest_error_not_io() {
    let dir = TempDir::new("fs_digest_failure");
    let s = FsBlobStore::new(dir.path().join("blobs"), FailingSha256).unwrap();
    // The failing backend cannot `put`, so plant a well-formed blob file directly.
    let id = oracle_id(b"planted");
    let path = s.blob_path(&id);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"planted").unwrap();

    assert_eq!(
        alloc_helpers::get_blob(&s, &id).unwrap_err(),
        StorageError::Digest(spacetime_crypto::CryptoErrorKind::Failed)
    );
}

#[cfg(unix)]
#[test]
fn fs_created_paths_are_private_regardless_of_umask() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, mut s) = fresh("fs_modes");
    let id = put_chunked(&mut s, b"private bytes", 4);

    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(s.root()), 0o700);
    assert_eq!(mode(&s.root().join("sha256")), 0o700);
    assert_eq!(mode(&s.root().join("tmp")), 0o700);
    assert_eq!(mode(s.blob_path(&id).parent().unwrap()), 0o700);
    assert_eq!(mode(&s.blob_path(&id)), 0o600);
}
