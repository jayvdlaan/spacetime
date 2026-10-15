//! Filesystem content-addressed blob store (`std`).
//!
//! Layout: `<root>/sha256/<aa>/<hex64>` (`aa` = the first byte's lowercase hex, the blob's
//! [`crate::BlobId::shard`]), with `<root>/tmp/` used for staging in-flight writes.
//!
//! # Crash safety
//!
//! A blob becomes visible at its final path only through `rename(2)`, which is atomic on POSIX, and
//! only after the complete file has been written and `fsync`ed. Before the rename every byte lives in
//! `<root>/tmp/`, which `open`, `len`, `contains` and `list` never consult, so a crash at any point
//! before the rename leaves at most an invisible temp file (removed by [`FsBlobStore::sweep_tmp`] or
//! by the writer's `Drop` in the non-crash case). A crash after the rename but before the directory
//! `fsync` can, on some filesystems, lose the directory entry — the blob is then simply absent, never
//! short. Readers therefore observe either nothing or the whole blob, and the id under which they find
//! it is the SHA-256 the store itself computed over exactly the bytes it wrote. [`FsBlobStore::new`]
//! deliberately does not sweep `tmp/`, because another process may be mid-write; the operator
//! calls [`FsBlobStore::sweep_tmp`] when it knows it is the only writer.
//!
//! # Concurrency
//!
//! Two writers with the same content — in one process (two handles), two threads or two processes —
//! each get a distinct temp file (`File::create_new` is `O_EXCL`; names carry the process id and a
//! process-wide counter). Each `finish` renames its own complete, hashed copy into place, and
//! `rename(2)` atomically replaces the previous one with byte-identical content (a reader that
//! already opened the old inode keeps reading it to the end). Either way exactly one final file
//! exists and both writers return the same `Ok(id)`. `remove` racing with `put` is last-writer-wins; immutable
//! content-addressed data makes that harmless. Windows is not a target (rename-over-existing and
//! directory `fsync` semantics differ and are untested there).
//!
//! # Symlinks and stray entries
//!
//! The store never creates symlinks; `open` and `len` follow them (`metadata`/`File::open`
//! semantics) but only accept a **regular file**: anything else at a blob path (a directory, a
//! FIFO, a symlink to one) is `Err(StorageError::Invalid)` from both, and `contains` is `false`.
//! `list` filters by file **name only** (exactly 64 lowercase hex characters under a matching
//! `<aa>` shard) and does not stat, so a directory sitting at a blob path still appears in `list`
//! even though [`crate::BlobStore::len`] on it returns `Err(StorageError::Invalid)`. A `put` never
//! treats such an entry as "the blob is already stored": the `rename` fails and
//! [`BlobWriter::finish`] reports the error instead of discarding the caller's bytes. `remove`
//! leaves the now-possibly-empty `<aa>` shard directory in place; cleaning it up is not required.
//!
//! # Permissions
//!
//! On unix the store creates its directories with mode `0o700` and every staging (and therefore
//! every stored) file with mode `0o600`, independent of the process umask — a root-of-trust blob
//! store must not become world-writable because a container left the umask at `0o000`. Modes of
//! directories that already exist are left alone, so an operator who deliberately widened a root
//! keeps that choice; note that only `open_verified` detects bytes substituted by someone else who
//! can write into the store.

use crate::blob::{storage_err_from_crypto, BlobId, BlobStore, BlobWriter, BLOB_ID_HEX_LEN};
use crate::{StorageError, StorageResult};
use spacetime_crypto::{Sha256, Sha256State};
use spacetime_io::{IoError, IoResult, Read, Write};
use std::fs::{self, File};
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Name of the shard directory under the root.
pub const SHA256_DIR: &str = "sha256";
/// Name of the staging directory under the root. Never read by `open`/`list`.
pub const TMP_DIR: &str = "tmp";

/// Filesystem content-addressed store: `<root>/sha256/<aa>/<hex64>`, `<root>/tmp/` for in-flight
/// writes. See the module docs for the crash-safety and concurrency arguments.
pub struct FsBlobStore<H> {
    hash: H,
    root: PathBuf,
}

impl<H> FsBlobStore<H> {
    /// Create (or reopen) a store at `root`: `create_dir_all`s `<root>`, `<root>/sha256` and
    /// `<root>/tmp` (mode `0o700` on unix), then `fsync`s `<root>` so those directory entries are
    /// themselves durable. Does NOT sweep `tmp/` — see [`FsBlobStore::sweep_tmp`].
    pub fn new(root: impl AsRef<Path>, hash: H) -> StorageResult<Self> {
        let root = root.as_ref().to_path_buf();
        create_dir_all_private(&root).map_err(|e| map_storage_error(&e))?;
        create_dir_all_private(&root.join(SHA256_DIR)).map_err(|e| map_storage_error(&e))?;
        create_dir_all_private(&root.join(TMP_DIR)).map_err(|e| map_storage_error(&e))?;
        // `finish` fsyncs everything below `sha256/`, but nothing else forces the link from
        // `<root>` to `sha256/` itself: without this a power cut can take a brand-new store's whole
        // shard tree with it, blobs `finish` already reported as durable included.
        fsync_dir(&root).map_err(|e| map_storage_error(&e))?;
        Ok(Self { hash, root })
    }

    /// The root directory this store was opened on.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Borrow the hash backend.
    pub fn hasher(&self) -> &H {
        &self.hash
    }

    /// `<root>/sha256/<aa>/<hex64>` for `id`.
    pub fn blob_path(&self, id: &BlobId) -> PathBuf {
        let mut hex = [0u8; BLOB_ID_HEX_LEN];
        let hex_str = id.to_hex(&mut hex);
        let shard = id.shard();
        let shard_str = core::str::from_utf8(&shard).expect("hex is ASCII");
        self.root.join(SHA256_DIR).join(shard_str).join(hex_str)
    }

    /// Remove every regular file in `<root>/tmp` (crash leftovers). Returns the number removed.
    ///
    /// Only call when no other writer on this root can be live — it would delete their in-flight
    /// file.
    pub fn sweep_tmp(&self) -> StorageResult<usize> {
        let dir = self.root.join(TMP_DIR);
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(map_storage_error(&e)),
        };
        let mut removed = 0usize;
        for entry in entries {
            let entry = entry.map_err(|e| map_storage_error(&e))?;
            let is_file = entry
                .file_type()
                .map_err(|e| map_storage_error(&e))?
                .is_file();
            if !is_file {
                continue;
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(map_storage_error(&e)),
            }
        }
        Ok(removed)
    }
}

/// `std::fs::File` adapted to [`spacetime_io::Read`]; also implements `std::io::Read` for std
/// consumers that want to use it directly (e.g. `read_to_end`).
pub struct FsBlobReader {
    file: File,
}

impl FsBlobReader {
    /// Unwrap the underlying `std::fs::File`.
    pub fn into_inner(self) -> File {
        self.file
    }
}

impl Read for FsBlobReader {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        loop {
            match self.file.read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_io_error(&e)),
            }
        }
    }
}

impl std::io::Read for FsBlobReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

/// Writer returned by [`FsBlobStore::put`]. Bytes are written to a staging file under `<root>/tmp/`
/// and hashed as they arrive; [`BlobWriter::finish`] `fsync`s the file and renames it into place.
///
/// # Errors
///
/// `finish` reports `Err` for two states in which the store is nevertheless intact, and a caller
/// that must not lose the blob responds to both by retrying the put:
///
/// - the directory `fsync` after a successful `rename` failed — the blob is already complete and
///   visible at its final path, only its directory entry may not have reached the disk, and the
///   retry re-stages and re-renames the same bytes;
/// - a non-regular entry (a directory, a FIFO) occupies the blob's final path, so the `rename`
///   could not replace it — `Err(StorageError::Io)`, never a silent `Ok` that throws the caller's
///   bytes away. The operator has to remove that entry first.
pub struct FsBlobWriter<'a, H: Sha256> {
    store: &'a FsBlobStore<H>,
    state: H::State,
    file: Option<File>,
    tmp_path: PathBuf,
    failed: bool,
}

impl<'a, H: Sha256> FsBlobWriter<'a, H> {
    /// Best-effort cleanup: drop the open file handle (if any) and remove the staging file. Used by
    /// every early-return path in `finish` as well as `abort`.
    fn discard(&mut self) {
        if let Some(f) = self.file.take() {
            drop(f);
        }
        let _ = fs::remove_file(&self.tmp_path);
    }
}

impl<'a, H: Sha256> Write for FsBlobWriter<'a, H> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if self.failed {
            return Err(IoError::Other);
        }
        let f = self.file.as_mut().ok_or(IoError::Other)?;
        let n = loop {
            match f.write(buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.failed = true;
                    return Err(map_io_error(&e));
                }
            }
        };
        if let Err(e) = self.state.update(&buf[..n]) {
            self.failed = true;
            return Err(crate::blob::io_err_from_crypto(e));
        }
        Ok(n)
    }
}

impl<'a, H: Sha256> BlobWriter for FsBlobWriter<'a, H> {
    fn finish(mut self) -> StorageResult<BlobId> {
        if self.failed {
            self.discard();
            return Err(StorageError::Io);
        }

        let file = match self.file.take() {
            Some(f) => f,
            None => {
                self.discard();
                return Err(StorageError::Io);
            }
        };
        if let Err(e) = file.sync_all() {
            self.discard();
            return Err(map_storage_error(&e));
        }
        let digest = match self.state.finalize() {
            Ok(d) => d,
            Err(e) => {
                self.discard();
                return Err(storage_err_from_crypto(e));
            }
        };
        let id = BlobId::new(digest);
        drop(file); // close before rename

        let final_path = self.store.blob_path(&id);
        let shard_dir = final_path
            .parent()
            .expect("blob_path always has a shard-directory parent");
        if let Err(e) = create_dir_all_private(shard_dir) {
            self.discard();
            return Err(map_storage_error(&e));
        }

        // Rename unconditionally rather than short-circuiting on "something already exists here".
        // `rename(2)` is atomic and these bytes provably hash to `id`, so an already-stored copy is
        // replaced by an identical one (immutable by content: the caller cannot tell, and a
        // truncated or bit-rotted object heals on the next honest put), while a directory or other
        // non-regular entry makes the rename fail and is reported instead of being mistaken for a
        // stored blob.
        if let Err(e) = fs::rename(&self.tmp_path, &final_path) {
            if is_regular_file(&final_path) {
                // A concurrent writer already put byte-identical content in place; it wins.
                let _ = fs::remove_file(&self.tmp_path);
                return Ok(id);
            }
            self.discard();
            return Err(map_storage_error(&e));
        }

        if fsync_dir(shard_dir).is_err() {
            // The blob is already in place; a retried put takes the "already exists" path above.
            return Err(StorageError::Io);
        }
        let sha256_dir = self.store.root.join(SHA256_DIR);
        if fsync_dir(&sha256_dir).is_err() {
            return Err(StorageError::Io);
        }

        Ok(id)
    }

    fn abort(mut self) {
        self.discard();
    }
}

impl<'a, H: Sha256> Drop for FsBlobWriter<'a, H> {
    fn drop(&mut self) {
        if let Some(f) = self.file.take() {
            drop(f);
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

impl<H: Sha256> BlobStore for FsBlobStore<H> {
    type Reader<'a>
        = FsBlobReader
    where
        Self: 'a;
    type Writer<'a>
        = FsBlobWriter<'a, H>
    where
        Self: 'a;
    type Digest = H::State;

    fn open(&self, id: &BlobId) -> StorageResult<Self::Reader<'_>> {
        let path = self.blob_path(id);
        // Stat first, exactly as `len` does: `File::open` on a directory succeeds on Linux, and an
        // `open` that returned a reader whose first `read` fails with `IoError::Other` would
        // disagree with `len`/`contains` about whether the blob is there at all.
        let meta = fs::metadata(&path).map_err(|e| map_storage_error(&e))?;
        if !meta.is_file() {
            return Err(StorageError::Invalid);
        }
        File::open(path)
            .map(|file| FsBlobReader { file })
            .map_err(|e| map_storage_error(&e))
    }

    fn digest_init(&self) -> StorageResult<Self::Digest> {
        self.hash.sha256_init().map_err(storage_err_from_crypto)
    }

    fn put(&mut self) -> StorageResult<Self::Writer<'_>> {
        let state = self.hash.sha256_init().map_err(storage_err_from_crypto)?;
        let pid = std::process::id();
        let tmp_dir = self.root.join(TMP_DIR);
        let mut opened = None;
        for _ in 0..1024 {
            let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tmp_path = tmp_dir.join(std::format!("{pid}-{n}"));
            match create_new_private(&tmp_path) {
                Ok(f) => {
                    opened = Some((f, tmp_path));
                    break;
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                // Deliberately not `map_storage_error`: a missing `<root>/tmp` is a broken store,
                // and `NotFound` from a write path would read as "that blob is not here".
                Err(_) => return Err(StorageError::Io),
            }
        }
        let (file, tmp_path) = opened.ok_or(StorageError::Io)?;
        Ok(FsBlobWriter {
            store: &*self,
            state,
            file: Some(file),
            tmp_path,
            failed: false,
        })
    }

    fn len(&self, id: &BlobId) -> StorageResult<u64> {
        let path = self.blob_path(id);
        let meta = fs::metadata(&path).map_err(|e| map_storage_error(&e))?;
        if !meta.is_file() {
            return Err(StorageError::Invalid);
        }
        Ok(meta.len())
    }

    fn remove(&mut self, id: &BlobId) -> StorageResult<()> {
        let path = self.blob_path(id);
        fs::remove_file(path).map_err(|e| map_storage_error(&e))
    }

    fn list(&self, f: &mut dyn FnMut(&BlobId) -> bool) -> StorageResult<()> {
        let sha256_dir = self.root.join(SHA256_DIR);
        let shard_entries = match fs::read_dir(&sha256_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(StorageError::Io),
        };
        for shard_entry in shard_entries {
            let shard_entry = shard_entry.map_err(|_| StorageError::Io)?;
            let shard_name = shard_entry.file_name();
            let Some(aa) = shard_name.to_str() else {
                continue;
            };
            if !is_lower_hex_shard(aa) {
                continue;
            }
            let shard_path = shard_entry.path();
            let inner_entries = match fs::read_dir(&shard_path) {
                Ok(e) => e,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(_) => match fs::metadata(&shard_path) {
                    Ok(m) if !m.is_dir() => continue,
                    _ => return Err(StorageError::Io),
                },
            };
            for inner_entry in inner_entries {
                let inner_entry = inner_entry.map_err(|_| StorageError::Io)?;
                let file_name = inner_entry.file_name();
                let Some(hex) = file_name.to_str() else {
                    continue;
                };
                if hex.len() != BLOB_ID_HEX_LEN || !hex.starts_with(aa) {
                    continue;
                }
                let Ok(id) = BlobId::from_hex(hex) else {
                    continue;
                };
                if !f(&id) {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Whether `p` is a regular file, not following a final symlink — the only entry a `finish` may
/// accept as "this blob is already stored".
fn is_regular_file(p: &Path) -> bool {
    fs::symlink_metadata(p)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// `create_dir_all` with mode `0o700` on unix, so the store does not inherit a permissive umask.
#[cfg(unix)]
fn create_dir_all_private(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p)
}

#[cfg(not(unix))]
fn create_dir_all_private(p: &Path) -> std::io::Result<()> {
    fs::create_dir_all(p)
}

/// `File::create_new` with mode `0o600` on unix (the mode the renamed-into-place blob keeps).
#[cfg(unix)]
fn create_new_private(p: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)
}

#[cfg(not(unix))]
fn create_new_private(p: &Path) -> std::io::Result<File> {
    File::create_new(p)
}

fn is_lower_hex_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

fn is_lower_hex_shard(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 2 && bytes.iter().all(|&b| is_lower_hex_byte(b))
}

/// `std::io::ErrorKind` -> `spacetime_io::IoError`.
fn map_io_error(e: &std::io::Error) -> IoError {
    match e.kind() {
        ErrorKind::NotFound => IoError::NotFound,
        ErrorKind::PermissionDenied => IoError::PermissionDenied,
        ErrorKind::WouldBlock => IoError::WouldBlock,
        ErrorKind::TimedOut => IoError::TimedOut,
        ErrorKind::UnexpectedEof => IoError::UnexpectedEof,
        ErrorKind::InvalidInput => IoError::InvalidInput,
        ErrorKind::ConnectionRefused => IoError::ConnectionRefused,
        ErrorKind::ConnectionReset => IoError::ConnectionReset,
        _ => IoError::Other,
    }
}

/// `std::io::Error` -> `StorageError`: `NotFound` -> `NotFound`, everything else -> `Io`.
fn map_storage_error(e: &std::io::Error) -> StorageError {
    match e.kind() {
        ErrorKind::NotFound => StorageError::NotFound,
        _ => StorageError::Io,
    }
}

#[cfg(unix)]
fn fsync_dir(p: &Path) -> std::io::Result<()> {
    File::open(p)?.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_p: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_io_error_table() {
        use std::io::Error;
        let cases = [
            (ErrorKind::NotFound, IoError::NotFound),
            (ErrorKind::PermissionDenied, IoError::PermissionDenied),
            (ErrorKind::WouldBlock, IoError::WouldBlock),
            (ErrorKind::TimedOut, IoError::TimedOut),
            (ErrorKind::UnexpectedEof, IoError::UnexpectedEof),
            (ErrorKind::InvalidInput, IoError::InvalidInput),
            (ErrorKind::ConnectionRefused, IoError::ConnectionRefused),
            (ErrorKind::ConnectionReset, IoError::ConnectionReset),
            (ErrorKind::Other, IoError::Other),
            (ErrorKind::AlreadyExists, IoError::Other),
        ];
        for (kind, expected) in cases {
            assert_eq!(map_io_error(&Error::from(kind)), expected, "{kind:?}");
        }
    }

    #[test]
    fn map_storage_error_table() {
        use std::io::Error;
        assert_eq!(
            map_storage_error(&Error::from(ErrorKind::NotFound)),
            StorageError::NotFound
        );
        assert_eq!(
            map_storage_error(&Error::from(ErrorKind::PermissionDenied)),
            StorageError::Io
        );
    }

    #[test]
    fn blob_path_layout() {
        let dir = std::env::temp_dir().join(std::format!(
            "spacetime-storage-blobpath-{}",
            std::process::id()
        ));
        // `new` needs no Sha256 bound; `()` stands in as an unused hash backend for this test.
        let store: FsBlobStore<()> = FsBlobStore::new(&dir, ()).unwrap();
        let id = BlobId::new([0xabu8; 32]);
        let expected = dir.join(SHA256_DIR).join("ab").join("ab".repeat(32));
        assert_eq!(store.blob_path(&id), expected);
        let _ = fs::remove_dir_all(&dir);
    }
}
