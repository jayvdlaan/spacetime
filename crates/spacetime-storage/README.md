spacetime-storage
=================

No_std-first key/value storage facades and a content-addressed streaming blob seam for Spacetime.

Badges
- Docs: https://docs.rs/spacetime-storage

Highlights
- No allocations in core traits.
- Caller-provided buffers for reads; optional alloc helpers.
- Prefix-scan iterator API without allocation.
- Lightweight namespacing via key prefixing.
- Content-addressed blobs: the store hashes on the way in (SHA-256 via the spacetime-crypto facade); open, verified open, streaming put, len/contains/remove/list.
- FsBlobStore: <root>/sha256/<aa>/<hex64>, tmp + fsync + rename — never a short object.

Features
- default: no_std
- alloc: enable convenience helpers returning Vec and the in-memory MemBlobStore
- std: enables std-only examples/tests, the in-memory MemStore and the filesystem FsBlobStore

Quickstart
- Build (std):
  - cargo check -p spacetime-storage --features std
- Run examples:
  - Basic usage: cargo run -p spacetime-storage --example memstore_basic --features std,alloc
  - Prefix scan: cargo run -p spacetime-storage --example prefix_scan --features std
  - Blob store: cargo run -p spacetime-storage --example blob_fs --features std
- Run tests (std): cargo test -p spacetime-storage --features std
- Build axes:
  - cargo build -p spacetime-storage --no-default-features
  - cargo build -p spacetime-storage --no-default-features --features alloc
  - cargo build -p spacetime-storage --features std
  - cargo build -p spacetime-storage --no-default-features --target riscv32imac-unknown-none-elf

API sketch
- trait KvStore:
  - get(&self, key, out) -> Result<usize>
  - put(&mut self, key, value) -> Result<()>
  - delete(&mut self, key) -> Result<()>
  - len(&self, key) -> Result<usize>
  - contains(&self, key) -> bool
- trait KvScan:
  - scan_prefix(&self, prefix) -> Iter that fills caller-provided key/value buffers
- struct Namespaced<S>:
  - wraps a store and prefixes keys; methods: get_ns, put_ns, delete_ns, len_ns, contains_ns

Transactions
- Traits TxnStore and Txn provide begin/commit/rollback.
- A std-only prototype transaction (MemTxn) is implemented for the in-memory MemStore with read-your-writes and commit/rollback semantics. See unit tests for usage.

Blob seam
- API sketch:
  - trait BlobStore: open(&self, id) -> Reader; digest_init(&self) -> Digest; open_verified(&self, id) -> VerifiedReader (provided); put(&mut self) -> Writer; len(&self, id) -> u64; contains(&self, id) -> bool; remove(&mut self, id); list(&self, f: &mut dyn FnMut(&BlobId) -> bool)
  - trait BlobWriter: Write; finish(self) -> BlobId; abort(self)
  - struct BlobId: 32-byte SHA-256, strict lowercase-hex codec (to_hex/from_hex/Display/FromStr), shard() for the `<aa>` directory name
  - struct VerifiedReader / enum Verification: a streaming reader that re-hashes as it reads and fails at EOF on a mismatch
  - alloc helpers: list_blobs, put_blob, get_blob (in `alloc_helpers`). Both `list_blobs` and `get_blob` are the unbounded forms — `list_blobs` holds every id (32 bytes each) and `get_blob` buffers the whole blob; on a large store or a constrained target use `BlobStore::list`'s callback form and read the reader in chunks.
- Semantics: immutable by content — a `finish()` whose id already exists is a successful no-op (the bytes are byte-identical by construction, so which copy survives is unobservable; the filesystem store renames its verified copy into place, which also repairs an object damaged by bit-rot or a truncating restore); ids are the real SHA-256 the store itself computed, never caller-supplied; `remove` of a missing id is `NotFound`; `list` order is unspecified; no chunking — a blob is one stream, whole files only.
- Layout (FsBlobStore): `<root>/sha256/<aa>/<hex64>` (`aa` = the blob's first byte, lowercase hex), `<root>/tmp/<pid>-<n>` for staging. `list` accepts only names that are exactly 64 lowercase hex characters under a matching `<aa>` shard directory. Symlinks are followed by `open`/`len`, never created, and a `put` replaces one that sits at a blob path rather than trusting it. `open`, `len` and `contains` accept only a regular file: a directory or other non-regular entry at a blob path is `Invalid`, and a `put` onto it fails with `Io` instead of silently discarding the caller's bytes. On unix the store creates its directories `0o700` and its files `0o600`, independent of the process umask; existing directories keep the mode the operator gave them, and only `open_verified` detects bytes substituted by someone else who can write into the store. The store leaves empty `<aa>` shard directories behind after a `remove` (cleaning them up is not required). Unix only — Windows `rename`-over-existing and directory `fsync` semantics differ and are untested.
- Atomicity: a blob becomes visible at its final path only through `rename(2)` (atomic on POSIX), only after the complete file has been written and `fsync`ed. Before the rename every byte lives in `tmp/`, which reads never consult, so a crash before the rename leaves at most an invisible temp file; a crash after the rename but before the directory `fsync` can lose the directory entry on some filesystems, so the blob is then simply absent, never short. Two writers with the same content — same process, two threads, or two processes — each get a distinct temp file (`O_EXCL`); each `finish` renames its own complete, hashed copy into place and `rename(2)` atomically replaces the previous, byte-identical one; both return the same id. `finish` returning `Err` does not always mean nothing landed: if the directory `fsync` after a successful rename fails, the blob is already complete at its final path and only its directory entry may be at risk — the safe response is to retry the put, which re-stages and re-renames the same bytes.
- Verified reads: `open_verified` streams bytes through unchanged and only fails on the read that hits EOF, with `IoError::InvalidInput`, if the recomputed digest differs from the id; `verification()` on the reader says why (`Pending`/`Verified`/`Mismatch`/`Failed`). A consumer that must not release unverified bytes buffers to the end itself — `alloc_helpers::get_blob` is that pattern. The filesystem store never *stores* a mismatched blob in the first place; `open_verified` defends against post-write tampering or bit-rot, not against the writer.
- Class partitioning: the seam knows nothing about classes. A consumer that wants `blobs/<class>/sha256/<aa>/<hex64>` gets it by constructing one `FsBlobStore` per class: `FsBlobStore::new(node.join("blobs").join(class), backend)`. A blob put in one class is invisible to another, and `rsync --exclude blobs/<class>/` works by path.
- Trust: an id is the digest of whichever `Sha256` backend the consumer injects; the `sha256/` path component asserts that backend really is SHA-256, and this crate cannot check that — choosing it is the consumer's security decision.
- Errors: `StorageError` gains `HashMismatch` (a verified read's digest differed at EOF) and `Digest(CryptoErrorKind)` (the SHA-256 backend failed); `spacetime_io::IoError::NotFound` maps to `StorageError::NotFound`, every other `IoError` variant maps to `StorageError::Io`.

Non-goals (see the module docs for the full list): chunking or a chunked manifest (blobs are whole files in v1); compression; encryption (wrap with age, e.g. `spacetime-age`, before `put`); classes, retention or placement inside the seam; a network transport or sync protocol; garbage collection of empty `<aa>` directories; a `dyn`-safe form of `BlobStore`; Windows semantics; a caller-supplied id on `put`; overwrite of an existing blob.

Notes
- The std MemStore is for development and testing only; it does not guarantee iteration order for prefix scans.
- Dev-only: sha2 is a dev-dependency for the test backend and the blob_fs example; src/ names no primitive.
