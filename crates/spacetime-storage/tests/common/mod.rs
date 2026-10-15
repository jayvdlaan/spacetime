//! Test-only real SHA-256: `sha2` behind the `spacetime-crypto` facade, the
//! Sha256 half of `spacetime-sshsig/tests/common/mod.rs`. Dev dependency only; `src/` never sees a
//! concrete primitive. Plus the store-agnostic conformance suite run by both `blob_mem.rs` and
//! `blob_fs.rs` — every item here is used by BOTH binaries (an item used by one only is dead code in
//! the other and fails `clippy -D warnings`).

use sha2::Digest;
use spacetime_crypto::{self as st, CryptoResult};
use spacetime_io::{write_all, IoError, Read, Write};
use spacetime_storage::{alloc_helpers, BlobId, BlobStore, BlobWriter, StorageError, Verification};

/// The RustCrypto SHA-256 primitive viewed through the `spacetime_crypto::Sha256` facade.
#[derive(Clone, Copy, Default)]
pub struct DevSha256;

pub struct DevSha256State(sha2::Sha256);

impl st::Sha256State for DevSha256State {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        Digest::update(&mut self.0, data);
        Ok(())
    }
    fn finalize(&mut self) -> CryptoResult<[u8; st::SHA256_LEN]> {
        Ok(self.0.finalize_reset().into())
    }
}

impl st::Sha256 for DevSha256 {
    type State = DevSha256State;
    fn sha256_init(&self) -> CryptoResult<Self::State> {
        Ok(DevSha256State(sha2::Sha256::new()))
    }
}

/// A `Sha256` facade backend whose streaming state fails on every `update` — drives the
/// writer-poisoning and digest-failure paths that a working backend cannot reach.
#[derive(Clone, Copy, Default)]
pub struct FailingSha256;

pub struct FailingSha256State;

impl st::Sha256State for FailingSha256State {
    fn update(&mut self, _data: &[u8]) -> CryptoResult<()> {
        Err(st::CryptoError::new(st::CryptoErrorKind::Failed))
    }
    fn finalize(&mut self) -> CryptoResult<[u8; st::SHA256_LEN]> {
        Err(st::CryptoError::new(st::CryptoErrorKind::Failed))
    }
}

impl st::Sha256 for FailingSha256 {
    type State = FailingSha256State;
    fn sha256_init(&self) -> CryptoResult<Self::State> {
        Ok(FailingSha256State)
    }
}

/// Independent oracle: `sha2::Sha256::digest(data)` as a `BlobId`.
pub fn oracle_id(data: &[u8]) -> BlobId {
    BlobId::new(sha2::Sha256::digest(data).into())
}

/// Deterministic pseudo-random byte at index `i` — no RNG crate, no seed to manage.
fn pattern_byte(i: usize) -> u8 {
    ((i * 31 + 7) as u8) ^ ((i >> 8) as u8)
}

/// Deterministic pseudo-random bytes of length `len` built from [`pattern_byte`].
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(pattern_byte).collect()
}

/// Write `data` through `store.put()` in `chunk`-byte writes via `write_all`, then `finish`.
pub fn put_chunked<S: BlobStore>(store: &mut S, data: &[u8], chunk: usize) -> BlobId {
    let mut w = store.put().unwrap();
    for c in data.chunks(chunk.max(1)) {
        write_all(&mut w, c).unwrap();
    }
    w.finish().unwrap()
}

/// Read a reader to the end in 4 KiB reads.
pub fn read_all<R: Read>(r: &mut R) -> Result<Vec<u8>, spacetime_io::IoError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The conformance suite: each fn below is exercised as one #[test] in each binary.
// ---------------------------------------------------------------------------

fn round_trip<S: BlobStore>(s: &mut S, data: &[u8], chunk: usize) {
    let id = put_chunked(s, data, chunk);
    assert_eq!(id, oracle_id(data));
    assert_eq!(s.len(&id).unwrap(), data.len() as u64);

    let mut r = s.open(&id).unwrap();
    assert_eq!(read_all(&mut r).unwrap(), data);

    let mut vr = s.open_verified(&id).unwrap();
    assert_eq!(read_all(&mut vr).unwrap(), data);
    assert_eq!(vr.verification(), Verification::Verified);
}

pub fn round_trip_empty<S: BlobStore>(s: &mut S) {
    round_trip(s, b"", 4096);
}

pub fn round_trip_one_byte<S: BlobStore>(s: &mut S) {
    round_trip(s, b"x", 4096);
}

pub fn round_trip_1mib<S: BlobStore>(s: &mut S) {
    let data = pattern(1 << 20);
    round_trip(s, &data, 4096);
}

/// The one large-blob test: writes and re-verifies 70,000,001 bytes without ever materializing the
/// whole blob in memory — the pattern is generated and compared one 4 KiB chunk at a time, both for
/// the write side and for the independent oracle and the verified read-back.
pub fn round_trip_70_000_001<S: BlobStore>(s: &mut S) {
    const LEN: usize = 70_000_001;
    const CHUNK: usize = 4096;

    let mut w = s.put().unwrap();
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; CHUNK];
    let mut written = 0usize;
    while written < LEN {
        let n = core::cmp::min(CHUNK, LEN - written);
        for (j, b) in buf[..n].iter_mut().enumerate() {
            *b = pattern_byte(written + j);
        }
        write_all(&mut w, &buf[..n]).unwrap();
        Digest::update(&mut hasher, &buf[..n]);
        written += n;
    }
    let id = w.finish().unwrap();
    let expected = BlobId::new(hasher.finalize_reset().into());
    assert_eq!(id, expected);
    assert_eq!(s.len(&id).unwrap(), LEN as u64);

    let mut vr = s.open_verified(&id).unwrap();
    let mut read = 0usize;
    loop {
        let n = vr.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        for (j, &b) in buf[..n].iter().enumerate() {
            assert_eq!(b, pattern_byte(read + j));
        }
        read += n;
    }
    assert_eq!(read, LEN);
    assert_eq!(vr.verification(), Verification::Verified);
}

pub fn id_is_sha256_of_bytes<S: BlobStore>(s: &mut S) {
    let a = put_chunked(s, b"payload one", 4);
    let b = put_chunked(s, b"payload two", 5);
    let c = put_chunked(s, b"payload three", 6);
    assert_eq!(a, oracle_id(b"payload one"));
    assert_eq!(b, oracle_id(b"payload two"));
    assert_eq!(c, oracle_id(b"payload three"));
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

pub fn duplicate_put_is_noop<S: BlobStore>(s: &mut S) {
    let data = b"duplicate content, put twice";
    let id1 = put_chunked(s, data, 5);
    let id2 = put_chunked(s, data, 9);
    assert_eq!(id1, id2);
    assert_eq!(s.len(&id1).unwrap(), data.len() as u64);

    let ids = alloc_helpers::list_blobs(s).unwrap();
    assert_eq!(ids.iter().filter(|&&i| i == id1).count(), 1);
}

pub fn contains_len_remove<S: BlobStore>(s: &mut S) {
    let data = b"contains len remove";
    let id = oracle_id(data);
    assert!(!s.contains(&id));

    let got = put_chunked(s, data, 7);
    assert_eq!(got, id);
    assert!(s.contains(&id));
    assert_eq!(s.len(&id).unwrap(), data.len() as u64);

    s.remove(&id).unwrap();
    assert!(!s.contains(&id));
    assert_eq!(s.len(&id), Err(StorageError::NotFound));
    assert_eq!(s.remove(&id), Err(StorageError::NotFound));
}

pub fn open_missing_is_not_found<S: BlobStore>(s: &mut S) {
    let id = oracle_id(b"never stored");
    assert_eq!(s.open(&id).err(), Some(StorageError::NotFound));
    assert_eq!(s.open_verified(&id).err(), Some(StorageError::NotFound));
    assert_eq!(s.len(&id), Err(StorageError::NotFound));
}

pub fn list_semantics<S: BlobStore>(s: &mut S) {
    let payloads: [&[u8]; 5] = [b"a", b"bb", b"ccc", b"dddd", b"eeeee"];
    let mut expected: Vec<BlobId> = payloads.iter().map(|p| put_chunked(s, p, 3)).collect();
    expected.sort();

    let mut got = alloc_helpers::list_blobs(s).unwrap();
    got.sort();
    assert_eq!(got, expected);

    let mut count = 0;
    s.list(&mut |_| {
        count += 1;
        count < 2
    })
    .unwrap();
    assert_eq!(count, 2);
}

pub fn abort_leaves_nothing<S: BlobStore>(s: &mut S) {
    let id = oracle_id(b"abort me");
    let mut w = s.put().unwrap();
    write_all(&mut w, b"abort me").unwrap();
    w.abort();
    assert!(!s.contains(&id));
    assert!(alloc_helpers::list_blobs(s).unwrap().is_empty());
}

pub fn drop_leaves_nothing<S: BlobStore>(s: &mut S) {
    let id = oracle_id(b"drop me");
    {
        let mut w = s.put().unwrap();
        write_all(&mut w, b"drop me").unwrap();
        // `w` drops here without `finish`/`abort`.
    }
    assert!(!s.contains(&id));
    assert!(alloc_helpers::list_blobs(s).unwrap().is_empty());
}

pub fn alloc_helpers_round_trip<S: BlobStore>(s: &mut S) {
    let data = pattern(5000);
    let id = alloc_helpers::put_blob(s, &data).unwrap();
    assert_eq!(id, oracle_id(&data));

    let got = alloc_helpers::get_blob(s, &id).unwrap();
    assert_eq!(got, data);

    let ids = alloc_helpers::list_blobs(s).unwrap();
    assert!(ids.contains(&id));
}

/// A store whose digest backend fails: the first `write` errors, the writer stays poisoned, and
/// `finish` reports `Io` without anything becoming visible. Call with a store built on
/// [`FailingSha256`].
pub fn write_error_poisons_writer<S: BlobStore>(s: &mut S) {
    let mut w = s.put().unwrap();
    assert!(
        write_all(&mut w, b"first chunk").is_err(),
        "a failing digest must fail the write"
    );
    // Poisoned: a caller that retries (or ignores the error and keeps streaming) must not be told
    // the next chunk was accepted.
    assert_eq!(w.write(b"second chunk"), Err(IoError::Other));
    assert_eq!(w.finish(), Err(StorageError::Io));
    assert!(alloc_helpers::list_blobs(s).unwrap().is_empty());
}
