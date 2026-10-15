//! The STREAM payload: ChaCha20-Poly1305 over 64 KiB chunks.
//!
//! ```text
//! payload = nonce[16] ‖ chunk_0 ‖ chunk_1 ‖ …
//! key     = HKDF-SHA-256(salt = nonce, ikm = file_key, info = "payload")
//! chunk_i = ChaCha20-Poly1305(key, nonce_i, aad = "", plaintext_i) ‖ tag
//! nonce_i = BE88(i) ‖ flag         flag = 0x01 on the last chunk, else 0x00
//! ```
//!
//! Every chunk but the last carries exactly 65 536 plaintext bytes; the
//! last carries 1..=65 536, or 0 only when the whole plaintext is empty
//! (so an empty file is `nonce ‖ 16-byte tag`, and a plaintext that is an
//! exact multiple of 64 KiB ends with a *full* final chunk).
//!
//! The API is caller-driven and buffer-based — no internal 64 KiB buffer, so
//! a `no_std` caller sizes its own. A std layer does the read-ahead
//! (deciding whether a full chunk is the last one requires knowing whether
//! more input follows).
//!
//! # Release rule (decrypt)
//!
//! [`StreamReader`] reproduces Go's behaviour, which the CCTV corpus asserts
//! through the hash of *released* plaintext: a full 65 552-byte chunk is
//! opened with `last = 0` first and, on failure, re-opened with `last = 1`;
//! the plaintext of every successfully opened chunk is handed to the caller
//! before a later trailing-data or truncation error is detected. The
//! two-buffer `chacha20poly1305_open_into` leaves the ciphertext intact
//! across a failed first attempt.

use spacetime_crypto::{ChaCha20Poly1305, CryptoErrorKind, HkdfSha256, Rng};

use crate::error::{Error, PayloadError};
use crate::keys::FileKey;
use crate::util::wipe;

/// Plaintext bytes per chunk.
pub const CHUNK_LEN: usize = 65_536;
/// Poly1305 tag length.
pub const CHUNK_TAG_LEN: usize = 16;
/// Sealed length of a full chunk.
pub const CHUNK_SEALED_LEN: usize = CHUNK_LEN + CHUNK_TAG_LEN;
/// Payload nonce length.
pub const PAYLOAD_NONCE_LEN: usize = 16;
/// HKDF info for the payload key.
pub const PAYLOAD_INFO: &[u8] = b"payload";

const fn perr(e: PayloadError) -> Error {
    Error::Payload(e)
}

/// `16 + n + 16 * max(1, ceil(n / 65536))`.
pub const fn sealed_payload_len(plaintext_len: usize) -> usize {
    let chunks = plaintext_len.div_ceil(CHUNK_LEN);
    let chunks = if chunks == 0 { 1 } else { chunks };
    PAYLOAD_NONCE_LEN + plaintext_len + CHUNK_TAG_LEN * chunks
}

/// Derive the payload key.
fn payload_key<B: HkdfSha256 + ?Sized>(
    b: &B,
    file_key: &FileKey,
    nonce: &[u8; PAYLOAD_NONCE_LEN],
) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    if let Err(e) = b.hkdf_sha256(nonce, file_key.as_bytes(), PAYLOAD_INFO, &mut key) {
        wipe(&mut key);
        return Err(e.into());
    }
    Ok(key)
}

/// Advance the 11-byte big-endian counter in `nonce[..11]`; a carry out of
/// byte 0 is `CounterOverflow`.
fn increment(nonce: &mut [u8; 12]) -> Result<(), Error> {
    for b in nonce[..11].iter_mut().rev() {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            return Ok(());
        }
    }
    Err(perr(PayloadError::CounterOverflow))
}

/// Shared counter state of the writer and the reader.
struct Counter {
    nonce: [u8; 12],
    started: bool,
}

impl Counter {
    const fn new() -> Self {
        Self {
            nonce: [0u8; 12],
            started: false,
        }
    }

    /// Move to the next chunk's counter value (no-op before the first
    /// chunk) and set the last-chunk flag.
    fn prepare(&mut self, last: bool) -> Result<&[u8; 12], Error> {
        if self.started {
            increment(&mut self.nonce)?;
        } else {
            self.started = true;
        }
        self.nonce[11] = u8::from(last);
        Ok(&self.nonce)
    }

    fn set_flag(&mut self, last: bool) -> &[u8; 12] {
        self.nonce[11] = u8::from(last);
        &self.nonce
    }
}

/// Encrypt side. Holds the derived 32-byte key (wiped on drop) and the
/// 12-byte chunk nonce.
pub struct StreamWriter<'b, B: ?Sized> {
    backend: &'b B,
    key: [u8; 32],
    counter: Counter,
    payload_nonce: [u8; PAYLOAD_NONCE_LEN],
    finished: bool,
}

impl<'b, B: HkdfSha256 + ChaCha20Poly1305 + ?Sized> StreamWriter<'b, B> {
    /// Draw the 16-byte payload nonce from `rng` and derive the key.
    pub fn new<R: Rng + ?Sized>(
        backend: &'b B,
        file_key: &FileKey,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut nonce = [0u8; PAYLOAD_NONCE_LEN];
        rng.fill_bytes(&mut nonce)?;
        Self::with_nonce(backend, file_key, &nonce)
    }

    /// Same with a caller-supplied nonce (round-trip tests against `file
    /// key:` vectors; the std layer never uses it).
    pub fn with_nonce(
        backend: &'b B,
        file_key: &FileKey,
        nonce: &[u8; PAYLOAD_NONCE_LEN],
    ) -> Result<Self, Error> {
        let key = payload_key(backend, file_key, nonce)?;
        Ok(Self {
            backend,
            key,
            counter: Counter::new(),
            payload_nonce: *nonce,
            finished: false,
        })
    }

    /// The 16 bytes the caller must emit before the first chunk.
    pub const fn nonce(&self) -> &[u8; PAYLOAD_NONCE_LEN] {
        &self.payload_nonce
    }

    /// Seal a full non-final chunk: `plaintext.len() == CHUNK_LEN` (else
    /// `Payload(ChunkLength)`), `out.len() >= CHUNK_SEALED_LEN` (else
    /// `BufferTooSmall`). The caller guarantees more plaintext follows.
    /// Returns 65 552.
    pub fn write_chunk(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.finished {
            return Err(perr(PayloadError::TrailingData));
        }
        if plaintext.len() != CHUNK_LEN {
            return Err(perr(PayloadError::ChunkLength));
        }
        if out.len() < CHUNK_SEALED_LEN {
            return Err(Error::BufferTooSmall);
        }
        let nonce = *self.counter.prepare(false)?;
        Ok(self
            .backend
            .chacha20poly1305_seal_into(&self.key, &nonce, &[], plaintext, out)?)
    }

    /// Seal the final chunk: `plaintext.len() <= CHUNK_LEN`; empty is
    /// allowed only as the first and only chunk (else
    /// `Payload(EmptyFinalChunk)`). Returns `len + 16`.
    pub fn write_last(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.finished {
            return Err(perr(PayloadError::TrailingData));
        }
        if plaintext.len() > CHUNK_LEN {
            return Err(perr(PayloadError::ChunkLength));
        }
        if plaintext.is_empty() && self.counter.started {
            return Err(perr(PayloadError::EmptyFinalChunk));
        }
        if out.len() < plaintext.len() + CHUNK_TAG_LEN {
            return Err(Error::BufferTooSmall);
        }
        let nonce = *self.counter.prepare(true)?;
        let n = self
            .backend
            .chacha20poly1305_seal_into(&self.key, &nonce, &[], plaintext, out)?;
        self.finished = true;
        Ok(n)
    }

    /// `true` once [`StreamWriter::write_last`] succeeded.
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    #[cfg(test)]
    pub(crate) fn set_counter_for_test(&mut self, counter: [u8; 11]) {
        self.counter.nonce[..11].copy_from_slice(&counter);
        self.counter.started = true;
    }
}

impl<B: ?Sized> Drop for StreamWriter<'_, B> {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

/// Decrypt side; same key derivation from the nonce read from the file.
pub struct StreamReader<'b, B: ?Sized> {
    backend: &'b B,
    key: [u8; 32],
    counter: Counter,
    finished: bool,
}

impl<'b, B: HkdfSha256 + ChaCha20Poly1305 + ?Sized> StreamReader<'b, B> {
    /// Derive the key from `file_key` and the file's payload nonce.
    pub fn new(
        backend: &'b B,
        file_key: &FileKey,
        nonce: &[u8; PAYLOAD_NONCE_LEN],
    ) -> Result<Self, Error> {
        let key = payload_key(backend, file_key, nonce)?;
        Ok(Self {
            backend,
            key,
            counter: Counter::new(),
            finished: false,
        })
    }

    /// Open a full 65 552-byte sealed chunk (`sealed.len() !=
    /// CHUNK_SEALED_LEN` → `Payload(ChunkLength)`; `out.len() < CHUNK_LEN`
    /// → `BufferTooSmall`). Opens with `last = 0`; on `AuthenticationFailed`
    /// opens again with `last = 1`, and if that succeeds the reader is
    /// finished. Both failing → `Payload(Authentication)`. After finished →
    /// `Payload(TrailingData)`. Returns 65 536.
    pub fn next_chunk(&mut self, sealed: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.finished {
            return Err(perr(PayloadError::TrailingData));
        }
        if sealed.len() != CHUNK_SEALED_LEN {
            return Err(perr(PayloadError::ChunkLength));
        }
        if out.len() < CHUNK_LEN {
            return Err(Error::BufferTooSmall);
        }
        let nonce = *self.counter.prepare(false)?;
        match self
            .backend
            .chacha20poly1305_open_into(&self.key, &nonce, &[], sealed, out)
        {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == CryptoErrorKind::AuthenticationFailed => {}
            Err(e) => return Err(e.into()),
        }
        let nonce = *self.counter.set_flag(true);
        match self
            .backend
            .chacha20poly1305_open_into(&self.key, &nonce, &[], sealed, out)
        {
            Ok(n) => {
                self.finished = true;
                Ok(n)
            }
            Err(e) if e.kind() == CryptoErrorKind::AuthenticationFailed => {
                Err(perr(PayloadError::Authentication))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Feed the final (short) chunk, `sealed.len() < CHUNK_SEALED_LEN`, the
    /// caller having hit EOF: finished && empty → `Ok(0)`; finished &&
    /// non-empty (any length) → `Payload(TrailingData)`; empty →
    /// `Payload(Truncated)`; `>= CHUNK_SEALED_LEN` → `Payload(ChunkLength)`;
    /// 1..=15 → `Payload(ChunkTooShort)`; exactly 16 with a chunk already
    /// opened → `Payload(EmptyFinalChunk)`; else open with `last = 1`
    /// (`AuthenticationFailed` → `Payload(Authentication)`), mark finished,
    /// return `len − 16`.
    pub fn last_chunk(&mut self, sealed: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.finished {
            return if sealed.is_empty() {
                Ok(0)
            } else {
                Err(perr(PayloadError::TrailingData))
            };
        }
        if sealed.len() >= CHUNK_SEALED_LEN {
            return Err(perr(PayloadError::ChunkLength));
        }
        if sealed.is_empty() {
            return Err(perr(PayloadError::Truncated));
        }
        if sealed.len() < CHUNK_TAG_LEN {
            return Err(perr(PayloadError::ChunkTooShort));
        }
        if sealed.len() == CHUNK_TAG_LEN && self.counter.started {
            return Err(perr(PayloadError::EmptyFinalChunk));
        }
        if out.len() < sealed.len() - CHUNK_TAG_LEN {
            return Err(Error::BufferTooSmall);
        }
        let nonce = *self.counter.prepare(true)?;
        match self
            .backend
            .chacha20poly1305_open_into(&self.key, &nonce, &[], sealed, out)
        {
            Ok(n) => {
                self.finished = true;
                Ok(n)
            }
            Err(e) if e.kind() == CryptoErrorKind::AuthenticationFailed => {
                Err(perr(PayloadError::Authentication))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// ≡ `last_chunk(&[], &mut [])`: `Ok(())` iff finished, else
    /// `Payload(Truncated)`.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.last_chunk(&[], &mut []).map(|_| ())
    }

    /// `true` once the final chunk has been opened.
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    #[cfg(test)]
    pub(crate) fn set_counter_for_test(&mut self, counter: [u8; 11]) {
        self.counter.nonce[..11].copy_from_slice(&counter);
        self.counter.started = true;
    }
}

impl<B: ?Sized> Drop for StreamReader<'_, B> {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacetime_crypto::{CryptoError, CryptoResult};

    /// Not cryptography: XORs every byte with `key[0] ^ nonce[11] ^ 0x5A`
    /// and uses a tag of the nonce's flag byte repeated. Enough to drive the
    /// state machine and the nonce-flag retry path.
    struct XorAead;

    impl HkdfSha256 for XorAead {
        fn hkdf_sha256_extract(
            &self,
            _: &[u8],
            ikm: &[u8],
            prk: &mut [u8; 32],
        ) -> CryptoResult<()> {
            prk[0] = ikm[0];
            Ok(())
        }
        fn hkdf_sha256_expand(&self, prk: &[u8; 32], _: &[u8], okm: &mut [u8]) -> CryptoResult<()> {
            okm.fill(prk[0]);
            Ok(())
        }
    }

    impl ChaCha20Poly1305 for XorAead {
        fn chacha20poly1305_seal(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 12],
            _: &[u8],
            buf: &mut [u8],
        ) -> CryptoResult<[u8; 16]> {
            for b in buf.iter_mut() {
                *b ^= key[0] ^ nonce[11] ^ 0x5A;
            }
            let mut tag = [nonce[11]; 16];
            tag[..11].copy_from_slice(&nonce[..11]);
            Ok(tag)
        }
        fn chacha20poly1305_open(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 12],
            _: &[u8],
            buf: &mut [u8],
            tag: &[u8; 16],
        ) -> CryptoResult<()> {
            let mut want = [nonce[11]; 16];
            want[..11].copy_from_slice(&nonce[..11]);
            if *tag != want {
                return Err(CryptoError::new(CryptoErrorKind::AuthenticationFailed));
            }
            for b in buf.iter_mut() {
                *b ^= key[0] ^ nonce[11] ^ 0x5A;
            }
            Ok(())
        }
    }

    fn fk() -> FileKey {
        FileKey::from_bytes([3u8; 16])
    }

    #[test]
    fn sealed_len_formula() {
        assert_eq!(sealed_payload_len(0), 32);
        assert_eq!(sealed_payload_len(1), 33);
        assert_eq!(sealed_payload_len(CHUNK_LEN), 16 + CHUNK_LEN + 16);
        assert_eq!(sealed_payload_len(CHUNK_LEN + 1), 16 + CHUNK_LEN + 1 + 32);
        assert_eq!(sealed_payload_len(2 * CHUNK_LEN), 16 + 2 * CHUNK_LEN + 32);
    }

    #[test]
    fn writer_api_misuse() {
        let mut w = StreamWriter::with_nonce(&XorAead, &fk(), &[9; 16]).unwrap();
        assert_eq!(w.nonce(), &[9; 16]);
        let mut out = [0u8; 64];
        assert_eq!(
            w.write_chunk(&[0; 10], &mut out),
            Err(perr(PayloadError::ChunkLength))
        );
        assert_eq!(
            w.write_last(&[0; 10], &mut [0u8; 25]),
            Err(Error::BufferTooSmall)
        );
        assert!(!w.is_finished());
        assert_eq!(w.write_last(&[1, 2, 3], &mut out).unwrap(), 19);
        assert!(w.is_finished());
        assert_eq!(
            w.write_last(&[], &mut out),
            Err(perr(PayloadError::TrailingData))
        );
        assert_eq!(
            w.write_chunk(&[0; CHUNK_LEN], &mut out),
            Err(perr(PayloadError::TrailingData))
        );
    }

    #[test]
    fn writer_empty_final_only_first() {
        let mut w = StreamWriter::with_nonce(&XorAead, &fk(), &[9; 16]).unwrap();
        let mut out = [0u8; 32];
        assert_eq!(w.write_last(&[], &mut out).unwrap(), 16);
        let mut w = StreamWriter::with_nonce(&XorAead, &fk(), &[9; 16]).unwrap();
        w.set_counter_for_test([0; 11]);
        assert_eq!(
            w.write_last(&[], &mut out),
            Err(perr(PayloadError::EmptyFinalChunk))
        );
    }

    #[test]
    fn writer_counter_overflow() {
        let mut w = StreamWriter::with_nonce(&XorAead, &fk(), &[9; 16]).unwrap();
        w.set_counter_for_test([0xff; 11]);
        let mut out = [0u8; 32];
        assert_eq!(
            w.write_last(&[1], &mut out),
            Err(perr(PayloadError::CounterOverflow))
        );
    }

    #[test]
    fn reader_api_misuse_and_edges() {
        let mut r = StreamReader::new(&XorAead, &fk(), &[9; 16]).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(
            r.next_chunk(&[0; 10], &mut out),
            Err(perr(PayloadError::ChunkLength))
        );
        assert_eq!(
            r.last_chunk(&[0; CHUNK_SEALED_LEN], &mut out),
            Err(perr(PayloadError::ChunkLength))
        );
        assert_eq!(
            r.last_chunk(&[], &mut out),
            Err(perr(PayloadError::Truncated))
        );
        assert_eq!(r.finish(), Err(perr(PayloadError::Truncated)));
        assert_eq!(
            r.last_chunk(&[0; 15], &mut out),
            Err(perr(PayloadError::ChunkTooShort))
        );
        assert_eq!(
            r.last_chunk(&[0; 40], &mut [0u8; 23]),
            Err(Error::BufferTooSmall)
        );
        // A 16-byte final chunk is fine as the first chunk.
        let mut sealed = [0u8; 16];
        let mut w = StreamWriter::with_nonce(&XorAead, &fk(), &[9; 16]).unwrap();
        w.write_last(&[], &mut sealed).unwrap();
        assert_eq!(r.last_chunk(&sealed, &mut out).unwrap(), 0);
        assert!(r.is_finished());
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(
            r.last_chunk(&[1], &mut out),
            Err(perr(PayloadError::TrailingData))
        );
        // Trailing data after the final chunk is `TrailingData` whatever its
        // length — a full chunk's worth is not an API-misuse `ChunkLength`.
        assert_eq!(
            r.last_chunk(&[0; CHUNK_SEALED_LEN], &mut out),
            Err(perr(PayloadError::TrailingData))
        );
        assert_eq!(
            r.next_chunk(&[0; CHUNK_SEALED_LEN], &mut [0u8; CHUNK_LEN]),
            Err(perr(PayloadError::TrailingData))
        );
        // ... but not after another chunk.
        let mut r = StreamReader::new(&XorAead, &fk(), &[9; 16]).unwrap();
        r.set_counter_for_test([0; 11]);
        assert_eq!(
            r.last_chunk(&sealed, &mut out),
            Err(perr(PayloadError::EmptyFinalChunk))
        );
    }

    #[test]
    fn reader_counter_overflow() {
        let mut r = StreamReader::new(&XorAead, &fk(), &[9; 16]).unwrap();
        r.set_counter_for_test([0xff; 11]);
        assert_eq!(
            r.last_chunk(&[0; 17], &mut [0u8; 1]),
            Err(perr(PayloadError::CounterOverflow))
        );
    }

    #[test]
    fn short_round_trip_and_bad_tag() {
        let mut w = StreamWriter::with_nonce(&XorAead, &fk(), &[9; 16]).unwrap();
        let mut sealed = [0u8; 19];
        w.write_last(b"abc", &mut sealed).unwrap();
        let mut r = StreamReader::new(&XorAead, &fk(), &[9; 16]).unwrap();
        let mut out = [0u8; 3];
        assert_eq!(r.last_chunk(&sealed, &mut out).unwrap(), 3);
        assert_eq!(&out, b"abc");
        sealed[18] ^= 1;
        let mut r = StreamReader::new(&XorAead, &fk(), &[9; 16]).unwrap();
        assert_eq!(
            r.last_chunk(&sealed, &mut out),
            Err(perr(PayloadError::Authentication))
        );
    }

    #[test]
    fn full_chunk_retry_with_last_flag() {
        // A full final chunk (sealed with last = 1) must open on the retry.
        let mut w = StreamWriter::with_nonce(&XorAead, &fk(), &[9; 16]).unwrap();
        let pt = [7u8; CHUNK_LEN];
        let mut sealed = [0u8; CHUNK_SEALED_LEN];
        assert_eq!(w.write_last(&pt, &mut sealed).unwrap(), CHUNK_SEALED_LEN);
        let mut r = StreamReader::new(&XorAead, &fk(), &[9; 16]).unwrap();
        let mut out = [0u8; CHUNK_LEN];
        assert_eq!(r.next_chunk(&sealed, &mut out).unwrap(), CHUNK_LEN);
        assert!(r.is_finished());
        assert_eq!(out, pt);
        assert_eq!(r.finish(), Ok(()));
        // A full non-final chunk followed by EOF is truncated.
        let mut w = StreamWriter::with_nonce(&XorAead, &fk(), &[9; 16]).unwrap();
        assert_eq!(w.write_chunk(&pt, &mut sealed).unwrap(), CHUNK_SEALED_LEN);
        let mut r = StreamReader::new(&XorAead, &fk(), &[9; 16]).unwrap();
        assert_eq!(r.next_chunk(&sealed, &mut out).unwrap(), CHUNK_LEN);
        assert!(!r.is_finished());
        assert_eq!(r.finish(), Err(perr(PayloadError::Truncated)));
        // Both nonce variants failing is an authentication error.
        sealed[0] ^= 1;
        let mut r = StreamReader::new(&XorAead, &fk(), &[9; 16]).unwrap();
        sealed[CHUNK_LEN] ^= 0x80;
        assert_eq!(
            r.next_chunk(&sealed, &mut out),
            Err(perr(PayloadError::Authentication))
        );
    }

    #[test]
    fn increment_carries() {
        let mut n = [0u8; 12];
        n[10] = 0xff;
        increment(&mut n).unwrap();
        assert_eq!(&n[..11], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
        let mut n = [0xffu8; 12];
        assert_eq!(increment(&mut n), Err(perr(PayloadError::CounterOverflow)));
    }
}
