//! [`VerifiedReader`]: a streaming reader that re-hashes a blob as it is read and fails at EOF if the
//! digest does not match the expected [`BlobId`].

use crate::blob::{io_err_from_crypto, BlobId};
use spacetime_crypto::Sha256State;
use spacetime_io::{IoError, IoResult, Read};

/// Outcome of a [`VerifiedReader`] so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// EOF not reached yet: the bytes returned so far are NOT yet verified.
    Pending,
    /// EOF reached and the digest matched.
    Verified,
    /// EOF reached and the digest differed. Every later `read` returns `Err(IoError::InvalidInput)`.
    Mismatch,
    /// The digest backend failed; verification is impossible. Every later `read` returns
    /// `Err(IoError::Other)`.
    Failed,
}

/// Wraps any [`Read`] and a streaming SHA-256 state; hashes every byte it hands out and, on the read
/// that observes EOF, finalizes and compares with the expected id.
///
/// Bytes stream through unchanged *before* they are verified — a consumer that must not release
/// unverified bytes has to buffer to the end itself (see `crate::alloc_helpers::get_blob`).
pub struct VerifiedReader<R, S> {
    inner: R,
    state: S,
    expected: BlobId,
    status: Verification,
}

impl<R, S> VerifiedReader<R, S> {
    /// Wrap `inner`, hashing with `state` and comparing against `expected` at EOF.
    pub fn new(inner: R, state: S, expected: BlobId) -> Self {
        Self {
            inner,
            state,
            expected,
            status: Verification::Pending,
        }
    }

    /// The id this reader is verifying against.
    pub const fn expected(&self) -> &BlobId {
        &self.expected
    }

    /// The current verification outcome.
    pub const fn verification(&self) -> Verification {
        self.status
    }

    /// Unwrap, discarding the digest state and the verification outcome.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read, S: Sha256State> Read for VerifiedReader<R, S> {
    /// `Ok(0)` means EOF *and* a matching digest — except for a call with an empty `buf`, which
    /// returns `Ok(0)` without touching the inner reader while verification is still
    /// [`Verification::Pending`]. A caller that loops until `Ok(0)` must therefore keep `buf`
    /// non-empty, or check [`VerifiedReader::verification`] before trusting the bytes.
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match self.status {
            Verification::Verified => return Ok(0),
            Verification::Mismatch => return Err(IoError::InvalidInput),
            Verification::Failed => return Err(IoError::Other),
            Verification::Pending => {}
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.state.update(&buf[..n]).map_err(|e| {
                self.status = Verification::Failed;
                io_err_from_crypto(e)
            })?;
            return Ok(n);
        }
        // n == 0: EOF from the inner reader.
        let got = self.state.finalize().map_err(|e| {
            self.status = Verification::Failed;
            io_err_from_crypto(e)
        })?;
        if got == *self.expected.as_bytes() {
            self.status = Verification::Verified;
            Ok(0)
        } else {
            self.status = Verification::Mismatch;
            Err(IoError::InvalidInput)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacetime_crypto::CryptoResult;

    /// Fake digest whose "hash" is just the total length seen, so tests do not need a real SHA-256.
    #[derive(Default)]
    struct LenDigest {
        len: u64,
    }

    impl Sha256State for LenDigest {
        fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
            self.len += data.len() as u64;
            Ok(())
        }
        fn finalize(&mut self) -> CryptoResult<[u8; 32]> {
            let mut out = [0u8; 32];
            out[0] = self.len as u8;
            Ok(out)
        }
    }

    struct FailingState;
    impl Sha256State for FailingState {
        fn update(&mut self, _data: &[u8]) -> CryptoResult<()> {
            Err(spacetime_crypto::CryptoError::new(
                spacetime_crypto::CryptoErrorKind::Failed,
            ))
        }
        fn finalize(&mut self) -> CryptoResult<[u8; 32]> {
            unreachable!("update always fails first in these tests")
        }
    }

    /// Reader over a fixed slice, counting how many times `read` was called (to prove a sticky
    /// mismatch never touches the inner reader again).
    struct SliceReader<'a> {
        data: &'a [u8],
        calls: usize,
    }

    impl<'a> SliceReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self { data, calls: 0 }
        }
    }

    impl<'a> Read for SliceReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
            self.calls += 1;
            let n = core::cmp::min(buf.len(), self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    struct WouldBlockOnce {
        blocked: bool,
    }
    impl Read for WouldBlockOnce {
        fn read(&mut self, _buf: &mut [u8]) -> IoResult<usize> {
            if !self.blocked {
                self.blocked = true;
                Err(IoError::WouldBlock)
            } else {
                Ok(0)
            }
        }
    }

    fn expected_of(len: u8) -> BlobId {
        let mut bytes = [0u8; 32];
        bytes[0] = len;
        BlobId::new(bytes)
    }

    #[test]
    fn bytes_pass_through_unchanged_in_order() {
        let payload = b"hello world";
        let inner = SliceReader::new(payload);
        let mut r = VerifiedReader::new(
            inner,
            LenDigest::default(),
            expected_of(payload.len() as u8),
        );
        let mut out = alloc_free_buf();
        let mut total = 0usize;
        loop {
            let mut chunk = [0u8; 4];
            let n = r.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            out[total..total + n].copy_from_slice(&chunk[..n]);
            total += n;
        }
        assert_eq!(&out[..total], payload);
        assert_eq!(r.verification(), Verification::Verified);
    }

    fn alloc_free_buf() -> [u8; 32] {
        [0u8; 32]
    }

    #[test]
    fn matching_digest_yields_ok_zero_and_verified() {
        let payload = b"hello world";
        let inner = SliceReader::new(payload);
        let mut r = VerifiedReader::new(
            inner,
            LenDigest::default(),
            expected_of(payload.len() as u8),
        );
        let mut buf = [0u8; 64];
        // drain
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
        }
        assert_eq!(r.verification(), Verification::Verified);
    }

    #[test]
    fn mismatched_digest_is_sticky_and_does_not_touch_inner_again() {
        let payload = b"hello world";
        let inner = SliceReader::new(payload);
        let mut r = VerifiedReader::new(inner, LenDigest::default(), expected_of(0)); // wrong length
        let mut buf = [0u8; 64];
        loop {
            match r.read(&mut buf) {
                Ok(0) => panic!("expected a mismatch error at EOF"),
                Ok(_) => continue,
                Err(IoError::InvalidInput) => break,
                Err(e) => panic!("unexpected error {e:?}"),
            }
        }
        assert_eq!(r.verification(), Verification::Mismatch);
        let calls_before = r.inner.calls;
        assert_eq!(r.read(&mut buf), Err(IoError::InvalidInput));
        assert_eq!(
            r.inner.calls, calls_before,
            "inner reader must not be touched again"
        );
    }

    #[test]
    fn empty_buf_returns_ok_zero_and_stays_pending() {
        let inner = SliceReader::new(b"data");
        let mut r = VerifiedReader::new(inner, LenDigest::default(), expected_of(4));
        assert_eq!(r.read(&mut []), Ok(0));
        assert_eq!(r.verification(), Verification::Pending);
    }

    #[test]
    fn would_block_propagates_and_stays_pending() {
        let inner = WouldBlockOnce { blocked: false };
        let mut r = VerifiedReader::new(inner, LenDigest::default(), expected_of(0));
        let mut buf = [0u8; 8];
        assert_eq!(r.read(&mut buf), Err(IoError::WouldBlock));
        assert_eq!(r.verification(), Verification::Pending);
    }

    #[test]
    fn digest_failure_yields_other_and_failed() {
        let inner = SliceReader::new(b"x");
        let mut r = VerifiedReader::new(inner, FailingState, expected_of(0));
        let mut buf = [0u8; 8];
        assert_eq!(r.read(&mut buf), Err(IoError::Other));
        assert_eq!(r.verification(), Verification::Failed);
    }

    #[test]
    fn into_inner_returns_inner_reader() {
        let inner = SliceReader::new(b"abc");
        let r = VerifiedReader::new(inner, LenDigest::default(), expected_of(3));
        let back = r.into_inner();
        assert_eq!(back.data, &b"abc"[..]);
    }
}
