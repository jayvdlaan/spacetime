//! HMAC-SHA-256 facade (RFC 2104; test vectors in RFC 4231).

use crate::CryptoResult;

/// HMAC-SHA-256 tag length in bytes.
pub const HMAC_SHA256_LEN: usize = 32;

/// HMAC-SHA-256 (RFC 2104, instantiated with SHA-256; vectors RFC 4231).
///
/// One-shot only: no streaming, no truncated-tag variant. SSHSIG and keeper
/// index names need exactly this shape.
///
/// # Errors
/// [`crate::CryptoErrorKind::AuthenticationFailed`] from
/// [`HmacSha256::hmac_sha256_verify`] on a tag mismatch;
/// `Unavailable`/`Failed` from either method for backend-internal reasons.
/// No input to `hmac_sha256` can be invalid (`key`/`data` may be any length,
/// including empty).
///
/// # Object safety
/// Object-safe: `&self`, slice/array parameters, no generics.
///
/// # Conformance
/// See `check_hmac_sha256` (feature `conformance`).
pub trait HmacSha256 {
    /// Compute the full 32-byte tag over `data` under `key`.
    ///
    /// `key` may be any length: RFC 2104 §2 hashes keys longer than the
    /// block size (64 bytes) before use. `data` may be empty.
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> CryptoResult<[u8; HMAC_SHA256_LEN]>;

    /// Recompute the tag over `data` under `key` and compare it against
    /// `tag` in constant time. Mismatch is
    /// [`crate::CryptoErrorKind::AuthenticationFailed`].
    ///
    /// This has no default implementation: the constant-time comparison is a
    /// backend security property, not facade plumbing.
    fn hmac_sha256_verify(
        &self,
        key: &[u8],
        data: &[u8],
        tag: &[u8; HMAC_SHA256_LEN],
    ) -> CryptoResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CryptoError, CryptoErrorKind};

    /// A fake that "tags" by XOR-folding the key into the data length --
    /// exactly the shape of a real HMAC (deterministic function of key and
    /// data), just not a cryptographic one. Enough to prove the trait is
    /// implementable without an allocator and that a mismatch error is
    /// classified correctly.
    struct XorFold;

    impl XorFold {
        fn tag(key: &[u8], data: &[u8]) -> [u8; HMAC_SHA256_LEN] {
            let mut out = [0u8; HMAC_SHA256_LEN];
            for (i, b) in key.iter().chain(data.iter()).enumerate() {
                out[i % HMAC_SHA256_LEN] ^= *b;
            }
            out
        }
    }

    impl HmacSha256 for XorFold {
        fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> CryptoResult<[u8; HMAC_SHA256_LEN]> {
            Ok(Self::tag(key, data))
        }

        fn hmac_sha256_verify(
            &self,
            key: &[u8],
            data: &[u8],
            tag: &[u8; HMAC_SHA256_LEN],
        ) -> CryptoResult<()> {
            if &Self::tag(key, data) == tag {
                Ok(())
            } else {
                Err(CryptoError::new(CryptoErrorKind::AuthenticationFailed))
            }
        }
    }

    #[test]
    fn tag_is_deterministic() {
        let h = XorFold;
        let a = h.hmac_sha256(b"key", b"data").unwrap();
        let b = h.hmac_sha256(b"key", b"data").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn verify_accepts_correct_tag() {
        let h = XorFold;
        let tag = h.hmac_sha256(b"key", b"data").unwrap();
        assert!(h.hmac_sha256_verify(b"key", b"data", &tag).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_tag() {
        let h = XorFold;
        let mut tag = h.hmac_sha256(b"key", b"data").unwrap();
        tag[0] ^= 0xFF;
        let err = h.hmac_sha256_verify(b"key", b"data", &tag).unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::AuthenticationFailed);
    }

    #[test]
    fn empty_key_and_data_are_valid() {
        let h = XorFold;
        assert!(h.hmac_sha256(b"", b"").is_ok());
    }
}
