//! ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha)
//! AEAD facades.
//!
//! Two traits, not one parameterized by nonce length: identifying an
//! algorithm by nonce length alone is obscure, and expressing `[u8; A::NONCE_LEN]`
//! would need unstable `generic_const_exprs`. A backend that only has the
//! 12-byte-nonce construction simply does not implement
//! [`XChaCha20Poly1305`].

use crate::{CryptoError, CryptoErrorKind, CryptoResult};

/// AEAD key length in bytes (both traits).
pub const AEAD_KEY_LEN: usize = 32;

/// AEAD authentication tag length in bytes (both traits).
pub const AEAD_TAG_LEN: usize = 16;

/// `ChaCha20Poly1305` nonce length in bytes (RFC 8439 §2.8: 96 bits).
pub const CHACHA20POLY1305_NONCE_LEN: usize = 12;

/// `XChaCha20Poly1305` nonce length in bytes (192 bits).
pub const XCHACHA20POLY1305_NONCE_LEN: usize = 24;

/// AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8): 32-byte key, 96-bit nonce,
/// 128-bit tag.
///
/// # Contract
/// An empty `buf` and an empty `aad` are valid inputs; "no AAD" and "empty
/// AAD" are the same computation (Poly1305 pads a zero-length AAD and
/// records its length as `0`), so a caller with an `Option<&[u8]>` AAD maps
/// `None` to `&[]`. Nonce uniqueness per key is entirely the caller's
/// responsibility — this facade has no RNG. A backend length limit (RFC
/// 8439 allows up to `2^38 - 64` bytes of plaintext, unreachable on a
/// 32-bit target) is reported as
/// [`crate::CryptoErrorKind::Unsupported`]. Tag comparison in
/// [`ChaCha20Poly1305::chacha20poly1305_open`] must be constant time.
///
/// # Errors
/// [`crate::CryptoErrorKind::AuthenticationFailed`] from `*_open*` on a tag
/// mismatch; [`crate::CryptoErrorKind::InvalidParameter`] from the `*_into`
/// helpers on a too-small output buffer or malformed `sealed` input;
/// `Unsupported`/`Unavailable`/`Failed` for backend limits/transient/internal
/// failures.
///
/// # Object safety
/// Object-safe: `&self`, array/slice parameters, no generics; the provided
/// methods are dyn-callable.
///
/// # Conformance
/// See `check_chacha20poly1305` (feature `conformance`).
pub trait ChaCha20Poly1305 {
    /// Encrypt `buf` in place (plaintext in, ciphertext out, same length)
    /// under `key`/`nonce`/`aad`; return the 16-byte tag.
    ///
    /// On `Err`, `buf` may be partially encrypted — the caller still owns
    /// the plaintext bytes it passed in and may retry or discard them.
    fn chacha20poly1305_seal(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; CHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; AEAD_TAG_LEN]>;

    /// Verify `tag` over `aad` and `buf` (as ciphertext) in constant time,
    /// then decrypt `buf` in place.
    ///
    /// On `Err` ([`crate::CryptoErrorKind::AuthenticationFailed`]), `buf`
    /// MUST NOT contain plaintext, not even partially: it must hold either
    /// exactly the ciphertext bytes the caller passed in, or all zeros.
    fn chacha20poly1305_open(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; CHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> CryptoResult<()>;

    /// Two-buffer seal producing the `ciphertext || tag` layout used by
    /// `airframe_crypt`. Requires `out.len() >= plaintext.len() + 16` (else
    /// [`crate::CryptoErrorKind::InvalidParameter`]); returns the number of
    /// bytes written to `out`.
    ///
    /// Provided: pure buffer plumbing around
    /// [`ChaCha20Poly1305::chacha20poly1305_seal`]; a backend does not need
    /// to override it.
    fn chacha20poly1305_seal_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; CHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        let n = plaintext.len();
        let total = n
            .checked_add(AEAD_TAG_LEN)
            .ok_or(CryptoError::new(CryptoErrorKind::InvalidParameter))?;
        if out.len() < total {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter));
        }
        let (body, rest) = out.split_at_mut(n);
        body.copy_from_slice(plaintext);
        match self.chacha20poly1305_seal(key, nonce, aad, body) {
            Ok(tag) => {
                rest[..AEAD_TAG_LEN].copy_from_slice(&tag);
                Ok(total)
            }
            Err(e) => {
                crate::util::wipe(body);
                Err(e)
            }
        }
    }

    /// Inverse of [`ChaCha20Poly1305::chacha20poly1305_seal_into`]:
    /// `sealed = ciphertext || tag`. Requires `sealed.len() >= 16` and
    /// `out.len() >= sealed.len() - 16` (else
    /// [`crate::CryptoErrorKind::InvalidParameter`]). On authentication
    /// failure, `out[..n]` is left all zeros and
    /// [`crate::CryptoErrorKind::AuthenticationFailed`] is returned; on
    /// success returns `n`, the plaintext length.
    ///
    /// Provided: pure buffer plumbing.
    fn chacha20poly1305_open_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; CHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        sealed: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        let n = sealed
            .len()
            .checked_sub(AEAD_TAG_LEN)
            .ok_or(CryptoError::new(CryptoErrorKind::InvalidParameter))?;
        if out.len() < n {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter));
        }
        let (ct, tag) = sealed.split_at(n);
        let tag: &[u8; AEAD_TAG_LEN] = tag
            .try_into()
            .map_err(|_| CryptoError::new(CryptoErrorKind::Failed))?; // cannot fail: tag.len() == AEAD_TAG_LEN
        let body = &mut out[..n];
        body.copy_from_slice(ct);
        match self.chacha20poly1305_open(key, nonce, aad, body, tag) {
            Ok(()) => Ok(n),
            Err(e) => {
                crate::util::wipe(body);
                Err(e)
            }
        }
    }
}

/// AEAD_XCHACHA20_POLY1305 (subkey = `HChaCha20(key, nonce[0..16])`, then
/// ChaCha20-Poly1305 with nonce `0x00000000 || nonce[16..24]`). 192-bit
/// nonce, safe to draw at random per message.
///
/// # Contract
/// Same as [`ChaCha20Poly1305`] (empty `buf`/`aad` valid, no RNG, constant-time
/// tag comparison, backend length limit maps to `Unsupported`).
///
/// # Errors
/// Same as [`ChaCha20Poly1305`].
///
/// # Object safety
/// Object-safe (see [`ChaCha20Poly1305`]).
///
/// # Conformance
/// See `check_xchacha20poly1305` (feature `conformance`).
pub trait XChaCha20Poly1305 {
    /// See [`ChaCha20Poly1305::chacha20poly1305_seal`].
    fn xchacha20poly1305_seal(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; AEAD_TAG_LEN]>;

    /// See [`ChaCha20Poly1305::chacha20poly1305_open`].
    fn xchacha20poly1305_open(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> CryptoResult<()>;

    /// See [`ChaCha20Poly1305::chacha20poly1305_seal_into`]. Provided:
    /// identical buffer plumbing.
    fn xchacha20poly1305_seal_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        let n = plaintext.len();
        let total = n
            .checked_add(AEAD_TAG_LEN)
            .ok_or(CryptoError::new(CryptoErrorKind::InvalidParameter))?;
        if out.len() < total {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter));
        }
        let (body, rest) = out.split_at_mut(n);
        body.copy_from_slice(plaintext);
        match self.xchacha20poly1305_seal(key, nonce, aad, body) {
            Ok(tag) => {
                rest[..AEAD_TAG_LEN].copy_from_slice(&tag);
                Ok(total)
            }
            Err(e) => {
                crate::util::wipe(body);
                Err(e)
            }
        }
    }

    /// See [`ChaCha20Poly1305::chacha20poly1305_open_into`]. Provided:
    /// identical buffer plumbing.
    fn xchacha20poly1305_open_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        sealed: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        let n = sealed
            .len()
            .checked_sub(AEAD_TAG_LEN)
            .ok_or(CryptoError::new(CryptoErrorKind::InvalidParameter))?;
        if out.len() < n {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter));
        }
        let (ct, tag) = sealed.split_at(n);
        let tag: &[u8; AEAD_TAG_LEN] = tag
            .try_into()
            .map_err(|_| CryptoError::new(CryptoErrorKind::Failed))?; // cannot fail
        let body = &mut out[..n];
        body.copy_from_slice(ct);
        match self.xchacha20poly1305_open(key, nonce, aad, body, tag) {
            Ok(()) => Ok(n),
            Err(e) => {
                crate::util::wipe(body);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pass-through fake: "encryption" XORs the buffer with a keystream
    /// derived from `key[0] ^ nonce[0]`, and the "tag" is a constant. This is
    /// not cryptography; it exists to exercise the provided `_seal_into` /
    /// `_open_into` plumbing (layout, lengths, short-buffer errors, wipe on
    /// failure) against a real state machine.
    struct XorAead {
        /// Tag that a successful seal returns and that open requires.
        good_tag: [u8; AEAD_TAG_LEN],
    }

    impl XorAead {
        fn new() -> Self {
            Self {
                good_tag: [0x5A; AEAD_TAG_LEN],
            }
        }

        fn keystream_byte(key: &[u8; AEAD_KEY_LEN], nonce: &[u8]) -> u8 {
            key[0] ^ nonce[0]
        }
    }

    impl ChaCha20Poly1305 for XorAead {
        fn chacha20poly1305_seal(
            &self,
            key: &[u8; AEAD_KEY_LEN],
            nonce: &[u8; CHACHA20POLY1305_NONCE_LEN],
            _aad: &[u8],
            buf: &mut [u8],
        ) -> CryptoResult<[u8; AEAD_TAG_LEN]> {
            let ks = Self::keystream_byte(key, nonce);
            for b in buf.iter_mut() {
                *b ^= ks;
            }
            Ok(self.good_tag)
        }

        fn chacha20poly1305_open(
            &self,
            key: &[u8; AEAD_KEY_LEN],
            nonce: &[u8; CHACHA20POLY1305_NONCE_LEN],
            _aad: &[u8],
            buf: &mut [u8],
            tag: &[u8; AEAD_TAG_LEN],
        ) -> CryptoResult<()> {
            if *tag != self.good_tag {
                return Err(CryptoError::new(CryptoErrorKind::AuthenticationFailed));
            }
            let ks = Self::keystream_byte(key, nonce);
            for b in buf.iter_mut() {
                *b ^= ks;
            }
            Ok(())
        }
    }

    const KEY: [u8; AEAD_KEY_LEN] = [1u8; AEAD_KEY_LEN];
    const NONCE: [u8; CHACHA20POLY1305_NONCE_LEN] = [2u8; CHACHA20POLY1305_NONCE_LEN];

    #[test]
    fn seal_into_layout_is_ciphertext_then_tag() {
        let a = XorAead::new();
        let plaintext = b"hello world!";
        let mut out = [0u8; 12 + AEAD_TAG_LEN];
        let n = a
            .chacha20poly1305_seal_into(&KEY, &NONCE, b"aad", plaintext, &mut out)
            .unwrap();
        assert_eq!(n, plaintext.len() + AEAD_TAG_LEN);
        assert_eq!(&out[12..], &a.good_tag);
        assert_ne!(&out[..12], plaintext); // actually encrypted
    }

    #[test]
    fn seal_into_short_buffer_is_invalid_parameter() {
        let a = XorAead::new();
        let plaintext = b"hello world!";
        let mut out = [0u8; 12 + AEAD_TAG_LEN - 1];
        let err = a
            .chacha20poly1305_seal_into(&KEY, &NONCE, b"aad", plaintext, &mut out)
            .unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
    }

    #[test]
    fn open_into_round_trips_through_seal_into() {
        let a = XorAead::new();
        let plaintext = b"round trip me";
        let mut sealed = [0u8; 13 + AEAD_TAG_LEN];
        a.chacha20poly1305_seal_into(&KEY, &NONCE, b"aad", plaintext, &mut sealed)
            .unwrap();

        let mut out = [0u8; 13];
        let n = a
            .chacha20poly1305_open_into(&KEY, &NONCE, b"aad", &sealed, &mut out)
            .unwrap();
        assert_eq!(n, plaintext.len());
        assert_eq!(&out, plaintext);
    }

    #[test]
    fn open_into_sealed_too_short_is_invalid_parameter() {
        let a = XorAead::new();
        let sealed = [0u8; AEAD_TAG_LEN - 1];
        let mut out = [0u8; 4];
        let err = a
            .chacha20poly1305_open_into(&KEY, &NONCE, b"aad", &sealed, &mut out)
            .unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
    }

    #[test]
    fn open_into_wipes_output_on_tamper() {
        let a = XorAead::new();
        let plaintext = b"secret data!";
        let mut sealed = [0u8; 12 + AEAD_TAG_LEN];
        a.chacha20poly1305_seal_into(&KEY, &NONCE, b"aad", plaintext, &mut sealed)
            .unwrap();
        // Flip a tag byte.
        sealed[12] ^= 0xFF;

        let mut out = [0xAAu8; 12];
        let err = a
            .chacha20poly1305_open_into(&KEY, &NONCE, b"aad", &sealed, &mut out)
            .unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::AuthenticationFailed);
        assert_eq!(out, [0u8; 12]);
    }

    #[test]
    fn empty_plaintext_and_aad_round_trip() {
        let a = XorAead::new();
        let mut sealed = [0u8; AEAD_TAG_LEN];
        let n = a
            .chacha20poly1305_seal_into(&KEY, &NONCE, &[], &[], &mut sealed)
            .unwrap();
        assert_eq!(n, AEAD_TAG_LEN);
        let mut out: [u8; 0] = [];
        let n = a
            .chacha20poly1305_open_into(&KEY, &NONCE, &[], &sealed, &mut out)
            .unwrap();
        assert_eq!(n, 0);
    }
}
