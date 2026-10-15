//! Ed25519 facades (RFC 8032): strict-profile verification, key import
//! validation, and deterministic signing from a seed.

use crate::CryptoResult;

/// Ed25519 seed length in bytes (RFC 8032 §5.1.5).
pub const ED25519_SEED_LEN: usize = 32;

/// Ed25519 public key length in bytes (compressed Edwards point).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature length in bytes (`R || S`).
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Ed25519 (RFC 8032, pure / no prehash / empty context) — **strict**
/// verification profile.
///
/// # Contract — the strict profile
///
/// Let `p = 2^255 - 19`, `L = 2^252 + 27742317777372353535851937790883648493`,
/// `R = signature[0..32]`, `S = signature[32..64]` (both little-endian),
/// `A = public_key`. [`Ed25519Verify::ed25519_verify`] returns `Ok(())` iff
/// **all** of the following hold:
///
/// - **V1 (canonical S):** `0 <= S < L`, compared as integers against `L`.
///   `S + L` (whose top three bits are still clear, so the legacy
///   `s[31] & 0xe0` check alone would pass it) is rejected. `S` is never
///   reduced mod `L` before this comparison.
/// - **V2 (canonical R):** `R` decodes per RFC 8032 §5.1.3 (`y < p` after
///   clearing bit 255 of the encoding, and if the decoded `x = 0` the sign
///   bit must be `0`), *and* re-encoding the decoded point yields exactly
///   the 32 input bytes.
/// - **V3 (canonical A):** the same decoding-and-re-encoding rule applied to
///   `A`.
/// - **V4 (no small order):** neither `R` nor `A` is one of the eight
///   torsion points (the points `P` with `[8]P = O`).
/// - **V5 (challenge over input bytes):** `k = SHA-512(R || A || message) mod L`,
///   computed over `R` and `A` exactly as received — never over a
///   re-encoding of the decoded points.
/// - **V6 (cofactorless equation):** `[S]B == R + [k]A` as points — **not**
///   the cofactored `[8][S]B == [8]R + [8][k]A`.
///
/// This is exactly ed25519-dalek 2.x's `verify_strict` (V1 via its scalar
/// canonicality check, V2+V6 via a bytewise comparison of
/// `compress([S]B - [k]A)` against `R`, V4 via `is_small_order()` on both `R`
/// and `A`) with V3 additionally stated. **ZIP-215 is NOT the profile here**:
/// ZIP-215 allows non-canonical encodings and small-order points and uses
/// the cofactored equation; none of that is accepted by this trait.
///
/// Two conformant implementations MUST agree on every `(A, message,
/// signature)` triple — the profile leaves no latitude.
///
/// ## Observability
///
/// Stated honestly so nobody over-claims what V2/V3 buy: the non-canonical
/// byte strings that a *lax* decoder (one that reduces `y` mod `p` and
/// ignores the `x = 0` sign rule) turns into valid curve points are the
/// encodings with `y in [p, 2^255)` whose reduced `y` lies on the curve —
/// twelve `y` values, 24 encodings counting both sign bits — plus the
/// `x = 0` encodings with the sign bit set (`y = 1`, `y = -1`). Of those,
/// only `y = p` (an order-4 point), `y = p + 1` (the identity) and the
/// `x = 0` cases reduce to torsion points, and V4 rejects them anyway; the
/// remaining ten `y` values reduce to points of unknown discrete log, for
/// which no valid signature exists, and none of them is torsion-free, so
/// the prime-order rule of [`Ed25519Verify::ed25519_validate_public_key`]
/// rejects them too. V2 and V3 therefore have **no observable effect** in
/// either `ed25519_verify` or `ed25519_validate_public_key`: they are
/// stated so that every backend returns the same answer on every byte
/// string (not just the ones that happen to matter today), and the
/// conformance harness **cannot detect** a backend that omits them. A
/// dalek-based backend gets V3 literally by adding
/// `verifying_key.to_bytes() == *public_key` (one `compress`), which is
/// the recommended implementation; a backend that decodes laxly and
/// compares *points* rather than *bytes* does not satisfy V2/V3 and must
/// add the bytewise comparison itself.
///
/// Implementation note for embedded backends: given V2 and V3 are enforced,
/// V4 can be implemented as a bytewise comparison of the (already-validated)
/// encoding against the eight canonical torsion encodings — no decompression
/// of `R` is required at all when the verification equation is checked as
/// `compress([S]B - [k]A) == R`.
///
/// ## Mixed-order keys
///
/// A public key that is the sum of a prime-order component and a torsion
/// component is canonical, non-identity, and not small-order, so it is
/// **accepted** by `ed25519_verify` — exactly as `verify_strict` accepts it
/// — and a signer holding such a key succeeds on only 1-in-8 messages
/// signed under it. That is precisely why
/// [`Ed25519Verify::ed25519_validate_public_key`] additionally requires the
/// key to be prime-order (prior to `[L]A = O`): it is the right place to
/// reject a mixed-order key, once, at import — not on every verification.
///
/// ## Error kind for a rejected signature
///
/// `ed25519_verify` returns
/// [`crate::CryptoErrorKind::AuthenticationFailed`] for **every**
/// input-caused rejection reason (undecodable or non-canonical `A` or `R`,
/// small-order `A` or `R`, `S >= L`, or the equation simply not holding) —
/// there is no reason oracle. A malformed key handed to `ed25519_verify`
/// itself is a failed verification, not an invalid parameter; that
/// distinction belongs to [`Ed25519Verify::ed25519_validate_public_key`],
/// which is the only method that returns
/// [`crate::CryptoErrorKind::InvalidParameter`].
///
/// # Object safety
/// Object-safe: `&self`, array/slice parameters, no generics.
///
/// # Conformance
/// See `check_ed25519_verify` (feature `conformance`), which checks the
/// RFC 8032 §7.1 positives, the documented negative vectors (small-order
/// key and `R`, non-canonical `S`, non-canonical `R`/`A`, equation
/// failure, and a small-order `R` under a mixed-order key — the only case
/// that isolates V4 on `R`), and `ed25519_validate_public_key` against the
/// canonical torsion encodings, non-canonical encodings and a mixed-order
/// key.
pub trait Ed25519Verify {
    /// Import-time key validation: `public_key` must decode per RFC 8032
    /// §5.1.3, re-encode to the same 32 bytes (canonical), be non-identity,
    /// and be prime-order (`[L]A = O`, i.e. torsion-free). Failure is
    /// [`crate::CryptoErrorKind::InvalidParameter`].
    ///
    /// Costs one scalar multiplication; intended to run once per key (e.g.
    /// when a registry roster is built), after which
    /// [`Ed25519Verify::ed25519_verify`] runs per signature without
    /// repeating this check.
    fn ed25519_validate_public_key(
        &self,
        public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    ) -> CryptoResult<()>;

    /// Strict verification (rules V1-V6 above) of `signature` over
    /// `message` under `public_key`. Any input-caused failure is
    /// [`crate::CryptoErrorKind::AuthenticationFailed`].
    fn ed25519_verify(
        &self,
        public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; ED25519_SIGNATURE_LEN],
    ) -> CryptoResult<()>;
}

/// Ed25519 signing from a 32-byte seed (RFC 8032 §5.1.5/§5.1.6).
/// Deterministic: no RNG is used anywhere in this trait.
///
/// # Contract
/// The public key is always re-derived from `seed` inside
/// [`Ed25519Sign::ed25519_sign`] — it is never accepted as a caller
/// parameter, because a caller-supplied public key that does not match the
/// seed's true public key would leak information about the secret scalar
/// through the signature. A backend must wipe the expanded key material
/// (`SHA-512(seed)`'s two halves, and the per-message nonce `r`) before
/// returning. Output always satisfies the strict profile in
/// [`Ed25519Verify`] by construction (canonical `R`, `S < L`).
///
/// # Errors
/// No input to either method can be invalid (a seed is any 32 bytes), so
/// only [`crate::CryptoErrorKind::Unavailable`] (transient) or
/// [`crate::CryptoErrorKind::Failed`] (backend-internal) are returned.
///
/// # Object safety
/// Object-safe: `&self`, array/slice parameters, no generics.
///
/// # Conformance
/// See `check_ed25519_sign` and `check_ed25519_roundtrip` (feature
/// `conformance`).
pub trait Ed25519Sign {
    /// Derive the public key `A = [a]B` from `seed`, where `(a, prefix) =
    /// SHA-512(seed)` clamped per RFC 8032 §5.1.5.
    fn ed25519_public_key(
        &self,
        seed: &[u8; ED25519_SEED_LEN],
    ) -> CryptoResult<[u8; ED25519_PUBLIC_KEY_LEN]>;

    /// Sign `message` under the key derived from `seed`, producing `R || S`
    /// per RFC 8032 §5.1.6.
    fn ed25519_sign(
        &self,
        seed: &[u8; ED25519_SEED_LEN],
        message: &[u8],
    ) -> CryptoResult<[u8; ED25519_SIGNATURE_LEN]>;
}

/// Edwards→Montgomery conversion of an Ed25519 public key, for protocols that
/// run X25519 against an Ed25519 key (age's `ssh-ed25519` recipient type).
///
/// # Contract
/// `A` is decoded per RFC 8032 §5.1.3 and must satisfy exactly the
/// [`Ed25519Verify::ed25519_validate_public_key`] predicate — canonical
/// encoding, non-identity, prime order — otherwise
/// [`crate::CryptoErrorKind::InvalidParameter`]. On success the result is the
/// little-endian `u = (1 + y) / (1 - y) mod p` of the decoded point, i.e. the
/// X25519 public key of the same secret scalar: for a key derived from a seed
/// with `a = clamp(SHA-512(seed)[0..32])`, `ed25519_public_to_x25519(A) ==
/// x25519_public_key(&a)`. Only `Unavailable`/`Failed` otherwise.
///
/// # Object safety
/// Object-safe: `&self`, array parameters, no generics.
///
/// # Conformance
/// See `check_ed25519_to_x25519` (feature `conformance`): RFC 8032 §7.1 keys
/// (TEST 1–3, SHA(abc)) against their Montgomery `u`, and every entry of
/// `ED25519_INVALID_PUBLIC_KEYS` rejected with `InvalidParameter`.
pub trait Ed25519ToX25519 {
    /// Convert `public_key` (compressed Edwards `A`) to the X25519 public key
    /// with the same discrete log.
    fn ed25519_public_to_x25519(
        &self,
        public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    ) -> CryptoResult<[u8; crate::x25519::X25519_KEY_LEN]>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CryptoError, CryptoErrorKind};

    /// A fake backend: "signatures" are `seed || first 32 bytes of the
    /// message, zero-padded`, and "public keys" are the seed itself. This is
    /// not cryptography -- it exists only to prove the traits are
    /// implementable without an allocator and that the documented error
    /// kinds are reachable.
    struct Fake {
        /// Public keys considered small-order/invalid for
        /// `ed25519_validate_public_key`.
        rejected_keys: [[u8; ED25519_PUBLIC_KEY_LEN]; 1],
    }

    impl Fake {
        fn new() -> Self {
            Self {
                rejected_keys: [[0u8; ED25519_PUBLIC_KEY_LEN]],
            }
        }
    }

    impl Ed25519Sign for Fake {
        fn ed25519_public_key(
            &self,
            seed: &[u8; ED25519_SEED_LEN],
        ) -> CryptoResult<[u8; ED25519_PUBLIC_KEY_LEN]> {
            Ok(*seed)
        }

        fn ed25519_sign(
            &self,
            seed: &[u8; ED25519_SEED_LEN],
            message: &[u8],
        ) -> CryptoResult<[u8; ED25519_SIGNATURE_LEN]> {
            let mut sig = [0u8; ED25519_SIGNATURE_LEN];
            sig[..32].copy_from_slice(seed);
            let n = message.len().min(32);
            sig[32..32 + n].copy_from_slice(&message[..n]);
            Ok(sig)
        }
    }

    impl Ed25519Verify for Fake {
        fn ed25519_validate_public_key(
            &self,
            public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
        ) -> CryptoResult<()> {
            if self.rejected_keys.contains(public_key) {
                Err(CryptoError::new(CryptoErrorKind::InvalidParameter))
            } else {
                Ok(())
            }
        }

        fn ed25519_verify(
            &self,
            public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
            message: &[u8],
            signature: &[u8; ED25519_SIGNATURE_LEN],
        ) -> CryptoResult<()> {
            let expected = self.ed25519_sign(public_key, message)?;
            if &expected == signature {
                Ok(())
            } else {
                Err(CryptoError::new(CryptoErrorKind::AuthenticationFailed))
            }
        }
    }

    impl Ed25519ToX25519 for Fake {
        fn ed25519_public_to_x25519(
            &self,
            public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
        ) -> CryptoResult<[u8; crate::x25519::X25519_KEY_LEN]> {
            if self.rejected_keys.contains(public_key) {
                Err(CryptoError::new(CryptoErrorKind::InvalidParameter))
            } else {
                Ok(*public_key)
            }
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let f = Fake::new();
        let seed = [7u8; ED25519_SEED_LEN];
        let pk = f.ed25519_public_key(&seed).unwrap();
        let sig = f.ed25519_sign(&seed, b"hello").unwrap();
        assert!(f.ed25519_verify(&pk, b"hello", &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let f = Fake::new();
        let seed = [7u8; ED25519_SEED_LEN];
        let pk = f.ed25519_public_key(&seed).unwrap();
        let sig = f.ed25519_sign(&seed, b"hello").unwrap();
        let err = f.ed25519_verify(&pk, b"goodbye", &sig).unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::AuthenticationFailed);
    }

    #[test]
    fn validate_public_key_rejects_known_bad_key() {
        let f = Fake::new();
        let err = f
            .ed25519_validate_public_key(&[0u8; ED25519_PUBLIC_KEY_LEN])
            .unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
    }

    #[test]
    fn validate_public_key_accepts_other_keys() {
        let f = Fake::new();
        assert!(f
            .ed25519_validate_public_key(&[9u8; ED25519_PUBLIC_KEY_LEN])
            .is_ok());
    }

    #[test]
    fn to_x25519_rejects_known_bad_key() {
        let f = Fake::new();
        let err = f
            .ed25519_public_to_x25519(&[0u8; ED25519_PUBLIC_KEY_LEN])
            .unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
    }

    #[test]
    fn to_x25519_maps_other_keys() {
        let f = Fake::new();
        assert_eq!(
            f.ed25519_public_to_x25519(&[9u8; ED25519_PUBLIC_KEY_LEN])
                .unwrap(),
            [9u8; ED25519_PUBLIC_KEY_LEN]
        );
    }
}
