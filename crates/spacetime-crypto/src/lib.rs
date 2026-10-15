//! Spacetime crypto facades: no_std-first **trait facades** for RNG/entropy,
//! SHA-2, HMAC, Ed25519 (strict), ChaCha20-Poly1305/XChaCha20-Poly1305,
//! HKDF, Argon2id, and X25519, plus an RFC-vector conformance harness.
//!
//! This crate defines the seam, not the backend: it contains **no concrete
//! cryptographic implementation and no cryptographic randomness**. A
//! downstream crate implements these traits against a real backend (pure
//! Rust, an OS API, or a hardware engine); this crate only fixes the shapes
//! and the error contracts so a portable verifier or reader can program
//! against them.
//!
//! Goals:
//! - no_std by default; no allocations required in any core trait method —
//!   non-secret fixed-size outputs return by value, secret or
//!   variable-length outputs go into caller-provided buffers.
//! - Every method is fallible ([`CryptoResult`]), since the facade also
//!   fronts hardware engines that can be busy or absent.
//! - One backend type can implement every trait below; traits use `&self`
//!   (streaming digest state uses `&mut self`) so `&dyn Trait` is shareable.
//!
//! Traits (RFC references in each module):
//! - [`Rng`], [`EntropySource`] — random bytes / entropy (pre-existing).
//! - [`Sha256`]/[`Sha256State`], [`Sha512`]/[`Sha512State`] — digest
//!   (`crate::digest`, FIPS 180-4).
//! - [`HmacSha256`] — MAC (`crate::hmac`, RFC 2104/4231).
//! - [`Ed25519Verify`], [`Ed25519Sign`] — signatures (`crate::ed25519`, RFC
//!   8032). `Ed25519Verify::ed25519_verify` implements the **strict**
//!   verification profile: canonical `S`, canonical and non-small-order `R`
//!   and `A`, the cofactorless equation. See `crate::ed25519` for the full
//!   normative statement. This is *not* the ZIP-215 profile.
//! - [`Ed25519ToX25519`] — Edwards→Montgomery public-key conversion for
//!   X25519 use of an Ed25519 key (`crate::ed25519`; domain = keys passing
//!   `ed25519_validate_public_key`).
//! - [`aead::ChaCha20Poly1305`], [`aead::XChaCha20Poly1305`] — AEAD
//!   (`crate::aead`, RFC 8439 / draft-irtf-cfrg-xchacha).
//! - [`kdf::HkdfSha256`], [`kdf::Argon2id`] — key derivation (`crate::kdf`,
//!   RFC 5869 / RFC 9106).
//! - [`x25519::X25519`] — Diffie-Hellman (`crate::x25519`, RFC 7748); an
//!   all-zero shared secret (low-order peer) is rejected.
//!
//! # Object safety
//!
//! | Trait | `dyn`-usable | Note |
//! |---|---|---|
//! | [`Sha256`], [`Sha512`] | yes, as `&dyn Sha256<State = S>` | associated type must be named |
//! | [`Sha256State`], [`Sha512State`] | yes | |
//! | [`HmacSha256`], [`Ed25519Verify`], [`Ed25519Sign`] | yes | `&self`, no generics |
//! | [`Ed25519ToX25519`] | yes | `&self`, no generics |
//! | [`aead::ChaCha20Poly1305`], [`aead::XChaCha20Poly1305`] | yes | provided methods dyn-callable |
//! | [`kdf::HkdfSha256`], [`kdf::Argon2id`] | yes | |
//! | [`x25519::X25519`] | yes | |
//! | [`Rng`], [`EntropySource`] | yes | unchanged |
//!
//! # Backend obligations
//!
//! Implementors must: run in constant time wherever timing could leak secret
//! data (key material, tag/MAC comparisons, the X25519 low-order check);
//! wipe expanded secret state before returning (signing's expanded key,
//! Argon2's memory blocks); fail closed (an AEAD open or a signature
//! verification that cannot be authenticated must not expose plaintext or
//! succeed).
//!
//! # Non-goals
//!
//! No handle-based/HSM signer trait (the [`Ed25519Sign`] seed API is for an
//! in-binary root key); no batch verification; no pre-decoded key handle; no
//! truncated or streaming HMAC; no streaming AEAD; no PEM/DER/SPKI/PKCS#8
//! (those are adapter-layer concerns in a crate that also implements a
//! richer consumer-facing trait such as `CipherSuite`); no RNG use inside
//! any facade method ([`Ed25519Sign`] is deterministic; AEAD nonces are
//! caller-supplied).
//!
//! # Error model
//!
//! [`CryptoErrorKind`] classifies failures into coarse buckets.
//! [`CryptoError`] wraps a kind and, when the `alloc` feature is enabled,
//! carries an optional human-readable detail message.
//!
//! Without `alloc`, [`CryptoError`] is `Copy`, `Eq`, and just as lightweight
//! as the original enum. With `alloc`, it gains a heap-allocated message
//! while still implementing `Clone`, `PartialEq`, and `Debug`.
//!
//! No new [`CryptoErrorKind`] variants were added for the traits in this
//! crate: every situation below maps onto the five existing variants.
//! Candidates such as `InvalidKey`, `InvalidSignature`, or `LowOrderPoint`
//! were deliberately rejected — they would invite a caller (above all a
//! registry verifier) to branch on *why* a verification failed, which
//! fail-closed design forbids, and they add nothing actionable that the
//! `alloc` detail message does not already carry.
//!
//! | Situation | Kind |
//! |---|---|
//! | Wrong buffer/output length; a parameter outside the RFC domain (Argon2 `m < 8p`, `t = 0`, `p = 0`, `p > 2^24-1`, salt too short, tag too short; HKDF OKM too long); Ed25519 public key fails import validation; X25519 low-order peer | [`CryptoErrorKind::InvalidParameter`] |
//! | `ed25519_public_to_x25519` on a key that fails import validation | [`CryptoErrorKind::InvalidParameter`] |
//! | `ed25519_verify` rejection for any input-caused reason; AEAD tag mismatch; HMAC verify mismatch | [`CryptoErrorKind::AuthenticationFailed`] (uniform — no reason oracle) |
//! | Algorithm/variant absent in this environment; backend implementation limit or policy ceiling | [`CryptoErrorKind::Unsupported`] |
//! | Transient (hardware engine busy, allocation failed) | [`CryptoErrorKind::Unavailable`] |
//! | Backend-internal error not attributable to inputs | [`CryptoErrorKind::Failed`] |
//! | Conformance harness: any check failed | [`CryptoErrorKind::InvalidParameter`] (+ message under `alloc`) |

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod util;

pub mod aead;
pub mod digest;
pub mod ed25519;
pub mod hmac;
pub mod kdf;
pub mod x25519;

#[cfg(feature = "conformance")]
pub mod conformance;

pub use aead::{
    ChaCha20Poly1305, XChaCha20Poly1305, AEAD_KEY_LEN, AEAD_TAG_LEN, CHACHA20POLY1305_NONCE_LEN,
    XCHACHA20POLY1305_NONCE_LEN,
};
pub use digest::{Sha256, Sha256State, Sha512, Sha512State, SHA256_LEN, SHA512_LEN};
pub use ed25519::{
    Ed25519Sign, Ed25519ToX25519, Ed25519Verify, ED25519_PUBLIC_KEY_LEN, ED25519_SEED_LEN,
    ED25519_SIGNATURE_LEN,
};
pub use hmac::{HmacSha256, HMAC_SHA256_LEN};
pub use kdf::{
    Argon2Params, Argon2id, HkdfSha256, ARGON2_MAX_P_COST, ARGON2_MIN_OUTPUT_LEN,
    ARGON2_MIN_SALT_LEN, ARGON2_VERSION, HKDF_SHA256_MAX_OKM_LEN, HKDF_SHA256_PRK_LEN,
};
pub use x25519::{X25519, X25519_KEY_LEN};

/// Classification of cryptographic errors.
///
/// Intentionally `#[non_exhaustive]` so future releases can add variants
/// without breaking downstream match arms.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum CryptoErrorKind {
    /// Operation is not supported by this implementation.
    Unsupported,
    /// Transient failure (e.g., entropy unavailable).
    Unavailable,
    /// Invalid parameter supplied (e.g., wrong key length).
    InvalidParameter,
    /// Authentication or verification failed.
    AuthenticationFailed,
    /// Unspecified failure.
    Failed,
}

impl core::fmt::Display for CryptoErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[allow(unreachable_patterns)] // wildcard needed for #[non_exhaustive]
        match self {
            CryptoErrorKind::Unsupported => f.write_str("unsupported operation"),
            CryptoErrorKind::Unavailable => f.write_str("resource unavailable"),
            CryptoErrorKind::InvalidParameter => f.write_str("invalid parameter"),
            CryptoErrorKind::AuthenticationFailed => f.write_str("authentication failed"),
            CryptoErrorKind::Failed => f.write_str("crypto operation failed"),
            _ => f.write_str("unknown crypto error"),
        }
    }
}

// ---------------------------------------------------------------------------
// CryptoError — without alloc (Copy, zero-cost wrapper around the kind)
// ---------------------------------------------------------------------------
#[cfg(not(feature = "alloc"))]
mod error_impl {
    use super::CryptoErrorKind;

    /// Error type for cryptographic operations.
    ///
    /// Without the `alloc` feature this is a thin `Copy` wrapper around
    /// [`CryptoErrorKind`].
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub struct CryptoError {
        kind: CryptoErrorKind,
    }

    impl CryptoError {
        /// Create a new error from a [`CryptoErrorKind`].
        #[inline]
        pub const fn new(kind: CryptoErrorKind) -> Self {
            Self { kind }
        }

        /// Return the error kind.
        #[inline]
        pub const fn kind(&self) -> CryptoErrorKind {
            self.kind
        }
    }

    impl core::fmt::Display for CryptoError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Display::fmt(&self.kind, f)
        }
    }

    impl From<CryptoErrorKind> for CryptoError {
        #[inline]
        fn from(kind: CryptoErrorKind) -> Self {
            Self::new(kind)
        }
    }
}

// ---------------------------------------------------------------------------
// CryptoError — with alloc (carries an optional detail message)
// ---------------------------------------------------------------------------
#[cfg(feature = "alloc")]
mod error_impl {
    use super::CryptoErrorKind;
    use alloc::boxed::Box;

    /// Error type for cryptographic operations.
    ///
    /// With the `alloc` feature enabled, an optional human-readable detail
    /// message can be attached via [`CryptoError::with_message`].
    #[derive(Clone, Debug)]
    pub struct CryptoError {
        kind: CryptoErrorKind,
        message: Option<Box<str>>,
    }

    impl CryptoError {
        /// Create a new error from a [`CryptoErrorKind`] (no detail message).
        #[inline]
        pub const fn new(kind: CryptoErrorKind) -> Self {
            Self {
                kind,
                message: None,
            }
        }

        /// Create a new error with a detail message.
        #[inline]
        pub fn with_message(kind: CryptoErrorKind, msg: &str) -> Self {
            Self {
                kind,
                message: Some(msg.into()),
            }
        }

        /// Return the error kind.
        #[inline]
        pub const fn kind(&self) -> CryptoErrorKind {
            self.kind
        }

        /// Return the optional detail message, if any.
        #[inline]
        pub fn message(&self) -> Option<&str> {
            self.message.as_deref()
        }
    }

    impl PartialEq for CryptoError {
        /// Two errors are equal when their *kinds* match; the message is
        /// considered supplementary and is not compared.
        fn eq(&self, other: &Self) -> bool {
            self.kind == other.kind
        }
    }

    impl Eq for CryptoError {}

    impl core::fmt::Display for CryptoError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Display::fmt(&self.kind, f)?;
            if let Some(msg) = &self.message {
                write!(f, ": {}", msg)?;
            }
            Ok(())
        }
    }

    impl From<CryptoErrorKind> for CryptoError {
        #[inline]
        fn from(kind: CryptoErrorKind) -> Self {
            Self::new(kind)
        }
    }
}

pub use error_impl::CryptoError;

pub type CryptoResult<T> = core::result::Result<T, CryptoError>;

/// Minimal random byte generator interface.
pub trait Rng {
    /// Fill the provided buffer with random bytes.
    fn fill_bytes(&mut self, out: &mut [u8]) -> CryptoResult<()>;
}

/// Entropy source trait that can provide limited high-quality entropy.
pub trait EntropySource {
    /// Try to read entropy into `out`. Returns the number of bytes written.
    fn try_read(&mut self, out: &mut [u8]) -> CryptoResult<usize>;
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::format;

    struct CounterRng(u8);
    impl Rng for CounterRng {
        fn fill_bytes(&mut self, out: &mut [u8]) -> CryptoResult<()> {
            for b in out.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn counter_rng_fills() {
        let mut r = CounterRng(5);
        let mut buf = [0u8; 4];
        r.fill_bytes(&mut buf).unwrap();
        assert_eq!(&buf, &[5, 6, 7, 8]);
    }

    #[test]
    fn error_from_kind() {
        let err = CryptoError::from(CryptoErrorKind::Unsupported);
        assert_eq!(err.kind(), CryptoErrorKind::Unsupported);
    }

    #[test]
    fn error_new() {
        let err = CryptoError::new(CryptoErrorKind::Failed);
        assert_eq!(err.kind(), CryptoErrorKind::Failed);
    }

    #[test]
    fn error_equality_by_kind() {
        let a = CryptoError::new(CryptoErrorKind::Unavailable);
        let b = CryptoError::new(CryptoErrorKind::Unavailable);
        let c = CryptoError::new(CryptoErrorKind::Failed);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn error_with_message() {
        let err =
            CryptoError::with_message(CryptoErrorKind::InvalidParameter, "key must be 32 bytes");
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
        assert_eq!(err.message(), Some("key must be 32 bytes"));
    }

    #[test]
    fn error_display_without_message() {
        let err = CryptoError::new(CryptoErrorKind::Unsupported);
        assert_eq!(format!("{}", err), "unsupported operation");
    }

    #[test]
    fn error_display_with_message() {
        let err = CryptoError::with_message(CryptoErrorKind::Failed, "HMAC mismatch");
        assert_eq!(format!("{}", err), "crypto operation failed: HMAC mismatch");
    }

    #[test]
    fn error_equality_ignores_message() {
        let a = CryptoError::with_message(CryptoErrorKind::Failed, "reason A");
        let b = CryptoError::with_message(CryptoErrorKind::Failed, "reason B");
        assert_eq!(a, b);
    }

    #[test]
    fn error_clone() {
        let err = CryptoError::with_message(CryptoErrorKind::AuthenticationFailed, "tag mismatch");
        let cloned = err.clone();
        assert_eq!(err, cloned);
        assert_eq!(cloned.message(), Some("tag mismatch"));
    }

    #[test]
    fn kind_display() {
        assert_eq!(
            format!("{}", CryptoErrorKind::AuthenticationFailed),
            "authentication failed",
        );
        assert_eq!(
            format!("{}", CryptoErrorKind::InvalidParameter),
            "invalid parameter",
        );
    }

    #[test]
    fn kind_display_all_variants() {
        assert_eq!(
            format!("{}", CryptoErrorKind::Unsupported),
            "unsupported operation"
        );
        assert_eq!(
            format!("{}", CryptoErrorKind::Unavailable),
            "resource unavailable"
        );
        assert_eq!(
            format!("{}", CryptoErrorKind::Failed),
            "crypto operation failed"
        );
    }

    #[test]
    fn entropy_source_trait() {
        struct FixedEntropy;
        impl EntropySource for FixedEntropy {
            fn try_read(&mut self, out: &mut [u8]) -> CryptoResult<usize> {
                for b in out.iter_mut() {
                    *b = 0xAA;
                }
                Ok(out.len())
            }
        }
        let mut e = FixedEntropy;
        let mut buf = [0u8; 8];
        let n = e.try_read(&mut buf).unwrap();
        assert_eq!(n, 8);
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn rng_empty_buffer() {
        let mut r = CounterRng(0);
        let mut buf = [0u8; 0];
        r.fill_bytes(&mut buf).unwrap();
    }

    #[test]
    fn crypto_result_type_alias() {
        let ok: CryptoResult<usize> = Ok(42);
        assert!(ok.is_ok());
        let err: CryptoResult<()> = Err(CryptoError::new(CryptoErrorKind::Failed));
        assert!(err.is_err());
    }
}
