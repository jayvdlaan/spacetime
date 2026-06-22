//! Spacetime crypto facades: RNG/entropy traits and minimal error model.
//!
//! Goals:
//! - no_std by default; avoid allocations in core traits.
//! - Simple, portable contracts for random bytes and entropy sources.
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

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

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
