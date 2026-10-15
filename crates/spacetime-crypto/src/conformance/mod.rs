//! RFC-vector conformance harness (feature `conformance`).
//!
//! Generic `check_*` functions that run the RFC test vectors in
//! [`vectors`] against **any** implementation of the facade traits, so a
//! downstream backend crate can prove its implementation from its own tests:
//!
//! ```ignore
//! // in the backend crate's tests, with spacetime-crypto's `conformance`
//! // feature enabled
//! #[test]
//! fn conforms() {
//!     spacetime_crypto::conformance::check_all(&MyBackend).unwrap();
//! }
//! ```
//!
//! # Semantics
//!
//! - Every `check_*` returns `Ok(())` or an error whose kind is **always**
//!   [`CryptoErrorKind::InvalidParameter`] — never the backend's own kind.
//!   Under the `alloc` feature the error carries a message of the form
//!   `conformance {check}: {vector}: {detail}` naming the first vector that
//!   failed and why; without `alloc` it is a bare `InvalidParameter`.
//! - The first failure wins: a check stops at the first vector that does not
//!   match.
//! - Negative cases demand the **exact** error kind the trait contract names
//!   (`AuthenticationFailed` for verify/open/HMAC-verify;
//!   `InvalidParameter` for key validation, the Ed25519→X25519 conversion
//!   of an invalid key, the X25519 low-order check, and HKDF/Argon2 domain
//!   errors). A wrong kind is a conformance failure.
//! - `Unsupported` anywhere is a failure: only run a check for an algorithm
//!   the backend claims.
//!
//! # No allocator required
//!
//! The harness uses fixed stack buffers and `&'static` data, so an embedded
//! backend can run it on target with the default (no_std, no alloc) feature
//! set. No single buffer exceeds 130 bytes, but the AEAD and digest runners
//! keep several of them live at once (the AEAD runner holds the plaintext,
//! ciphertext, two sealed copies and two output buffers for one vector), so
//! the *frame* is larger than any one buffer. Measured on x86_64 with
//! rustc 1.98 against a lookup-table backend (the backend's own frames come
//! on top): the digest and AEAD runners need about 5.4 KiB and 5.1 KiB of
//! stack in a debug build, the other checks under 2 KiB; in a release build
//! the two big runners drop to about 1.2 KiB and the rest under 0.5 KiB.
//! Run the harness on target as a release build, and size the stack for the
//! frame, not the buffer.
//! One sub-check — HKDF expand into an over-long buffer — needs a heap
//! allocation and only runs under `alloc`; it is documented on
//! `check_hkdf_sha256`.
//!
//! # What this crate proves about the harness
//!
//! This crate contains no cryptography, so its own tests exercise the
//! harness only with lookup-table doubles (`tests/conformance_doubles.rs`):
//! they prove the checks compile against any implementor, pass a backend
//! that returns the tabled answers, and reject one that returns a wrong
//! answer, a wrong error kind, or leaks plaintext. The real cryptographic
//! run of these vectors happens in a backend crate.

use crate::{CryptoError, CryptoErrorKind, CryptoResult};

pub mod vectors;

mod aead;
mod digest;
mod ed25519;
mod hmac;
mod kdf;
mod x25519;

pub use aead::{check_chacha20poly1305, check_xchacha20poly1305};
pub use digest::{check_sha256, check_sha512};
pub use ed25519::{
    check_ed25519_roundtrip, check_ed25519_sign, check_ed25519_to_x25519, check_ed25519_verify,
};
pub use hmac::check_hmac_sha256;
pub use kdf::{check_argon2id, check_hkdf_sha256};
pub use x25519::check_x25519;

/// Run every check against a backend that implements every facade trait.
///
/// Stops at the first failing check; the returned error names it (under
/// `alloc`).
pub fn check_all<B>(b: &B) -> CryptoResult<()>
where
    B: crate::Sha256
        + crate::Sha512
        + crate::HmacSha256
        + crate::Ed25519Verify
        + crate::Ed25519Sign
        + crate::Ed25519ToX25519
        + crate::ChaCha20Poly1305
        + crate::XChaCha20Poly1305
        + crate::HkdfSha256
        + crate::Argon2id
        + crate::X25519
        + ?Sized,
{
    check_sha256(b)?;
    check_sha512(b)?;
    check_hmac_sha256(b)?;
    check_ed25519_verify(b)?;
    check_ed25519_sign(b)?;
    check_ed25519_roundtrip(b)?;
    check_ed25519_to_x25519(b)?;
    check_chacha20poly1305(b)?;
    check_xchacha20poly1305(b)?;
    check_hkdf_sha256(b)?;
    check_argon2id(b)?;
    check_x25519(b)
}

/// Build the harness error for a failed expectation.
///
/// Under `alloc`: `InvalidParameter` with the message
/// `conformance {check}: {vector}: {detail}`. Without `alloc`: a bare
/// `InvalidParameter`.
pub(crate) fn fail(check: &'static str, vector: &'static str, detail: &str) -> CryptoError {
    #[cfg(feature = "alloc")]
    {
        let msg = alloc::format!("conformance {check}: {vector}: {detail}");
        CryptoError::with_message(CryptoErrorKind::InvalidParameter, &msg)
    }
    #[cfg(not(feature = "alloc"))]
    {
        let _ = (check, vector, detail);
        CryptoError::new(CryptoErrorKind::InvalidParameter)
    }
}

/// Build the harness error for a backend error observed where success was
/// required: detail is `backend returned: {kind}` (plus the backend's own
/// message, if it attached one).
pub(crate) fn backend_err(
    check: &'static str,
    vector: &'static str,
    err: CryptoError,
) -> CryptoError {
    #[cfg(feature = "alloc")]
    {
        let detail = match err.message() {
            Some(m) => alloc::format!("backend returned: {} ({m})", err.kind()),
            None => alloc::format!("backend returned: {}", err.kind()),
        };
        fail(check, vector, &detail)
    }
    #[cfg(not(feature = "alloc"))]
    {
        let _ = err;
        fail(check, vector, "backend error")
    }
}

/// The `(check, vector)` pair a sub-check is running under; every helper
/// routes its failure through [`fail`] / [`backend_err`] with these names.
#[derive(Copy, Clone)]
pub(crate) struct Case {
    check: &'static str,
    vector: &'static str,
}

impl Case {
    pub(crate) const fn new(check: &'static str, vector: &'static str) -> Self {
        Self { check, vector }
    }

    /// Fail this case with a fixed detail.
    pub(crate) fn fail(&self, detail: &'static str) -> CryptoError {
        fail(self.check, self.vector, detail)
    }

    /// Fail unless `cond` holds.
    pub(crate) fn ensure(&self, cond: bool, detail: &'static str) -> CryptoResult<()> {
        if cond {
            Ok(())
        } else {
            Err(self.fail(detail))
        }
    }

    /// A backend call that must succeed; any error becomes a harness error.
    pub(crate) fn ok<T>(&self, r: CryptoResult<T>) -> CryptoResult<T> {
        r.map_err(|e| backend_err(self.check, self.vector, e))
    }

    /// `got` must equal `want` bytewise; `what` names the compared value.
    pub(crate) fn eq(&self, what: &'static str, got: &[u8], want: &[u8]) -> CryptoResult<()> {
        if got == want {
            return Ok(());
        }
        #[cfg(feature = "alloc")]
        {
            let mut detail = alloc::format!("{what} mismatch: got ");
            push_hex(&mut detail, got);
            detail.push_str(", want ");
            push_hex(&mut detail, want);
            Err(fail(self.check, self.vector, &detail))
        }
        #[cfg(not(feature = "alloc"))]
        {
            Err(self.fail(what))
        }
    }

    /// A backend call that must fail with **exactly** `want`; `Ok` or any
    /// other kind is a harness error. `step` names the call.
    pub(crate) fn kind<T>(
        &self,
        step: &'static str,
        r: CryptoResult<T>,
        want: CryptoErrorKind,
    ) -> CryptoResult<()> {
        match r {
            Err(e) if e.kind() == want => Ok(()),
            Err(e) => {
                #[cfg(feature = "alloc")]
                {
                    let detail = alloc::format!(
                        "{step}: expected `{want}`, backend returned `{}`",
                        e.kind()
                    );
                    Err(fail(self.check, self.vector, &detail))
                }
                #[cfg(not(feature = "alloc"))]
                {
                    let _ = e;
                    Err(self.fail(step))
                }
            }
            Ok(_) => {
                #[cfg(feature = "alloc")]
                {
                    let detail = alloc::format!("{step}: expected `{want}`, backend returned Ok");
                    Err(fail(self.check, self.vector, &detail))
                }
                #[cfg(not(feature = "alloc"))]
                {
                    Err(self.fail(step))
                }
            }
        }
    }
}

#[cfg(feature = "alloc")]
fn push_hex(s: &mut alloc::string::String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_is_always_invalid_parameter() {
        let e = fail("check_x", "vector y", "detail z");
        assert_eq!(e.kind(), CryptoErrorKind::InvalidParameter);
        #[cfg(feature = "alloc")]
        assert_eq!(e.message(), Some("conformance check_x: vector y: detail z"));
    }

    #[test]
    fn backend_err_never_leaks_the_backend_kind() {
        let e = backend_err(
            "check_x",
            "vector y",
            CryptoError::new(CryptoErrorKind::Unsupported),
        );
        assert_eq!(e.kind(), CryptoErrorKind::InvalidParameter);
        #[cfg(feature = "alloc")]
        assert_eq!(
            e.message(),
            Some("conformance check_x: vector y: backend returned: unsupported operation")
        );
    }

    #[test]
    fn case_kind_demands_the_exact_kind() {
        let c = Case::new("check_x", "vector y");
        assert!(c
            .kind(
                "verify",
                Err::<(), _>(CryptoError::new(CryptoErrorKind::AuthenticationFailed)),
                CryptoErrorKind::AuthenticationFailed,
            )
            .is_ok());
        let wrong = c
            .kind(
                "verify",
                Err::<(), _>(CryptoError::new(CryptoErrorKind::Failed)),
                CryptoErrorKind::AuthenticationFailed,
            )
            .unwrap_err();
        assert_eq!(wrong.kind(), CryptoErrorKind::InvalidParameter);
        let ok = c
            .kind("verify", Ok(()), CryptoErrorKind::AuthenticationFailed)
            .unwrap_err();
        assert_eq!(ok.kind(), CryptoErrorKind::InvalidParameter);
        #[cfg(feature = "alloc")]
        {
            assert!(wrong
                .message()
                .unwrap()
                .contains("backend returned `crypto operation failed`"));
            assert!(ok.message().unwrap().contains("backend returned Ok"));
        }
    }

    #[test]
    fn case_eq_reports_both_sides() {
        let c = Case::new("check_x", "vector y");
        assert!(c.eq("digest", &[1, 2], &[1, 2]).is_ok());
        let e = c.eq("digest", &[0xab], &[0xcd]).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::InvalidParameter);
        #[cfg(feature = "alloc")]
        assert_eq!(
            e.message(),
            Some("conformance check_x: vector y: digest mismatch: got ab, want cd")
        );
    }
}
