//! Conformance checks for [`Ed25519Verify`], [`Ed25519Sign`] and
//! [`Ed25519ToX25519`].

use super::vectors::{ED25519, ED25519_INVALID_PUBLIC_KEYS, ED25519_REJECT, ED25519_TO_X25519};
use super::Case;
use crate::{CryptoErrorKind, CryptoResult, Ed25519Sign, Ed25519ToX25519, Ed25519Verify};

/// Run the strict-profile verification vectors against `v`.
///
/// - Every RFC 8032 §7.1 positive in [`ED25519`] must verify.
/// - Every entry of [`ED25519_REJECT`] must fail with exactly
///   `AuthenticationFailed` (NEG-1 … NEG-6: small-order `A` and `R`,
///   `S + L`, non-canonical `R` with either sign bit, non-canonical `A`,
///   an equation failure, and a small-order `R` under a mixed-order `A`).
/// - Derived cases must fail with exactly `AuthenticationFailed`: the TEST 2
///   signature over the TEST 3 message; the TEST 1 signature with `R[0]`
///   flipped; the TEST 1 signature with `S[0]` flipped.
/// - `ed25519_validate_public_key` must accept the four RFC keys and reject
///   every entry of [`ED25519_INVALID_PUBLIC_KEYS`] with exactly
///   `InvalidParameter`.
pub fn check_ed25519_verify<V: Ed25519Verify + ?Sized>(v: &V) -> CryptoResult<()> {
    const CHECK: &str = "check_ed25519_verify";

    for t in ED25519 {
        let case = Case::new(CHECK, t.name);
        case.ok(v.ed25519_verify(&t.public_key, t.message, &t.signature))?;
    }

    for r in ED25519_REJECT {
        let case = Case::new(CHECK, r.name);
        case.kind(
            "verify",
            v.ed25519_verify(&r.public_key, r.message, &r.signature),
            CryptoErrorKind::AuthenticationFailed,
        )?;
    }

    if let [t1, t2, t3, ..] = ED25519 {
        let case = Case::new(CHECK, "derived: TEST 2 signature over the TEST 3 message");
        case.kind(
            "verify",
            v.ed25519_verify(&t2.public_key, t3.message, &t2.signature),
            CryptoErrorKind::AuthenticationFailed,
        )?;

        let case = Case::new(CHECK, "derived: TEST 1 signature with R[0] flipped");
        let mut sig = t1.signature;
        sig[0] ^= 0x01;
        case.kind(
            "verify",
            v.ed25519_verify(&t1.public_key, t1.message, &sig),
            CryptoErrorKind::AuthenticationFailed,
        )?;

        let case = Case::new(CHECK, "derived: TEST 1 signature with S[0] flipped");
        let mut sig = t1.signature;
        sig[32] ^= 0x01;
        case.kind(
            "verify",
            v.ed25519_verify(&t1.public_key, t1.message, &sig),
            CryptoErrorKind::AuthenticationFailed,
        )?;
    }

    for t in ED25519 {
        let case = Case::new(CHECK, t.name);
        case.ok(v.ed25519_validate_public_key(&t.public_key))?;
    }

    for k in ED25519_INVALID_PUBLIC_KEYS {
        let case = Case::new(CHECK, k.name);
        case.kind(
            "validate_public_key",
            v.ed25519_validate_public_key(&k.key),
            CryptoErrorKind::InvalidParameter,
        )?;
    }

    Ok(())
}

/// Run the RFC 8032 §7.1 signing vectors against `s`: for each entry of
/// [`ED25519`], the derived public key and the signature must match exactly.
pub fn check_ed25519_sign<S: Ed25519Sign + ?Sized>(s: &S) -> CryptoResult<()> {
    for t in ED25519 {
        let case = Case::new("check_ed25519_sign", t.name);
        let pk = case.ok(s.ed25519_public_key(&t.seed))?;
        case.eq("public key", &pk, &t.public_key)?;
        let sig = case.ok(s.ed25519_sign(&t.seed, t.message))?;
        case.eq("signature", &sig, &t.signature)?;
    }
    Ok(())
}

/// Sign each RFC message with its seed and verify with the derived key
/// (must succeed); verify the same signature against the *next* vector's
/// message (must fail with exactly `AuthenticationFailed`).
pub fn check_ed25519_roundtrip<B: Ed25519Sign + Ed25519Verify + ?Sized>(b: &B) -> CryptoResult<()> {
    for (i, t) in ED25519.iter().enumerate() {
        let case = Case::new("check_ed25519_roundtrip", t.name);
        let pk = case.ok(b.ed25519_public_key(&t.seed))?;
        let sig = case.ok(b.ed25519_sign(&t.seed, t.message))?;
        case.ok(b.ed25519_verify(&pk, t.message, &sig))?;

        let other = &ED25519[(i + 1) % ED25519.len()];
        if other.message != t.message {
            case.kind(
                "verify against a different message",
                b.ed25519_verify(&pk, other.message, &sig),
                CryptoErrorKind::AuthenticationFailed,
            )?;
        }
    }
    Ok(())
}

/// RFC 8032 §7.1 keys must map to the tabled Montgomery `u`; every key in
/// [`ED25519_INVALID_PUBLIC_KEYS`] must be rejected with exactly
/// `InvalidParameter`.
pub fn check_ed25519_to_x25519<C: Ed25519ToX25519 + ?Sized>(c: &C) -> CryptoResult<()> {
    const CHECK: &str = "check_ed25519_to_x25519";
    for v in ED25519_TO_X25519 {
        let case = Case::new(CHECK, v.name);
        let u = case.ok(c.ed25519_public_to_x25519(&v.public_key))?;
        case.eq("X25519 public key", &u, &v.x25519_public)?;
    }
    for k in ED25519_INVALID_PUBLIC_KEYS {
        let case = Case::new(CHECK, k.name);
        case.kind(
            "convert an invalid key",
            c.ed25519_public_to_x25519(&k.key),
            CryptoErrorKind::InvalidParameter,
        )?;
    }
    Ok(())
}
