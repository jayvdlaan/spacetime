//! Conformance check for [`HmacSha256`].

use super::vectors::HMAC_SHA256;
use super::Case;
use crate::{CryptoErrorKind, CryptoResult, HmacSha256};

/// Run the RFC 4231 vectors against `h`.
///
/// For every vector in [`HMAC_SHA256`]: `hmac_sha256` must produce the
/// tag; `hmac_sha256_verify` must accept it; and must reject — with exactly
/// `AuthenticationFailed` — the tag with byte 0 flipped and the tag with
/// byte 31 flipped.
pub fn check_hmac_sha256<H: HmacSha256 + ?Sized>(h: &H) -> CryptoResult<()> {
    for v in HMAC_SHA256 {
        let case = Case::new("check_hmac_sha256", v.name);

        let got = case.ok(h.hmac_sha256(v.key, v.data))?;
        case.eq("tag", &got, &v.mac)?;

        case.ok(h.hmac_sha256_verify(v.key, v.data, &v.mac))?;

        let mut bad = v.mac;
        bad[0] ^= 0x01;
        case.kind(
            "verify with tag byte 0 flipped",
            h.hmac_sha256_verify(v.key, v.data, &bad),
            CryptoErrorKind::AuthenticationFailed,
        )?;

        let mut bad = v.mac;
        bad[31] ^= 0x80;
        case.kind(
            "verify with tag byte 31 flipped",
            h.hmac_sha256_verify(v.key, v.data, &bad),
            CryptoErrorKind::AuthenticationFailed,
        )?;
    }
    Ok(())
}
