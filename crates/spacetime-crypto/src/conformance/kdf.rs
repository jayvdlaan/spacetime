//! Conformance checks for [`HkdfSha256`] and [`Argon2id`].

use super::vectors::{ARGON2ID, HKDF_SHA256};
use super::Case;
use crate::{
    Argon2Params, Argon2id, CryptoErrorKind, CryptoResult, HkdfSha256, ARGON2_MIN_OUTPUT_LEN,
    ARGON2_MIN_SALT_LEN, HKDF_SHA256_PRK_LEN,
};

/// Longest OKM among the RFC 5869 vectors (A.2).
const MAX_OKM: usize = 82;

/// Run the RFC 5869 A.1–A.3 vectors against `k`.
///
/// For every vector in [`HKDF_SHA256`]: `hkdf_sha256_extract` must
/// produce the PRK; `hkdf_sha256_expand` from the RFC's PRK must produce
/// the OKM; the provided `hkdf_sha256` must produce the OKM; `expand` into
/// an empty slice must succeed.
///
/// Under the `alloc` feature only, `expand` into a buffer of
/// `HKDF_SHA256_MAX_OKM_LEN + 1` (8161) bytes must fail with exactly
/// `InvalidParameter`; without `alloc` that sub-check is skipped, since the
/// harness has no 8 KiB stack buffer to spare on embedded targets.
pub fn check_hkdf_sha256<K: HkdfSha256 + ?Sized>(k: &K) -> CryptoResult<()> {
    for v in HKDF_SHA256 {
        let case = Case::new("check_hkdf_sha256", v.name);
        let n = v.okm.len();
        case.ensure(n <= MAX_OKM, "vector OKM does not fit the harness buffer")?;

        let mut prk = [0u8; HKDF_SHA256_PRK_LEN];
        case.ok(k.hkdf_sha256_extract(v.salt, v.ikm, &mut prk))?;
        case.eq("PRK", &prk, &v.prk)?;

        let mut okm = [0u8; MAX_OKM];
        case.ok(k.hkdf_sha256_expand(&v.prk, v.info, &mut okm[..n]))?;
        case.eq("OKM (expand)", &okm[..n], v.okm)?;

        let mut okm = [0u8; MAX_OKM];
        case.ok(k.hkdf_sha256(v.salt, v.ikm, v.info, &mut okm[..n]))?;
        case.eq("OKM (extract + expand)", &okm[..n], v.okm)?;

        let mut empty: [u8; 0] = [];
        case.ok(k.hkdf_sha256_expand(&v.prk, v.info, &mut empty))?;

        #[cfg(feature = "alloc")]
        {
            let mut too_long = alloc::vec![0u8; crate::HKDF_SHA256_MAX_OKM_LEN + 1];
            case.kind(
                "expand into 8161 bytes",
                k.hkdf_sha256_expand(&v.prk, v.info, &mut too_long),
                CryptoErrorKind::InvalidParameter,
            )?;
        }
    }
    Ok(())
}

/// Run the RFC 9106 §5.3 Argon2id vector against `k`, then the parameter
/// domain checks.
///
/// The vector (`m = 32` KiB, `t = 3`, `p = 4`, with secret key and
/// associated data) must produce the tag. Then, with otherwise valid
/// inputs, each of the following must fail with exactly `InvalidParameter`:
/// `Argon2Params::new(31, 3, 4)` (`m < 8p`), `(32, 0, 4)` (`t = 0`),
/// `(32, 3, 0)` (`p = 0`), `(32, 3, 1 << 24)` (`p > 2^24 - 1`), a 7-byte
/// salt, and a 3-byte output.
pub fn check_argon2id<K: Argon2id + ?Sized>(k: &K) -> CryptoResult<()> {
    const CHECK: &str = "check_argon2id";

    for v in ARGON2ID {
        let case = Case::new(CHECK, v.name);
        let mut out = [0u8; 32];
        case.ok(k.argon2id(&v.params, v.password, v.salt, v.secret, v.ad, &mut out))?;
        case.eq("tag", &out, &v.tag)?;
    }

    let good = Argon2Params::new(32, 3, 4);
    let salt = [0x02u8; 16];
    let mut out = [0u8; 32];

    let bad_params: [(&'static str, Argon2Params); 4] = [
        ("m_cost_kib below 8 * p_cost", Argon2Params::new(31, 3, 4)),
        ("t_cost = 0", Argon2Params::new(32, 0, 4)),
        ("p_cost = 0", Argon2Params::new(32, 3, 0)),
        ("p_cost = 2^24", Argon2Params::new(32, 3, 1 << 24)),
    ];
    for (name, params) in bad_params {
        let case = Case::new(CHECK, name);
        case.kind(
            "argon2id",
            k.argon2id(&params, b"password", &salt, &[], &[], &mut out),
            CryptoErrorKind::InvalidParameter,
        )?;
    }

    let case = Case::new(CHECK, "salt shorter than 8 bytes");
    let short_salt = [0x02u8; ARGON2_MIN_SALT_LEN - 1];
    case.kind(
        "argon2id",
        k.argon2id(&good, b"password", &short_salt, &[], &[], &mut out),
        CryptoErrorKind::InvalidParameter,
    )?;

    let case = Case::new(CHECK, "output shorter than 4 bytes");
    let mut short_out = [0u8; ARGON2_MIN_OUTPUT_LEN - 1];
    case.kind(
        "argon2id",
        k.argon2id(&good, b"password", &salt, &[], &[], &mut short_out),
        CryptoErrorKind::InvalidParameter,
    )?;

    Ok(())
}
