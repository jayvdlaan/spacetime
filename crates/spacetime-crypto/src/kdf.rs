//! HKDF-SHA-256 (RFC 5869) and Argon2id (RFC 9106) facades.
//!
//! Two traits: HKDF is cheap and belongs on every reader; Argon2id needs at
//! least `8 * p_cost` KiB of memory and is opt-in per backend.

use crate::{CryptoError, CryptoErrorKind, CryptoResult};

/// HKDF-SHA-256 pseudorandom key (PRK) length in bytes.
pub const HKDF_SHA256_PRK_LEN: usize = 32;

/// Maximum HKDF-SHA-256 output-keying-material length in bytes (RFC 5869
/// §2.3: `255 * HashLen`).
pub const HKDF_SHA256_MAX_OKM_LEN: usize = 255 * 32;

/// HKDF instantiated with HMAC-SHA-256 (RFC 5869).
///
/// # Errors
/// [`crate::CryptoErrorKind::InvalidParameter`] from
/// [`HkdfSha256::hkdf_sha256_expand`] when `okm.len() >
/// HKDF_SHA256_MAX_OKM_LEN`; otherwise only
/// `Unavailable`/`Failed`.
///
/// # Object safety
/// Object-safe: `&self`, slice/array parameters, no generics.
///
/// # Conformance
/// See `check_hkdf_sha256` (feature `conformance`).
pub trait HkdfSha256 {
    /// `PRK = HMAC-SHA-256(salt, IKM)`.
    ///
    /// An empty `salt` is RFC 5869's "salt not provided" case (a `HashLen`
    /// all-zero key): this is bytewise identical to computing HMAC with an
    /// empty key, so a `None`-style and a `Some(&[])`-style backend agree.
    fn hkdf_sha256_extract(
        &self,
        salt: &[u8],
        ikm: &[u8],
        prk: &mut [u8; HKDF_SHA256_PRK_LEN],
    ) -> CryptoResult<()>;

    /// Fill `okm` with `T(1) || T(2) || ...` truncated to `okm.len()`.
    ///
    /// `okm.len() > HKDF_SHA256_MAX_OKM_LEN` is
    /// [`crate::CryptoErrorKind::InvalidParameter`]; `okm.len() == 0` is
    /// `Ok(())` and writes nothing.
    fn hkdf_sha256_expand(
        &self,
        prk: &[u8; HKDF_SHA256_PRK_LEN],
        info: &[u8],
        okm: &mut [u8],
    ) -> CryptoResult<()>;

    /// `extract` then `expand` in one call.
    ///
    /// Provided: pure plumbing. The PRK is a stack-local temporary and is
    /// wiped before returning, regardless of success or failure.
    fn hkdf_sha256(
        &self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> CryptoResult<()> {
        let mut prk = [0u8; HKDF_SHA256_PRK_LEN];
        let r = self
            .hkdf_sha256_extract(salt, ikm, &mut prk)
            .and_then(|()| self.hkdf_sha256_expand(&prk, info, okm));
        crate::util::wipe(&mut prk);
        r
    }
}

/// Argon2 version implemented by this facade (RFC 9106 §3.1: `0x13`, i.e.
/// v1.3). Fixed, not a parameter: `airframe_crypt`'s `Argon2Params.version`
/// field is documented as "other values map to v1.3", so nothing is lost by
/// fixing it here; a backend's adapter layer rejects any other requested
/// version before calling in.
pub const ARGON2_VERSION: u32 = 0x13;

/// Minimum Argon2 salt length in bytes (RFC 9106 §3.1; 16 bytes is
/// recommended but 8 is the RFC floor).
pub const ARGON2_MIN_SALT_LEN: usize = 8;

/// Minimum Argon2 output (tag) length in bytes (RFC 9106 §3.1: `T >= 4`).
pub const ARGON2_MIN_OUTPUT_LEN: usize = 4;

/// Maximum Argon2 parallelism (RFC 9106 §3.1: `p <= 2^24 - 1`).
pub const ARGON2_MAX_P_COST: u32 = (1 << 24) - 1;

/// Argon2id cost parameters (RFC 9106 §3.1).
///
/// Field names and units match `airframe_crypt`'s `Argon2Params`
/// (`m_cost_kib` in KiB, `t_cost`, `p_cost`) so a backend can map between the
/// two 1:1; `airframe_crypt`'s `variant` and `version` fields are fixed here
/// (Argon2id, [`ARGON2_VERSION`]) and are the adapter's business to check.
///
/// There is no `Default`: a sanctioned default cost is a policy decision,
/// not part of this facade.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Argon2Params {
    /// Memory size in KiB (`m`). RFC domain: `8 * p_cost <= m_cost_kib <=
    /// 2^32 - 1`.
    pub m_cost_kib: u32,
    /// Number of passes (`t`). RFC domain: `1 <= t_cost <= 2^32 - 1`.
    pub t_cost: u32,
    /// Degree of parallelism / lanes (`p`). RFC domain: `1 <= p_cost <=
    /// 2^24 - 1`. A single-threaded backend MUST still accept `p_cost > 1`
    /// (lanes may be processed sequentially; the output is unaffected).
    pub p_cost: u32,
}

impl Argon2Params {
    /// Construct a parameter set. Does not itself validate — call
    /// [`Argon2Params::validate`] before use.
    pub const fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost_kib,
            t_cost,
            p_cost,
        }
    }

    /// Check the RFC 9106 §3.1 domain **only**: `t_cost >= 1`, `1 <= p_cost
    /// <= 2^24 - 1`, `m_cost_kib >= 8 * p_cost`.
    ///
    /// Policy floors (e.g. `airframe_crypt`'s 8 MiB minimum) and ceilings
    /// (e.g. a caller's maximum-memory policy) are deliberately **not**
    /// checked here — they belong in the adapter or consumer that calls this
    /// facade, never inside the facade itself, or a conformant backend could
    /// never pass the RFC 9106 §5.3 vector (`m = 32` KiB, `p = 4`, which is
    /// exactly the RFC floor `8 * p`).
    pub fn validate(&self) -> CryptoResult<()> {
        if self.t_cost == 0 {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter));
        }
        if self.p_cost == 0 || self.p_cost > ARGON2_MAX_P_COST {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter));
        }
        let min_m = (self.p_cost as u64) * 8;
        if (self.m_cost_kib as u64) < min_m {
            return Err(CryptoError::new(CryptoErrorKind::InvalidParameter));
        }
        Ok(())
    }
}

/// Argon2id (RFC 9106, type 2, version [`ARGON2_VERSION`]) with secret key
/// `K` and associated data `X`.
///
/// # Errors
/// [`crate::CryptoErrorKind::InvalidParameter`] when `params.validate()`
/// fails, `salt.len() < ARGON2_MIN_SALT_LEN`, `out.len() <
/// ARGON2_MIN_OUTPUT_LEN`, or any input exceeds `2^32 - 1` bytes.
/// [`crate::CryptoErrorKind::Unsupported`] for a memory size above the
/// backend's own arena or policy ceiling, or an implementation cap (e.g. the
/// RustCrypto `argon2` crate limits associated data to 32 bytes).
/// [`crate::CryptoErrorKind::Unavailable`] if allocation fails.
///
/// # Object safety
/// Object-safe: `&self`, slice/array parameters, no generics.
///
/// # Conformance
/// See `check_argon2id` (feature `conformance`).
pub trait Argon2id {
    /// Derive `out.len()` bytes of key material from `password` and `salt`,
    /// with optional secret key `secret` and associated data `ad`.
    ///
    /// `password`, `secret`, and `ad` may be empty. The backend MUST wipe
    /// its working memory blocks after use.
    fn argon2id(
        &self,
        params: &Argon2Params,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        ad: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_rfc_9106_vector_costs() {
        // RFC 9106 §5.3: m = 32 KiB (== 8 * p), t = 3, p = 4 -- the RFC
        // floor itself, which the facade must not reject.
        let p = Argon2Params::new(32, 3, 4);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_t_cost() {
        let p = Argon2Params::new(32, 0, 4);
        let err = p.validate().unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
    }

    #[test]
    fn validate_rejects_zero_p_cost() {
        let p = Argon2Params::new(32, 3, 0);
        let err = p.validate().unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
    }

    #[test]
    fn validate_rejects_p_cost_above_max() {
        let p = Argon2Params::new(u32::MAX, 3, 1 << 24);
        let err = p.validate().unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
    }

    #[test]
    fn validate_rejects_memory_below_eight_times_p() {
        let p = Argon2Params::new(31, 3, 4);
        let err = p.validate().unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
    }

    /// A fake HKDF: extract copies (a folded version of) the salt/IKM into
    /// the PRK, expand fills OKM by repeating the PRK. Not cryptography;
    /// proves the trait is implementable without an allocator and that the
    /// provided combinator wires extract into expand and enforces the OKM
    /// length ceiling.
    struct FoldHkdf;

    impl HkdfSha256 for FoldHkdf {
        fn hkdf_sha256_extract(
            &self,
            salt: &[u8],
            ikm: &[u8],
            prk: &mut [u8; HKDF_SHA256_PRK_LEN],
        ) -> CryptoResult<()> {
            for (i, b) in salt.iter().chain(ikm.iter()).enumerate() {
                prk[i % HKDF_SHA256_PRK_LEN] ^= *b;
            }
            Ok(())
        }

        fn hkdf_sha256_expand(
            &self,
            prk: &[u8; HKDF_SHA256_PRK_LEN],
            _info: &[u8],
            okm: &mut [u8],
        ) -> CryptoResult<()> {
            if okm.len() > HKDF_SHA256_MAX_OKM_LEN {
                return Err(CryptoError::new(CryptoErrorKind::InvalidParameter));
            }
            for (i, b) in okm.iter_mut().enumerate() {
                *b = prk[i % HKDF_SHA256_PRK_LEN];
            }
            Ok(())
        }
    }

    #[test]
    fn hkdf_combinator_wires_extract_into_expand() {
        let h = FoldHkdf;
        let mut okm = [0u8; 16];
        h.hkdf_sha256("salt".as_bytes(), b"ikm", b"info", &mut okm)
            .unwrap();
        assert!(okm.iter().any(|&b| b != 0));
    }

    #[test]
    fn hkdf_combinator_propagates_expand_error() {
        struct AlwaysTooLong;
        impl HkdfSha256 for AlwaysTooLong {
            fn hkdf_sha256_extract(
                &self,
                _salt: &[u8],
                _ikm: &[u8],
                _prk: &mut [u8; HKDF_SHA256_PRK_LEN],
            ) -> CryptoResult<()> {
                Ok(())
            }
            fn hkdf_sha256_expand(
                &self,
                _prk: &[u8; HKDF_SHA256_PRK_LEN],
                _info: &[u8],
                _okm: &mut [u8],
            ) -> CryptoResult<()> {
                Err(CryptoError::new(CryptoErrorKind::InvalidParameter))
            }
        }

        let h = AlwaysTooLong;
        let mut okm = [0u8; 4];
        let err = h
            .hkdf_sha256(b"salt", b"ikm", b"info", &mut okm)
            .unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
    }

    #[test]
    fn hkdf_empty_okm_is_ok() {
        let h = FoldHkdf;
        let mut okm: [u8; 0] = [];
        assert!(h.hkdf_sha256(b"salt", b"ikm", b"info", &mut okm).is_ok());
    }
}
