//! SHA-256 and SHA-512 digest facades (FIPS 180-4).
//!
//! Two independent trait families — `Sha256`/`Sha256State` and
//! `Sha512`/`Sha512State` — so a backend that only has one hash size simply
//! does not implement the other trait; there is no "unsupported hash"
//! variant to check at run time.

/// SHA-256 digest length in bytes.
pub const SHA256_LEN: usize = 32;

/// SHA-512 digest length in bytes.
pub const SHA512_LEN: usize = 64;

/// Streaming SHA-256 state, obtained from [`Sha256::sha256_init`].
///
/// # Object safety
/// Object-safe: `&self`/`&mut self` methods only, no generics, no `Self`
/// return type.
pub trait Sha256State {
    /// Absorb `data`. Any number of calls (including zero), in any chunking,
    /// must produce the same digest as a single call with the concatenation
    /// of all chunks.
    fn update(&mut self, data: &[u8]) -> CryptoResult<()>;

    /// Digest of everything absorbed since `sha256_init` (or the previous
    /// `finalize`), then reset the state so the object is reusable for the
    /// next message.
    fn finalize(&mut self) -> CryptoResult<[u8; SHA256_LEN]>;
}

/// SHA-256 (FIPS 180-4). Exactly SHA-256; no other 256-bit hash satisfies
/// this trait.
///
/// # Errors
/// No input to this trait can be invalid, so implementations only return
/// [`crate::CryptoErrorKind::Unavailable`] (transient) or
/// [`crate::CryptoErrorKind::Failed`] (backend-internal).
///
/// # Object safety
/// Object-safe as `&dyn Sha256<State = S>` for a concrete `S` — the
/// associated type must be named at the use site.
///
/// # Conformance
/// See `check_sha256` (feature `conformance`).
pub trait Sha256 {
    /// Streaming state type returned by [`Sha256::sha256_init`].
    type State: Sha256State;

    /// Create a fresh streaming state.
    fn sha256_init(&self) -> CryptoResult<Self::State>;

    /// One-shot digest of `data`.
    ///
    /// Provided: delegates to init/update/finalize. A backend MAY override
    /// this with a faster path but MUST return the same bytes as the
    /// streaming API.
    fn sha256(&self, data: &[u8]) -> CryptoResult<[u8; SHA256_LEN]> {
        let mut st = self.sha256_init()?;
        st.update(data)?;
        st.finalize()
    }
}

/// Streaming SHA-512 state, obtained from [`Sha512::sha512_init`].
///
/// # Object safety
/// Object-safe (see [`Sha256State`]).
pub trait Sha512State {
    /// Absorb `data`. See [`Sha256State::update`] for the chunking contract.
    fn update(&mut self, data: &[u8]) -> CryptoResult<()>;

    /// Digest of everything absorbed since init / the last finalize, then
    /// reset the state (the object is reusable).
    fn finalize(&mut self) -> CryptoResult<[u8; SHA512_LEN]>;
}

/// SHA-512 (FIPS 180-4). Exactly SHA-512.
///
/// A backend that implements Ed25519 ([`crate::Ed25519Sign`] /
/// [`crate::Ed25519Verify`]) has SHA-512 by construction, since RFC 8032
/// hashes internally with it; this trait exposes that primitive directly so
/// a reader can also verify a `sk-ssh-ed25519@openssh.com` / SSHSIG blob
/// whose predicate names `sha512`.
///
/// # Errors
/// Same as [`Sha256`]: only `Unavailable`/`Failed`.
///
/// # Object safety
/// Object-safe as `&dyn Sha512<State = S>`.
pub trait Sha512 {
    /// Streaming state type returned by [`Sha512::sha512_init`].
    type State: Sha512State;

    /// Create a fresh streaming state.
    fn sha512_init(&self) -> CryptoResult<Self::State>;

    /// One-shot digest of `data`. Provided; see [`Sha256::sha256`].
    fn sha512(&self, data: &[u8]) -> CryptoResult<[u8; SHA512_LEN]> {
        let mut st = self.sha512_init()?;
        st.update(data)?;
        st.finalize()
    }
}

use crate::CryptoResult;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CryptoError, CryptoErrorKind};

    /// A fake SHA-256 whose "digest" is just the length of the absorbed
    /// data, repeated to fill 32 bytes — enough to prove the provided
    /// one-shot method delegates to init/update/finalize rather than
    /// computing something else.
    #[derive(Default)]
    struct LenDigestState {
        len: u64,
    }

    impl Sha256State for LenDigestState {
        fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
            self.len += data.len() as u64;
            Ok(())
        }

        fn finalize(&mut self) -> CryptoResult<[u8; SHA256_LEN]> {
            let mut out = [0u8; SHA256_LEN];
            out[..8].copy_from_slice(&self.len.to_le_bytes());
            self.len = 0;
            Ok(out)
        }
    }

    struct LenDigest;

    impl Sha256 for LenDigest {
        type State = LenDigestState;

        fn sha256_init(&self) -> CryptoResult<Self::State> {
            Ok(LenDigestState::default())
        }
    }

    #[test]
    fn one_shot_delegates_to_streaming() {
        let d = LenDigest;
        let mut st = d.sha256_init().unwrap();
        st.update(b"hello").unwrap();
        st.update(b" world").unwrap();
        let streamed = st.finalize().unwrap();

        let one_shot = d.sha256(b"hello world").unwrap();
        assert_eq!(streamed, one_shot);
        assert_eq!(&one_shot[..8], &11u64.to_le_bytes());
    }

    #[test]
    fn state_resets_after_finalize() {
        let d = LenDigest;
        let mut st = d.sha256_init().unwrap();
        st.update(b"abc").unwrap();
        let _ = st.finalize().unwrap();
        st.update(b"de").unwrap();
        let second = st.finalize().unwrap();
        assert_eq!(&second[..8], &2u64.to_le_bytes());
    }

    struct FailingSha256;
    struct FailingState;

    impl Sha256State for FailingState {
        fn update(&mut self, _data: &[u8]) -> CryptoResult<()> {
            Ok(())
        }
        fn finalize(&mut self) -> CryptoResult<[u8; SHA256_LEN]> {
            Err(CryptoError::new(CryptoErrorKind::Unavailable))
        }
    }

    impl Sha256 for FailingSha256 {
        type State = FailingState;
        fn sha256_init(&self) -> CryptoResult<Self::State> {
            Ok(FailingState)
        }
    }

    #[test]
    fn one_shot_propagates_finalize_error() {
        let d = FailingSha256;
        let err = d.sha256(b"x").unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::Unavailable);
    }

    #[derive(Default)]
    struct LenDigestState512 {
        len: u64,
    }

    impl Sha512State for LenDigestState512 {
        fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
            self.len += data.len() as u64;
            Ok(())
        }
        fn finalize(&mut self) -> CryptoResult<[u8; SHA512_LEN]> {
            let mut out = [0u8; SHA512_LEN];
            out[..8].copy_from_slice(&self.len.to_le_bytes());
            self.len = 0;
            Ok(out)
        }
    }

    struct LenDigest512;

    impl Sha512 for LenDigest512 {
        type State = LenDigestState512;
        fn sha512_init(&self) -> CryptoResult<Self::State> {
            Ok(LenDigestState512::default())
        }
    }

    #[test]
    fn sha512_one_shot_delegates_to_streaming() {
        let d = LenDigest512;
        let one_shot = d.sha512(b"hello world").unwrap();
        assert_eq!(&one_shot[..8], &11u64.to_le_bytes());
    }
}
