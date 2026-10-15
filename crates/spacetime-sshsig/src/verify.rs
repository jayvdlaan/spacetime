//! The pinned verification predicate over a parsed
//! [`SshSig`].
//!
//! Every check is listed below in the order it runs; the first failure
//! wins. Nothing here allocates and nothing here reads `sig.namespace` after
//! step 4 — the signed data is rebuilt from the **caller's** namespace.
//!
//! | # | Check | Error |
//! |---|---|---|
//! | 1 | expected namespace non-empty and ≤ [`MAX_NAMESPACE_LEN`] | [`Error::EmptyNamespace`] / [`Error::NamespaceTooLong`] |
//! | 2 | `reserved` empty | [`Error::ReservedNotEmpty`] |
//! | 3 | `hash_algorithm == "sha512"` | [`Error::HashAlgorithmNotSha512`] |
//! | 4 | blob namespace == expected namespace | [`Error::NamespaceMismatch`] |
//! | 5 | embedded key == expected signer (when given) | [`Error::SignerMismatch`] |
//! | 6 | signed data = `"SSHSIG" ‖ string(expected ns) ‖ string("") ‖ string("sha512") ‖ string(SHA-512(message))` | — |
//! | 7a | sk: `flags & 0x01` (user presence) | [`Error::SkUserPresenceMissing`] |
//! | 7b | sk: `flags & 0x04` when the policy requires user verification | [`Error::SkUserVerificationMissing`] |
//! | 7c | strict Ed25519 (`Ed25519Verify::ed25519_verify`) | [`Error::SignatureInvalid`] |
//!
//! The sk Ed25519 message (PROTOCOL.u2f, no extensions) is
//! `SHA-256(application) ‖ flags ‖ counter (be32) ‖ SHA-256(signed data)`,
//! with `application` taken from the **key blob**.
//!
//! Version, magic, section lengths and the key/signature families are
//! enforced earlier by [`SshSig::parse`]. `ed25519_validate_public_key` is
//! **not** run here (see [`crate::PublicKey::validate`]): the strict verify
//! profile already rejects a non-canonical or small-order `A`, and the
//! prime-order check belongs to roster construction.

use spacetime_crypto::{Ed25519Verify, Sha256, Sha512};

use crate::blob::{Signature, SshSig, HASH_ALGORITHM_SHA512, MAGIC};
use crate::error::Error;
use crate::pubkey::PublicKey;
use crate::wire::Writer;

/// Longest namespace `verify` / `sign` accept, so the signed-data buffer
/// is a fixed stack array.
pub const MAX_NAMESPACE_LEN: usize = 255;
/// sk flag bit: user presence (always required).
pub const SK_FLAG_USER_PRESENCE: u8 = 0x01;
/// sk flag bit: user verification (required iff
/// [`SkPolicy::require_user_verification`]).
pub const SK_FLAG_USER_VERIFICATION: u8 = 0x04;

/// Fixed part of the signed data: 6 magic + 4 ns len + 4 reserved + (4 + 6)
/// hash_algorithm + (4 + 64) digest = 92.
pub(crate) const SIGNED_DATA_FIXED_LEN: usize = 92;
/// Stack buffer size for the signed data at the longest namespace.
pub(crate) const SIGNED_DATA_MAX_LEN: usize = SIGNED_DATA_FIXED_LEN + MAX_NAMESPACE_LEN;

/// Caller policy for `sk-ssh-ed25519@openssh.com` signatures. User presence
/// (`0x01`) is always required; this only adds user verification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SkPolicy {
    /// Require `flags & 0x04` (the authenticator verified the user, e.g. by
    /// PIN or biometric).
    pub require_user_verification: bool,
}

/// What the caller expects of a signature. Private fields + builder so
/// fields can be added later.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'e> {
    namespace: &'e str,
    signer: Option<&'e PublicKey<'e>>,
    sk: SkPolicy,
}

impl<'e> Expected<'e> {
    /// Expect `namespace`; any signer; default sk policy.
    ///
    /// Without [`with_signer`](Self::with_signer) the key that verifies is
    /// whatever the signature carried: a successful [`verify`] then proves
    /// only that the holder of [`Verified::public_key`] signed the message.
    /// Treat that key as an identity to look up in a validated roster, not
    /// as proof of who signed.
    pub const fn new(namespace: &'e str) -> Self {
        Self {
            namespace,
            signer: None,
            sk: SkPolicy {
                require_user_verification: false,
            },
        }
    }

    /// Require the embedded key to equal `signer` (type, key bytes and, for
    /// sk keys, the application).
    pub const fn with_signer(self, signer: &'e PublicKey<'e>) -> Self {
        Self {
            signer: Some(signer),
            ..self
        }
    }

    /// Set the sk policy.
    pub const fn with_sk_policy(self, sk: SkPolicy) -> Self {
        Self { sk, ..self }
    }

    /// The expected namespace.
    pub const fn namespace(&self) -> &'e str {
        self.namespace
    }

    /// The expected signer, if any.
    pub const fn signer(&self) -> Option<&'e PublicKey<'e>> {
        self.signer
    }

    /// The sk policy.
    pub const fn sk_policy(&self) -> SkPolicy {
        self.sk
    }
}

/// Authenticator data carried by an sk signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkAttestation {
    /// The flags byte (`0x01` user presence, `0x04` user verification).
    pub flags: u8,
    /// The signature counter.
    pub counter: u32,
}

/// Proof of a successful [`verify`]; constructible only inside this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified<'a> {
    public_key: PublicKey<'a>,
    sk: Option<SkAttestation>,
}

impl<'a> Verified<'a> {
    /// The key that made the signature. When no signer was pinned with
    /// [`Expected::with_signer`] this is the key embedded in the signature
    /// itself — an identity to match against a validated roster, not proof
    /// of who signed.
    pub const fn public_key(&self) -> &PublicKey<'a> {
        &self.public_key
    }

    /// Authenticator data for an sk signature; `None` for `ssh-ed25519`.
    pub const fn sk(&self) -> Option<SkAttestation> {
        self.sk
    }

    /// Owned copy.
    #[cfg(feature = "alloc")]
    pub fn to_buf(&self) -> VerifiedBuf {
        VerifiedBuf {
            public_key: self.public_key.to_buf(),
            sk: self.sk,
        }
    }
}

/// Owned [`Verified`].
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBuf {
    /// The key that made the signature.
    pub public_key: crate::pubkey::PublicKeyBuf,
    /// Authenticator data for an sk signature; `None` for `ssh-ed25519`.
    pub sk: Option<SkAttestation>,
}

/// Check the caller's namespace (step 1).
pub(crate) fn check_namespace(namespace: &str) -> Result<(), Error> {
    if namespace.is_empty() {
        return Err(Error::EmptyNamespace);
    }
    if namespace.len() > MAX_NAMESPACE_LEN {
        return Err(Error::NamespaceTooLong);
    }
    Ok(())
}

/// Build the signed data (step 6) into `buf`:
/// `MAGIC ‖ string(namespace) ‖ string("") ‖ string("sha512") ‖ string(message_sha512)`.
/// Returns its length, `92 + namespace.len()`. `namespace` must already
/// pass [`check_namespace`].
pub(crate) fn signed_data(
    namespace: &str,
    message_sha512: &[u8; 64],
    buf: &mut [u8; SIGNED_DATA_MAX_LEN],
) -> Result<usize, Error> {
    let mut w = Writer::new(buf);
    w.put_bytes(MAGIC)?;
    w.put_string(namespace.as_bytes())?;
    w.put_string(b"")?;
    w.put_string(HASH_ALGORITHM_SHA512)?;
    w.put_string(message_sha512)?;
    Ok(w.finish())
}

/// Hash `message` with SHA-512 (one shot), then [`verify_digest`].
pub fn verify<'a, B: ?Sized + Ed25519Verify + Sha256 + Sha512>(
    backend: &B,
    sig: &SshSig<'a>,
    expected: &Expected<'_>,
    message: &[u8],
) -> Result<Verified<'a>, Error> {
    let digest = backend.sha512(message)?;
    verify_digest(backend, sig, expected, &digest)
}

/// The predicate over a precomputed `SHA-512(message)`. This is the
/// streaming entry point: a std layer feeds a large file through
/// `Sha512State::update` and passes `finalize()` here.
pub fn verify_digest<'a, B: ?Sized + Ed25519Verify + Sha256>(
    backend: &B,
    sig: &SshSig<'a>,
    expected: &Expected<'_>,
    message_sha512: &[u8; 64],
) -> Result<Verified<'a>, Error> {
    // 1. caller input
    check_namespace(expected.namespace())?;
    // 2. reserved
    if !sig.reserved.is_empty() {
        return Err(Error::ReservedNotEmpty);
    }
    // 3. hash_algorithm
    if sig.hash_algorithm != HASH_ALGORITHM_SHA512 {
        return Err(Error::HashAlgorithmNotSha512);
    }
    // 4. namespace (compared only; never used below)
    if sig.namespace != expected.namespace().as_bytes() {
        return Err(Error::NamespaceMismatch);
    }
    // 5. signer
    if let Some(signer) = expected.signer() {
        if *signer != sig.public_key {
            return Err(Error::SignerMismatch);
        }
    }
    // 6. signed data from the caller's constant
    let mut buf = [0u8; SIGNED_DATA_MAX_LEN];
    let n = signed_data(expected.namespace(), message_sha512, &mut buf)?;
    let data = &buf[..n];
    // 7. curve operation
    let sk = match (sig.public_key, sig.signature) {
        (PublicKey::Ed25519 { key }, Signature::Ed25519 { sig }) => {
            backend.ed25519_verify(key, data, sig)?;
            None
        }
        (
            PublicKey::SkEd25519 { key, application },
            Signature::SkEd25519 {
                sig,
                flags,
                counter,
            },
        ) => {
            if flags & SK_FLAG_USER_PRESENCE == 0 {
                return Err(Error::SkUserPresenceMissing);
            }
            if expected.sk_policy().require_user_verification
                && flags & SK_FLAG_USER_VERIFICATION == 0
            {
                return Err(Error::SkUserVerificationMissing);
            }
            let mut m = [0u8; 32 + 1 + 4 + 32];
            m[..32].copy_from_slice(&backend.sha256(application)?);
            m[32] = flags;
            m[33..37].copy_from_slice(&counter.to_be_bytes());
            m[37..].copy_from_slice(&backend.sha256(data)?);
            backend.ed25519_verify(key, &m, sig)?;
            Some(SkAttestation { flags, counter })
        }
        // `SshSig::parse` rejects mixed families (`KeyTypeMismatch`).
        _ => return Err(Error::KeyTypeMismatch),
    };
    Ok(Verified {
        public_key: sig.public_key,
        sk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacetime_crypto::{CryptoError, CryptoErrorKind, CryptoResult, Sha256State};

    const KEY: [u8; 32] = [0x44; 32];
    const SIG: [u8; 64] = [0x55; 64];
    const NS: &str = "spacetime-sshsig-test-v1";
    const DIGEST: [u8; 64] = [0x66; 64];

    /// A backend that must never be reached: every method panics.
    struct Unreachable;
    struct NoState;
    impl Sha256State for NoState {
        fn update(&mut self, _: &[u8]) -> CryptoResult<()> {
            panic!("backend reached")
        }
        fn finalize(&mut self) -> CryptoResult<[u8; 32]> {
            panic!("backend reached")
        }
    }
    impl Sha256 for Unreachable {
        type State = NoState;
        fn sha256_init(&self) -> CryptoResult<Self::State> {
            panic!("backend reached")
        }
    }
    impl Ed25519Verify for Unreachable {
        fn ed25519_validate_public_key(&self, _: &[u8; 32]) -> CryptoResult<()> {
            panic!("backend reached")
        }
        fn ed25519_verify(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> CryptoResult<()> {
            panic!("backend reached")
        }
    }

    /// A recording backend: SHA-256 is a length tag; `ed25519_verify`
    /// accepts iff the message equals what the test predicted, and records
    /// the message length.
    struct Recorder {
        accept_len: usize,
        kind: CryptoErrorKind,
    }
    #[derive(Default)]
    struct TagState {
        len: u64,
    }
    impl Sha256State for TagState {
        fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
            self.len += data.len() as u64;
            Ok(())
        }
        fn finalize(&mut self) -> CryptoResult<[u8; 32]> {
            let mut out = [0u8; 32];
            out[..8].copy_from_slice(&self.len.to_le_bytes());
            self.len = 0;
            Ok(out)
        }
    }
    impl Sha256 for Recorder {
        type State = TagState;
        fn sha256_init(&self) -> CryptoResult<Self::State> {
            Ok(TagState::default())
        }
    }
    impl Ed25519Verify for Recorder {
        fn ed25519_validate_public_key(&self, _: &[u8; 32]) -> CryptoResult<()> {
            Ok(())
        }
        fn ed25519_verify(&self, _: &[u8; 32], msg: &[u8], _: &[u8; 64]) -> CryptoResult<()> {
            if msg.len() == self.accept_len {
                Ok(())
            } else {
                Err(CryptoError::new(self.kind))
            }
        }
    }

    fn sig() -> SshSig<'static> {
        SshSig {
            public_key: PublicKey::Ed25519 { key: &KEY },
            namespace: NS.as_bytes(),
            reserved: b"",
            hash_algorithm: HASH_ALGORITHM_SHA512,
            signature: Signature::Ed25519 { sig: &SIG },
        }
    }

    fn sk_sig(flags: u8) -> SshSig<'static> {
        SshSig {
            public_key: PublicKey::SkEd25519 {
                key: &KEY,
                application: b"ssh:",
            },
            signature: Signature::SkEd25519 {
                sig: &SIG,
                flags,
                counter: 9,
            },
            ..sig()
        }
    }

    #[test]
    fn caller_namespace_checked_before_backend() {
        assert_eq!(
            verify_digest(&Unreachable, &sig(), &Expected::new(""), &DIGEST),
            Err(Error::EmptyNamespace)
        );
        let long = [b'n'; 256];
        let long = core::str::from_utf8(&long).unwrap();
        assert_eq!(
            verify_digest(&Unreachable, &sig(), &Expected::new(long), &DIGEST),
            Err(Error::NamespaceTooLong)
        );
        let max = [b'n'; 255];
        let max = core::str::from_utf8(&max).unwrap();
        // 255 passes step 1 and fails at step 4 (blob namespace differs).
        assert_eq!(
            verify_digest(&Unreachable, &sig(), &Expected::new(max), &DIGEST),
            Err(Error::NamespaceMismatch)
        );
    }

    #[test]
    fn structural_predicate_order() {
        let e = Expected::new(NS);
        let s = SshSig {
            reserved: b"x",
            hash_algorithm: b"sha256",
            ..sig()
        };
        assert_eq!(
            verify_digest(&Unreachable, &s, &e, &DIGEST),
            Err(Error::ReservedNotEmpty)
        );
        let s = SshSig {
            hash_algorithm: b"sha256",
            namespace: b"other",
            ..sig()
        };
        assert_eq!(
            verify_digest(&Unreachable, &s, &e, &DIGEST),
            Err(Error::HashAlgorithmNotSha512)
        );
        let s = SshSig {
            namespace: b"other",
            ..sig()
        };
        assert_eq!(
            verify_digest(&Unreachable, &s, &e, &DIGEST),
            Err(Error::NamespaceMismatch)
        );
        let other = [0x99u8; 32];
        let other_key = PublicKey::Ed25519 { key: &other };
        let e = Expected::new(NS).with_signer(&other_key);
        assert_eq!(
            verify_digest(&Unreachable, &sig(), &e, &DIGEST),
            Err(Error::SignerMismatch)
        );
        // An sk signer with a different application is also a mismatch.
        let sk_other = PublicKey::SkEd25519 {
            key: &KEY,
            application: b"ssh:other",
        };
        let e = Expected::new(NS).with_signer(&sk_other);
        assert_eq!(
            verify_digest(&Unreachable, &sk_sig(1), &e, &DIGEST),
            Err(Error::SignerMismatch)
        );
    }

    #[test]
    fn ed25519_path_signs_92_plus_ns_bytes() {
        let ok = Recorder {
            accept_len: SIGNED_DATA_FIXED_LEN + NS.len(),
            kind: CryptoErrorKind::AuthenticationFailed,
        };
        let e = Expected::new(NS);
        let v = verify_digest(&ok, &sig(), &e, &DIGEST).unwrap();
        assert_eq!(v.public_key(), &PublicKey::Ed25519 { key: &KEY });
        assert_eq!(v.sk(), None);
        let signer = PublicKey::Ed25519 { key: &KEY };
        let e = Expected::new(NS).with_signer(&signer);
        assert!(verify_digest(&ok, &sig(), &e, &DIGEST).is_ok());

        let bad = Recorder {
            accept_len: 0,
            kind: CryptoErrorKind::AuthenticationFailed,
        };
        assert_eq!(
            verify_digest(&bad, &sig(), &e, &DIGEST),
            Err(Error::SignatureInvalid)
        );
        let down = Recorder {
            accept_len: 0,
            kind: CryptoErrorKind::Unavailable,
        };
        assert_eq!(
            verify_digest(&down, &sig(), &e, &DIGEST),
            Err(Error::Backend(CryptoErrorKind::Unavailable))
        );
    }

    #[test]
    fn signed_data_layout() {
        let mut buf = [0u8; SIGNED_DATA_MAX_LEN];
        let n = signed_data("ab", &DIGEST, &mut buf).unwrap();
        assert_eq!(n, 94);
        let mut want = [0u8; 94];
        want[..6].copy_from_slice(b"SSHSIG");
        want[9] = 2;
        want[10..12].copy_from_slice(b"ab");
        // reserved: 4 zero bytes at 12..16
        want[19] = 6;
        want[20..26].copy_from_slice(b"sha512");
        want[29] = 64;
        want[30..94].copy_from_slice(&DIGEST);
        assert_eq!(&buf[..n], &want[..]);
    }

    #[test]
    fn sk_flags_precede_curve_operation() {
        let e = Expected::new(NS);
        assert_eq!(
            verify_digest(&Unreachable, &sk_sig(0x00), &e, &DIGEST),
            Err(Error::SkUserPresenceMissing)
        );
        assert_eq!(
            verify_digest(&Unreachable, &sk_sig(0x04), &e, &DIGEST),
            Err(Error::SkUserPresenceMissing)
        );
        let uv = Expected::new(NS).with_sk_policy(SkPolicy {
            require_user_verification: true,
        });
        assert_eq!(
            verify_digest(&Unreachable, &sk_sig(0x01), &uv, &DIGEST),
            Err(Error::SkUserVerificationMissing)
        );
    }

    #[test]
    fn sk_path_signs_69_bytes() {
        let ok = Recorder {
            accept_len: 69,
            kind: CryptoErrorKind::AuthenticationFailed,
        };
        let e = Expected::new(NS);
        let v = verify_digest(&ok, &sk_sig(0x01), &e, &DIGEST).unwrap();
        assert_eq!(
            v.sk(),
            Some(SkAttestation {
                flags: 0x01,
                counter: 9
            })
        );
        assert!(v.public_key().is_sk());
        let uv = Expected::new(NS).with_sk_policy(SkPolicy {
            require_user_verification: true,
        });
        assert!(verify_digest(&ok, &sk_sig(0x05), &uv, &DIGEST).is_ok());
        let bad = Recorder {
            accept_len: 0,
            kind: CryptoErrorKind::AuthenticationFailed,
        };
        assert_eq!(
            verify_digest(&bad, &sk_sig(0x05), &uv, &DIGEST),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn expected_accessors() {
        let signer = PublicKey::Ed25519 { key: &KEY };
        let e = Expected::new(NS)
            .with_signer(&signer)
            .with_sk_policy(SkPolicy {
                require_user_verification: true,
            });
        assert_eq!(e.namespace(), NS);
        assert_eq!(e.signer(), Some(&signer));
        assert!(e.sk_policy().require_user_verification);
        assert_eq!(SkPolicy::default(), Expected::new(NS).sk_policy());
    }

    #[cfg(feature = "alloc")]
    mod with_alloc {
        use super::super::*;
        use super::{sig, Recorder, DIGEST, KEY, NS};
        use crate::pubkey::PublicKeyBuf;
        use spacetime_crypto::CryptoErrorKind;

        #[test]
        fn verified_to_buf() {
            let ok = Recorder {
                accept_len: SIGNED_DATA_FIXED_LEN + NS.len(),
                kind: CryptoErrorKind::AuthenticationFailed,
            };
            let v = verify_digest(&ok, &sig(), &Expected::new(NS), &DIGEST).unwrap();
            assert_eq!(
                v.to_buf(),
                VerifiedBuf {
                    public_key: PublicKeyBuf::Ed25519 { key: KEY },
                    sk: None
                }
            );
        }
    }
}
