//! Deterministic `ssh-ed25519` SSHSIG signing from a 32-byte seed.
//!
//! For a given `(seed, namespace, message)` the output is byte-identical to
//! `ssh-keygen -Y sign -f <key> -n <namespace> <file>`: Ed25519 is
//! deterministic (RFC 8032 §5.1.6), the blob layout is fixed, and
//! [`crate::armor::encode`] writes the exact text ssh-keygen writes (proven
//! by the `deterministic_sign` vectors in `tests/vectors/`). The public key
//! is re-derived from the seed by the backend; a caller-supplied public key
//! is never accepted (see `spacetime_crypto::Ed25519Sign`).
//!
//! sk keys are verify-only: no sk signing exists here.

use spacetime_crypto::{Ed25519Sign, Sha512};

use crate::armor;
use crate::blob::{Signature, SshSig, HASH_ALGORITHM_SHA512};
use crate::error::Error;
use crate::pubkey::PublicKey;
use crate::verify::{check_namespace, signed_data, MAX_NAMESPACE_LEN, SIGNED_DATA_MAX_LEN};

/// Stack size for a raw blob at the longest namespace.
const BLOB_MAX_LEN: usize = crate::blob::ed25519_sshsig_len(MAX_NAMESPACE_LEN);

/// SHA-512(message) then [`sign_digest`]. Writes the RAW blob
/// ([`crate::ed25519_sshsig_len`]`(namespace.len())` bytes) into `out`.
pub fn sign<B: ?Sized + Ed25519Sign + Sha512>(
    backend: &B,
    seed: &[u8; 32],
    namespace: &str,
    message: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    check_namespace(namespace)?;
    let digest = backend.sha512(message)?;
    sign_digest(backend, seed, namespace, &digest, out)
}

/// Core: namespace checks ([`Error::EmptyNamespace`] /
/// [`Error::NamespaceTooLong`]); signed data exactly as `verify` builds it;
/// `pk = backend.ed25519_public_key(seed)`; `sig = backend.ed25519_sign(seed,
/// signed_data)`; then the blob `{ Ed25519(pk), namespace, reserved: "",
/// hash_algorithm: "sha512", Ed25519(sig) }` is encoded into `out`.
pub fn sign_digest<B: ?Sized + Ed25519Sign>(
    backend: &B,
    seed: &[u8; 32],
    namespace: &str,
    message_sha512: &[u8; 64],
    out: &mut [u8],
) -> Result<usize, Error> {
    check_namespace(namespace)?;
    let mut buf = [0u8; SIGNED_DATA_MAX_LEN];
    let n = signed_data(namespace, message_sha512, &mut buf)?;
    let pk = backend.ed25519_public_key(seed)?;
    let sig = backend.ed25519_sign(seed, &buf[..n])?;
    let blob = SshSig {
        public_key: PublicKey::Ed25519 { key: &pk },
        namespace: namespace.as_bytes(),
        reserved: b"",
        hash_algorithm: HASH_ALGORITHM_SHA512,
        signature: Signature::Ed25519 { sig: &sig },
    };
    blob.encode(out)
}

/// [`sign`] + [`armor::encode`] (the blob is staged in a stack buffer).
/// Writes [`armor::encoded_len`]`(blob_len)` bytes.
pub fn sign_armored<B: ?Sized + Ed25519Sign + Sha512>(
    backend: &B,
    seed: &[u8; 32],
    namespace: &str,
    message: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    check_namespace(namespace)?;
    let digest = backend.sha512(message)?;
    sign_armored_digest(backend, seed, namespace, &digest, out)
}

/// [`sign_digest`] + [`armor::encode`].
pub fn sign_armored_digest<B: ?Sized + Ed25519Sign>(
    backend: &B,
    seed: &[u8; 32],
    namespace: &str,
    message_sha512: &[u8; 64],
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut blob = [0u8; BLOB_MAX_LEN];
    let n = sign_digest(backend, seed, namespace, message_sha512, &mut blob)?;
    armor::encode(&blob[..n], out)
}

/// [`sign`] into a fresh `Vec` (the raw blob).
#[cfg(feature = "alloc")]
pub fn sign_vec<B: ?Sized + Ed25519Sign + Sha512>(
    backend: &B,
    seed: &[u8; 32],
    namespace: &str,
    message: &[u8],
) -> Result<alloc::vec::Vec<u8>, Error> {
    check_namespace(namespace)?;
    let mut v = alloc::vec![0u8; crate::blob::ed25519_sshsig_len(namespace.len())];
    let n = sign(backend, seed, namespace, message, &mut v)?;
    v.truncate(n);
    Ok(v)
}

/// [`sign_armored`] into a fresh `String`.
#[cfg(feature = "alloc")]
pub fn sign_armored_string<B: ?Sized + Ed25519Sign + Sha512>(
    backend: &B,
    seed: &[u8; 32],
    namespace: &str,
    message: &[u8],
) -> Result<alloc::string::String, Error> {
    Ok(armor::encode_string(&sign_vec(
        backend, seed, namespace, message,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::ed25519_sshsig_len;
    use spacetime_crypto::{CryptoResult, Sha512State};

    /// Fake signer: public key = seed, signature = first 32 bytes of the
    /// message ‖ seed. Enough to prove the plumbing without curve code.
    struct Fake;
    #[derive(Default)]
    struct FakeState {
        len: u64,
    }
    impl Sha512State for FakeState {
        fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
            self.len += data.len() as u64;
            Ok(())
        }
        fn finalize(&mut self) -> CryptoResult<[u8; 64]> {
            let mut out = [0u8; 64];
            out[..8].copy_from_slice(&self.len.to_le_bytes());
            self.len = 0;
            Ok(out)
        }
    }
    impl Sha512 for Fake {
        type State = FakeState;
        fn sha512_init(&self) -> CryptoResult<Self::State> {
            Ok(FakeState::default())
        }
    }
    impl Ed25519Sign for Fake {
        fn ed25519_public_key(&self, seed: &[u8; 32]) -> CryptoResult<[u8; 32]> {
            Ok(*seed)
        }
        fn ed25519_sign(&self, seed: &[u8; 32], message: &[u8]) -> CryptoResult<[u8; 64]> {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&message[..32]);
            sig[32..].copy_from_slice(seed);
            Ok(sig)
        }
    }

    const SEED: [u8; 32] = [0x77; 32];
    const NS: &str = "ns-1";

    #[test]
    fn sign_produces_parseable_blob() {
        let mut out = [0u8; 256];
        let n = sign(&Fake, &SEED, NS, b"hello", &mut out).unwrap();
        assert_eq!(n, ed25519_sshsig_len(NS.len()));
        let parsed = SshSig::parse(&out[..n]).unwrap();
        assert_eq!(parsed.public_key, PublicKey::Ed25519 { key: &SEED });
        assert_eq!(parsed.namespace, NS.as_bytes());
        assert_eq!(parsed.reserved, b"");
        assert_eq!(parsed.hash_algorithm, b"sha512");
        // The fake signature starts with the signed data's first 32 bytes:
        // "SSHSIG" ‖ u32 4 ‖ "ns-1" ‖ u32 0 ‖ u32 6 ‖ "sha512" ‖ u32 64 ...
        let sig = parsed.signature.sig();
        assert_eq!(&sig[..6], b"SSHSIG");
        assert_eq!(&sig[6..10], &[0, 0, 0, 4]);
        assert_eq!(&sig[10..14], b"ns-1");
        assert_eq!(&sig[32..], &SEED);

        // sign_digest with the same digest gives the same bytes.
        let digest = Fake.sha512(b"hello").unwrap();
        let mut out2 = [0u8; 256];
        let n2 = sign_digest(&Fake, &SEED, NS, &digest, &mut out2).unwrap();
        assert_eq!(&out[..n], &out2[..n2]);
    }

    #[test]
    fn sign_namespace_and_buffer_errors() {
        let mut out = [0u8; 256];
        assert_eq!(
            sign(&Fake, &SEED, "", b"", &mut out),
            Err(Error::EmptyNamespace)
        );
        let long = [b'n'; 256];
        let long = core::str::from_utf8(&long).unwrap();
        assert_eq!(
            sign(&Fake, &SEED, long, b"", &mut out),
            Err(Error::NamespaceTooLong)
        );
        assert_eq!(
            sign_digest(&Fake, &SEED, "", &[0; 64], &mut out),
            Err(Error::EmptyNamespace)
        );
        assert_eq!(
            sign(&Fake, &SEED, NS, b"", &mut out[..173]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            sign_armored(&Fake, &SEED, NS, b"", &mut out[..100]),
            Err(Error::BufferTooSmall)
        );
        let max = [b'n'; 255];
        let max = core::str::from_utf8(&max).unwrap();
        let mut big = [0u8; 1024];
        assert_eq!(
            sign(&Fake, &SEED, max, b"", &mut big),
            Ok(ed25519_sshsig_len(255))
        );
        assert_eq!(
            sign_armored(&Fake, &SEED, max, b"", &mut big),
            Ok(armor::encoded_len(ed25519_sshsig_len(255)))
        );
    }

    #[test]
    fn sign_armored_matches_sign_plus_encode() {
        let mut raw = [0u8; 256];
        let n = sign(&Fake, &SEED, NS, b"hello", &mut raw).unwrap();
        let mut armored = [0u8; 512];
        let a = armor::encode(&raw[..n], &mut armored).unwrap();
        let mut direct = [0u8; 512];
        let d = sign_armored(&Fake, &SEED, NS, b"hello", &mut direct).unwrap();
        assert_eq!(&armored[..a], &direct[..d]);
        let digest = Fake.sha512(b"hello").unwrap();
        let mut via_digest = [0u8; 512];
        let v = sign_armored_digest(&Fake, &SEED, NS, &digest, &mut via_digest).unwrap();
        assert_eq!(&armored[..a], &via_digest[..v]);
    }

    #[cfg(feature = "alloc")]
    mod with_alloc {
        use super::super::*;
        use super::{Fake, NS, SEED};

        #[test]
        fn alloc_forms_match_buffer_forms() {
            let mut raw = [0u8; 256];
            let n = sign(&Fake, &SEED, NS, b"hello", &mut raw).unwrap();
            assert_eq!(sign_vec(&Fake, &SEED, NS, b"hello").unwrap(), &raw[..n]);
            let mut armored = [0u8; 512];
            let a = sign_armored(&Fake, &SEED, NS, b"hello", &mut armored).unwrap();
            assert_eq!(
                sign_armored_string(&Fake, &SEED, NS, b"hello")
                    .unwrap()
                    .as_bytes(),
                &armored[..a]
            );
            assert_eq!(
                sign_vec(&Fake, &SEED, "", b"hello"),
                Err(Error::EmptyNamespace)
            );
        }
    }
}
