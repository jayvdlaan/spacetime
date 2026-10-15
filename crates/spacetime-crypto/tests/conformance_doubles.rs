//! Proves the conformance harness with test doubles only.
//!
//! This crate contains no cryptography, so these tests cannot (and do not)
//! establish that any vector is correct. What they establish is that the
//! harness itself works: every `check_*` compiles against an arbitrary
//! implementor (including trait objects), passes a backend that returns the
//! tabled answers, and fails — naming the first offending vector — a
//! backend that returns a wrong answer, a wrong error kind, or leaks
//! plaintext. The real cryptographic run of the harness happens in a
//! downstream backend crate.
//!
//! `Tabled` is data lookup in `conformance::vectors`, not cryptography.

#![cfg(feature = "conformance")]

use spacetime_crypto as sc;
use spacetime_crypto::conformance::{self, vectors};
use spacetime_crypto::{CryptoError, CryptoErrorKind, CryptoResult};

fn failed() -> CryptoError {
    CryptoError::new(CryptoErrorKind::Failed)
}

fn auth_failed() -> CryptoError {
    CryptoError::new(CryptoErrorKind::AuthenticationFailed)
}

fn invalid() -> CryptoError {
    CryptoError::new(CryptoErrorKind::InvalidParameter)
}

// ---------------------------------------------------------------------------
// Tabled: answers by lookup in the vector tables
// ---------------------------------------------------------------------------

/// A backend that returns the expected output for every known input and
/// `Failed` (or a fixed constant) otherwise.
#[derive(Copy, Clone)]
struct Tabled;

/// Capacity of the tabled digest states; every digest vector fits.
const ABSORB_CAP: usize = 128;

/// Buffers absorbed bytes so `finalize` can look the whole message up.
struct Absorber {
    buf: [u8; ABSORB_CAP],
    len: usize,
}

impl Default for Absorber {
    fn default() -> Self {
        Self {
            buf: [0u8; ABSORB_CAP],
            len: 0,
        }
    }
}

impl Absorber {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        let end = self.len.checked_add(data.len()).ok_or_else(failed)?;
        if end > ABSORB_CAP {
            return Err(failed());
        }
        self.buf[self.len..end].copy_from_slice(data);
        self.len = end;
        Ok(())
    }

    /// Return the absorbed message and reset.
    fn take(&mut self) -> ([u8; ABSORB_CAP], usize) {
        let out = (self.buf, self.len);
        self.len = 0;
        out
    }
}

#[derive(Default)]
struct TabledSha256State(Absorber);

impl sc::Sha256State for TabledSha256State {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.0.update(data)
    }

    fn finalize(&mut self) -> CryptoResult<[u8; 32]> {
        let (buf, len) = self.0.take();
        vectors::SHA256
            .iter()
            .find(|v| v.message == &buf[..len])
            .map(|v| v.digest)
            .ok_or_else(failed)
    }
}

impl sc::Sha256 for Tabled {
    type State = TabledSha256State;

    fn sha256_init(&self) -> CryptoResult<Self::State> {
        Ok(TabledSha256State::default())
    }
}

#[derive(Default)]
struct TabledSha512State(Absorber);

impl sc::Sha512State for TabledSha512State {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.0.update(data)
    }

    fn finalize(&mut self) -> CryptoResult<[u8; 64]> {
        let (buf, len) = self.0.take();
        vectors::SHA512
            .iter()
            .find(|v| v.message == &buf[..len])
            .map(|v| v.digest)
            .ok_or_else(failed)
    }
}

impl sc::Sha512 for Tabled {
    type State = TabledSha512State;

    fn sha512_init(&self) -> CryptoResult<Self::State> {
        Ok(TabledSha512State::default())
    }
}

impl sc::HmacSha256 for Tabled {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> CryptoResult<[u8; 32]> {
        vectors::HMAC_SHA256
            .iter()
            .find(|v| v.key == key && v.data == data)
            .map(|v| v.mac)
            .ok_or_else(failed)
    }

    fn hmac_sha256_verify(&self, key: &[u8], data: &[u8], tag: &[u8; 32]) -> CryptoResult<()> {
        if &self.hmac_sha256(key, data)? == tag {
            Ok(())
        } else {
            Err(auth_failed())
        }
    }
}

impl sc::Ed25519Verify for Tabled {
    fn ed25519_validate_public_key(&self, public_key: &[u8; 32]) -> CryptoResult<()> {
        if vectors::ED25519.iter().any(|v| &v.public_key == public_key) {
            Ok(())
        } else {
            Err(invalid())
        }
    }

    fn ed25519_verify(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> CryptoResult<()> {
        let known = vectors::ED25519.iter().any(|v| {
            &v.public_key == public_key && v.message == message && &v.signature == signature
        });
        if known {
            Ok(())
        } else {
            Err(auth_failed())
        }
    }
}

impl sc::Ed25519Sign for Tabled {
    fn ed25519_public_key(&self, seed: &[u8; 32]) -> CryptoResult<[u8; 32]> {
        vectors::ED25519
            .iter()
            .find(|v| &v.seed == seed)
            .map(|v| v.public_key)
            .ok_or_else(failed)
    }

    fn ed25519_sign(&self, seed: &[u8; 32], message: &[u8]) -> CryptoResult<[u8; 64]> {
        vectors::ED25519
            .iter()
            .find(|v| &v.seed == seed && v.message == message)
            .map(|v| v.signature)
            .ok_or_else(failed)
    }
}

impl sc::Ed25519ToX25519 for Tabled {
    fn ed25519_public_to_x25519(&self, public_key: &[u8; 32]) -> CryptoResult<[u8; 32]> {
        if vectors::ED25519_INVALID_PUBLIC_KEYS
            .iter()
            .any(|k| &k.key == public_key)
        {
            return Err(invalid());
        }
        vectors::ED25519_TO_X25519
            .iter()
            .find(|v| &v.public_key == public_key)
            .map(|v| v.x25519_public)
            .ok_or_else(failed)
    }
}

/// Tag the tabled AEAD returns for the empty-plaintext/empty-AAD round trip
/// (no RFC vector exists for it).
const EMPTY_TAG: [u8; 16] = [0x5A; 16];

fn tabled_seal<const N: usize>(
    table: &[vectors::AeadVector<N>],
    key: &[u8; 32],
    nonce: &[u8; N],
    aad: &[u8],
    buf: &mut [u8],
) -> CryptoResult<[u8; 16]> {
    if buf.is_empty() && aad.is_empty() {
        return Ok(EMPTY_TAG);
    }
    let v = table
        .iter()
        .find(|v| &v.key == key && &v.nonce == nonce && v.aad == aad && v.plaintext == &*buf)
        .ok_or_else(failed)?;
    buf.copy_from_slice(v.ciphertext);
    Ok(v.tag)
}

/// Verifies by lookup and leaves `buf` untouched on failure.
fn tabled_open<const N: usize>(
    table: &[vectors::AeadVector<N>],
    key: &[u8; 32],
    nonce: &[u8; N],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> CryptoResult<()> {
    if buf.is_empty() && aad.is_empty() {
        return if *tag == EMPTY_TAG {
            Ok(())
        } else {
            Err(auth_failed())
        };
    }
    match table.iter().find(|v| {
        &v.key == key && &v.nonce == nonce && v.aad == aad && v.ciphertext == &*buf && &v.tag == tag
    }) {
        Some(v) => {
            buf.copy_from_slice(v.plaintext);
            Ok(())
        }
        None => Err(auth_failed()),
    }
}

impl sc::ChaCha20Poly1305 for Tabled {
    fn chacha20poly1305_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; 16]> {
        tabled_seal(vectors::CHACHA20POLY1305, key, nonce, aad, buf)
    }

    fn chacha20poly1305_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> CryptoResult<()> {
        tabled_open(vectors::CHACHA20POLY1305, key, nonce, aad, buf, tag)
    }
}

impl sc::XChaCha20Poly1305 for Tabled {
    fn xchacha20poly1305_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; 16]> {
        tabled_seal(vectors::XCHACHA20POLY1305, key, nonce, aad, buf)
    }

    fn xchacha20poly1305_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> CryptoResult<()> {
        tabled_open(vectors::XCHACHA20POLY1305, key, nonce, aad, buf, tag)
    }
}

impl sc::HkdfSha256 for Tabled {
    fn hkdf_sha256_extract(&self, salt: &[u8], ikm: &[u8], prk: &mut [u8; 32]) -> CryptoResult<()> {
        let v = vectors::HKDF_SHA256
            .iter()
            .find(|v| v.salt == salt && v.ikm == ikm)
            .ok_or_else(failed)?;
        *prk = v.prk;
        Ok(())
    }

    fn hkdf_sha256_expand(&self, prk: &[u8; 32], info: &[u8], okm: &mut [u8]) -> CryptoResult<()> {
        if okm.len() > sc::HKDF_SHA256_MAX_OKM_LEN {
            return Err(invalid());
        }
        if okm.is_empty() {
            return Ok(());
        }
        let v = vectors::HKDF_SHA256
            .iter()
            .find(|v| &v.prk == prk && v.info == info && v.okm.len() >= okm.len())
            .ok_or_else(failed)?;
        okm.copy_from_slice(&v.okm[..okm.len()]);
        Ok(())
    }
}

impl sc::Argon2id for Tabled {
    fn argon2id(
        &self,
        params: &sc::Argon2Params,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        ad: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        params.validate()?;
        if salt.len() < sc::ARGON2_MIN_SALT_LEN || out.len() < sc::ARGON2_MIN_OUTPUT_LEN {
            return Err(invalid());
        }
        let v = vectors::ARGON2ID
            .iter()
            .find(|v| {
                &v.params == params
                    && v.password == password
                    && v.salt == salt
                    && v.secret == secret
                    && v.ad == ad
                    && v.tag.len() == out.len()
            })
            .ok_or_else(failed)?;
        out.copy_from_slice(&v.tag);
        Ok(())
    }
}

impl sc::X25519 for Tabled {
    fn x25519_public_key(&self, secret: &[u8; 32]) -> CryptoResult<[u8; 32]> {
        for v in vectors::X25519 {
            if &v.alice_secret == secret {
                return Ok(v.alice_public);
            }
            if &v.bob_secret == secret {
                return Ok(v.bob_public);
            }
        }
        Err(failed())
    }

    fn x25519(
        &self,
        secret: &[u8; 32],
        peer_public: &[u8; 32],
        shared: &mut [u8; 32],
    ) -> CryptoResult<()> {
        if vectors::X25519_LOW_ORDER_PEERS
            .iter()
            .any(|k| &k.key == peer_public)
        {
            *shared = [0u8; 32];
            return Err(invalid());
        }
        for v in vectors::X25519 {
            if (&v.alice_secret == secret && &v.bob_public == peer_public)
                || (&v.bob_secret == secret && &v.alice_public == peer_public)
            {
                *shared = v.shared;
                return Ok(());
            }
        }
        Err(failed())
    }
}

// ---------------------------------------------------------------------------
// Uniform doubles: Zeros (always Ok, all-zero outputs) and AlwaysUnsupported
// ---------------------------------------------------------------------------

trait Uniform: Copy {
    fn unit(&self) -> CryptoResult<()>;
}

/// Every method succeeds with all-zero output.
#[derive(Copy, Clone)]
struct Zeros;

impl Uniform for Zeros {
    fn unit(&self) -> CryptoResult<()> {
        Ok(())
    }
}

/// Every method returns `Unsupported`.
#[derive(Copy, Clone)]
struct AlwaysUnsupported;

impl Uniform for AlwaysUnsupported {
    fn unit(&self) -> CryptoResult<()> {
        Err(CryptoError::new(CryptoErrorKind::Unsupported))
    }
}

struct UniformState<B>(B);

impl<B: Uniform> sc::Sha256State for UniformState<B> {
    fn update(&mut self, _data: &[u8]) -> CryptoResult<()> {
        self.0.unit()
    }
    fn finalize(&mut self) -> CryptoResult<[u8; 32]> {
        self.0.unit().map(|()| [0u8; 32])
    }
}

impl<B: Uniform> sc::Sha512State for UniformState<B> {
    fn update(&mut self, _data: &[u8]) -> CryptoResult<()> {
        self.0.unit()
    }
    fn finalize(&mut self) -> CryptoResult<[u8; 64]> {
        self.0.unit().map(|()| [0u8; 64])
    }
}

macro_rules! impl_uniform {
    ($t:ty) => {
        impl sc::Sha256 for $t {
            type State = UniformState<$t>;
            fn sha256_init(&self) -> CryptoResult<Self::State> {
                self.unit().map(|()| UniformState(*self))
            }
        }

        impl sc::Sha512 for $t {
            type State = UniformState<$t>;
            fn sha512_init(&self) -> CryptoResult<Self::State> {
                self.unit().map(|()| UniformState(*self))
            }
        }

        impl sc::HmacSha256 for $t {
            fn hmac_sha256(&self, _key: &[u8], _data: &[u8]) -> CryptoResult<[u8; 32]> {
                self.unit().map(|()| [0u8; 32])
            }
            fn hmac_sha256_verify(
                &self,
                _key: &[u8],
                _data: &[u8],
                _tag: &[u8; 32],
            ) -> CryptoResult<()> {
                self.unit()
            }
        }

        impl sc::Ed25519Verify for $t {
            fn ed25519_validate_public_key(&self, _public_key: &[u8; 32]) -> CryptoResult<()> {
                self.unit()
            }
            fn ed25519_verify(
                &self,
                _public_key: &[u8; 32],
                _message: &[u8],
                _signature: &[u8; 64],
            ) -> CryptoResult<()> {
                self.unit()
            }
        }

        impl sc::Ed25519Sign for $t {
            fn ed25519_public_key(&self, _seed: &[u8; 32]) -> CryptoResult<[u8; 32]> {
                self.unit().map(|()| [0u8; 32])
            }
            fn ed25519_sign(&self, _seed: &[u8; 32], _message: &[u8]) -> CryptoResult<[u8; 64]> {
                self.unit().map(|()| [0u8; 64])
            }
        }

        impl sc::Ed25519ToX25519 for $t {
            fn ed25519_public_to_x25519(&self, _pk: &[u8; 32]) -> CryptoResult<[u8; 32]> {
                self.unit().map(|()| [0u8; 32])
            }
        }

        impl sc::ChaCha20Poly1305 for $t {
            fn chacha20poly1305_seal(
                &self,
                _key: &[u8; 32],
                _nonce: &[u8; 12],
                _aad: &[u8],
                buf: &mut [u8],
            ) -> CryptoResult<[u8; 16]> {
                self.unit().map(|()| {
                    buf.fill(0);
                    [0u8; 16]
                })
            }
            fn chacha20poly1305_open(
                &self,
                _key: &[u8; 32],
                _nonce: &[u8; 12],
                _aad: &[u8],
                buf: &mut [u8],
                _tag: &[u8; 16],
            ) -> CryptoResult<()> {
                self.unit().map(|()| buf.fill(0))
            }
        }

        impl sc::XChaCha20Poly1305 for $t {
            fn xchacha20poly1305_seal(
                &self,
                _key: &[u8; 32],
                _nonce: &[u8; 24],
                _aad: &[u8],
                buf: &mut [u8],
            ) -> CryptoResult<[u8; 16]> {
                self.unit().map(|()| {
                    buf.fill(0);
                    [0u8; 16]
                })
            }
            fn xchacha20poly1305_open(
                &self,
                _key: &[u8; 32],
                _nonce: &[u8; 24],
                _aad: &[u8],
                buf: &mut [u8],
                _tag: &[u8; 16],
            ) -> CryptoResult<()> {
                self.unit().map(|()| buf.fill(0))
            }
        }

        impl sc::HkdfSha256 for $t {
            fn hkdf_sha256_extract(
                &self,
                _salt: &[u8],
                _ikm: &[u8],
                prk: &mut [u8; 32],
            ) -> CryptoResult<()> {
                self.unit().map(|()| *prk = [0u8; 32])
            }
            fn hkdf_sha256_expand(
                &self,
                _prk: &[u8; 32],
                _info: &[u8],
                okm: &mut [u8],
            ) -> CryptoResult<()> {
                self.unit().map(|()| okm.fill(0))
            }
        }

        impl sc::Argon2id for $t {
            fn argon2id(
                &self,
                _params: &sc::Argon2Params,
                _password: &[u8],
                _salt: &[u8],
                _secret: &[u8],
                _ad: &[u8],
                out: &mut [u8],
            ) -> CryptoResult<()> {
                self.unit().map(|()| out.fill(0))
            }
        }

        impl sc::X25519 for $t {
            fn x25519_public_key(&self, _secret: &[u8; 32]) -> CryptoResult<[u8; 32]> {
                self.unit().map(|()| [0u8; 32])
            }
            fn x25519(
                &self,
                _secret: &[u8; 32],
                _peer_public: &[u8; 32],
                shared: &mut [u8; 32],
            ) -> CryptoResult<()> {
                self.unit().map(|()| *shared = [0u8; 32])
            }
        }
    };
}

impl_uniform!(Zeros);
impl_uniform!(AlwaysUnsupported);

// ---------------------------------------------------------------------------
// Targeted wrong doubles
// ---------------------------------------------------------------------------

/// A verifier that accepts everything (the positives pass; the negatives
/// must be caught).
struct AcceptAll;

impl sc::Ed25519Verify for AcceptAll {
    fn ed25519_validate_public_key(&self, _public_key: &[u8; 32]) -> CryptoResult<()> {
        Ok(())
    }
    fn ed25519_verify(
        &self,
        _public_key: &[u8; 32],
        _message: &[u8],
        _signature: &[u8; 64],
    ) -> CryptoResult<()> {
        Ok(())
    }
}

/// Like `Tabled`, but reports `Failed` where the contract demands
/// `AuthenticationFailed`.
struct WrongKind;

fn demote<T>(r: CryptoResult<T>) -> CryptoResult<T> {
    r.map_err(|e| {
        if e.kind() == CryptoErrorKind::AuthenticationFailed {
            failed()
        } else {
            e
        }
    })
}

impl sc::Ed25519Verify for WrongKind {
    fn ed25519_validate_public_key(&self, public_key: &[u8; 32]) -> CryptoResult<()> {
        Tabled.ed25519_validate_public_key(public_key)
    }
    fn ed25519_verify(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> CryptoResult<()> {
        demote(Tabled.ed25519_verify(public_key, message, signature))
    }
}

impl sc::HmacSha256 for WrongKind {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> CryptoResult<[u8; 32]> {
        Tabled.hmac_sha256(key, data)
    }
    fn hmac_sha256_verify(&self, key: &[u8], data: &[u8], tag: &[u8; 32]) -> CryptoResult<()> {
        demote(Tabled.hmac_sha256_verify(key, data, tag))
    }
}

impl sc::ChaCha20Poly1305 for WrongKind {
    fn chacha20poly1305_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; 16]> {
        Tabled.chacha20poly1305_seal(key, nonce, aad, buf)
    }
    fn chacha20poly1305_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> CryptoResult<()> {
        demote(Tabled.chacha20poly1305_open(key, nonce, aad, buf, tag))
    }
}

/// A converter that maps the positives correctly but accepts invalid keys
/// (returns a constant instead of `InvalidParameter`).
struct LaxConverter;

impl sc::Ed25519ToX25519 for LaxConverter {
    fn ed25519_public_to_x25519(&self, public_key: &[u8; 32]) -> CryptoResult<[u8; 32]> {
        Tabled
            .ed25519_public_to_x25519(public_key)
            .or(Ok([0u8; 32]))
    }
}

impl sc::Ed25519ToX25519 for WrongKind {
    fn ed25519_public_to_x25519(&self, public_key: &[u8; 32]) -> CryptoResult<[u8; 32]> {
        Tabled
            .ed25519_public_to_x25519(public_key)
            .map_err(|_| failed())
    }
}

/// An AEAD whose `open` writes the plaintext into the buffer *and then*
/// reports the authentication failure.
struct LeakyAead;

impl sc::ChaCha20Poly1305 for LeakyAead {
    fn chacha20poly1305_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; 16]> {
        Tabled.chacha20poly1305_seal(key, nonce, aad, buf)
    }
    fn chacha20poly1305_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> CryptoResult<()> {
        let r = Tabled.chacha20poly1305_open(key, nonce, aad, buf, tag);
        if r.is_err() {
            if let Some(v) = vectors::CHACHA20POLY1305.iter().find(|v| &v.key == key) {
                let n = buf.len().min(v.plaintext.len());
                buf[..n].copy_from_slice(&v.plaintext[..n]);
            }
        }
        r
    }
}

/// An X25519 that rejects low-order peers with the right kind but forgets
/// to zero the shared buffer.
struct UnzeroedX25519;

impl sc::X25519 for UnzeroedX25519 {
    fn x25519_public_key(&self, secret: &[u8; 32]) -> CryptoResult<[u8; 32]> {
        Tabled.x25519_public_key(secret)
    }
    fn x25519(
        &self,
        secret: &[u8; 32],
        peer_public: &[u8; 32],
        shared: &mut [u8; 32],
    ) -> CryptoResult<()> {
        let mut scratch = [0u8; 32];
        let r = Tabled.x25519(secret, peer_public, &mut scratch);
        if r.is_ok() {
            *shared = scratch;
        }
        r
    }
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

/// The harness must have failed with `InvalidParameter`; under `alloc` the
/// message must name the check and the first offending vector.
fn expect_failure(r: CryptoResult<()>, check: &str, vector: &str) -> CryptoError {
    let e = r.expect_err("harness accepted a wrong answer");
    assert_eq!(e.kind(), CryptoErrorKind::InvalidParameter);
    #[cfg(feature = "alloc")]
    {
        let m = e
            .message()
            .expect("harness errors carry a message under alloc");
        let prefix = format!("conformance {check}: {vector}: ");
        assert!(
            m.starts_with(&prefix),
            "expected prefix {prefix:?}, got {m:?}"
        );
    }
    #[cfg(not(feature = "alloc"))]
    let _ = (check, vector);
    e
}

#[cfg(feature = "alloc")]
fn assert_message_contains(e: &CryptoError, needle: &str) {
    let m = e
        .message()
        .expect("harness errors carry a message under alloc");
    assert!(m.contains(needle), "expected {needle:?} in {m:?}");
}

#[test]
fn tabled_passes_every_check() {
    conformance::check_sha256(&Tabled).unwrap();
    conformance::check_sha512(&Tabled).unwrap();
    conformance::check_hmac_sha256(&Tabled).unwrap();
    conformance::check_ed25519_verify(&Tabled).unwrap();
    conformance::check_ed25519_sign(&Tabled).unwrap();
    conformance::check_ed25519_roundtrip(&Tabled).unwrap();
    conformance::check_ed25519_to_x25519(&Tabled).unwrap();
    conformance::check_chacha20poly1305(&Tabled).unwrap();
    conformance::check_xchacha20poly1305(&Tabled).unwrap();
    conformance::check_hkdf_sha256(&Tabled).unwrap();
    conformance::check_argon2id(&Tabled).unwrap();
    conformance::check_x25519(&Tabled).unwrap();
    conformance::check_all(&Tabled).unwrap();
}

#[test]
fn checks_accept_trait_objects() {
    let d: &dyn sc::Sha256<State = TabledSha256State> = &Tabled;
    conformance::check_sha256(d).unwrap();
    let d: &dyn sc::Sha512<State = TabledSha512State> = &Tabled;
    conformance::check_sha512(d).unwrap();
    let h: &dyn sc::HmacSha256 = &Tabled;
    conformance::check_hmac_sha256(h).unwrap();
    let v: &dyn sc::Ed25519Verify = &Tabled;
    conformance::check_ed25519_verify(v).unwrap();
    let s: &dyn sc::Ed25519Sign = &Tabled;
    conformance::check_ed25519_sign(s).unwrap();
    let c: &dyn sc::Ed25519ToX25519 = &Tabled;
    conformance::check_ed25519_to_x25519(c).unwrap();
    let a: &dyn sc::ChaCha20Poly1305 = &Tabled;
    conformance::check_chacha20poly1305(a).unwrap();
    let a: &dyn sc::XChaCha20Poly1305 = &Tabled;
    conformance::check_xchacha20poly1305(a).unwrap();
    let k: &dyn sc::HkdfSha256 = &Tabled;
    conformance::check_hkdf_sha256(k).unwrap();
    let k: &dyn sc::Argon2id = &Tabled;
    conformance::check_argon2id(k).unwrap();
    let x: &dyn sc::X25519 = &Tabled;
    conformance::check_x25519(x).unwrap();
}

#[test]
fn zeros_fails_every_check_on_its_first_vector() {
    expect_failure(
        conformance::check_sha256(&Zeros),
        "check_sha256",
        vectors::SHA256[0].name,
    );
    expect_failure(
        conformance::check_sha512(&Zeros),
        "check_sha512",
        vectors::SHA512[0].name,
    );
    expect_failure(
        conformance::check_hmac_sha256(&Zeros),
        "check_hmac_sha256",
        vectors::HMAC_SHA256[0].name,
    );
    // Every verify succeeds, so the positives pass and the first reject
    // vector is where the harness must object.
    expect_failure(
        conformance::check_ed25519_verify(&Zeros),
        "check_ed25519_verify",
        vectors::ED25519_REJECT[0].name,
    );
    expect_failure(
        conformance::check_ed25519_sign(&Zeros),
        "check_ed25519_sign",
        vectors::ED25519[0].name,
    );
    expect_failure(
        conformance::check_ed25519_roundtrip(&Zeros),
        "check_ed25519_roundtrip",
        vectors::ED25519[0].name,
    );
    expect_failure(
        conformance::check_ed25519_to_x25519(&Zeros),
        "check_ed25519_to_x25519",
        vectors::ED25519_TO_X25519[0].name,
    );
    expect_failure(
        conformance::check_chacha20poly1305(&Zeros),
        "check_chacha20poly1305",
        vectors::CHACHA20POLY1305[0].name,
    );
    expect_failure(
        conformance::check_xchacha20poly1305(&Zeros),
        "check_xchacha20poly1305",
        vectors::XCHACHA20POLY1305[0].name,
    );
    expect_failure(
        conformance::check_hkdf_sha256(&Zeros),
        "check_hkdf_sha256",
        vectors::HKDF_SHA256[0].name,
    );
    expect_failure(
        conformance::check_argon2id(&Zeros),
        "check_argon2id",
        vectors::ARGON2ID[0].name,
    );
    expect_failure(
        conformance::check_x25519(&Zeros),
        "check_x25519",
        vectors::X25519[0].name,
    );
    expect_failure(
        conformance::check_all(&Zeros),
        "check_sha256",
        vectors::SHA256[0].name,
    );
}

#[test]
fn accept_all_fails_on_the_first_reject_vector() {
    let e = expect_failure(
        conformance::check_ed25519_verify(&AcceptAll),
        "check_ed25519_verify",
        vectors::ED25519_REJECT[0].name,
    );
    #[cfg(feature = "alloc")]
    assert_message_contains(&e, "expected `authentication failed`, backend returned Ok");
    let _ = e;
}

#[test]
fn lax_converter_is_caught() {
    let e = expect_failure(
        conformance::check_ed25519_to_x25519(&LaxConverter),
        "check_ed25519_to_x25519",
        vectors::ED25519_INVALID_PUBLIC_KEYS[0].name,
    );
    #[cfg(feature = "alloc")]
    assert_message_contains(&e, "expected `invalid parameter`, backend returned Ok");
    let _ = e;
}

#[test]
fn wrong_error_kind_is_a_conformance_failure() {
    let e = expect_failure(
        conformance::check_ed25519_verify(&WrongKind),
        "check_ed25519_verify",
        vectors::ED25519_REJECT[0].name,
    );
    #[cfg(feature = "alloc")]
    assert_message_contains(
        &e,
        "expected `authentication failed`, backend returned `crypto operation failed`",
    );
    let _ = e;

    expect_failure(
        conformance::check_hmac_sha256(&WrongKind),
        "check_hmac_sha256",
        vectors::HMAC_SHA256[0].name,
    );
    expect_failure(
        conformance::check_chacha20poly1305(&WrongKind),
        "check_chacha20poly1305",
        vectors::CHACHA20POLY1305[0].name,
    );
    expect_failure(
        conformance::check_ed25519_to_x25519(&WrongKind),
        "check_ed25519_to_x25519",
        vectors::ED25519_INVALID_PUBLIC_KEYS[0].name,
    );
}

#[test]
fn plaintext_exposure_on_failed_open_is_caught() {
    let e = expect_failure(
        conformance::check_chacha20poly1305(&LeakyAead),
        "check_chacha20poly1305",
        vectors::CHACHA20POLY1305[0].name,
    );
    #[cfg(feature = "alloc")]
    assert_message_contains(&e, "plaintext exposure");
    let _ = e;
}

#[test]
fn unzeroed_shared_secret_on_low_order_peer_is_caught() {
    let e = expect_failure(
        conformance::check_x25519(&UnzeroedX25519),
        "check_x25519",
        vectors::X25519_LOW_ORDER_PEERS[0].name,
    );
    #[cfg(feature = "alloc")]
    assert_message_contains(&e, "not all-zero");
    let _ = e;
}

#[test]
fn unsupported_is_a_conformance_failure_everywhere() {
    let results = [
        conformance::check_sha256(&AlwaysUnsupported),
        conformance::check_sha512(&AlwaysUnsupported),
        conformance::check_hmac_sha256(&AlwaysUnsupported),
        conformance::check_ed25519_verify(&AlwaysUnsupported),
        conformance::check_ed25519_sign(&AlwaysUnsupported),
        conformance::check_ed25519_roundtrip(&AlwaysUnsupported),
        conformance::check_ed25519_to_x25519(&AlwaysUnsupported),
        conformance::check_chacha20poly1305(&AlwaysUnsupported),
        conformance::check_xchacha20poly1305(&AlwaysUnsupported),
        conformance::check_hkdf_sha256(&AlwaysUnsupported),
        conformance::check_argon2id(&AlwaysUnsupported),
        conformance::check_x25519(&AlwaysUnsupported),
        conformance::check_all(&AlwaysUnsupported),
    ];
    for r in results {
        let e = r.expect_err("Unsupported must never pass a check");
        assert_eq!(e.kind(), CryptoErrorKind::InvalidParameter);
        #[cfg(feature = "alloc")]
        assert_message_contains(&e, "unsupported operation");
    }
}
