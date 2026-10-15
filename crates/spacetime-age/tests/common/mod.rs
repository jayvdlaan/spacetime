//! Test-only real backend (contract §0 D13): RustCrypto primitives behind
//! the `spacetime-crypto` facades, implemented as `airframe_crypt`'s
//! `backend_rustcrypto/spacetime_facade.rs` does. Dev dependency only;
//! `src/` never sees a concrete primitive. `tests/backend_conformance.rs`
//! proves this backend with the facade's RFC harness before any other test
//! trusts it as an oracle.
//!
//! Only what every test binary uses lives here (an item unused by one
//! binary is dead code there); the counter RNG of the encrypt-side
//! binaries is `rng.rs`.

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::KeyInit;
use sha2::Digest;
use spacetime_crypto::{self as st, CryptoError, CryptoErrorKind, CryptoResult};

/// The RustCrypto primitives viewed through the facade traits.
pub struct DalekBackend;

fn invalid() -> CryptoError {
    CryptoError::new(CryptoErrorKind::InvalidParameter)
}

fn auth_failed() -> CryptoError {
    CryptoError::new(CryptoErrorKind::AuthenticationFailed)
}

pub struct Sha256State(sha2::Sha256);
pub struct Sha512State(sha2::Sha512);

impl st::Sha256State for Sha256State {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        Digest::update(&mut self.0, data);
        Ok(())
    }
    fn finalize(&mut self) -> CryptoResult<[u8; st::SHA256_LEN]> {
        Ok(self.0.finalize_reset().into())
    }
}

impl st::Sha512State for Sha512State {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        Digest::update(&mut self.0, data);
        Ok(())
    }
    fn finalize(&mut self) -> CryptoResult<[u8; st::SHA512_LEN]> {
        Ok(self.0.finalize_reset().into())
    }
}

impl st::Sha256 for DalekBackend {
    type State = Sha256State;
    fn sha256_init(&self) -> CryptoResult<Self::State> {
        Ok(Sha256State(sha2::Sha256::new()))
    }
}

impl st::Sha512 for DalekBackend {
    type State = Sha512State;
    fn sha512_init(&self) -> CryptoResult<Self::State> {
        Ok(Sha512State(sha2::Sha512::new()))
    }
}

impl st::HmacSha256 for DalekBackend {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> CryptoResult<[u8; st::HMAC_SHA256_LEN]> {
        use hmac::Mac;
        let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
            .map_err(|_| CryptoError::new(CryptoErrorKind::Failed))?;
        m.update(data);
        Ok(m.finalize().into_bytes().into())
    }

    fn hmac_sha256_verify(
        &self,
        key: &[u8],
        data: &[u8],
        tag: &[u8; st::HMAC_SHA256_LEN],
    ) -> CryptoResult<()> {
        use hmac::Mac;
        let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
            .map_err(|_| CryptoError::new(CryptoErrorKind::Failed))?;
        m.update(data);
        m.verify_slice(tag).map_err(|_| auth_failed())
    }
}

impl st::HkdfSha256 for DalekBackend {
    fn hkdf_sha256_extract(
        &self,
        salt: &[u8],
        ikm: &[u8],
        prk: &mut [u8; st::HKDF_SHA256_PRK_LEN],
    ) -> CryptoResult<()> {
        let (out, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
        prk.copy_from_slice(&out);
        Ok(())
    }

    fn hkdf_sha256_expand(
        &self,
        prk: &[u8; st::HKDF_SHA256_PRK_LEN],
        info: &[u8],
        okm: &mut [u8],
    ) -> CryptoResult<()> {
        if okm.len() > st::HKDF_SHA256_MAX_OKM_LEN {
            return Err(invalid());
        }
        let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).map_err(|_| invalid())?;
        hk.expand(info, okm).map_err(|_| invalid())
    }
}

impl st::ChaCha20Poly1305 for DalekBackend {
    fn chacha20poly1305_seal(
        &self,
        key: &[u8; st::AEAD_KEY_LEN],
        nonce: &[u8; st::CHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; st::AEAD_TAG_LEN]> {
        let c = chacha20poly1305::ChaCha20Poly1305::new(key.into());
        let tag = c
            .encrypt_in_place_detached(nonce.into(), aad, buf)
            .map_err(|_| CryptoError::new(CryptoErrorKind::Failed))?;
        Ok(tag.into())
    }

    /// On failure `buf` is untouched by a failed detached decrypt (the
    /// crate verifies the tag before applying the keystream), which
    /// satisfies "exactly the ciphertext bytes the caller passed in".
    fn chacha20poly1305_open(
        &self,
        key: &[u8; st::AEAD_KEY_LEN],
        nonce: &[u8; st::CHACHA20POLY1305_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; st::AEAD_TAG_LEN],
    ) -> CryptoResult<()> {
        let c = chacha20poly1305::ChaCha20Poly1305::new(key.into());
        c.decrypt_in_place_detached(nonce.into(), aad, buf, tag.into())
            .map_err(|_| auth_failed())
    }
}

impl st::X25519 for DalekBackend {
    fn x25519_public_key(
        &self,
        secret: &[u8; st::X25519_KEY_LEN],
    ) -> CryptoResult<[u8; st::X25519_KEY_LEN]> {
        let sk = x25519_dalek::StaticSecret::from(*secret);
        Ok(x25519_dalek::PublicKey::from(&sk).to_bytes())
    }

    fn x25519(
        &self,
        secret: &[u8; st::X25519_KEY_LEN],
        peer_public: &[u8; st::X25519_KEY_LEN],
        shared: &mut [u8; st::X25519_KEY_LEN],
    ) -> CryptoResult<()> {
        let sk = x25519_dalek::StaticSecret::from(*secret);
        let ss = sk.diffie_hellman(&x25519_dalek::PublicKey::from(*peer_public));
        if !ss.was_contributory() {
            *shared = [0u8; 32];
            return Err(invalid());
        }
        *shared = *ss.as_bytes();
        Ok(())
    }
}

impl st::Ed25519Sign for DalekBackend {
    fn ed25519_public_key(
        &self,
        seed: &[u8; st::ED25519_SEED_LEN],
    ) -> CryptoResult<[u8; st::ED25519_PUBLIC_KEY_LEN]> {
        Ok(ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes())
    }

    fn ed25519_sign(
        &self,
        seed: &[u8; st::ED25519_SEED_LEN],
        message: &[u8],
    ) -> CryptoResult<[u8; st::ED25519_SIGNATURE_LEN]> {
        let sk = ed25519_dalek::SigningKey::from_bytes(seed);
        Ok(ed25519_dalek::Signer::sign(&sk, message).to_bytes())
    }
}

/// Canonical (`to_bytes() == input`), not small-order, torsion-free; every
/// failure is `InvalidParameter`.
fn decode_strict(public_key: &[u8; 32]) -> CryptoResult<ed25519_dalek::VerifyingKey> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|_| invalid())?;
    if vk.to_bytes() != *public_key {
        return Err(invalid());
    }
    let point = vk.to_edwards();
    if point.is_small_order() || !point.is_torsion_free() {
        return Err(invalid());
    }
    Ok(vk)
}

impl st::Ed25519Verify for DalekBackend {
    fn ed25519_validate_public_key(
        &self,
        public_key: &[u8; st::ED25519_PUBLIC_KEY_LEN],
    ) -> CryptoResult<()> {
        decode_strict(public_key).map(|_| ())
    }

    fn ed25519_verify(
        &self,
        public_key: &[u8; st::ED25519_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; st::ED25519_SIGNATURE_LEN],
    ) -> CryptoResult<()> {
        let failed = || CryptoError::new(CryptoErrorKind::AuthenticationFailed);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|_| failed())?;
        if vk.to_bytes() != *public_key {
            return Err(failed());
        }
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        vk.verify_strict(message, &sig).map_err(|_| failed())
    }
}

impl st::Ed25519ToX25519 for DalekBackend {
    fn ed25519_public_to_x25519(
        &self,
        public_key: &[u8; st::ED25519_PUBLIC_KEY_LEN],
    ) -> CryptoResult<[u8; st::X25519_KEY_LEN]> {
        Ok(decode_strict(public_key)?.to_montgomery().to_bytes())
    }
}

/// Decode a hex string (test manifests only).
pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Decode a 32-byte hex string.
pub fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32 bytes")
}
