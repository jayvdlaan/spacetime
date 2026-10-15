//! Test-only real backend (contract §0 D10): `sha2` + `ed25519-dalek`
//! behind the `spacetime-crypto` facades, implemented exactly as
//! `airframe_crypt`'s `backend_rustcrypto/spacetime_facade.rs` does. Dev
//! dependency only; `src/` never sees a concrete primitive.

use sha2::Digest;
use spacetime_crypto::{self as st, CryptoError, CryptoErrorKind, CryptoResult};

/// The RustCrypto primitives viewed through the facade traits.
pub struct DalekBackend;

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

impl st::Ed25519Verify for DalekBackend {
    /// V3 (canonical: `to_bytes() == input`), V4 (not small-order) and
    /// prime order (`is_torsion_free`) — every failure is `InvalidParameter`.
    fn ed25519_validate_public_key(
        &self,
        public_key: &[u8; st::ED25519_PUBLIC_KEY_LEN],
    ) -> CryptoResult<()> {
        let invalid = || CryptoError::new(CryptoErrorKind::InvalidParameter);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|_| invalid())?;
        if vk.to_bytes() != *public_key {
            return Err(invalid());
        }
        let point = vk.to_edwards();
        if point.is_small_order() || !point.is_torsion_free() {
            return Err(invalid());
        }
        Ok(())
    }

    /// Strict profile: V3 by the bytewise re-encoding check, V1/V2/V4–V6 by
    /// `verify_strict`; every input-caused failure is `AuthenticationFailed`.
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
