//! Object-safety and no-alloc implementability witness for every facade
//! trait.
//!
//! Runs with the crate's default features (no `std`, no `alloc`, no
//! `conformance`), so `cargo test --workspace` exercises it on every gate
//! run. `Nil` is a unit struct that implements every trait in the crate root's
//! object-safety table with constant answers — it is a shape witness, not a
//! backend. Each row of that table is asserted by coercing `&Nil` to the
//! `&dyn Trait` the table promises, and every *provided* method is called
//! once through the trait object so its dyn-dispatchability is compiled in,
//! not just claimed.

use spacetime_crypto as sc;
use spacetime_crypto::{CryptoResult, EntropySource, Rng};

/// Shape witness: implements every facade trait with constant answers.
struct Nil;

/// Streaming state for the digest traits: carries nothing.
struct NilState;

impl sc::Sha256State for NilState {
    fn update(&mut self, _data: &[u8]) -> CryptoResult<()> {
        Ok(())
    }
    fn finalize(&mut self) -> CryptoResult<[u8; sc::SHA256_LEN]> {
        Ok([0; sc::SHA256_LEN])
    }
}

impl sc::Sha256 for Nil {
    type State = NilState;
    fn sha256_init(&self) -> CryptoResult<Self::State> {
        Ok(NilState)
    }
}

impl sc::Sha512State for NilState {
    fn update(&mut self, _data: &[u8]) -> CryptoResult<()> {
        Ok(())
    }
    fn finalize(&mut self) -> CryptoResult<[u8; sc::SHA512_LEN]> {
        Ok([0; sc::SHA512_LEN])
    }
}

impl sc::Sha512 for Nil {
    type State = NilState;
    fn sha512_init(&self) -> CryptoResult<Self::State> {
        Ok(NilState)
    }
}

impl sc::HmacSha256 for Nil {
    fn hmac_sha256(&self, _key: &[u8], _data: &[u8]) -> CryptoResult<[u8; sc::HMAC_SHA256_LEN]> {
        Ok([0; sc::HMAC_SHA256_LEN])
    }
    fn hmac_sha256_verify(
        &self,
        _key: &[u8],
        _data: &[u8],
        _tag: &[u8; sc::HMAC_SHA256_LEN],
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl sc::Ed25519Verify for Nil {
    fn ed25519_validate_public_key(
        &self,
        _public_key: &[u8; sc::ED25519_PUBLIC_KEY_LEN],
    ) -> CryptoResult<()> {
        Ok(())
    }
    fn ed25519_verify(
        &self,
        _public_key: &[u8; sc::ED25519_PUBLIC_KEY_LEN],
        _message: &[u8],
        _signature: &[u8; sc::ED25519_SIGNATURE_LEN],
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl sc::Ed25519Sign for Nil {
    fn ed25519_public_key(
        &self,
        _seed: &[u8; sc::ED25519_SEED_LEN],
    ) -> CryptoResult<[u8; sc::ED25519_PUBLIC_KEY_LEN]> {
        Ok([0; sc::ED25519_PUBLIC_KEY_LEN])
    }
    fn ed25519_sign(
        &self,
        _seed: &[u8; sc::ED25519_SEED_LEN],
        _message: &[u8],
    ) -> CryptoResult<[u8; sc::ED25519_SIGNATURE_LEN]> {
        Ok([0; sc::ED25519_SIGNATURE_LEN])
    }
}

impl sc::Ed25519ToX25519 for Nil {
    fn ed25519_public_to_x25519(
        &self,
        _public_key: &[u8; sc::ED25519_PUBLIC_KEY_LEN],
    ) -> CryptoResult<[u8; sc::X25519_KEY_LEN]> {
        Ok([0; sc::X25519_KEY_LEN])
    }
}

impl sc::ChaCha20Poly1305 for Nil {
    fn chacha20poly1305_seal(
        &self,
        _key: &[u8; sc::AEAD_KEY_LEN],
        _nonce: &[u8; sc::CHACHA20POLY1305_NONCE_LEN],
        _aad: &[u8],
        _buf: &mut [u8],
    ) -> CryptoResult<[u8; sc::AEAD_TAG_LEN]> {
        Ok([0; sc::AEAD_TAG_LEN])
    }
    fn chacha20poly1305_open(
        &self,
        _key: &[u8; sc::AEAD_KEY_LEN],
        _nonce: &[u8; sc::CHACHA20POLY1305_NONCE_LEN],
        _aad: &[u8],
        _buf: &mut [u8],
        _tag: &[u8; sc::AEAD_TAG_LEN],
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl sc::XChaCha20Poly1305 for Nil {
    fn xchacha20poly1305_seal(
        &self,
        _key: &[u8; sc::AEAD_KEY_LEN],
        _nonce: &[u8; sc::XCHACHA20POLY1305_NONCE_LEN],
        _aad: &[u8],
        _buf: &mut [u8],
    ) -> CryptoResult<[u8; sc::AEAD_TAG_LEN]> {
        Ok([0; sc::AEAD_TAG_LEN])
    }
    fn xchacha20poly1305_open(
        &self,
        _key: &[u8; sc::AEAD_KEY_LEN],
        _nonce: &[u8; sc::XCHACHA20POLY1305_NONCE_LEN],
        _aad: &[u8],
        _buf: &mut [u8],
        _tag: &[u8; sc::AEAD_TAG_LEN],
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl sc::HkdfSha256 for Nil {
    fn hkdf_sha256_extract(
        &self,
        _salt: &[u8],
        _ikm: &[u8],
        prk: &mut [u8; sc::HKDF_SHA256_PRK_LEN],
    ) -> CryptoResult<()> {
        *prk = [0; sc::HKDF_SHA256_PRK_LEN];
        Ok(())
    }
    fn hkdf_sha256_expand(
        &self,
        _prk: &[u8; sc::HKDF_SHA256_PRK_LEN],
        _info: &[u8],
        okm: &mut [u8],
    ) -> CryptoResult<()> {
        okm.fill(0);
        Ok(())
    }
}

impl sc::Argon2id for Nil {
    fn argon2id(
        &self,
        params: &sc::Argon2Params,
        _password: &[u8],
        _salt: &[u8],
        _secret: &[u8],
        _ad: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        params.validate()?;
        out.fill(0);
        Ok(())
    }
}

impl sc::X25519 for Nil {
    fn x25519_public_key(
        &self,
        _secret: &[u8; sc::X25519_KEY_LEN],
    ) -> CryptoResult<[u8; sc::X25519_KEY_LEN]> {
        Ok([0; sc::X25519_KEY_LEN])
    }
    fn x25519(
        &self,
        _secret: &[u8; sc::X25519_KEY_LEN],
        _peer_public: &[u8; sc::X25519_KEY_LEN],
        shared: &mut [u8; sc::X25519_KEY_LEN],
    ) -> CryptoResult<()> {
        *shared = [0; sc::X25519_KEY_LEN];
        Ok(())
    }
}

impl Rng for Nil {
    fn fill_bytes(&mut self, out: &mut [u8]) -> CryptoResult<()> {
        out.fill(0);
        Ok(())
    }
}

impl EntropySource for Nil {
    fn try_read(&mut self, out: &mut [u8]) -> CryptoResult<usize> {
        out.fill(0);
        Ok(out.len())
    }
}

// One assertion per row of the crate-root object-safety table: each
// function only type-checks if the trait is dyn-compatible in the stated
// form. They are called from the tests below so the file has no dead code.
fn dyn_sha256(_: &dyn sc::Sha256<State = NilState>) {}
fn dyn_sha512(_: &dyn sc::Sha512<State = NilState>) {}
fn dyn_sha256_state(_: &mut dyn sc::Sha256State) {}
fn dyn_sha512_state(_: &mut dyn sc::Sha512State) {}
fn dyn_hmac(_: &dyn sc::HmacSha256) {}
fn dyn_ed25519_verify(_: &dyn sc::Ed25519Verify) {}
fn dyn_ed25519_sign(_: &dyn sc::Ed25519Sign) {}
fn dyn_ed25519_to_x25519(_: &dyn sc::Ed25519ToX25519) {}
fn dyn_chacha(_: &dyn sc::ChaCha20Poly1305) {}
fn dyn_xchacha(_: &dyn sc::XChaCha20Poly1305) {}
fn dyn_hkdf(_: &dyn sc::HkdfSha256) {}
fn dyn_argon2id(_: &dyn sc::Argon2id) {}
fn dyn_x25519(_: &dyn sc::X25519) {}
fn dyn_rng(_: &mut dyn Rng) {}
fn dyn_entropy(_: &mut dyn EntropySource) {}

#[test]
fn every_table_row_coerces_to_a_trait_object() {
    let mut nil = Nil;
    let mut st = NilState;
    dyn_sha256(&nil);
    dyn_sha512(&nil);
    dyn_sha256_state(&mut st);
    dyn_sha512_state(&mut st);
    dyn_hmac(&nil);
    dyn_ed25519_verify(&nil);
    dyn_ed25519_sign(&nil);
    dyn_ed25519_to_x25519(&nil);
    dyn_chacha(&nil);
    dyn_xchacha(&nil);
    dyn_hkdf(&nil);
    dyn_argon2id(&nil);
    dyn_x25519(&nil);
    dyn_rng(&mut nil);
    dyn_entropy(&mut nil);
}

#[test]
fn provided_digest_one_shots_dispatch_through_dyn() {
    let d256: &dyn sc::Sha256<State = NilState> = &Nil;
    assert_eq!(d256.sha256(b"abc").unwrap(), [0; sc::SHA256_LEN]);
    let d512: &dyn sc::Sha512<State = NilState> = &Nil;
    assert_eq!(d512.sha512(b"abc").unwrap(), [0; sc::SHA512_LEN]);
}

#[test]
fn provided_aead_two_buffer_forms_dispatch_through_dyn() {
    let key = [0u8; sc::AEAD_KEY_LEN];
    let pt = [1u8; 8];
    let mut sealed = [0u8; 8 + sc::AEAD_TAG_LEN];
    let mut out = [0xAAu8; 8];

    let c: &dyn sc::ChaCha20Poly1305 = &Nil;
    let nonce = [0u8; sc::CHACHA20POLY1305_NONCE_LEN];
    let n = c
        .chacha20poly1305_seal_into(&key, &nonce, &[], &pt, &mut sealed)
        .unwrap();
    assert_eq!(n, 8 + sc::AEAD_TAG_LEN);
    let m = c
        .chacha20poly1305_open_into(&key, &nonce, &[], &sealed, &mut out)
        .unwrap();
    assert_eq!(m, 8);
    assert_eq!(out, pt);

    let x: &dyn sc::XChaCha20Poly1305 = &Nil;
    let xnonce = [0u8; sc::XCHACHA20POLY1305_NONCE_LEN];
    let n = x
        .xchacha20poly1305_seal_into(&key, &xnonce, &[], &pt, &mut sealed)
        .unwrap();
    assert_eq!(n, 8 + sc::AEAD_TAG_LEN);
    let m = x
        .xchacha20poly1305_open_into(&key, &xnonce, &[], &sealed, &mut out)
        .unwrap();
    assert_eq!(m, 8);
    assert_eq!(out, pt);
}

#[test]
fn provided_hkdf_combinator_dispatches_through_dyn() {
    let k: &dyn sc::HkdfSha256 = &Nil;
    let mut okm = [0xAAu8; 16];
    k.hkdf_sha256(&[], b"ikm", b"info", &mut okm).unwrap();
    assert_eq!(okm, [0u8; 16]);
}

#[test]
fn required_methods_dispatch_through_dyn_without_alloc() {
    let nil = Nil;
    let h: &dyn sc::HmacSha256 = &nil;
    assert!(h.hmac_sha256_verify(b"k", b"d", &[0; 32]).is_ok());
    let v: &dyn sc::Ed25519Verify = &nil;
    assert!(v.ed25519_verify(&[0; 32], b"m", &[0; 64]).is_ok());
    let s: &dyn sc::Ed25519Sign = &nil;
    assert_eq!(s.ed25519_public_key(&[0; 32]).unwrap(), [0; 32]);
    let a: &dyn sc::Argon2id = &nil;
    let mut out = [0xAAu8; 4];
    a.argon2id(
        &sc::Argon2Params::new(32, 3, 4),
        b"pw",
        b"saltsalt",
        &[],
        &[],
        &mut out,
    )
    .unwrap();
    assert_eq!(out, [0u8; 4]);
    let x: &dyn sc::X25519 = &nil;
    let mut shared = [0xAAu8; 32];
    x.x25519(&[0; 32], &[0; 32], &mut shared).unwrap();
    assert_eq!(shared, [0u8; 32]);
}
