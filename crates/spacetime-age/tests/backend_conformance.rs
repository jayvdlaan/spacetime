//! Proves the test-only `DalekBackend` with the `spacetime-crypto`
//! conformance harness before any other test uses it as an oracle, and
//! runs the committed Edwards→Montgomery vectors through it.

mod common;

use common::{hex32, DalekBackend};
use serde_json::Value;
use spacetime_crypto::conformance;
use spacetime_crypto::{CryptoErrorKind, Ed25519ToX25519};

#[test]
fn sha256() {
    conformance::check_sha256(&DalekBackend).unwrap();
}

#[test]
fn sha512() {
    conformance::check_sha512(&DalekBackend).unwrap();
}

#[test]
fn hmac_sha256() {
    conformance::check_hmac_sha256(&DalekBackend).unwrap();
}

#[test]
fn ed25519_verify() {
    conformance::check_ed25519_verify(&DalekBackend).unwrap();
}

#[test]
fn ed25519_sign() {
    conformance::check_ed25519_sign(&DalekBackend).unwrap();
}

#[test]
fn ed25519_roundtrip() {
    conformance::check_ed25519_roundtrip(&DalekBackend).unwrap();
}

#[test]
fn chacha20poly1305() {
    conformance::check_chacha20poly1305(&DalekBackend).unwrap();
}

#[test]
fn hkdf_sha256() {
    conformance::check_hkdf_sha256(&DalekBackend).unwrap();
}

#[test]
fn x25519() {
    conformance::check_x25519(&DalekBackend).unwrap();
}

#[test]
fn ed25519_to_x25519() {
    conformance::check_ed25519_to_x25519(&DalekBackend).unwrap();
}

#[test]
fn ed25519_to_x25519_json_vectors() {
    let j: Value = serde_json::from_str(include_str!("vectors/rage/ed25519_to_x25519.json"))
        .expect("ed25519_to_x25519.json parses");
    let vectors = j["vectors"].as_array().expect("vectors");
    assert_eq!(vectors.len(), 5);
    for v in vectors {
        let pk = hex32(v["ed25519_public_hex"].as_str().unwrap());
        let want = hex32(v["x25519_public_hex"].as_str().unwrap());
        let got = DalekBackend.ed25519_public_to_x25519(&pk).unwrap();
        assert_eq!(got, want, "{}", v["name"]);
    }
    let invalid = j["invalid"].as_array().expect("invalid");
    assert_eq!(invalid.len(), 5);
    for v in invalid {
        let pk = hex32(v["ed25519_public_hex"].as_str().unwrap());
        let e = DalekBackend.ed25519_public_to_x25519(&pk).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::InvalidParameter, "{}", v["name"]);
    }
}
