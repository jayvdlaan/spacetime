//! The `alloc` conveniences against the buffer API and the vector corpus
//! (`required-features = ["alloc"]`).

mod common;

use common::{hex, hex32, DalekBackend};
use serde_json::Value;
use spacetime_sshsig::{
    armor, sign, sign_armored, sign_armored_string, sign_vec, verify, AllowedSignerBuf,
    AllowedSigners, Expected, PublicKeyBuf, SshSig, VerifiedBuf,
};

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/");
const MANIFEST: &str = include_str!("vectors/manifest.json");

fn manifest() -> Value {
    serde_json::from_str(MANIFEST).expect("manifest.json parses")
}

fn read(rel: &str) -> Vec<u8> {
    let path = format!("{VECTORS}{rel}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn read_string(rel: &str) -> String {
    String::from_utf8(read(rel)).expect("utf-8")
}

#[test]
fn sign_alloc_forms_equal_buffer_api() {
    let m = manifest();
    let seed = hex32(m["keys"]["a"]["seed_hex"].as_str().unwrap());
    let ns = m["namespace"].as_str().unwrap();
    let message = read(m["messages"]["hello"].as_str().unwrap());

    let mut raw = [0u8; 1024];
    let n = sign(&DalekBackend, &seed, ns, &message, &mut raw).unwrap();
    assert_eq!(
        sign_vec(&DalekBackend, &seed, ns, &message).unwrap(),
        &raw[..n]
    );

    let mut armored = [0u8; 1024];
    let a = sign_armored(&DalekBackend, &seed, ns, &message, &mut armored).unwrap();
    let s = sign_armored_string(&DalekBackend, &seed, ns, &message).unwrap();
    assert_eq!(s.as_bytes(), &armored[..a]);
    assert_eq!(s.as_bytes(), &read("sigs/ok_ed25519_hello.sig")[..]);

    // encode_vec / encode_armored round-trip the parsed signature.
    let parsed = SshSig::parse(&raw[..n]).unwrap();
    assert_eq!(parsed.encode_vec(), &raw[..n]);
    assert_eq!(parsed.encode_armored(), s);
}

#[test]
fn armor_alloc_forms() {
    let armored = read("sigs/ok_ed25519_hello.sig");
    let blob = armor::decode_vec(&armored).unwrap();
    let mut buf = [0u8; 1024];
    let n = armor::decode(&armored, &mut buf).unwrap();
    assert_eq!(blob, &buf[..n]);
    assert_eq!(armor::encode_string(&blob).as_bytes(), &armored[..]);
    assert_eq!(armor::base64_decode_vec(b"U1NIU0lH").unwrap(), b"SSHSIG");
}

#[test]
fn public_key_buf_lines() {
    let m = manifest();
    for k in ["a", "b", "c"] {
        let line = read_string(m["keys"][k]["public_file"].as_str().unwrap());
        let (key, comment) = PublicKeyBuf::parse_line(&line).unwrap();
        assert_eq!(
            comment.as_deref(),
            Some(format!("spacetime-sshsig-{k}").as_str())
        );
        assert_eq!(
            key.as_key().key(),
            &hex32(m["keys"][k]["public_key_hex"].as_str().unwrap())
        );
        // `to_line` is the line without the comment.
        let want = line.trim_end().rsplit_once(' ').unwrap().0;
        assert_eq!(key.to_line(), want, "key {k}");
        assert_eq!(
            key.as_key().fingerprint_string(&DalekBackend).unwrap(),
            m["keys"][k]["fingerprint"].as_str().unwrap()
        );
        assert_eq!(key.as_key().to_buf(), key);
    }
    let c = hex(m["keys"]["c"]["public_key_hex"].as_str().unwrap());
    let (key, _) = PublicKeyBuf::parse_line(&read_string("keys/c.pub")).unwrap();
    assert_eq!(
        key,
        PublicKeyBuf::SkEd25519 {
            key: c.try_into().unwrap(),
            application: b"ssh:".to_vec()
        }
    );
}

#[test]
fn verified_to_buf() {
    let m = manifest();
    let ns = m["namespace"].as_str().unwrap();
    let message = read(m["messages"]["hello"].as_str().unwrap());
    for (sig, key) in [
        ("sigs/ok_ed25519_hello.sig", "a"),
        ("sigs/ok_sk_up.sig", "c"),
    ] {
        let blob = armor::decode_vec(&read(sig)).unwrap();
        let parsed = SshSig::parse(&blob).unwrap();
        let (want_key, _) = PublicKeyBuf::parse_line(&read_string(
            m["keys"][key]["public_file"].as_str().unwrap(),
        ))
        .unwrap();
        let v = verify(&DalekBackend, &parsed, &Expected::new(ns), &message).unwrap();
        let owned: VerifiedBuf = v.to_buf();
        assert_eq!(owned.public_key, want_key);
        assert_eq!(owned.sk, v.sk());
        assert_eq!(owned.sk.is_some(), key == "c");
    }
}

#[test]
fn allowed_signer_to_buf_on_fixture() {
    let m = manifest();
    let text = read_string(m["allowed_signers"]["file"].as_str().unwrap());
    let entries = m["allowed_signers"]["entries"].as_array().unwrap();
    let got: Vec<AllowedSignerBuf> = AllowedSigners::new(&text)
        .map(|r| r.unwrap().to_buf().unwrap())
        .collect();
    assert_eq!(got.len(), entries.len());
    for (g, want) in got.iter().zip(entries) {
        let strings = |v: &Value| -> Option<Vec<String>> {
            v.as_array()
                .map(|a| a.iter().map(|s| s.as_str().unwrap().to_owned()).collect())
        };
        assert_eq!(Some(g.principals.clone()), strings(&want["principals"]));
        assert_eq!(g.cert_authority, want["cert_authority"].as_bool().unwrap());
        let ns = m["namespace"].as_str().unwrap();
        for p in &g.principals {
            let windowed = g.valid_after.is_some() || g.valid_before.is_some();
            assert_eq!(
                g.accepts(p, ns),
                !g.cert_authority && !windowed && g.allows_namespace(ns)
            );
        }
        assert_eq!(g.namespaces, strings(&want["namespaces"]));
        assert_eq!(g.valid_after.as_deref(), want["valid_after"].as_str());
        assert_eq!(g.valid_before.as_deref(), want["valid_before"].as_str());
        assert_eq!(g.comment.as_deref(), want["comment"].as_str());
        let k = want["key"].as_str().unwrap();
        let (want_key, _) =
            PublicKeyBuf::parse_line(&read_string(m["keys"][k]["public_file"].as_str().unwrap()))
                .unwrap();
        assert_eq!(g.key, want_key);
    }
}
