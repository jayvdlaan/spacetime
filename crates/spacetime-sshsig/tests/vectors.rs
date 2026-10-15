//! The committed vector corpus (`tests/vectors/manifest.json`) run through
//! the crate's real `parse` / `verify` / `sign` with the test backend.
//!
//! Runs with the crate's default features and uses ONLY the caller-buffer
//! API, so it proves the `no_std` surface end to end. Never shells out:
//! `ssh-keygen` is not needed.

mod common;

use common::{hex32, DalekBackend};
use serde_json::Value;
use spacetime_crypto::{Sha512, Sha512State};
use spacetime_sshsig::pubkey::parse_public_key_line;
use spacetime_sshsig::{
    armor, sign_armored, verify, verify_digest, AllowedSigner, AllowedSigners, Error, Expected,
    PublicKey, SkAttestation, SkPolicy, SshSig, FINGERPRINT_LEN, SK_FLAG_USER_PRESENCE,
    SK_FLAG_USER_VERIFICATION,
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

fn vectors(m: &Value) -> &[Value] {
    m["vectors"].as_array().expect("vectors array")
}

fn message_of(m: &Value, v: &Value) -> Vec<u8> {
    let key = v["message"].as_str().expect("message");
    read(m["messages"][key].as_str().expect("message path"))
}

/// The manifest key's `.pub` line, parsed into `buf`.
fn key_of<'b>(m: &Value, name: &str, buf: &'b mut [u8]) -> PublicKey<'b> {
    let line = read_string(
        m["keys"][name]["public_file"]
            .as_str()
            .expect("public_file"),
    );
    parse_public_key_line(&line, buf).expect("key line").key
}

/// Decode + parse into `buf`; `Err(name)` on the first failure.
fn parse_into<'b>(armored: &[u8], buf: &'b mut [u8; 1024]) -> Result<SshSig<'b>, Error> {
    let n = armor::decode(armored, buf)?;
    let blob: &'b [u8] = &buf[..n];
    SshSig::parse(blob)
}

fn expect_str<'a>(v: &'a Value, which: &str) -> &'a str {
    v["expect"][which]
        .as_str()
        .unwrap_or_else(|| panic!("{}: expect.{which}", v["name"]))
}

#[test]
fn manifest_shape() {
    let m = manifest();
    assert_eq!(m["schema"], 1);
    assert_eq!(m["namespace"], "spacetime-sshsig-test-v1");
    assert_eq!(vectors(&m).len(), 40);
    for k in ["a", "b", "c"] {
        assert!(m["keys"][k].is_object(), "key {k}");
    }
}

#[test]
fn parse_expectations() {
    let m = manifest();
    for v in vectors(&m) {
        let name = v["name"].as_str().unwrap();
        let armored = read(v["sig"].as_str().unwrap());
        let mut buf = [0u8; 1024];
        let got = match parse_into(&armored, &mut buf) {
            Ok(_) => "ok",
            Err(e) => e.name(),
        };
        assert_eq!(got, expect_str(v, "parse"), "{name}: parse");
    }
}

/// Run `verify` for one vector under the manifest's policy (or an override).
fn verify_vector(m: &Value, v: &Value, uv: Option<bool>) -> Result<Option<SkAttestation>, Error> {
    let armored = read(v["sig"].as_str().unwrap());
    let mut buf = [0u8; 1024];
    let sig = parse_into(&armored, &mut buf).expect("parse ok");
    let ns = v["expected_namespace"].as_str().unwrap();
    let uv = uv.unwrap_or_else(|| v["policy"]["require_user_verification"].as_bool().unwrap());
    let policy = SkPolicy {
        require_user_verification: uv,
    };
    let message = message_of(m, v);
    let mut kbuf = [0u8; 256];
    let signer = v["key"].as_str().map(|k| key_of(m, k, &mut kbuf));
    let expected = Expected::new(ns).with_sk_policy(policy);
    let expected = match &signer {
        Some(k) => expected.with_signer(k),
        None => expected,
    };
    let verified = verify(&DalekBackend, &sig, &expected, &message)?;
    assert_eq!(verified.public_key(), &sig.public_key);
    if let Some(k) = &signer {
        assert_eq!(verified.public_key(), k);
    }
    assert_eq!(verified.sk().is_some(), sig.public_key.is_sk());
    Ok(verified.sk())
}

#[test]
fn verify_expectations() {
    let m = manifest();
    for v in vectors(&m) {
        let name = v["name"].as_str().unwrap();
        if expect_str(v, "parse") != "ok" {
            assert!(
                v["expect"]["verify"].is_null(),
                "{name}: verify must be null"
            );
            continue;
        }
        let want = expect_str(v, "verify");
        match verify_vector(&m, v, None) {
            Ok(sk) => {
                assert_eq!(want, "ok", "{name}: verify unexpectedly ok");
                if let Some(sk) = sk {
                    assert_ne!(sk.flags & SK_FLAG_USER_PRESENCE, 0, "{name}");
                }
            }
            Err(e) => assert_eq!(e.name(), want, "{name}: verify"),
        }
        if v["also_uv_required"].as_bool() == Some(true) {
            let sk = verify_vector(&m, v, Some(true))
                .unwrap_or_else(|e| panic!("{name}: uv-required: {e}"))
                .expect("sk attestation");
            assert_ne!(sk.flags & SK_FLAG_USER_VERIFICATION, 0, "{name}");
        }
    }
    // The two synthetic sk positives carry known authenticator data.
    let by_name = |n: &str| vectors(&m).iter().find(|v| v["name"] == n).unwrap().clone();
    assert_eq!(
        verify_vector(&m, &by_name("ok_sk_up"), None).unwrap(),
        Some(SkAttestation {
            flags: 0x01,
            counter: 7
        })
    );
    assert_eq!(
        verify_vector(&m, &by_name("ok_sk_up_uv"), None).unwrap(),
        Some(SkAttestation {
            flags: 0x05,
            counter: 8
        })
    );
}

#[test]
fn verify_digest_matches_verify() {
    let m = manifest();
    let mut ran = 0;
    for v in vectors(&m) {
        if v["kind"] != "positive" {
            continue;
        }
        let name = v["name"].as_str().unwrap();
        let armored = read(v["sig"].as_str().unwrap());
        let mut buf = [0u8; 1024];
        let sig = parse_into(&armored, &mut buf).unwrap();
        let ns = v["expected_namespace"].as_str().unwrap();
        let message = message_of(&m, v);
        let expected = Expected::new(ns);

        // Stream the message in 4 KiB chunks.
        let mut st = DalekBackend.sha512_init().unwrap();
        for chunk in message.chunks(4096) {
            st.update(chunk).unwrap();
        }
        let digest = st.finalize().unwrap();
        assert_eq!(digest, DalekBackend.sha512(&message).unwrap());

        let a = verify(&DalekBackend, &sig, &expected, &message)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let b = verify_digest(&DalekBackend, &sig, &expected, &digest)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(a, b, "{name}");
        ran += 1;
    }
    assert_eq!(ran, 8);
}

#[test]
fn sign_is_byte_identical_to_ssh_keygen() {
    let m = manifest();
    let mut ran = 0;
    for v in vectors(&m) {
        if v["deterministic_sign"].as_bool() != Some(true) {
            continue;
        }
        let name = v["name"].as_str().unwrap();
        let key = v["key"].as_str().unwrap();
        let seed = hex32(m["keys"][key]["seed_hex"].as_str().unwrap());
        let ns = v["expected_namespace"].as_str().unwrap();
        let message = message_of(&m, v);
        let want = read(v["sig"].as_str().unwrap());
        let mut out = [0u8; 1024];
        let n = sign_armored(&DalekBackend, &seed, ns, &message, &mut out).unwrap();
        assert_eq!(
            &out[..n],
            &want[..],
            "{name}: not byte-identical to ssh-keygen"
        );
        ran += 1;
    }
    assert_eq!(ran, 4);
}

#[test]
fn encode_round_trip() {
    let m = manifest();
    for v in vectors(&m) {
        if expect_str(v, "parse") != "ok" {
            continue;
        }
        let name = v["name"].as_str().unwrap();
        let armored = read(v["sig"].as_str().unwrap());
        let mut raw = [0u8; 1024];
        let n = armor::decode(&armored, &mut raw).unwrap();
        let parsed = SshSig::parse(&raw[..n]).unwrap();
        let mut enc = [0u8; 1024];
        let e = parsed.encode(&mut enc).unwrap();
        assert_eq!(e, parsed.encoded_len(), "{name}");
        assert_eq!(&enc[..e], &raw[..n], "{name}: encode != decoded bytes");
        assert_eq!(SshSig::parse(&enc[..e]).unwrap(), parsed, "{name}");
    }
}

#[test]
fn fingerprints() {
    let m = manifest();
    for k in ["a", "b", "c"] {
        let line = read_string(m["keys"][k]["public_file"].as_str().unwrap());
        let mut buf = [0u8; 256];
        let parsed = parse_public_key_line(&line, &mut buf).unwrap();
        assert_eq!(
            parsed.key.key_type(),
            m["keys"][k]["type"].as_str().unwrap()
        );
        assert_eq!(
            parsed.key.key(),
            &hex32(m["keys"][k]["public_key_hex"].as_str().unwrap())
        );
        assert_eq!(
            parsed.comment,
            Some(format!("spacetime-sshsig-{k}").as_str())
        );
        if let PublicKey::SkEd25519 { application, .. } = parsed.key {
            assert_eq!(
                application,
                m["keys"][k]["application"].as_str().unwrap().as_bytes()
            );
        }
        let mut out = [0u8; FINGERPRINT_LEN];
        let fp = parsed.key.fingerprint(&DalekBackend, &mut out).unwrap();
        assert_eq!(fp, m["keys"][k]["fingerprint"].as_str().unwrap(), "key {k}");
    }
}

#[test]
fn allowed_signers_fixture() {
    let m = manifest();
    let text = read_string(m["allowed_signers"]["file"].as_str().unwrap());
    let entries = m["allowed_signers"]["entries"].as_array().unwrap();
    let mut it = AllowedSigners::new(&text);
    for want in entries {
        let line = want["line"].as_u64().unwrap();
        let got = it
            .next()
            .expect("entry")
            .unwrap_or_else(|e| panic!("line {line}: {e}"));
        let principals: Vec<&str> = got.principals().collect();
        let want_principals: Vec<&str> = want["principals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(principals, want_principals, "line {line}");
        let cert_authority = want["cert_authority"].as_bool().unwrap();
        assert_eq!(got.cert_authority, cert_authority, "line {line}");
        for p in &want_principals {
            assert!(got.has_principal(p));
            // A cert-authority entry never vouches for a plain signature
            // (ssh-keygen's find-principals omits `root` for the same reason).
            let ns = m["namespace"].as_str().unwrap();
            let windowed = got.valid_after.is_some() || got.valid_before.is_some();
            assert_eq!(
                got.accepts(p, ns),
                !cert_authority && !windowed && got.allows_namespace(ns),
                "line {line}"
            );
        }
        match want["namespaces"].as_array() {
            None => {
                assert_eq!(got.namespaces, None, "line {line}");
                assert!(got.allows_namespace("anything"));
            }
            Some(ns) => {
                let got_ns: Vec<&str> = got.namespace_list().collect();
                let want_ns: Vec<&str> = ns.iter().map(|n| n.as_str().unwrap()).collect();
                assert_eq!(got_ns, want_ns, "line {line}");
                for n in &want_ns {
                    assert!(got.allows_namespace(n));
                }
                assert!(!got.allows_namespace("not-listed"));
            }
        }
        assert_eq!(got.valid_after, want["valid_after"].as_str(), "line {line}");
        assert_eq!(
            got.valid_before,
            want["valid_before"].as_str(),
            "line {line}"
        );
        assert_eq!(got.comment, want["comment"].as_str(), "line {line}");
        let key_name = want["key"].as_str().unwrap();
        let mut kbuf = [0u8; 256];
        let want_key = key_of(&m, key_name, &mut kbuf);
        let mut dbuf = [0u8; 256];
        let got_key = got.decode_key(&mut dbuf).unwrap();
        assert_eq!(got_key, want_key, "line {line}");
        assert_eq!(got.key_type, want_key.key_type());
    }
    assert!(it.next().is_none(), "more entries than the manifest lists");

    for bad in m["allowed_signers"]["bad_lines"].as_array().unwrap() {
        let line = bad["line"].as_str().unwrap();
        match AllowedSigner::parse_line(line) {
            Err(e) => assert_eq!(e.name(), bad["expect"].as_str().unwrap(), "{line:?}"),
            Ok(None) => panic!("{line:?}: parsed as a comment"),
            Ok(Some(entry)) => {
                assert!(
                    bad["expect"].is_null(),
                    "{line:?}: expected {}",
                    bad["expect"]
                );
                let want = bad["expect_decode"].as_str().unwrap();
                let mut buf = [0u8; 256];
                let got = match entry.decode_key(&mut buf) {
                    Ok(_) => "ok",
                    Err(e) => e.name(),
                };
                assert_eq!(got, want, "{line:?}: decode");
            }
        }
    }
}

#[test]
fn validate_public_key() {
    let m = manifest();
    for k in ["a", "b", "c"] {
        let mut buf = [0u8; 256];
        let key = key_of(&m, k, &mut buf);
        assert_eq!(key.validate(&DalekBackend), Ok(()), "key {k}");
    }
    // Identity, non-canonical identity (y = p + 1), order-4 point.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut noncanonical = [0xffu8; 32];
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    let zero = [0u8; 32];
    for bad in [&identity, &noncanonical, &zero] {
        assert_eq!(
            PublicKey::Ed25519 { key: bad }.validate(&DalekBackend),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::SkEd25519 {
                key: bad,
                application: b"ssh:"
            }
            .validate(&DalekBackend),
            Err(Error::InvalidPublicKey)
        );
    }
}
