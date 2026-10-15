//! The `alloc` conveniences (`encrypt_vec`, `decrypt_vec`,
//! `encrypt_armored_string`, `decrypt_armored_vec`, `inspect_auto`,
//! `to_age_string`, `Inspection::to_buf`, `armor::encode_string` /
//! `decode_vec`) must agree with the buffer API on the round-trip matrix
//! and decrypt every strict CCTV `success` vector and every rage vector.

mod common;
#[path = "common/rng.rs"]
mod rng;

use common::{hex, hex32, DalekBackend};
use rng::CounterRng;
use serde_json::Value;
use spacetime_age::{
    armor, decrypt_armored_vec, decrypt_vec, encrypt_armored_string, encrypt_header, encrypt_vec,
    encrypted_len, inspect, inspect_auto, Error, FileKey, Identity, Recipient, StanzaKind,
    StreamWriter, CHUNK_LEN, PAYLOAD_NONCE_LEN,
};
use spacetime_crypto::Sha256;

const LENGTHS: &[usize] = &[
    0, 1, 15, 16, 17, 65535, 65536, 65537, 131072, 131073, 204800,
];
const CCTV: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/cctv/testdata");
const RAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/rage/");

fn x_identity() -> Identity {
    Identity::from_age_str(
        "AGE-SECRET-KEY-1YX9CYV6YH7FDPQ9XXP4E2TT7T6XSJWQ67CLVE4CNG5YCZ5D9N77QZ8EEGV",
    )
    .unwrap()
}

fn s_identity() -> Identity {
    Identity::ssh_ed25519(hex32(
        "2fd4d6679dfea3aae5df5cd19cd04f80609aa11a49feaa6308e472c3b7b0c2c5",
    ))
}

fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Buffer-API encrypt under the same RNG stream as `encrypt_vec`.
fn encrypt_buffers(rng: &mut CounterRng, recipients: &[Recipient], pt: &[u8]) -> Vec<u8> {
    let file_key = FileKey::generate(rng).unwrap();
    let mut out = vec![0u8; encrypted_len(recipients, pt.len())];
    let mut pos = encrypt_header(&DalekBackend, rng, recipients, &file_key, &mut out).unwrap();
    let mut w = StreamWriter::new(&DalekBackend, &file_key, rng).unwrap();
    out[pos..pos + PAYLOAD_NONCE_LEN].copy_from_slice(w.nonce());
    pos += PAYLOAD_NONCE_LEN;
    let mut chunks = pt.chunks(CHUNK_LEN).peekable();
    let mut any = false;
    while let Some(c) = chunks.next() {
        any = true;
        pos += if chunks.peek().is_some() {
            w.write_chunk(c, &mut out[pos..]).unwrap()
        } else {
            w.write_last(c, &mut out[pos..]).unwrap()
        };
    }
    if !any {
        pos += w.write_last(&[], &mut out[pos..]).unwrap();
    }
    assert_eq!(pos, out.len());
    out
}

#[test]
fn vec_api_equals_buffer_api_on_the_matrix() {
    let x = x_identity();
    let s = s_identity();
    let rx = x.recipient(&DalekBackend).unwrap();
    let rs = s.recipient(&DalekBackend).unwrap();
    let sets: Vec<(Vec<Recipient>, Vec<Identity>)> = vec![
        (vec![rx], vec![x.clone()]),
        (vec![rs], vec![s.clone()]),
        (vec![rx, rs], vec![x.clone(), s.clone()]),
        (vec![rs, rx], vec![s, x]),
    ];
    for &len in LENGTHS {
        let pt = plaintext(len);
        for (recipients, identities) in &sets {
            let a = encrypt_buffers(&mut CounterRng(3), recipients, &pt);
            let b = encrypt_vec(&DalekBackend, &mut CounterRng(3), recipients, &pt).unwrap();
            assert_eq!(a, b, "len {len}");
            assert_eq!(b.len(), encrypted_len(recipients, len));
            for id in identities {
                assert_eq!(
                    decrypt_vec(&DalekBackend, std::slice::from_ref(id), &b).unwrap(),
                    pt
                );
            }
            let armored =
                encrypt_armored_string(&DalekBackend, &mut CounterRng(3), recipients, &pt).unwrap();
            assert_eq!(armored, armor::encode_string(&b));
            assert_eq!(armor::decode_vec(armored.as_bytes()).unwrap(), b);
            assert_eq!(
                decrypt_armored_vec(&DalekBackend, identities, armored.as_bytes()).unwrap(),
                pt
            );
            assert_eq!(
                decrypt_armored_vec(&DalekBackend, identities, &b).map(|_| ()),
                Err(Error::Armor(spacetime_age::ArmorError::MissingBegin))
            );
            // inspect_auto handles both forms identically.
            let i1 = inspect_auto(&b).unwrap();
            let i2 = inspect_auto(armored.as_bytes()).unwrap();
            assert_eq!(i1, i2);
            assert_eq!(i1, inspect(&b).unwrap().to_buf());
            assert_eq!(i1.stanzas.len(), recipients.len());
            assert_eq!(i1.header_len, inspect(&b).unwrap().header.len());
            for (st, r) in i1.stanzas.iter().zip(recipients) {
                match r {
                    Recipient::X25519 { .. } => {
                        assert_eq!(st.kind, StanzaKind::X25519);
                        assert_eq!(st.stanza_type, "X25519");
                        assert_eq!(st.args.len(), 1);
                    }
                    Recipient::SshEd25519 { .. } => {
                        assert_eq!(st.kind, StanzaKind::SshEd25519);
                        assert_eq!(st.args.len(), 2);
                        assert_eq!(st.args[0], "64jdUw");
                    }
                }
                assert_eq!(st.body.len(), 32);
            }
            let tag = [0xeb, 0x88, 0xdd, 0x53];
            assert_eq!(i1.is_single_ssh_ed25519(&tag), i1.ssh_ed25519 == 1);
        }
    }
}

#[test]
fn decrypt_vec_errors_release_nothing_and_match_the_buffer_api() {
    let x = x_identity();
    let rx = x.recipient(&DalekBackend).unwrap();
    let pt = plaintext(CHUNK_LEN);
    let mut file = encrypt_vec(&DalekBackend, &mut CounterRng(0), &[rx], &pt).unwrap();
    assert_eq!(
        decrypt_vec(&DalekBackend, &[s_identity()], &file).map(|_| ()),
        Err(Error::NoMatch)
    );
    file.push(0);
    assert_eq!(
        decrypt_vec(&DalekBackend, std::slice::from_ref(&x), &file).map(|_| ()),
        Err(Error::Payload(spacetime_age::PayloadError::TrailingData))
    );
    // A full chunk's worth of trailing bytes after the (full) final chunk
    // is still `TrailingData`, not the API-misuse `ChunkLength`.
    file.resize(file.len() - 1 + spacetime_age::CHUNK_SEALED_LEN, 0);
    assert_eq!(
        decrypt_vec(&DalekBackend, &[x], &file).map(|_| ()),
        Err(Error::Payload(spacetime_age::PayloadError::TrailingData))
    );
    assert_eq!(
        encrypt_vec(&DalekBackend, &mut CounterRng(0), &[], b"x").map(|_| ()),
        Err(Error::NoRecipients)
    );
}

#[test]
fn key_strings() {
    let x = x_identity();
    assert_eq!(
        x.to_age_string().unwrap(),
        "AGE-SECRET-KEY-1YX9CYV6YH7FDPQ9XXP4E2TT7T6XSJWQ67CLVE4CNG5YCZ5D9N77QZ8EEGV"
    );
    assert_eq!(
        x.recipient(&DalekBackend).unwrap().to_age_string().unwrap(),
        "age15weja5qsvsv9utrqyke5nza08vmals2lyls73n5v7hltfk46mcqsy3c60l"
    );
    assert_eq!(
        s_identity().to_age_string().map(|_| ()),
        Err(Error::Key(spacetime_age::KeyError::NotEncodable))
    );
}

/// Every strict CCTV `success` vector through `decrypt_vec` /
/// `decrypt_armored_vec`.
#[test]
fn cctv_success_vectors_through_decrypt_vec() {
    let mut names: Vec<_> = std::fs::read_dir(CCTV)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 147);
    let mut checked = 0;
    for name in names {
        let raw = std::fs::read(format!("{CCTV}/{name}")).unwrap();
        let sep = raw.windows(2).position(|w| w == b"\n\n").unwrap();
        let header = std::str::from_utf8(&raw[..sep]).unwrap();
        let mut body = raw[sep + 2..].to_vec();
        let mut expect = "";
        let mut payload = "";
        let mut identities = Vec::new();
        let mut passphrase = false;
        let mut armored = false;
        let mut unsupported = false;
        for line in header.lines() {
            let (k, v) = line.split_once(": ").unwrap_or((line, ""));
            match k {
                "expect" => expect = v,
                "payload" => payload = v,
                "identity" => match Identity::from_age_str(v) {
                    Ok(id) => identities.push(id),
                    Err(_) => unsupported = true,
                },
                "passphrase" => passphrase = true,
                "armored" => armored = v == "yes",
                "compressed" => body = miniz_oxide::inflate::decompress_to_vec_zlib(&body).unwrap(),
                _ => {}
            }
        }
        if expect != "success" || passphrase || (unsupported && identities.is_empty()) {
            continue;
        }
        let got = if armored {
            decrypt_armored_vec(&DalekBackend, &identities, &body)
        } else {
            decrypt_vec(&DalekBackend, &identities, &body)
        }
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(DalekBackend.sha256(&got).unwrap(), hex32(payload), "{name}");
        checked += 1;
    }
    assert_eq!(checked, 19);
}

/// Every rage vector through `decrypt_vec` / `decrypt_armored_vec`, and
/// every `pyref` vector reproduced with `encrypt_vec`.
#[test]
fn rage_vectors_through_the_vec_api() {
    let m: Value = serde_json::from_str(include_str!("vectors/rage/manifest.json")).unwrap();
    let read = |rel: &str| std::fs::read(format!("{RAGE}{rel}")).unwrap();
    let identity = |k: &str| match k {
        "x25519" => {
            Identity::from_age_str(m["keys"]["x25519"]["identity"].as_str().unwrap()).unwrap()
        }
        "ssh_ed25519" => Identity::ssh_ed25519(hex32(
            m["keys"]["ssh_ed25519"]["seed_hex"].as_str().unwrap(),
        )),
        _ => unreachable!(),
    };
    let recipient = |k: &str| match k {
        "x25519" => {
            Recipient::from_age_str(m["keys"]["x25519"]["recipient"].as_str().unwrap()).unwrap()
        }
        "ssh_ed25519" => Recipient::SshEd25519 {
            public_key: hex32(m["keys"]["ssh_ed25519"]["public_key_hex"].as_str().unwrap()),
        },
        _ => unreachable!(),
    };
    let mut n = 0;
    let mut pyref = 0;
    for v in m["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let file = read(v["file"].as_str().unwrap());
        let armored = v["armored"].as_bool().unwrap();
        let pt = match v["plaintext_hex"].as_str() {
            Some(h) => hex(h),
            None => read(
                m["payloads"][v["payload"].as_str().unwrap()]["file"]
                    .as_str()
                    .unwrap(),
            ),
        };
        for k in v["identities_ok"].as_array().unwrap() {
            let ids = [identity(k.as_str().unwrap())];
            let got = if armored {
                decrypt_armored_vec(&DalekBackend, &ids, &file)
            } else {
                decrypt_vec(&DalekBackend, &ids, &file)
            }
            .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(got, pt, "{name}");
        }
        if v["kind"] == "pyref" {
            let recipients: Vec<Recipient> = v["recipients"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| recipient(k.as_str().unwrap()))
                .collect();
            let ours = if armored {
                encrypt_armored_string(&DalekBackend, &mut CounterRng(0), &recipients, &pt)
                    .unwrap()
                    .into_bytes()
            } else {
                encrypt_vec(&DalekBackend, &mut CounterRng(0), &recipients, &pt).unwrap()
            };
            assert_eq!(ours, file, "{name}: encrypt_vec differs");
            pyref += 1;
        }
        n += 1;
    }
    assert_eq!(n, 39);
    assert_eq!(pyref, 8);
}
