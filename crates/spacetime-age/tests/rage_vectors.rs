//! The rage-oracle corpus (`tests/vectors/rage/manifest.json`): 31 files
//! encrypted by `rage` 0.12.1 (decrypt-only oracles — CCTV has no
//! ssh-ed25519 vectors) and 8 deterministic `pyref_*` files produced by the
//! vendored Python reference under a counter RNG (encrypt known-answer
//! tests, since the same byte stream through `CounterRng(0)` must
//! reproduce them byte for byte).
//!
//! Runs with the crate's default features and uses ONLY the caller-buffer
//! API. Never shells out.

mod common;
#[path = "common/rng.rs"]
mod rng;

use common::{hex, hex32, DalekBackend};
use rng::CounterRng;
use serde_json::Value;
use spacetime_age::{
    armor, encrypt_header, encrypted_len, header_len_for, inspect, unwrap_file_key, Error, FileKey,
    Header, Identity, Recipient, StreamReader, StreamWriter, CHUNK_LEN, CHUNK_SEALED_LEN,
    PAYLOAD_NONCE_LEN,
};
use spacetime_crypto::Sha256;

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/rage/");
const MANIFEST: &str = include_str!("vectors/rage/manifest.json");

fn manifest() -> Value {
    serde_json::from_str(MANIFEST).expect("manifest.json parses")
}

fn read(rel: &str) -> Vec<u8> {
    let path = format!("{VECTORS}{rel}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn vectors(m: &Value) -> &[Value] {
    m["vectors"].as_array().expect("vectors array")
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string"))
        .collect()
}

/// The identity named `key` in the manifest.
fn identity(m: &Value, key: &str) -> Identity {
    match key {
        "x25519" => Identity::from_age_str(m["keys"]["x25519"]["identity"].as_str().unwrap())
            .expect("x25519 identity"),
        "ssh_ed25519" => Identity::ssh_ed25519(hex32(
            m["keys"]["ssh_ed25519"]["seed_hex"].as_str().unwrap(),
        )),
        other => panic!("unknown identity {other}"),
    }
}

/// The recipient named `key` in the manifest.
fn recipient(m: &Value, key: &str) -> Recipient {
    match key {
        "x25519" => Recipient::from_age_str(m["keys"]["x25519"]["recipient"].as_str().unwrap())
            .expect("x25519 recipient"),
        "ssh_ed25519" => Recipient::SshEd25519 {
            public_key: hex32(m["keys"]["ssh_ed25519"]["public_key_hex"].as_str().unwrap()),
        },
        "other" => Recipient::from_age_str(m["keys"]["other"]["recipient"].as_str().unwrap())
            .expect("other recipient"),
        other => panic!("unknown recipient {other}"),
    }
}

/// The plaintext the vector encrypts.
fn plaintext_of(m: &Value, v: &Value) -> Vec<u8> {
    if let Some(h) = v["plaintext_hex"].as_str() {
        return hex(h);
    }
    let p = v["payload"].as_str().expect("payload");
    let entry = &m["payloads"][p];
    let data = read(entry["file"].as_str().unwrap());
    assert_eq!(data.len(), entry["len"].as_u64().unwrap() as usize);
    assert_eq!(
        DalekBackend.sha256(&data).unwrap(),
        hex32(entry["sha256"].as_str().unwrap())
    );
    data
}

/// The binary age file of the vector (dearmored with the buffer API).
fn binary_of(v: &Value) -> Vec<u8> {
    let file = read(v["file"].as_str().unwrap());
    if v["armored"].as_bool().unwrap() {
        assert!(armor::is_armored(&file), "{}", v["name"]);
        let mut buf = vec![0u8; armor::max_decoded_len(file.len())];
        let n = armor::decode(&file, &mut buf).unwrap_or_else(|e| panic!("{}: {e}", v["name"]));
        buf.truncate(n);
        buf
    } else {
        assert!(!armor::is_armored(&file), "{}", v["name"]);
        file
    }
}

/// Buffer-API decrypt driver (as in `tests/cctv.rs`).
fn decrypt(file: &[u8], identities: &[Identity]) -> Result<Vec<u8>, Error> {
    let header = Header::parse(file)?;
    let file_key = unwrap_file_key(&DalekBackend, &header, identities)?;
    let mut reader = StreamReader::new(&DalekBackend, &file_key, header.nonce())?;
    let mut buf = vec![0u8; CHUNK_LEN];
    let mut out = Vec::new();
    let mut payload = header.payload();
    while payload.len() >= CHUNK_SEALED_LEN {
        let (chunk, rest) = payload.split_at(CHUNK_SEALED_LEN);
        let n = reader.next_chunk(chunk, &mut buf)?;
        out.extend_from_slice(&buf[..n]);
        payload = rest;
        if reader.is_finished() {
            break;
        }
    }
    let n = reader.last_chunk(payload, &mut buf)?;
    out.extend_from_slice(&buf[..n]);
    Ok(out)
}

/// Buffer-API encrypt: `FileKey::generate` → `encrypt_header` →
/// `StreamWriter::new` → chunks, exactly the §4 draw order.
fn encrypt(rng: &mut CounterRng, recipients: &[Recipient], plaintext: &[u8]) -> Vec<u8> {
    let file_key = FileKey::generate(rng).unwrap();
    let mut out = vec![0u8; encrypted_len(recipients, plaintext.len())];
    let mut pos = encrypt_header(&DalekBackend, rng, recipients, &file_key, &mut out).unwrap();
    assert_eq!(pos, header_len_for(recipients));
    let mut w = StreamWriter::new(&DalekBackend, &file_key, rng).unwrap();
    out[pos..pos + PAYLOAD_NONCE_LEN].copy_from_slice(w.nonce());
    pos += PAYLOAD_NONCE_LEN;
    let mut chunks = plaintext.chunks(CHUNK_LEN).peekable();
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
    assert_eq!(pos, out.len(), "encrypted_len must be exact");
    out
}

#[test]
fn manifest_shape_and_fixed_keys() {
    let m = manifest();
    assert_eq!(m["schema"], 1);
    assert_eq!(vectors(&m).len(), 39);
    let x = &m["keys"]["x25519"];
    let id = Identity::from_age_str(x["identity"].as_str().unwrap()).unwrap();
    assert_eq!(id.secret(), &hex32(x["secret_hex"].as_str().unwrap()));
    let r = id.recipient(&DalekBackend).unwrap();
    assert_eq!(
        r,
        Recipient::X25519 {
            public_key: hex32(x["public_key_hex"].as_str().unwrap())
        }
    );
    let mut buf = [0u8; spacetime_age::RECIPIENT_STR_LEN];
    assert_eq!(
        r.encode_age(&mut buf).unwrap(),
        x["recipient"].as_str().unwrap()
    );
    let mut buf = [0u8; spacetime_age::IDENTITY_STR_LEN];
    assert_eq!(
        id.encode_age(&mut buf).unwrap(),
        x["identity"].as_str().unwrap()
    );

    let s = &m["keys"]["ssh_ed25519"];
    let id = Identity::ssh_ed25519(hex32(s["seed_hex"].as_str().unwrap()));
    let r = id.recipient(&DalekBackend).unwrap();
    let pk = hex32(s["public_key_hex"].as_str().unwrap());
    assert_eq!(r, Recipient::SshEd25519 { public_key: pk });
    let tag = r.ssh_tag(&DalekBackend).unwrap().unwrap();
    assert_eq!(tag.to_vec(), hex(s["tag_hex"].as_str().unwrap()));
    let mut b64 = [0u8; 6];
    spacetime_age::base64::encode_nopad(&tag, &mut b64).unwrap();
    assert_eq!(&b64, s["tag_b64"].as_str().unwrap().as_bytes());
    assert_eq!(
        spacetime_crypto::Ed25519ToX25519::ed25519_public_to_x25519(&DalekBackend, &pk).unwrap(),
        hex32(s["x25519_public_hex"].as_str().unwrap())
    );
    // The tag is SHA-256 over the wire form built in-crate.
    let wire = r.ssh_wire().unwrap();
    assert_eq!(&DalekBackend.sha256(&wire).unwrap()[..4], &tag);
}

#[test]
fn every_vector_decrypts_with_its_identities_and_not_the_others() {
    let m = manifest();
    let tag: [u8; 4] = hex(m["keys"]["ssh_ed25519"]["tag_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let mut n = 0;
    for v in vectors(&m) {
        let name = v["name"].as_str().unwrap();
        let file = binary_of(v);
        let plaintext = plaintext_of(&m, v);
        let recipients = strs(&v["recipients"]);
        for key in strs(&v["identities_ok"]) {
            let got = decrypt(&file, &[identity(&m, key)])
                .unwrap_or_else(|e| panic!("{name}: decrypt with {key}: {e}"));
            assert_eq!(got, plaintext, "{name}: plaintext with {key}");
        }
        let no_match: Vec<Identity> = strs(&v["identities_no_match"])
            .iter()
            .map(|k| identity(&m, k))
            .collect();
        if !no_match.is_empty() {
            assert_eq!(
                decrypt(&file, &no_match).map(|_| ()),
                Err(Error::NoMatch),
                "{name}: non-matching identities"
            );
        }
        assert_eq!(
            decrypt(&file, &[]).map(|_| ()),
            Err(Error::NoMatch),
            "{name}"
        );

        let i = inspect(&file).unwrap_or_else(|e| panic!("{name}: inspect: {e}"));
        let has = |k: &str| usize::from(recipients.contains(&k));
        assert_eq!(
            i.x25519,
            has("x25519") + has("other"),
            "{name}: x25519 count"
        );
        assert_eq!(i.ssh_ed25519, has("ssh_ed25519"), "{name}: ssh count");
        assert_eq!(i.scrypt, 0, "{name}");
        assert_eq!(i.ssh_rsa, 0, "{name}");
        if recipients.contains(&"ssh_ed25519") {
            assert_eq!(i.ssh_ed25519_tag, Some(tag), "{name}");
            assert!(i.is_single_ssh_ed25519(&tag), "{name}");
        } else {
            assert_eq!(i.ssh_ed25519_tag, None, "{name}");
            assert!(!i.is_single_ssh_ed25519(&tag), "{name}");
        }
        n += 1;
    }
    assert_eq!(n, 39);
}

#[test]
fn pyref_vectors_are_reproduced_byte_for_byte() {
    let m = manifest();
    let mut n = 0;
    for v in vectors(&m) {
        if v["kind"].as_str().unwrap() != "pyref" {
            continue;
        }
        let name = v["name"].as_str().unwrap();
        assert_eq!(v["rng"].as_str().unwrap(), "counter:0", "{name}");
        let file = read(v["file"].as_str().unwrap());
        assert_eq!(
            DalekBackend.sha256(&file).unwrap(),
            hex32(v["sha256"].as_str().unwrap()),
            "{name}: file hash"
        );
        let recipients: Vec<Recipient> = strs(&v["recipients"])
            .iter()
            .map(|k| recipient(&m, k))
            .collect();
        let plaintext = plaintext_of(&m, v);
        let ours = encrypt(&mut CounterRng(0), &recipients, &plaintext);
        if v["armored"].as_bool().unwrap() {
            let mut armored = vec![0u8; armor::encoded_len(ours.len())];
            let k = armor::encode(&ours, &mut armored).unwrap();
            assert_eq!(k, armored.len());
            assert_eq!(armored, file, "{name}: armored output differs");
        } else {
            assert_eq!(ours, file, "{name}: output differs");
        }
        n += 1;
    }
    assert_eq!(n, 8);
}

#[test]
fn pyref_both_det_known_answer() {
    let m = manifest();
    let v = vectors(&m)
        .iter()
        .find(|v| v["name"] == "pyref_both_det")
        .expect("pyref_both_det");
    let file = read(v["file"].as_str().unwrap());
    assert_eq!(file.len(), 314);
    assert_eq!(
        DalekBackend.sha256(&file).unwrap(),
        hex32("9750c16527fcd0f924c40529d9ec1f072eceef822a5c9054c32c02f54201df1b")
    );
    let text = String::from_utf8_lossy(&file[..278]);
    assert!(text.contains("-> X25519 2J47rXlDfb7Z+ENBgwT0YP8Fx/6B/kqVd6gEy5Nn/2Y\n"));
    assert!(text.contains("-> ssh-ed25519 64jdUw NOQtSvXvlKB6OoQgG4idTNGnQ8snsRtqEEOKj+uOWEc\n"));
    assert!(text.contains("--- Yah3lrbDKtcPMuA1MxOkdcGYsTQY4frDk+lKZTPI3qo\n"));
    let mut armored = vec![0u8; armor::encoded_len(file.len())];
    armor::encode(&file, &mut armored).unwrap();
    assert_eq!(armored.len(), 495);
    assert_eq!(
        DalekBackend.sha256(&armored).unwrap(),
        hex32("1fc65fff10b9d4ea808748e03cce51b9099e5b734d8ad77e39871717f285e5e3")
    );
    let recipients = [recipient(&m, "x25519"), recipient(&m, "ssh_ed25519")];
    assert_eq!(encrypt(&mut CounterRng(0), &recipients, b"det\n"), file);
}
