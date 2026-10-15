//! The vendored C2SP CCTV age corpus (`tests/vectors/cctv/testdata`, 147
//! files) run through the crate's **buffer API only** with the test backend,
//! so it proves the `no_std` surface end to end. Never shells out.
//!
//! Expectation semantics (`tests/vectors/cctv/README.md`): the outcome class
//! must equal `expect`, and for `success` / `payload failure` the SHA-256 of
//! every plaintext byte *released* to the caller must equal `payload`.
//!
//! Skip policy (contract §5.2, D14): vectors carrying `passphrase:` lines
//! (scrypt) and vectors whose only identities are hybrid
//! `AGE-SECRET-KEY-PQ-…` strings exercise features this crate does not
//! implement. They are never dropped: they run in "unsupported" mode (the
//! outcome must be an `Err` of the expected class, `NoMatch` or
//! `Unsupported(Scrypt)`, with nothing released, and the payload hash is
//! deliberately not checked) and are counted by reason. The totals —
//! 103 strict, 26 passphrase, 18 hybrid — are asserted so they cannot drift
//! silently. `compressed: zlib` vectors are inflated, never skipped.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::{hex, hex32, DalekBackend};
use spacetime_age::{
    armor, unwrap_file_key, Error, FileKey, Header, Identity, StreamReader, StreamWriter,
    CHUNK_LEN, CHUNK_SEALED_LEN,
};
use spacetime_crypto::Sha256;

const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/cctv/testdata");

/// One parsed vector file.
struct Vector {
    expect: String,
    payload_hash: Option<String>,
    file_key: Option<Vec<u8>>,
    identities: Vec<String>,
    has_passphrase: bool,
    armored: bool,
    /// The age file after inflation.
    file: Vec<u8>,
}

fn load(name: &str) -> Vector {
    let path = PathBuf::from(TESTDATA).join(name);
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let sep = raw
        .windows(2)
        .position(|w| w == b"\n\n")
        .unwrap_or_else(|| panic!("{name}: no header separator"));
    let header = std::str::from_utf8(&raw[..sep]).expect("utf-8 header");
    let mut body = raw[sep + 2..].to_vec();
    let mut v = Vector {
        expect: String::new(),
        payload_hash: None,
        file_key: None,
        identities: Vec::new(),
        has_passphrase: false,
        armored: false,
        file: Vec::new(),
    };
    let mut compressed = false;
    for line in header.lines() {
        let (k, val) = line.split_once(": ").unwrap_or((line, ""));
        match k {
            "expect" => v.expect = val.to_string(),
            "payload" => v.payload_hash = Some(val.to_string()),
            "file key" => v.file_key = Some(hex(val)),
            "identity" => v.identities.push(val.to_string()),
            "passphrase" => v.has_passphrase = true,
            "armored" => v.armored = val == "yes",
            "compressed" => {
                assert_eq!(val, "zlib", "{name}: unknown compression");
                compressed = true;
            }
            _ => {} // comment and unknown keys are ignored
        }
    }
    assert!(!v.expect.is_empty(), "{name}: no expect");
    if compressed {
        body = miniz_oxide::inflate::decompress_to_vec_zlib(&body)
            .unwrap_or_else(|e| panic!("{name}: inflate: {e:?}"));
    }
    v.file = body;
    v
}

/// Drive the buffer API exactly as a `no_std` caller would. Returns the
/// outcome and everything released.
fn drive(file: &[u8], identities: &[Identity]) -> (Result<(), Error>, Vec<u8>) {
    let mut released = Vec::new();
    let r = drive_into(file, identities, &mut released);
    (r, released)
}

fn drive_into(file: &[u8], identities: &[Identity], released: &mut Vec<u8>) -> Result<(), Error> {
    let header = Header::parse(file)?;
    let file_key = unwrap_file_key(&DalekBackend, &header, identities)?;
    let mut reader = StreamReader::new(&DalekBackend, &file_key, header.nonce())?;
    let mut buf = vec![0u8; CHUNK_LEN];
    let mut payload = header.payload();
    while payload.len() >= CHUNK_SEALED_LEN {
        let (chunk, rest) = payload.split_at(CHUNK_SEALED_LEN);
        let n = reader.next_chunk(chunk, &mut buf)?;
        released.extend_from_slice(&buf[..n]);
        payload = rest;
        if reader.is_finished() {
            break;
        }
    }
    let n = reader.last_chunk(payload, &mut buf)?;
    released.extend_from_slice(&buf[..n]);
    Ok(())
}

/// Dearmor (buffer API) when the vector says so.
fn dearmor(v: &Vector) -> Result<Vec<u8>, Error> {
    if !v.armored {
        return Ok(v.file.clone());
    }
    let mut buf = vec![0u8; armor::max_decoded_len(v.file.len())];
    let n = armor::decode(&v.file, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn class_name(r: &Result<(), Error>) -> &'static str {
    match r {
        Ok(()) => "success",
        Err(e) => e.class().cctv_name().unwrap_or("(not a CCTV class)"),
    }
}

#[derive(Default, Debug)]
struct Totals {
    strict: BTreeMap<String, usize>,
    skipped_passphrase: usize,
    skipped_hybrid: usize,
    matched_anyway: usize,
}

fn all_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(TESTDATA)
        .unwrap_or_else(|e| panic!("read_dir {TESTDATA}: {e}"))
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 147, "the vendored corpus has 147 files");
    names
}

#[test]
fn every_vector_matches_its_expectation() {
    let mut totals = Totals::default();
    for name in all_names() {
        let v = load(&name);
        let mut identities = Vec::new();
        let mut unsupported_identity = false;
        for s in &v.identities {
            match Identity::from_age_str(s) {
                Ok(id) => identities.push(id),
                Err(_) => unsupported_identity = true,
            }
        }
        let strict = !(v.has_passphrase || (unsupported_identity && identities.is_empty()));

        let (outcome, released) = match dearmor(&v) {
            Ok(file) => drive(&file, &identities),
            Err(e) => (Err(e), Vec::new()),
        };
        let got = class_name(&outcome);

        if strict {
            assert_eq!(
                got, v.expect,
                "{name}: expected `{}`, got {outcome:?}",
                v.expect
            );
            if v.expect == "success" || v.expect == "payload failure" {
                let want = v
                    .payload_hash
                    .as_deref()
                    .unwrap_or_else(|| panic!("{name}: no payload hash"));
                assert_eq!(
                    DalekBackend.sha256(&released).unwrap(),
                    hex32(want),
                    "{name}: released {} bytes with the wrong hash",
                    released.len()
                );
            } else {
                assert!(
                    v.payload_hash.is_none(),
                    "{name}: payload hash on a {} vector",
                    v.expect
                );
            }
            *totals.strict.entry(v.expect.clone()).or_default() += 1;
        } else {
            // Unsupported mode: an Err of the expected class, NoMatch or
            // Unsupported(Scrypt); nothing released; the payload hash is
            // deliberately not checked (nothing can be released without
            // the feature).
            let e = outcome.expect_err("unsupported vector decrypted");
            let acceptable = got == v.expect
                || matches!(e, Error::NoMatch)
                || matches!(
                    e,
                    Error::Unsupported(spacetime_age::UnsupportedStanza::Scrypt)
                );
            assert!(acceptable, "{name}: unsupported vector failed as {e:?}");
            assert!(
                released.is_empty(),
                "{name}: released bytes without the feature"
            );
            if got == v.expect {
                totals.matched_anyway += 1;
            }
            if v.has_passphrase {
                totals.skipped_passphrase += 1;
            } else {
                totals.skipped_hybrid += 1;
            }
        }
    }

    let strict_total: usize = totals.strict.values().sum();
    println!(
        "cctv: strict={strict_total} {:?} skipped_passphrase={} skipped_hybrid={} matched_anyway={}",
        totals.strict, totals.skipped_passphrase, totals.skipped_hybrid, totals.matched_anyway
    );
    assert_eq!(strict_total, 103);
    assert_eq!(totals.strict["header failure"], 34);
    assert_eq!(totals.strict["armor failure"], 26);
    assert_eq!(totals.strict["success"], 19);
    assert_eq!(totals.strict["payload failure"], 19);
    assert_eq!(totals.strict["no match"], 4);
    assert_eq!(totals.strict["HMAC failure"], 1);
    assert_eq!(totals.skipped_passphrase, 26);
    assert_eq!(totals.skipped_hybrid, 18);
    assert_eq!(
        strict_total + totals.skipped_passphrase + totals.skipped_hybrid,
        147
    );
}

/// The exact error variants of the trailing-data vectors (the corpus only
/// pins the class): a second full final chunk must be `TrailingData`, not
/// the API-misuse `ChunkLength`.
#[test]
fn trailing_data_vectors_report_trailing_data() {
    for name in [
        "stream_two_final_chunks_full",
        "stream_two_final_chunks",
        "stream_trailing_garbage_long",
    ] {
        let v = load(name);
        let identities: Vec<Identity> = v
            .identities
            .iter()
            .map(|s| Identity::from_age_str(s).unwrap())
            .collect();
        let (outcome, released) = drive(&v.file, &identities);
        assert_eq!(
            outcome,
            Err(Error::Payload(spacetime_age::PayloadError::TrailingData)),
            "{name}"
        );
        assert_eq!(released.len(), CHUNK_LEN, "{name}");
    }
}

/// `v` with outer whitespace stripped, `\r\n` → `\n`, and a final `\n`.
fn normalise_armor(v: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(v);
    let mut out = s
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .replace("\r\n", "\n");
    out.push('\n');
    out.into_bytes()
}

#[test]
fn armor_round_trips() {
    let mut checked = 0;
    for name in all_names() {
        let v = load(&name);
        if !v.armored || v.expect == "armor failure" {
            continue;
        }
        let decoded = dearmor(&v).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut re = vec![0u8; armor::encoded_len(decoded.len())];
        let n = armor::encode(&decoded, &mut re).unwrap();
        assert_eq!(n, re.len());
        assert_eq!(
            re,
            normalise_armor(&v.file),
            "{name}: armor re-encode differs"
        );
        checked += 1;
    }
    println!("cctv: armor round trips checked={checked}");
    assert!(checked >= 10, "{checked}");
}

#[test]
fn header_round_trips() {
    let mut checked = 0;
    for name in all_names() {
        let v = load(&name);
        let strict = !v.has_passphrase
            && !(v
                .identities
                .iter()
                .all(|s| Identity::from_age_str(s).is_err())
                && !v.identities.is_empty());
        if !strict || v.expect == "header failure" || v.expect == "armor failure" {
            continue;
        }
        let file = dearmor(&v).unwrap_or_else(|e| panic!("{name}: {e}"));
        let h = Header::parse(&file).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut out = vec![0u8; h.len()];
        assert_eq!(h.encode(&mut out).unwrap(), h.len());
        assert_eq!(out, &file[..h.len()], "{name}: header re-encode differs");
        checked += 1;
    }
    println!("cctv: header round trips checked={checked}");
    assert_eq!(checked, 19 + 19 + 4 + 1);
}

#[test]
fn payload_round_trips_with_the_file_key() {
    let mut checked = 0;
    for name in all_names() {
        let v = load(&name);
        if v.expect != "success" || v.has_passphrase {
            continue;
        }
        let Some(fk) = v.file_key.as_ref() else {
            continue;
        };
        let identities: Vec<Identity> = v
            .identities
            .iter()
            .filter_map(|s| Identity::from_age_str(s).ok())
            .collect();
        if identities.is_empty() {
            continue; // hybrid-only success vectors are skipped above
        }
        let file = dearmor(&v).unwrap_or_else(|e| panic!("{name}: {e}"));
        let (outcome, plaintext) = drive(&file, &identities);
        outcome.unwrap_or_else(|e| panic!("{name}: {e}"));
        let h = Header::parse(&file).unwrap();
        let file_key = FileKey::from_bytes(fk.as_slice().try_into().expect("16-byte file key"));
        let mut w = StreamWriter::with_nonce(&DalekBackend, &file_key, h.nonce()).unwrap();
        let mut out = vec![0u8; spacetime_age::sealed_payload_len(plaintext.len())];
        out[..16].copy_from_slice(w.nonce());
        let mut pos = 16;
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
        assert_eq!(pos, out.len());
        assert_eq!(
            &file[h.len()..],
            &out[..],
            "{name}: payload re-encrypt differs"
        );
        checked += 1;
    }
    println!("cctv: payload round trips checked={checked}");
    assert!(checked >= 10, "{checked}");
}
