//! Encrypt → decrypt round trips through the buffer API with the test
//! backend and a counter RNG, over the plaintext-length × recipient-set
//! matrix of contract §2.16, plus the tamper cases whose released prefix is
//! pinned by the STREAM release rule.

mod common;
#[path = "common/rng.rs"]
mod rng;

use common::DalekBackend;
use rng::CounterRng;
use spacetime_age::{
    armor, encrypt_header, encrypted_len, header_len_for, inspect, unwrap_file_key, Error, FileKey,
    Header, Identity, PayloadError, Recipient, StreamReader, StreamWriter, CHUNK_LEN,
    CHUNK_SEALED_LEN, PAYLOAD_NONCE_LEN,
};
use spacetime_crypto::Sha256;

const LENGTHS: &[usize] = &[
    0, 1, 15, 16, 17, 65535, 65536, 65537, 131072, 131073, 204800,
];

fn x_identity() -> Identity {
    Identity::from_age_str(
        "AGE-SECRET-KEY-1YX9CYV6YH7FDPQ9XXP4E2TT7T6XSJWQ67CLVE4CNG5YCZ5D9N77QZ8EEGV",
    )
    .unwrap()
}

fn x2_identity() -> Identity {
    Identity::x25519([7u8; 32])
}

fn s_identity() -> Identity {
    Identity::ssh_ed25519(common::hex32(
        "2fd4d6679dfea3aae5df5cd19cd04f80609aa11a49feaa6308e472c3b7b0c2c5",
    ))
}

fn recipient_of(id: &Identity) -> Recipient {
    id.recipient(&DalekBackend).unwrap()
}

fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Buffer-API encrypt; returns the file and its header length.
fn encrypt(rng: &mut CounterRng, recipients: &[Recipient], pt: &[u8]) -> Vec<u8> {
    let file_key = FileKey::generate(rng).unwrap();
    let mut out = vec![0u8; encrypted_len(recipients, pt.len())];
    let mut pos = encrypt_header(&DalekBackend, rng, recipients, &file_key, &mut out).unwrap();
    assert_eq!(pos, header_len_for(recipients));
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
    assert!(w.is_finished());
    assert_eq!(pos, out.len(), "encrypted_len must be exact");
    out
}

/// Buffer-API decrypt driver; returns the outcome and the released bytes.
fn decrypt(file: &[u8], identities: &[Identity]) -> (Result<(), Error>, Vec<u8>) {
    let mut released = Vec::new();
    let r = (|| {
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
    })();
    (r, released)
}

fn recipient_sets() -> Vec<(&'static str, Vec<Recipient>, Vec<Identity>)> {
    let x = x_identity();
    let s = s_identity();
    let x2 = x2_identity();
    vec![
        ("[x]", vec![recipient_of(&x)], vec![x.clone()]),
        ("[s]", vec![recipient_of(&s)], vec![s.clone()]),
        (
            "[x, s]",
            vec![recipient_of(&x), recipient_of(&s)],
            vec![x.clone(), s.clone()],
        ),
        (
            "[s, x]",
            vec![recipient_of(&s), recipient_of(&x)],
            vec![s.clone(), x.clone()],
        ),
        (
            "[x, x']",
            vec![recipient_of(&x), recipient_of(&x2)],
            vec![x, x2],
        ),
    ]
}

#[test]
fn matrix_round_trips() {
    let mut rng = CounterRng(0);
    for &len in LENGTHS {
        let pt = plaintext(len);
        for (label, recipients, identities) in recipient_sets() {
            let file = encrypt(&mut rng, &recipients, &pt);
            for id in &identities {
                let (r, got) = decrypt(&file, std::slice::from_ref(id));
                r.unwrap_or_else(|e| panic!("{label} len {len}: {e}"));
                assert_eq!(got, pt, "{label} len {len}");
            }
            let (r, got) = decrypt(&file, &identities);
            r.unwrap();
            assert_eq!(got, pt);
            // Header re-encode and inspection.
            let h = Header::parse(&file).unwrap();
            let mut out = vec![0u8; h.len()];
            h.encode(&mut out).unwrap();
            assert_eq!(out, &file[..h.len()]);
            let i = inspect(&file).unwrap();
            let x = recipients
                .iter()
                .filter(|r| matches!(r, Recipient::X25519 { .. }))
                .count();
            assert_eq!(i.x25519, x);
            assert_eq!(i.ssh_ed25519, recipients.len() - x);
            assert_eq!(i.unknown, 0);
            let tag = recipient_of(&s_identity())
                .ssh_tag(&DalekBackend)
                .unwrap()
                .unwrap();
            assert_eq!(i.is_single_ssh_ed25519(&tag), recipients.len() - x == 1);
            // Armor identity.
            let mut armored = vec![0u8; armor::encoded_len(file.len())];
            let n = armor::encode(&file, &mut armored).unwrap();
            assert_eq!(n, armored.len());
            let mut back = vec![0u8; armor::max_decoded_len(n)];
            let m = armor::decode(&armored, &mut back).unwrap();
            assert_eq!(&back[..m], &file[..]);
        }
    }
}

#[test]
fn non_matching_identity_is_no_match() {
    let mut rng = CounterRng(0);
    let file = encrypt(&mut rng, &[recipient_of(&x_identity())], b"hello");
    assert_eq!(decrypt(&file, &[s_identity()]).0, Err(Error::NoMatch));
    assert_eq!(decrypt(&file, &[x2_identity()]).0, Err(Error::NoMatch));
    assert_eq!(decrypt(&file, &[]).0, Err(Error::NoMatch));
    let file = encrypt(&mut rng, &[recipient_of(&s_identity())], b"hello");
    assert_eq!(decrypt(&file, &[x_identity()]).0, Err(Error::NoMatch));
    // Another Ed25519 seed: tag mismatch → skip → NoMatch.
    assert_eq!(
        decrypt(&file, &[Identity::ssh_ed25519([9u8; 32])]).0,
        Err(Error::NoMatch)
    );
}

#[test]
fn tampering() {
    let mut rng = CounterRng(0);
    let ids = [x_identity()];
    let pt = plaintext(2 * CHUNK_LEN + 5);
    let file = encrypt(&mut rng, &[recipient_of(&ids[0])], &pt);
    let h = Header::parse(&file).unwrap();
    let hlen = h.len();

    // MAC line base64 tampered → HmacMismatch (nothing released).
    let mut t = file.clone();
    let mac_pos = hlen - 48 + 4;
    t[mac_pos] = if t[mac_pos] == b'A' { b'B' } else { b'A' };
    let (r, got) = decrypt(&t, &ids);
    assert_eq!(r, Err(Error::HmacMismatch));
    assert!(got.is_empty());

    // Last payload byte flipped → Authentication with all but the last chunk released.
    let mut t = file.clone();
    *t.last_mut().unwrap() ^= 0x01;
    let (r, got) = decrypt(&t, &ids);
    assert_eq!(r, Err(Error::Payload(PayloadError::Authentication)));
    assert_eq!(got, &pt[..2 * CHUNK_LEN]);

    // One byte appended to a short final chunk: the reader sees a 22-byte
    // final chunk and cannot tell it from corruption → Authentication with
    // the full chunks released.
    let mut t = file.clone();
    t.push(0);
    let (r, got) = decrypt(&t, &ids);
    assert_eq!(r, Err(Error::Payload(PayloadError::Authentication)));
    assert_eq!(got, &pt[..2 * CHUNK_LEN]);

    // One byte appended after a *full* final chunk → TrailingData with
    // everything released (the CCTV `stream_trailing_garbage_*` shape).
    let pt_full = plaintext(2 * CHUNK_LEN);
    let mut t = encrypt(&mut rng, &[recipient_of(&ids[0])], &pt_full);
    t.push(0);
    let (r, got) = decrypt(&t, &ids);
    assert_eq!(r, Err(Error::Payload(PayloadError::TrailingData)));
    assert_eq!(got, pt_full);

    // Last chunk truncated to 8 bytes → ChunkTooShort.
    let last_start = hlen + 16 + 2 * CHUNK_SEALED_LEN;
    let t = &file[..last_start + 8];
    let (r, got) = decrypt(t, &ids);
    assert_eq!(r, Err(Error::Payload(PayloadError::ChunkTooShort)));
    assert_eq!(got, &pt[..2 * CHUNK_LEN]);

    // Final chunk of a 2-chunk file deleted → Truncated with the first chunk released.
    let pt2 = plaintext(CHUNK_LEN + 1);
    let file2 = encrypt(&mut rng, &[recipient_of(&ids[0])], &pt2);
    let h2 = Header::parse(&file2).unwrap();
    let t = &file2[..h2.len() + 16 + CHUNK_SEALED_LEN];
    let (r, got) = decrypt(t, &ids);
    assert_eq!(r, Err(Error::Payload(PayloadError::Truncated)));
    assert_eq!(got, &pt2[..CHUNK_LEN]);

    // A stanza byte tampered: the share changes → the AEAD rejects → NoMatch.
    let mut t = file.clone();
    t[40] = if t[40] == b'A' { b'B' } else { b'A' };
    assert_eq!(decrypt(&t, &ids).0, Err(Error::NoMatch));
}

#[test]
fn encrypt_header_errors() {
    let mut rng = CounterRng(0);
    let fk = FileKey::from_bytes([1; 16]);
    let mut out = [0u8; 512];
    assert_eq!(
        encrypt_header(&DalekBackend, &mut rng, &[], &fk, &mut out),
        Err(Error::NoRecipients)
    );
    let r = recipient_of(&x_identity());
    assert_eq!(
        encrypt_header(&DalekBackend, &mut rng, &[r], &fk, &mut [0u8; 100]),
        Err(Error::BufferTooSmall)
    );
    // Low-order X25519 recipient key (all zero).
    assert_eq!(
        encrypt_header(
            &DalekBackend,
            &mut rng,
            &[Recipient::X25519 {
                public_key: [0; 32]
            }],
            &fk,
            &mut out
        ),
        Err(Error::Key(spacetime_age::KeyError::InvalidPublicKey))
    );
    // Invalid Ed25519 recipient key (identity point).
    let mut id_pt = [0u8; 32];
    id_pt[0] = 1;
    assert_eq!(
        encrypt_header(
            &DalekBackend,
            &mut rng,
            &[Recipient::SshEd25519 { public_key: id_pt }],
            &fk,
            &mut out
        ),
        Err(Error::Key(spacetime_age::KeyError::InvalidPublicKey))
    );
}

#[test]
fn low_order_share_is_fatal() {
    // Build a valid file, then replace the X25519 share with the all-zero
    // point: the unwrap must abort with LowOrderShare rather than skip.
    let mut rng = CounterRng(0);
    let ids = [x_identity()];
    let file = encrypt(&mut rng, &[recipient_of(&ids[0])], b"x");
    let mut t = file.clone();
    let share = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    t[32..32 + 43].copy_from_slice(share);
    assert_eq!(
        decrypt(&t, &ids).0,
        Err(Error::Header(spacetime_age::HeaderError::LowOrderShare))
    );
    // The same share in an ssh-ed25519 stanza is fatal too.
    let sids = [s_identity()];
    let file = encrypt(&mut rng, &[recipient_of(&sids[0])], b"x");
    let mut t = file.clone();
    t[44..44 + 43].copy_from_slice(share);
    assert_eq!(
        decrypt(&t, &sids).0,
        Err(Error::Header(spacetime_age::HeaderError::LowOrderShare))
    );
}

#[test]
fn ssh_tag_matches_sha256_of_the_wire_form() {
    let r = recipient_of(&s_identity());
    let wire = r.ssh_wire().unwrap();
    let d = DalekBackend.sha256(&wire).unwrap();
    assert_eq!(r.ssh_tag(&DalekBackend).unwrap().unwrap(), d[..4]);
    assert_eq!(
        recipient_of(&x_identity()).ssh_tag(&DalekBackend).unwrap(),
        None
    );
}
