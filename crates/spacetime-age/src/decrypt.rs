//! Decrypt side: file-key unwrapping and the `alloc` whole-file
//! conveniences.
//!
//! Unwrap order is Go's: identities outer, stanzas inner; the first success
//! wins; a fatal stanza error (`Header(LowOrderShare)`, `Backend`) aborts.
//! An ssh-ed25519 tag mismatch, or a tag match whose AEAD fails, is a
//! *skip* (Go semantics; rage treats the latter as fatal). After the loop:
//! `Unsupported(Scrypt)` if a scrypt stanza was seen, else
//! `Unsupported(SshRsa)` if an ssh-rsa stanza was seen, else `NoMatch`.
//! The header MAC is verified before a file key is returned — a file key is
//! never handed out unauthenticated.

use spacetime_crypto::{
    ChaCha20Poly1305, Ed25519Sign, HkdfSha256, HmacSha256, Sha256, Sha512, X25519,
};

use crate::error::{Error, UnsupportedStanza};
use crate::header::{verify_mac, Header};
use crate::keys::{FileKey, Identity, IdentityKind};
use crate::{ssh_ed25519, x25519};

/// Everything the decrypt side needs from a backend.
pub trait DecryptBackend:
    Sha256 + Sha512 + HmacSha256 + HkdfSha256 + ChaCha20Poly1305 + X25519 + Ed25519Sign
{
}

impl<
        T: Sha256
            + Sha512
            + HmacSha256
            + HkdfSha256
            + ChaCha20Poly1305
            + X25519
            + Ed25519Sign
            + ?Sized,
    > DecryptBackend for T
{
}

/// Find the file key of `header` with `identities` (order above) and verify
/// the header MAC under it. `identities.is_empty()` → `NoMatch` (after the
/// unsupported check).
pub fn unwrap_file_key<B: DecryptBackend + ?Sized>(
    b: &B,
    header: &Header<'_>,
    identities: &[Identity],
) -> Result<FileKey, Error> {
    for id in identities {
        for st in header.stanzas() {
            let found = match id.kind() {
                IdentityKind::X25519 => x25519::unwrap(b, id.secret(), &st)?,
                IdentityKind::SshEd25519 => ssh_ed25519::unwrap(b, id.secret(), &st)?,
            };
            if let Some(fk) = found {
                verify_mac(b, &fk, header)?;
                return Ok(fk);
            }
        }
    }
    let (_, _, scrypt, ssh_rsa, _) = header.counts();
    if scrypt > 0 {
        Err(Error::Unsupported(UnsupportedStanza::Scrypt))
    } else if ssh_rsa > 0 {
        Err(Error::Unsupported(UnsupportedStanza::SshRsa))
    } else {
        Err(Error::NoMatch)
    }
}

/// Whole-file decryption: parse, unwrap, stream every chunk. `Err` releases
/// nothing (the partial plaintext is dropped).
#[cfg(feature = "alloc")]
pub fn decrypt_vec<B: DecryptBackend + ?Sized>(
    b: &B,
    identities: &[Identity],
    ciphertext: &[u8],
) -> Result<alloc::vec::Vec<u8>, Error> {
    use crate::stream::{StreamReader, CHUNK_LEN, CHUNK_SEALED_LEN};

    let header = Header::parse(ciphertext)?;
    let file_key = unwrap_file_key(b, &header, identities)?;
    let mut reader = StreamReader::new(b, &file_key, header.nonce())?;
    let mut payload = header.payload();
    let mut out = alloc::vec::Vec::with_capacity(payload.len());
    let mut buf = alloc::vec![0u8; CHUNK_LEN];
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

/// [`crate::armor::decode_vec`] then [`decrypt_vec`].
#[cfg(feature = "alloc")]
pub fn decrypt_armored_vec<B: DecryptBackend + ?Sized>(
    b: &B,
    identities: &[Identity],
    armored: &[u8],
) -> Result<alloc::vec::Vec<u8>, Error> {
    let v = crate::armor::decode_vec(armored)?;
    decrypt_vec(b, identities, &v)
}
