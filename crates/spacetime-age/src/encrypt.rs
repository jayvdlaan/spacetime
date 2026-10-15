//! Encrypt side: header construction and the `alloc` whole-file
//! conveniences.
//!
//! Randomness is drawn from the caller's `Rng` in a pinned order, which
//! makes encryption byte-deterministic under a deterministic `Rng` (the
//! `pyref_*` known-answer vectors): 16 bytes for the file key
//! ([`FileKey::generate`], called by `encrypt_vec` / the std layer), then
//! 32 bytes per recipient in recipient order — drawn immediately before that
//! recipient's stanza is built — then 16 bytes for the payload nonce
//! ([`crate::StreamWriter::new`]). No facade method draws randomness of its own.

use spacetime_crypto::{
    ChaCha20Poly1305, Ed25519ToX25519, HkdfSha256, HmacSha256, Rng, Sha256, X25519,
};

use crate::error::Error;
use crate::header::{compute_mac, encode_mac_line, MAC_LINE_LEN, MAGIC};
use crate::keys::{FileKey, Recipient};
use crate::stream::sealed_payload_len;
use crate::{ssh_ed25519, x25519};

/// Everything the encrypt side needs from a backend.
pub trait EncryptBackend:
    Sha256 + HmacSha256 + HkdfSha256 + ChaCha20Poly1305 + X25519 + Ed25519ToX25519
{
}

impl<
        T: Sha256 + HmacSha256 + HkdfSha256 + ChaCha20Poly1305 + X25519 + Ed25519ToX25519 + ?Sized,
    > EncryptBackend for T
{
}

/// `22 + 98·#X25519 + 110·#ssh-ed25519 + 48`.
pub const fn encrypt_header_len(x25519: usize, ssh_ed25519: usize) -> usize {
    MAGIC.len() + x25519::STANZA_LEN * x25519 + ssh_ed25519::STANZA_LEN * ssh_ed25519 + MAC_LINE_LEN
}

/// Header length for `recipients` (no grease is ever emitted).
pub fn header_len_for(recipients: &[Recipient]) -> usize {
    let x = recipients
        .iter()
        .filter(|r| matches!(r, Recipient::X25519 { .. }))
        .count();
    encrypt_header_len(x, recipients.len() - x)
}

/// Header plus [`sealed_payload_len`] (binary, unarmored).
pub fn encrypted_len(recipients: &[Recipient], plaintext_len: usize) -> usize {
    header_len_for(recipients) + sealed_payload_len(plaintext_len)
}

/// Write `MAGIC`, one stanza per recipient in order (drawing 32 `rng` bytes
/// each), and the MAC line into `out`. Returns [`header_len_for`]
/// `(recipients)`. An empty `recipients` is `NoRecipients`; a short `out`
/// is `BufferTooSmall`; a low-order or invalid recipient key is
/// `Key(InvalidPublicKey)`.
pub fn encrypt_header<B: EncryptBackend + ?Sized, R: Rng + ?Sized>(
    b: &B,
    rng: &mut R,
    recipients: &[Recipient],
    file_key: &FileKey,
    out: &mut [u8],
) -> Result<usize, Error> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }
    let total = header_len_for(recipients);
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    let mut pos = 0usize;
    out[..MAGIC.len()].copy_from_slice(MAGIC);
    pos += MAGIC.len();
    for r in recipients {
        pos += match r {
            Recipient::X25519 { public_key } => {
                x25519::wrap(b, rng, public_key, file_key, &mut out[pos..])?
            }
            Recipient::SshEd25519 { public_key } => {
                ssh_ed25519::wrap(b, rng, public_key, file_key, &mut out[pos..])?
            }
        };
    }
    out[pos..pos + 3].copy_from_slice(b"---");
    let mac = compute_mac(b, file_key, &out[..pos + 3])?;
    pos += encode_mac_line(&mac, &mut out[pos..])?;
    debug_assert_eq!(pos, total);
    Ok(pos)
}

/// Whole-file encryption: [`FileKey::generate`] → [`encrypt_header`] →
/// [`crate::StreamWriter::new`] → chunks. The result has exactly
/// [`encrypted_len`] bytes.
#[cfg(feature = "alloc")]
pub fn encrypt_vec<B: EncryptBackend + ?Sized, R: Rng + ?Sized>(
    b: &B,
    rng: &mut R,
    recipients: &[Recipient],
    plaintext: &[u8],
) -> Result<alloc::vec::Vec<u8>, Error> {
    use crate::stream::{StreamWriter, CHUNK_LEN, PAYLOAD_NONCE_LEN};

    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }
    let file_key = FileKey::generate(rng)?;
    let mut out = alloc::vec![0u8; encrypted_len(recipients, plaintext.len())];
    let mut pos = encrypt_header(b, rng, recipients, &file_key, &mut out)?;
    let mut w = StreamWriter::new(b, &file_key, rng)?;
    out[pos..pos + PAYLOAD_NONCE_LEN].copy_from_slice(w.nonce());
    pos += PAYLOAD_NONCE_LEN;
    let mut chunks = plaintext.chunks(CHUNK_LEN).peekable();
    let mut wrote_any = false;
    while let Some(chunk) = chunks.next() {
        wrote_any = true;
        pos += if chunks.peek().is_some() {
            w.write_chunk(chunk, &mut out[pos..])?
        } else {
            w.write_last(chunk, &mut out[pos..])?
        };
    }
    if !wrote_any {
        pos += w.write_last(&[], &mut out[pos..])?;
    }
    debug_assert_eq!(pos, out.len());
    Ok(out)
}

/// [`encrypt_vec`] then [`crate::armor::encode_string`].
#[cfg(feature = "alloc")]
pub fn encrypt_armored_string<B: EncryptBackend + ?Sized, R: Rng + ?Sized>(
    b: &B,
    rng: &mut R,
    recipients: &[Recipient],
    plaintext: &[u8],
) -> Result<alloc::string::String, Error> {
    let v = encrypt_vec(b, rng, recipients, plaintext)?;
    Ok(crate::armor::encode_string(&v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lengths() {
        assert_eq!(encrypt_header_len(0, 0), 70);
        assert_eq!(encrypt_header_len(1, 0), 168);
        assert_eq!(encrypt_header_len(1, 1), 278);
        let x = Recipient::X25519 {
            public_key: [1; 32],
        };
        let s = Recipient::SshEd25519 {
            public_key: [2; 32],
        };
        assert_eq!(header_len_for(&[x, s]), 278);
        assert_eq!(header_len_for(&[s, s, x]), 22 + 98 + 220 + 48);
        // det.age: 22 + 98 + 110 + 48 + 16 + 4 + 16 = 314
        assert_eq!(encrypted_len(&[x, s], 4), 314);
        assert_eq!(encrypted_len(&[x], 0), 168 + 32);
    }
}
