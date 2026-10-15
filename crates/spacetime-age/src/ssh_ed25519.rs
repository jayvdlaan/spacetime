//! The `ssh-ed25519` recipient type: an OpenSSH Ed25519 key used for age.
//!
//! This is the recipe `rage` 0.12 and Go `agessh` implement (verified
//! against rage in both directions — note the HKDF argument roles):
//!
//! ```text
//! wire  = uint32(11) ‖ "ssh-ed25519" ‖ uint32(32) ‖ pk           (51 bytes)
//! tag   = SHA-256(wire)[0..4]
//! LABEL = "age-encryption.org/v1/ssh-ed25519"
//! tweak = HKDF-SHA-256(salt = wire, ikm = "", info = LABEL)      (32 bytes, used as an X25519 scalar)
//! pk_mont = Edwards→Montgomery(pk)                               (Ed25519ToX25519 on encrypt;
//!                                                                 X25519(clamp(SHA-512(seed)[..32]), 9) on decrypt)
//! ```
//!
//! Wrap: `e ← rng[32]`, `eph = X25519(e, 9)`, `inner = X25519(e, pk_mont)`,
//! `shared = X25519(tweak, inner)`, `wrap_key = HKDF(salt = eph ‖ pk_mont,
//! ikm = shared, info = LABEL)` — the salt uses the **untweaked** `pk_mont`
//! — then `body = ChaCha20-Poly1305(wrap_key, 0¹², "", file_key) ‖ tag`, and
//! the stanza is `-> ssh-ed25519 b64(tag) b64(eph)\n b64(body)\n` (110 bytes).
//!
//! Unwrap (from the 32-byte seed): recompute the tag, skip on mismatch;
//! `a = SHA-512(seed)[0..32]` (the facade clamps), `inner = X25519(a,
//! eph)`, `shared = X25519(tweak, inner)`, same wrap key; an all-zero
//! result from either X25519 is fatal (`Header(LowOrderShare)`), an AEAD
//! failure means "not ours" (`Ok(None)`).

use spacetime_crypto::{
    ChaCha20Poly1305, CryptoErrorKind, Ed25519Sign, Ed25519ToX25519, HkdfSha256, Rng, Sha256,
    Sha512, X25519,
};

use crate::base64;
use crate::error::{Error, HeaderError, KeyError};
use crate::keys::{FileKey, FILE_KEY_LEN};
use crate::stanza::{encode_stanza, Stanza, StanzaKind, STANZA_TYPE_SSH_ED25519};
use crate::util::wipe;

/// HKDF info / label string.
pub const INFO: &[u8] = b"age-encryption.org/v1/ssh-ed25519";
/// Encoded stanza length: `"-> ssh-ed25519 " + 6 + " " + 43 + "\n" + 43 + "\n"`.
pub const STANZA_LEN: usize = 110;
/// SSH wire form length of an ssh-ed25519 public key.
pub const WIRE_LEN: usize = 51;
/// Sealed file key length: 16 + 16-byte tag.
const BODY_LEN: usize = FILE_KEY_LEN + 16;

const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// `uint32(11) ‖ "ssh-ed25519" ‖ uint32(32) ‖ public_key`.
pub fn ssh_wire(public_key: &[u8; 32]) -> [u8; WIRE_LEN] {
    let mut w = [0u8; WIRE_LEN];
    w[..4].copy_from_slice(&[0, 0, 0, 11]);
    w[4..15].copy_from_slice(b"ssh-ed25519");
    w[15..19].copy_from_slice(&[0, 0, 0, 32]);
    w[19..].copy_from_slice(public_key);
    w
}

/// `SHA-256(ssh_wire(public_key))[0..4]`.
pub fn tag<H: Sha256 + ?Sized>(h: &H, public_key: &[u8; 32]) -> Result<[u8; 4], Error> {
    let d = h.sha256(&ssh_wire(public_key))?;
    let mut t = [0u8; 4];
    t.copy_from_slice(&d[..4]);
    Ok(t)
}

/// `HKDF(salt = wire, ikm = "", info = LABEL)`.
fn tweak<B: HkdfSha256 + ?Sized>(b: &B, wire: &[u8; WIRE_LEN]) -> Result<[u8; 32], Error> {
    let mut t = [0u8; 32];
    if let Err(e) = b.hkdf_sha256(wire, &[], INFO, &mut t) {
        wipe(&mut t);
        return Err(e.into());
    }
    Ok(t)
}

/// `X25519(tweak, X25519(k, u))`; wipes `tweak`. `InvalidParameter` from
/// either step is mapped to `low_order`.
fn tweaked_dh<B: X25519 + ?Sized>(
    b: &B,
    k: &[u8; 32],
    u: &[u8; 32],
    tweak: &mut [u8; 32],
    low_order: Error,
) -> Result<[u8; 32], Error> {
    let mut inner = [0u8; 32];
    let mut shared = [0u8; 32];
    let r = b
        .x25519(k, u, &mut inner)
        .and_then(|()| b.x25519(tweak, &inner, &mut shared));
    wipe(&mut inner);
    wipe(tweak);
    match r {
        Ok(()) => Ok(shared),
        Err(e) if e.kind() == CryptoErrorKind::InvalidParameter => {
            wipe(&mut shared);
            Err(low_order)
        }
        Err(e) => {
            wipe(&mut shared);
            Err(e.into())
        }
    }
}

/// `HKDF(salt = share ‖ pk_mont, ikm = shared, info = LABEL)`; wipes `shared`.
fn wrap_key<B: HkdfSha256 + ?Sized>(
    b: &B,
    share: &[u8; 32],
    pk_mont: &[u8; 32],
    shared: &mut [u8; 32],
) -> Result<[u8; 32], Error> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(share);
    salt[32..].copy_from_slice(pk_mont);
    let mut key = [0u8; 32];
    let r = b.hkdf_sha256(&salt, shared, INFO, &mut key);
    wipe(shared);
    if let Err(e) = r {
        wipe(&mut key);
        return Err(e.into());
    }
    Ok(key)
}

/// Build the stanza for the Ed25519 `public_key`, drawing the 32-byte
/// ephemeral scalar from `rng`. Writes the whole stanza text (110 bytes).
pub fn wrap<
    B: Sha256 + HkdfSha256 + Ed25519ToX25519 + X25519 + ChaCha20Poly1305 + ?Sized,
    R: Rng + ?Sized,
>(
    b: &B,
    rng: &mut R,
    public_key: &[u8; 32],
    file_key: &FileKey,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < STANZA_LEN {
        return Err(Error::BufferTooSmall);
    }
    let pk_mont = match b.ed25519_public_to_x25519(public_key) {
        Ok(u) => u,
        Err(e) if e.kind() == CryptoErrorKind::InvalidParameter => {
            return Err(Error::Key(KeyError::InvalidPublicKey));
        }
        Err(e) => return Err(e.into()),
    };
    let wire = ssh_wire(public_key);
    let tag = tag(b, public_key)?;
    let mut tw = tweak(b, &wire)?;
    let mut e = [0u8; 32];
    if let Err(err) = rng.fill_bytes(&mut e) {
        wipe(&mut tw);
        return Err(err.into());
    }
    let r = wrap_with(b, &e, &mut tw, &pk_mont, &tag, file_key, out);
    wipe(&mut e);
    r
}

fn wrap_with<B: HkdfSha256 + X25519 + ChaCha20Poly1305 + ?Sized>(
    b: &B,
    e: &[u8; 32],
    tw: &mut [u8; 32],
    pk_mont: &[u8; 32],
    tag: &[u8; 4],
    file_key: &FileKey,
    out: &mut [u8],
) -> Result<usize, Error> {
    let eph = match b.x25519_public_key(e) {
        Ok(p) => p,
        Err(err) => {
            wipe(tw);
            return Err(err.into());
        }
    };
    let mut shared = tweaked_dh(b, e, pk_mont, tw, Error::Key(KeyError::InvalidPublicKey))?;
    let mut key = wrap_key(b, &eph, pk_mont, &mut shared)?;
    let mut body = [0u8; BODY_LEN];
    let sealed =
        b.chacha20poly1305_seal_into(&key, &ZERO_NONCE, &[], file_key.as_bytes(), &mut body);
    wipe(&mut key);
    sealed?;
    let mut tag_b64 = [0u8; 6];
    base64::encode_nopad(tag, &mut tag_b64)?;
    let mut share_b64 = [0u8; 43];
    base64::encode_nopad(&eph, &mut share_b64)?;
    let failed = || Error::Backend(CryptoErrorKind::Failed);
    let tag_s = core::str::from_utf8(&tag_b64).map_err(|_| failed())?;
    let share_s = core::str::from_utf8(&share_b64).map_err(|_| failed())?;
    encode_stanza(STANZA_TYPE_SSH_ED25519, &[tag_s, share_s], &body, out)
}

/// Try to unwrap `stanza` with the Ed25519 `seed`. `Ok(None)`: not an
/// ssh-ed25519 stanza, tag mismatch, or the AEAD rejected it.
/// `Err(Header(LowOrderShare))` is fatal.
pub fn unwrap<
    B: Sha256 + Sha512 + HkdfSha256 + Ed25519Sign + X25519 + ChaCha20Poly1305 + ?Sized,
>(
    b: &B,
    seed: &[u8; 32],
    stanza: &Stanza<'_>,
) -> Result<Option<FileKey>, Error> {
    if stanza.kind() != StanzaKind::SshEd25519 {
        return Ok(None);
    }
    let e = Error::Header(HeaderError::SshEd25519Stanza);
    let want_tag = stanza.arg_bytes::<4>(0, e)?;
    let share = stanza.arg_bytes::<32>(1, e)?;
    let body = stanza.body_array::<BODY_LEN>(e)?;

    let pk = b.ed25519_public_key(seed)?;
    if tag(b, &pk)? != want_tag {
        return Ok(None);
    }
    let wire = ssh_wire(&pk);

    let mut h = b.sha512(seed)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    wipe(&mut h);
    let r = unwrap_with(b, &a, &wire, &share, &body);
    wipe(&mut a);
    r
}

fn unwrap_with<B: HkdfSha256 + X25519 + ChaCha20Poly1305 + ?Sized>(
    b: &B,
    a: &[u8; 32],
    wire: &[u8; WIRE_LEN],
    share: &[u8; 32],
    body: &[u8; BODY_LEN],
) -> Result<Option<FileKey>, Error> {
    let pk_mont = b.x25519_public_key(a)?;
    let mut tw = tweak(b, wire)?;
    let mut shared = tweaked_dh(
        b,
        a,
        share,
        &mut tw,
        Error::Header(HeaderError::LowOrderShare),
    )?;
    let mut key = wrap_key(b, share, &pk_mont, &mut shared)?;
    let mut fk = [0u8; FILE_KEY_LEN];
    let r = b.chacha20poly1305_open_into(&key, &ZERO_NONCE, &[], body, &mut fk);
    wipe(&mut key);
    match r {
        Ok(_) => Ok(Some(FileKey::from_bytes(fk))),
        Err(err) if err.kind() == CryptoErrorKind::AuthenticationFailed => {
            wipe(&mut fk);
            Ok(None)
        }
        Err(err) => {
            wipe(&mut fk);
            Err(err.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_layout() {
        let w = ssh_wire(&[0xAB; 32]);
        assert_eq!(&w[..4], &[0, 0, 0, 11]);
        assert_eq!(&w[4..15], b"ssh-ed25519");
        assert_eq!(&w[15..19], &[0, 0, 0, 32]);
        assert!(w[19..].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn stanza_len_is_the_encoded_len() {
        assert_eq!(
            crate::stanza::encoded_len(STANZA_TYPE_SSH_ED25519.len(), 1 + 6 + 1 + 43, BODY_LEN),
            STANZA_LEN
        );
    }
}
