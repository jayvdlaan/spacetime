//! The native `X25519` recipient type.
//!
//! Wrap (`pk` = recipient public key, `file_key`):
//!
//! ```text
//! e ← rng[32];  eph = X25519(e, 9)
//! shared = X25519(e, pk)                              (all-zero → Key(InvalidPublicKey))
//! wrap_key = HKDF-SHA-256(salt = eph ‖ pk, ikm = shared, info = "age-encryption.org/v1/X25519")
//! body = ChaCha20-Poly1305(wrap_key, nonce = 0¹², aad = "", file_key) ‖ tag   (32 bytes)
//! -> X25519 b64(eph)\n b64(body)\n                    (98 bytes)
//! ```
//!
//! Unwrap mirrors it with `pk = X25519(secret, 9)` and `shared =
//! X25519(secret, eph)`; an all-zero `shared` is fatal
//! (`Header(LowOrderShare)`), an AEAD failure means "not ours" (`Ok(None)`).

use spacetime_crypto::{ChaCha20Poly1305, CryptoErrorKind, HkdfSha256, Rng, X25519};

use crate::base64;
use crate::error::{Error, HeaderError, KeyError};
use crate::keys::{FileKey, FILE_KEY_LEN};
use crate::stanza::{encode_stanza, Stanza, StanzaKind, STANZA_TYPE_X25519};
use crate::util::wipe;

/// HKDF info string.
pub const INFO: &[u8] = b"age-encryption.org/v1/X25519";
/// Encoded stanza length: `"-> X25519 " + 43 + "\n" + 43 + "\n"`.
pub const STANZA_LEN: usize = 98;
/// Sealed file key length: 16 + 16-byte tag.
const BODY_LEN: usize = FILE_KEY_LEN + 16;

const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// The wrap key for a `(share, pk, shared)` triple; wipes `shared`.
fn wrap_key<B: HkdfSha256 + ?Sized>(
    b: &B,
    share: &[u8; 32],
    pk: &[u8; 32],
    shared: &mut [u8; 32],
) -> Result<[u8; 32], Error> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(share);
    salt[32..].copy_from_slice(pk);
    let mut key = [0u8; 32];
    let r = b.hkdf_sha256(&salt, shared, INFO, &mut key);
    wipe(shared);
    if let Err(e) = r {
        wipe(&mut key);
        return Err(e.into());
    }
    Ok(key)
}

/// Build the stanza for `public_key`, drawing the 32-byte ephemeral scalar
/// from `rng`. Writes the whole stanza text (98 bytes) into `out`.
pub fn wrap<B: X25519 + HkdfSha256 + ChaCha20Poly1305 + ?Sized, R: Rng + ?Sized>(
    b: &B,
    rng: &mut R,
    public_key: &[u8; 32],
    file_key: &FileKey,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < STANZA_LEN {
        return Err(Error::BufferTooSmall);
    }
    let mut e = [0u8; 32];
    rng.fill_bytes(&mut e)?;
    let r = wrap_with(b, &e, public_key, file_key, out);
    wipe(&mut e);
    r
}

fn wrap_with<B: X25519 + HkdfSha256 + ChaCha20Poly1305 + ?Sized>(
    b: &B,
    e: &[u8; 32],
    public_key: &[u8; 32],
    file_key: &FileKey,
    out: &mut [u8],
) -> Result<usize, Error> {
    let eph = b.x25519_public_key(e)?;
    let mut shared = [0u8; 32];
    match b.x25519(e, public_key, &mut shared) {
        Ok(()) => {}
        Err(err) if err.kind() == CryptoErrorKind::InvalidParameter => {
            return Err(Error::Key(KeyError::InvalidPublicKey));
        }
        Err(err) => return Err(err.into()),
    }
    let mut key = wrap_key(b, &eph, public_key, &mut shared)?;
    let mut body = [0u8; BODY_LEN];
    let sealed =
        b.chacha20poly1305_seal_into(&key, &ZERO_NONCE, &[], file_key.as_bytes(), &mut body);
    wipe(&mut key);
    sealed?;
    let mut share_b64 = [0u8; 43];
    base64::encode_nopad(&eph, &mut share_b64)?;
    let share =
        core::str::from_utf8(&share_b64).map_err(|_| Error::Backend(CryptoErrorKind::Failed))?;
    encode_stanza(STANZA_TYPE_X25519, &[share], &body, out)
}

/// Try to unwrap `stanza` with `secret`. `Ok(None)`: not an X25519 stanza,
/// or the AEAD rejected it (not ours). `Err(Header(LowOrderShare))` is
/// fatal.
pub fn unwrap<B: X25519 + HkdfSha256 + ChaCha20Poly1305 + ?Sized>(
    b: &B,
    secret: &[u8; 32],
    stanza: &Stanza<'_>,
) -> Result<Option<FileKey>, Error> {
    if stanza.kind() != StanzaKind::X25519 {
        return Ok(None);
    }
    let e = Error::Header(HeaderError::X25519Stanza);
    let share = stanza.arg_bytes::<32>(0, e)?;
    let body = stanza.body_array::<BODY_LEN>(e)?;
    let pk = b.x25519_public_key(secret)?;
    let mut shared = [0u8; 32];
    match b.x25519(secret, &share, &mut shared) {
        Ok(()) => {}
        Err(err) if err.kind() == CryptoErrorKind::InvalidParameter => {
            return Err(Error::Header(HeaderError::LowOrderShare));
        }
        Err(err) => return Err(err.into()),
    }
    let mut key = wrap_key(b, &share, &pk, &mut shared)?;
    let mut fk = [0u8; FILE_KEY_LEN];
    let r = b.chacha20poly1305_open_into(&key, &ZERO_NONCE, &[], &body, &mut fk);
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
    fn stanza_len_is_the_encoded_len() {
        assert_eq!(
            crate::stanza::encoded_len(STANZA_TYPE_X25519.len(), 1 + 43, BODY_LEN),
            STANZA_LEN
        );
    }

    #[test]
    fn unwrap_ignores_other_kinds_without_touching_the_backend() {
        struct Never;
        impl X25519 for Never {
            fn x25519_public_key(&self, _: &[u8; 32]) -> spacetime_crypto::CryptoResult<[u8; 32]> {
                panic!("must not be called")
            }
            fn x25519(
                &self,
                _: &[u8; 32],
                _: &[u8; 32],
                _: &mut [u8; 32],
            ) -> spacetime_crypto::CryptoResult<()> {
                panic!("must not be called")
            }
        }
        impl HkdfSha256 for Never {
            fn hkdf_sha256_extract(
                &self,
                _: &[u8],
                _: &[u8],
                _: &mut [u8; 32],
            ) -> spacetime_crypto::CryptoResult<()> {
                panic!("must not be called")
            }
            fn hkdf_sha256_expand(
                &self,
                _: &[u8; 32],
                _: &[u8],
                _: &mut [u8],
            ) -> spacetime_crypto::CryptoResult<()> {
                panic!("must not be called")
            }
        }
        impl ChaCha20Poly1305 for Never {
            fn chacha20poly1305_seal(
                &self,
                _: &[u8; 32],
                _: &[u8; 12],
                _: &[u8],
                _: &mut [u8],
            ) -> spacetime_crypto::CryptoResult<[u8; 16]> {
                panic!("must not be called")
            }
            fn chacha20poly1305_open(
                &self,
                _: &[u8; 32],
                _: &[u8; 12],
                _: &[u8],
                _: &mut [u8],
                _: &[u8; 16],
            ) -> spacetime_crypto::CryptoResult<()> {
                panic!("must not be called")
            }
        }
        let st = Stanza::new("ssh-ed25519", "a b", b"");
        assert!(unwrap(&Never, &[1; 32], &st).unwrap().is_none());
    }
}
