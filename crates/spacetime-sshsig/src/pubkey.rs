//! OpenSSH public-key blobs (RFC 8709 §4, PROTOCOL.u2f), `.pub` /
//! `authorized_keys`-style lines and `SHA256:` fingerprints.
//!
//! Only two key types exist here: `ssh-ed25519` and
//! `sk-ssh-ed25519@openssh.com`. Everything else (RSA, ECDSA, DSA, every
//! `*-cert-v01@openssh.com`) is an explicit [`Error::UnknownKeyType`] at
//! parse time — never a silent accept. Parsing is zero-copy: a
//! [`PublicKey`] borrows the key bytes and the sk `application` from the
//! blob it was parsed from.

use spacetime_crypto::{Ed25519Verify, Sha256, Sha256State};

use crate::armor::{self, Base64Encoder};
use crate::error::{Error, Section};
use crate::wire::{string_len, Reader, Writer};

/// Key type string of a plain Ed25519 key (RFC 8709).
pub const KEY_TYPE_ED25519: &str = "ssh-ed25519";
/// Key type string of a FIDO/U2F-backed Ed25519 key (PROTOCOL.u2f).
pub const KEY_TYPE_SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";
/// `"SHA256:"` (7) + 43 base64 characters without padding.
pub const FINGERPRINT_LEN: usize = 50;

const FINGERPRINT_PREFIX: &[u8] = b"SHA256:";

/// Borrowed view of an OpenSSH public-key blob (RFC 8709 §4 / PROTOCOL.u2f).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKey<'a> {
    /// `string "ssh-ed25519" || string key[32]`
    Ed25519 {
        /// The compressed Edwards point.
        key: &'a [u8; 32],
    },
    /// `string "sk-ssh-ed25519@openssh.com" || string key[32] || string application`
    SkEd25519 {
        /// The compressed Edwards point.
        key: &'a [u8; 32],
        /// The FIDO relying-party id (`ssh:` for plain OpenSSH keys). Its
        /// SHA-256 is the first field of the sk signing formula.
        application: &'a [u8],
    },
}

impl<'a> PublicKey<'a> {
    /// The key type string (`ssh-ed25519` / `sk-ssh-ed25519@openssh.com`).
    pub const fn key_type(&self) -> &'static str {
        match self {
            PublicKey::Ed25519 { .. } => KEY_TYPE_ED25519,
            PublicKey::SkEd25519 { .. } => KEY_TYPE_SK_ED25519,
        }
    }

    /// The 32-byte Ed25519 public key.
    pub const fn key(&self) -> &'a [u8; 32] {
        match self {
            PublicKey::Ed25519 { key } | PublicKey::SkEd25519 { key, .. } => key,
        }
    }

    /// `true` for `sk-ssh-ed25519@openssh.com`.
    pub const fn is_sk(&self) -> bool {
        matches!(self, PublicKey::SkEd25519 { .. })
    }

    /// Parse a whole key blob; it must be consumed exactly
    /// ([`Error::TrailingBytes`]`(`[`Section::PublicKey`]`)`).
    ///
    /// A type string other than the two constants →
    /// [`Error::UnknownKeyType`] (this covers `ssh-rsa`, `ecdsa-*`,
    /// `*-cert-v01@openssh.com`, `ssh-dss`); a key string that is not 32
    /// bytes → [`Error::BadKeyLength`].
    pub fn parse_blob(blob: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(blob);
        let key_type = r.string()?;
        let is_sk = if key_type == KEY_TYPE_ED25519.as_bytes() {
            false
        } else if key_type == KEY_TYPE_SK_ED25519.as_bytes() {
            true
        } else {
            return Err(Error::UnknownKeyType);
        };
        let key = <&[u8; 32]>::try_from(r.string()?).map_err(|_| Error::BadKeyLength)?;
        let pk = if is_sk {
            let application = r.string()?;
            PublicKey::SkEd25519 { key, application }
        } else {
            PublicKey::Ed25519 { key }
        };
        r.finish(Section::PublicKey)?;
        Ok(pk)
    }

    /// Encoded blob length: 51 for `ssh-ed25519`, `70 + application.len()`
    /// for `sk-ssh-ed25519@openssh.com`.
    pub const fn blob_len(&self) -> usize {
        match self {
            PublicKey::Ed25519 { .. } => string_len(KEY_TYPE_ED25519.len()) + string_len(32),
            PublicKey::SkEd25519 { application, .. } => {
                string_len(KEY_TYPE_SK_ED25519.len())
                    + string_len(32)
                    + string_len(application.len())
            }
        }
    }

    /// Write the blob fields through `w` (used by [`PublicKey::encode_blob`]
    /// and by the SSHSIG encoder, which wraps them in a `string`).
    pub(crate) fn write_to(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.for_each_part(|part| w.put_bytes(part))
    }

    /// Visit the blob's wire bytes piecewise, in order, without a scratch
    /// buffer: `len(type) || type || len(key) || key [|| len(app) || app]`.
    fn for_each_part<F>(&self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&[u8]) -> Result<(), Error>,
    {
        let key_type = self.key_type().as_bytes();
        let type_len = u32::try_from(key_type.len()).map_err(|_| Error::TooLong)?;
        f(&type_len.to_be_bytes())?;
        f(key_type)?;
        f(&32u32.to_be_bytes())?;
        f(self.key())?;
        if let PublicKey::SkEd25519 { application, .. } = self {
            let app_len = u32::try_from(application.len()).map_err(|_| Error::TooLong)?;
            f(&app_len.to_be_bytes())?;
            f(application)?;
        }
        Ok(())
    }

    /// Encode the blob into `out`; returns bytes written
    /// ([`PublicKey::blob_len`]).
    pub fn encode_blob(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        self.write_to(&mut w)?;
        Ok(w.finish())
    }

    /// `SHA256:` + base64-nopad(SHA-256(blob)) — the string `ssh-keygen -lf`
    /// prints. Hashes the blob piecewise through [`Sha256State`] (no
    /// scratch buffer). Returns the `&str` view of `out`.
    pub fn fingerprint<'o, H: ?Sized + Sha256>(
        &self,
        h: &H,
        out: &'o mut [u8; FINGERPRINT_LEN],
    ) -> Result<&'o str, Error> {
        let mut st = h.sha256_init()?;
        self.for_each_part(|part| st.update(part).map_err(Error::from))?;
        let digest = st.finalize()?;
        out[..FINGERPRINT_PREFIX.len()].copy_from_slice(FINGERPRINT_PREFIX);
        let n = armor::base64_encode_nopad(&digest, &mut out[FINGERPRINT_PREFIX.len()..])?;
        let len = FINGERPRINT_PREFIX.len() + n;
        Ok(core::str::from_utf8(&out[..len]).expect("prefix and base64 are ASCII"))
    }

    /// Import-time validation via
    /// [`Ed25519Verify::ed25519_validate_public_key`] (canonical,
    /// non-identity, prime-order). `InvalidParameter` →
    /// [`Error::InvalidPublicKey`]. Run once when a roster is built;
    /// [`crate::verify()`] does not repeat it.
    pub fn validate<V: ?Sized + Ed25519Verify>(&self, v: &V) -> Result<(), Error> {
        v.ed25519_validate_public_key(self.key())
            .map_err(Error::from)
    }

    /// Owned copy.
    #[cfg(feature = "alloc")]
    pub fn to_buf(&self) -> PublicKeyBuf {
        match *self {
            PublicKey::Ed25519 { key } => PublicKeyBuf::Ed25519 { key: *key },
            PublicKey::SkEd25519 { key, application } => PublicKeyBuf::SkEd25519 {
                key: *key,
                application: application.into(),
            },
        }
    }

    /// [`PublicKey::fingerprint`] into a fresh `String`.
    #[cfg(feature = "alloc")]
    pub fn fingerprint_string<H: ?Sized + Sha256>(
        &self,
        h: &H,
    ) -> Result<alloc::string::String, Error> {
        let mut out = [0u8; FINGERPRINT_LEN];
        let s = self.fingerprint(h, &mut out)?;
        Ok(alloc::string::String::from(s))
    }
}

/// A parsed `<type> <base64> [comment]` line. `key` borrows the caller's
/// decode buffer, `comment` the line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeyLine<'l, 'b> {
    /// The decoded key.
    pub key: PublicKey<'b>,
    /// Everything after the base64 token, trimmed; `None` when empty.
    pub comment: Option<&'l str>,
}

/// Strip one trailing `"\n"` or `"\r\n"`.
pub(crate) fn strip_newline(line: &str) -> &str {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.strip_suffix('\r').unwrap_or(line)
}

/// Split off the first token (delimited by ASCII whitespace) after
/// trimming leading whitespace. Returns `(token, rest)` with `rest` also
/// left-trimmed; `None` when no token remains.
pub(crate) fn next_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start_matches(|c: char| c.is_ascii_whitespace());
    if s.is_empty() {
        return None;
    }
    let end = s.find(|c: char| c.is_ascii_whitespace()).unwrap_or(s.len());
    let (tok, rest) = s.split_at(end);
    Some((
        tok,
        rest.trim_start_matches(|c: char| c.is_ascii_whitespace()),
    ))
}

/// Parse one OpenSSH public-key line (`authorized_keys` / `.pub` shape
/// without options).
///
/// Grammar: strip one trailing `"\n"` / `"\r\n"`; split on ASCII
/// whitespace; token 0 = type, token 1 = base64, remainder (trimmed) =
/// comment or `None`. Fewer than two tokens or bad base64 →
/// [`Error::PublicKeyLineInvalid`]; type token not equal to the decoded
/// blob's type → [`Error::PublicKeyTypeMismatch`]; unknown blob type →
/// [`Error::UnknownKeyType`]. The decoded blob is written into `buf`
/// ([`Error::BufferTooSmall`] if short).
pub fn parse_public_key_line<'l, 'b>(
    line: &'l str,
    buf: &'b mut [u8],
) -> Result<PublicKeyLine<'l, 'b>, Error> {
    let line = strip_newline(line);
    let (key_type, rest) = next_token(line).ok_or(Error::PublicKeyLineInvalid)?;
    let (b64, rest) = next_token(rest).ok_or(Error::PublicKeyLineInvalid)?;
    let n = match armor::base64_decode(b64.as_bytes(), buf) {
        Ok(n) => n,
        Err(Error::ArmorBadBase64) => return Err(Error::PublicKeyLineInvalid),
        Err(e) => return Err(e),
    };
    let blob: &'b [u8] = &buf[..n];
    let key = PublicKey::parse_blob(blob)?;
    if key.key_type() != key_type {
        return Err(Error::PublicKeyTypeMismatch);
    }
    let comment = rest.trim_end_matches(|c: char| c.is_ascii_whitespace());
    let comment = if comment.is_empty() {
        None
    } else {
        Some(comment)
    };
    Ok(PublicKeyLine { key, comment })
}

/// Write `<type> <base64(blob)>` (no comment, no newline). Returns bytes
/// written.
pub fn encode_public_key_line(key: &PublicKey<'_>, out: &mut [u8]) -> Result<usize, Error> {
    let key_type = key.key_type().as_bytes();
    let needed = key_type.len() + 1 + armor::base64_encoded_len(key.blob_len());
    if out.len() < needed {
        return Err(Error::BufferTooSmall);
    }
    out[..key_type.len()].copy_from_slice(key_type);
    out[key_type.len()] = b' ';
    let mut enc = Base64Encoder::new(out, key_type.len() + 1, 0);
    key.for_each_part(|part| enc.update(part))?;
    enc.finish(true)
}

/// Owned public key.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKeyBuf {
    /// `ssh-ed25519`
    Ed25519 {
        /// The compressed Edwards point.
        key: [u8; 32],
    },
    /// `sk-ssh-ed25519@openssh.com`
    SkEd25519 {
        /// The compressed Edwards point.
        key: [u8; 32],
        /// The FIDO relying-party id.
        application: alloc::vec::Vec<u8>,
    },
}

#[cfg(feature = "alloc")]
impl PublicKeyBuf {
    /// Borrowed view.
    pub fn as_key(&self) -> PublicKey<'_> {
        match self {
            PublicKeyBuf::Ed25519 { key } => PublicKey::Ed25519 { key },
            PublicKeyBuf::SkEd25519 { key, application } => PublicKey::SkEd25519 {
                key,
                application: application.as_slice(),
            },
        }
    }

    /// [`parse_public_key_line`] into owned values.
    pub fn parse_line(line: &str) -> Result<(Self, Option<alloc::string::String>), Error> {
        let mut buf = alloc::vec![0u8; armor::max_decoded_len(line.len())];
        let parsed = parse_public_key_line(line, &mut buf)?;
        Ok((
            parsed.key.to_buf(),
            parsed.comment.map(alloc::string::String::from),
        ))
    }

    /// `"<type> <base64>"` — [`encode_public_key_line`] as a `String`.
    pub fn to_line(&self) -> alloc::string::String {
        let key = self.as_key();
        let mut v = alloc::vec![
            0u8;
            key.key_type().len() + 1 + armor::base64_encoded_len(key.blob_len())
        ];
        let n = encode_public_key_line(&key, &mut v).expect("buffer sized exactly");
        v.truncate(n);
        alloc::string::String::from_utf8(v).expect("type and base64 are ASCII")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacetime_crypto::{CryptoError, CryptoErrorKind, CryptoResult, Sha256, Sha256State};

    const KEY: [u8; 32] = [0x11; 32];

    /// `string "ssh-ed25519" || string key`
    fn ed25519_blob() -> [u8; 51] {
        let mut b = [0u8; 51];
        b[3] = 11;
        b[4..15].copy_from_slice(b"ssh-ed25519");
        b[18] = 32;
        b[19..51].copy_from_slice(&KEY);
        b
    }

    /// `string "sk-ssh-ed25519@openssh.com" || string key || string "ssh:"`
    fn sk_blob() -> [u8; 74] {
        let mut b = [0u8; 74];
        b[3] = 26;
        b[4..30].copy_from_slice(b"sk-ssh-ed25519@openssh.com");
        b[33] = 32;
        b[34..66].copy_from_slice(&KEY);
        b[69] = 4;
        b[70..74].copy_from_slice(b"ssh:");
        b
    }

    #[test]
    fn parse_and_encode_ed25519() {
        let blob = ed25519_blob();
        let pk = PublicKey::parse_blob(&blob).unwrap();
        assert_eq!(pk, PublicKey::Ed25519 { key: &KEY });
        assert_eq!(pk.key_type(), KEY_TYPE_ED25519);
        assert!(!pk.is_sk());
        assert_eq!(pk.blob_len(), 51);
        let mut out = [0u8; 51];
        assert_eq!(pk.encode_blob(&mut out), Ok(51));
        assert_eq!(out, blob);
        assert_eq!(pk.encode_blob(&mut out[..50]), Err(Error::BufferTooSmall));
    }

    #[test]
    fn parse_and_encode_sk() {
        let blob = sk_blob();
        let pk = PublicKey::parse_blob(&blob).unwrap();
        assert_eq!(
            pk,
            PublicKey::SkEd25519 {
                key: &KEY,
                application: b"ssh:"
            }
        );
        assert_eq!(pk.key_type(), KEY_TYPE_SK_ED25519);
        assert!(pk.is_sk());
        assert_eq!(pk.blob_len(), 74);
        let mut out = [0u8; 74];
        assert_eq!(pk.encode_blob(&mut out), Ok(74));
        assert_eq!(out, blob);
    }

    #[test]
    fn parse_blob_errors() {
        let mut blob = ed25519_blob();
        blob[4] = b'x';
        assert_eq!(PublicKey::parse_blob(&blob), Err(Error::UnknownKeyType));

        let blob = ed25519_blob();
        assert_eq!(PublicKey::parse_blob(&blob[..50]), Err(Error::Truncated));
        let mut short = [0u8; 50];
        short.copy_from_slice(&blob[..50]);
        short[18] = 31;
        assert_eq!(PublicKey::parse_blob(&short), Err(Error::BadKeyLength));

        let mut long = [0u8; 52];
        long[..51].copy_from_slice(&blob);
        assert_eq!(
            PublicKey::parse_blob(&long),
            Err(Error::TrailingBytes(Section::PublicKey))
        );

        // sk without an application string is truncated.
        let sk = sk_blob();
        assert_eq!(PublicKey::parse_blob(&sk[..66]), Err(Error::Truncated));
        assert_eq!(PublicKey::parse_blob(&[]), Err(Error::Truncated));
    }

    /// A SHA-256 stand-in that records the length of what it absorbed; used
    /// to prove the piecewise hashing covers exactly the blob bytes.
    struct LenHash;
    #[derive(Default)]
    struct LenState {
        len: u64,
    }
    impl Sha256State for LenState {
        fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
            self.len += data.len() as u64;
            Ok(())
        }
        fn finalize(&mut self) -> CryptoResult<[u8; 32]> {
            let mut out = [0u8; 32];
            out[..8].copy_from_slice(&self.len.to_le_bytes());
            self.len = 0;
            Ok(out)
        }
    }
    impl Sha256 for LenHash {
        type State = LenState;
        fn sha256_init(&self) -> CryptoResult<Self::State> {
            Ok(LenState::default())
        }
    }

    #[test]
    fn fingerprint_shape_and_coverage() {
        let blob = ed25519_blob();
        let pk = PublicKey::parse_blob(&blob).unwrap();
        let mut out = [0u8; FINGERPRINT_LEN];
        let s = pk.fingerprint(&LenHash, &mut out).unwrap();
        assert_eq!(s.len(), FINGERPRINT_LEN);
        assert!(s.starts_with("SHA256:"));
        // 51 bytes absorbed → digest = 51 LE || zeros → base64 "MwAAAAAAAAAAAAAA..."
        let mut expect = [0u8; 43];
        let mut digest = [0u8; 32];
        digest[0] = 51;
        armor::base64_encode_nopad(&digest, &mut expect).unwrap();
        assert_eq!(&s.as_bytes()[7..], &expect[..]);
    }

    struct FailingHash;
    struct FailingState;
    impl Sha256State for FailingState {
        fn update(&mut self, _: &[u8]) -> CryptoResult<()> {
            Err(CryptoError::new(CryptoErrorKind::Unavailable))
        }
        fn finalize(&mut self) -> CryptoResult<[u8; 32]> {
            Ok([0; 32])
        }
    }
    impl Sha256 for FailingHash {
        type State = FailingState;
        fn sha256_init(&self) -> CryptoResult<Self::State> {
            Ok(FailingState)
        }
    }

    #[test]
    fn fingerprint_propagates_backend_error() {
        let blob = ed25519_blob();
        let pk = PublicKey::parse_blob(&blob).unwrap();
        let mut out = [0u8; FINGERPRINT_LEN];
        assert_eq!(
            pk.fingerprint(&FailingHash, &mut out),
            Err(Error::Backend(CryptoErrorKind::Unavailable))
        );
    }

    struct RejectAll;
    impl Ed25519Verify for RejectAll {
        fn ed25519_validate_public_key(&self, _: &[u8; 32]) -> CryptoResult<()> {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter))
        }
        fn ed25519_verify(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> CryptoResult<()> {
            Err(CryptoError::new(CryptoErrorKind::AuthenticationFailed))
        }
    }

    #[test]
    fn validate_maps_invalid_parameter() {
        let blob = ed25519_blob();
        let pk = PublicKey::parse_blob(&blob).unwrap();
        assert_eq!(pk.validate(&RejectAll), Err(Error::InvalidPublicKey));
    }

    #[test]
    fn public_key_line_round_trip() {
        let blob = ed25519_blob();
        let pk = PublicKey::parse_blob(&blob).unwrap();
        let mut line = [0u8; 11 + 1 + 68];
        let n = encode_public_key_line(&pk, &mut line).unwrap();
        assert_eq!(n, line.len());
        assert!(line.starts_with(b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert_eq!(
            encode_public_key_line(&pk, &mut line[..79]),
            Err(Error::BufferTooSmall)
        );

        let text = core::str::from_utf8(&line[..n]).unwrap();
        let mut buf = [0u8; 64];
        let parsed = parse_public_key_line(text, &mut buf).unwrap();
        assert_eq!(parsed.key, pk);
        assert_eq!(parsed.comment, None);

        // With comment, extra whitespace and a CRLF ending.
        let mut with_comment = [0u8; 120];
        with_comment[..n].copy_from_slice(&line[..n]);
        let tail = b"  \tmy key  \r\n";
        with_comment[n..n + tail.len()].copy_from_slice(tail);
        let text = core::str::from_utf8(&with_comment[..n + tail.len()]).unwrap();
        let mut buf = [0u8; 64];
        let parsed = parse_public_key_line(text, &mut buf).unwrap();
        assert_eq!(parsed.key, pk);
        assert_eq!(parsed.comment, Some("my key"));
    }

    #[test]
    fn public_key_line_errors() {
        let mut buf = [0u8; 64];
        assert_eq!(
            parse_public_key_line("", &mut buf),
            Err(Error::PublicKeyLineInvalid)
        );
        assert_eq!(
            parse_public_key_line("ssh-ed25519", &mut buf),
            Err(Error::PublicKeyLineInvalid)
        );
        assert_eq!(
            parse_public_key_line("ssh-ed25519 not*base64", &mut buf),
            Err(Error::PublicKeyLineInvalid)
        );
        let blob = ed25519_blob();
        let pk = PublicKey::parse_blob(&blob).unwrap();
        let mut line = [0u8; 80];
        let n = encode_public_key_line(&pk, &mut line).unwrap();
        let text = core::str::from_utf8(&line[..n]).unwrap();
        // Type token disagrees with the blob.
        let mut wrong = [0u8; 80];
        wrong[..n].copy_from_slice(&line[..n]);
        wrong[..11].copy_from_slice(b"ssh-ed25518");
        let wrong = core::str::from_utf8(&wrong[..n]).unwrap();
        assert_eq!(
            parse_public_key_line(wrong, &mut buf),
            Err(Error::PublicKeyTypeMismatch)
        );
        // Blob of an unknown type.
        assert_eq!(
            parse_public_key_line("ssh-rsa AAAAB3NzaC1yc2E=", &mut buf),
            Err(Error::UnknownKeyType)
        );
        // Decode buffer too small.
        assert_eq!(
            parse_public_key_line(text, &mut buf[..50]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn token_helpers() {
        assert_eq!(strip_newline("a\n"), "a");
        assert_eq!(strip_newline("a\r\n"), "a");
        assert_eq!(strip_newline("a\n\n"), "a\n");
        assert_eq!(next_token("  a b "), Some(("a", "b ")));
        assert_eq!(next_token("a"), Some(("a", "")));
        assert_eq!(next_token("   "), None);
    }

    #[cfg(feature = "alloc")]
    mod with_alloc {
        use super::super::*;
        use super::{ed25519_blob, sk_blob, KEY};
        use alloc::string::String;

        #[test]
        fn buf_round_trips() {
            let blob = sk_blob();
            let pk = PublicKey::parse_blob(&blob).unwrap();
            let owned = pk.to_buf();
            assert_eq!(
                owned,
                PublicKeyBuf::SkEd25519 {
                    key: KEY,
                    application: b"ssh:".to_vec()
                }
            );
            assert_eq!(owned.as_key(), pk);
            let line = owned.to_line();
            let (back, comment) = PublicKeyBuf::parse_line(&line).unwrap();
            assert_eq!(back, owned);
            assert_eq!(comment, None);

            let blob = ed25519_blob();
            let pk = PublicKey::parse_blob(&blob).unwrap();
            let mut line = pk.to_buf().to_line();
            line.push_str(" c\n");
            let (back, comment) = PublicKeyBuf::parse_line(&line).unwrap();
            assert_eq!(back.as_key(), pk);
            assert_eq!(comment, Some(String::from("c")));
        }
    }
}
