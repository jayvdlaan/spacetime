//! One header stanza: a borrowed view of a validated stanza and the
//! canonical encoder.
//!
//! ```text
//! -> <type> <arg>…\n
//! <base64 body, 64 characters per line, final line strictly shorter (may be empty)>\n
//! ```
//!
//! The type and every argument are `0x21..=0x7E` bytes without spaces. The
//! body is raw (unpadded) canonical base64. A [`Stanza`] is only ever
//! produced by [`crate::Header::parse`], which enforces that grammar, so the
//! accessors here cannot fail on structure — only on a caller buffer.

use crate::base64;
use crate::error::{Error, HeaderError};

/// The X25519 recipient stanza type.
pub const STANZA_TYPE_X25519: &str = "X25519";
/// The ssh-ed25519 recipient stanza type.
pub const STANZA_TYPE_SSH_ED25519: &str = "ssh-ed25519";
/// The scrypt (passphrase) stanza type — recognised, unsupported.
pub const STANZA_TYPE_SCRYPT: &str = "scrypt";
/// The ssh-rsa stanza type — recognised, unsupported.
pub const STANZA_TYPE_SSH_RSA: &str = "ssh-rsa";
/// Body line width.
pub const BODY_LINE_LEN: usize = 64;

/// Classification of a stanza type (exact, case-sensitive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StanzaKind {
    /// `X25519`.
    X25519,
    /// `ssh-ed25519`.
    SshEd25519,
    /// `scrypt` (unsupported, never grease).
    Scrypt,
    /// `ssh-rsa` (unsupported, never grease).
    SshRsa,
    /// Anything else — grease, ignored.
    Unknown,
}

/// Borrowed view of one validated stanza.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stanza<'a> {
    ty: &'a str,
    /// Raw text after the type (`""` when there are no arguments).
    args: &'a str,
    /// Raw base64 text including internal `\n` separators, without the
    /// final line's `\n`.
    body: &'a [u8],
}

impl<'a> Stanza<'a> {
    pub(crate) const fn new(ty: &'a str, args: &'a str, body: &'a [u8]) -> Self {
        Self { ty, args, body }
    }

    /// The stanza type.
    pub const fn stanza_type(&self) -> &'a str {
        self.ty
    }

    /// Classify the type.
    pub fn kind(&self) -> StanzaKind {
        match self.ty {
            STANZA_TYPE_X25519 => StanzaKind::X25519,
            STANZA_TYPE_SSH_ED25519 => StanzaKind::SshEd25519,
            STANZA_TYPE_SCRYPT => StanzaKind::Scrypt,
            STANZA_TYPE_SSH_RSA => StanzaKind::SshRsa,
            _ => StanzaKind::Unknown,
        }
    }

    /// The arguments (type excluded); empty when there are none.
    pub fn args(&self) -> Args<'a> {
        Args {
            rest: if self.args.is_empty() {
                None
            } else {
                Some(self.args)
            },
        }
    }

    /// Number of arguments.
    pub fn arg_count(&self) -> usize {
        self.args().count()
    }

    /// Argument `index`, if present.
    pub fn arg(&self, index: usize) -> Option<&'a str> {
        self.args().nth(index)
    }

    /// Decode argument `index` as raw base64 into an exact-size array;
    /// missing, wrong size or non-canonical → `err`.
    pub fn arg_bytes<const N: usize>(&self, index: usize, err: Error) -> Result<[u8; N], Error> {
        let a = self.arg(index).ok_or(err)?;
        if a.len() != base64::encoded_len_nopad(N) {
            return Err(err);
        }
        let mut out = [0u8; N];
        let n = base64::decode_nopad(a.as_bytes(), &mut out, err)?;
        if n != N {
            return Err(err);
        }
        Ok(out)
    }

    /// The raw body text (base64, with internal `\n`s).
    pub(crate) const fn body_text(&self) -> &'a [u8] {
        self.body
    }

    /// Decoded body length (from the character count).
    pub fn body_len(&self) -> usize {
        let chars = self.body.iter().filter(|&&c| c != b'\n').count();
        base64::decoded_len_nopad(chars).unwrap_or(0)
    }

    /// Decode the body into `out`; returns the decoded length.
    /// `BufferTooSmall` if `out` is shorter than [`Stanza::body_len`].
    pub fn body(&self, out: &mut [u8]) -> Result<usize, Error> {
        base64::decode_nopad_lines(self.body, out, Error::Header(HeaderError::BadBase64))
    }

    /// Decode the body into an exact-size array; a different length → `err`.
    pub fn body_array<const N: usize>(&self, err: Error) -> Result<[u8; N], Error> {
        if self.body_len() != N {
            return Err(err);
        }
        let mut out = [0u8; N];
        let n = self.body(&mut out)?;
        if n != N {
            return Err(err);
        }
        Ok(out)
    }
}

/// Iterator over a stanza's arguments (split on `' '`).
#[derive(Clone, Copy, Debug)]
pub struct Args<'a> {
    rest: Option<&'a str>,
}

impl<'a> Iterator for Args<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let rest = self.rest.take()?;
        match rest.find(' ') {
            Some(i) => {
                self.rest = Some(&rest[i + 1..]);
                Some(&rest[..i])
            }
            None => Some(rest),
        }
    }
}

/// Byte length of [`encode_stanza`] output: `3 + ty + Σ(1 + arg) + 1 +
/// b64 + line breaks`, where the body lines are `b64 / 64` full lines plus
/// one final line (possibly empty), each `\n`-terminated.
pub const fn encoded_len(ty_len: usize, args_len_with_spaces: usize, body_len: usize) -> usize {
    let b64 = base64::encoded_len_nopad(body_len);
    3 + ty_len + args_len_with_spaces + 1 + b64 + b64 / BODY_LINE_LEN + 1
}

fn valid_token(t: &str) -> bool {
    t.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

/// Emit `"-> " ty {" " arg}* "\n"` then the raw base64 body in 64-character
/// lines, each `\n`-terminated, the last line strictly shorter than 64 (an
/// empty line when `b64_len % 64 == 0`, including `body.is_empty()`).
/// `ty`/args containing `' '` or bytes outside `0x21..=0x7E` →
/// `Header(InvalidCharacter)`; an empty `ty` → `Header(NoArguments)`; an
/// empty argument → `Header(EmptyArgument)`. Returns the length written.
pub fn encode_stanza(ty: &str, args: &[&str], body: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if ty.is_empty() {
        return Err(Error::Header(HeaderError::NoArguments));
    }
    if !valid_token(ty) {
        return Err(Error::Header(HeaderError::InvalidCharacter));
    }
    let mut args_len = 0usize;
    for a in args {
        if a.is_empty() {
            return Err(Error::Header(HeaderError::EmptyArgument));
        }
        if !valid_token(a) {
            return Err(Error::Header(HeaderError::InvalidCharacter));
        }
        args_len += 1 + a.len();
    }
    let total = encoded_len(ty.len(), args_len, body.len());
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    let mut pos = 0usize;
    out[pos..pos + 3].copy_from_slice(b"-> ");
    pos += 3;
    out[pos..pos + ty.len()].copy_from_slice(ty.as_bytes());
    pos += ty.len();
    for a in args {
        out[pos] = b' ';
        pos += 1;
        out[pos..pos + a.len()].copy_from_slice(a.as_bytes());
        pos += a.len();
    }
    out[pos] = b'\n';
    pos += 1;
    pos += base64::encode_wrapped(body, &mut out[pos..], false, BODY_LINE_LEN)?;
    out[pos] = b'\n';
    pos += 1;
    debug_assert_eq!(pos, total);
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_exact() {
        for (ty, kind) in [
            ("X25519", StanzaKind::X25519),
            ("ssh-ed25519", StanzaKind::SshEd25519),
            ("scrypt", StanzaKind::Scrypt),
            ("ssh-rsa", StanzaKind::SshRsa),
            ("x25519", StanzaKind::Unknown),
            ("SCRYPT", StanzaKind::Unknown),
            ("mlkem768x25519", StanzaKind::Unknown),
        ] {
            assert_eq!(Stanza::new(ty, "", b"").kind(), kind, "{ty}");
        }
    }

    #[test]
    fn args_iterate() {
        let s = Stanza::new("t", "a bb ccc", b"");
        assert_eq!(s.arg_count(), 3);
        assert_eq!(s.arg(0), Some("a"));
        assert_eq!(s.arg(1), Some("bb"));
        assert_eq!(s.arg(2), Some("ccc"));
        assert_eq!(s.arg(3), None);
        let s = Stanza::new("t", "", b"");
        assert_eq!(s.arg_count(), 0);
        assert_eq!(s.arg(0), None);
    }

    #[test]
    fn arg_bytes_exact_size() {
        let s = Stanza::new("t", "Zm9v Zg", b"");
        let err = Error::Header(HeaderError::X25519Stanza);
        assert_eq!(s.arg_bytes::<3>(0, err).unwrap(), *b"foo");
        assert_eq!(s.arg_bytes::<1>(1, err).unwrap(), *b"f");
        assert_eq!(s.arg_bytes::<2>(0, err), Err(err));
        assert_eq!(s.arg_bytes::<3>(2, err), Err(err));
        // wrong canonicality: 'h' has non-zero low bits
        let s = Stanza::new("t", "Zh", b"");
        assert_eq!(s.arg_bytes::<1>(0, err), Err(err));
    }

    #[test]
    fn body_decoding() {
        let s = Stanza::new("t", "", b"Zm9vYmFy");
        assert_eq!(s.body_len(), 6);
        let mut out = [0u8; 8];
        assert_eq!(s.body(&mut out).unwrap(), 6);
        assert_eq!(&out[..6], b"foobar");
        assert_eq!(s.body_array::<6>(Error::NoMatch).unwrap(), *b"foobar");
        assert_eq!(s.body_array::<5>(Error::NoMatch), Err(Error::NoMatch));
        assert_eq!(s.body(&mut [0u8; 5]), Err(Error::BufferTooSmall));
        let s = Stanza::new("t", "", b"");
        assert_eq!(s.body_len(), 0);
        assert_eq!(s.body(&mut []).unwrap(), 0);
    }

    #[test]
    fn encoded_lengths() {
        // X25519: "-> X25519 " + 43 + "\n" + 43 + "\n" = 98
        assert_eq!(encoded_len(6, 44, 32), 98);
        // ssh-ed25519: "-> ssh-ed25519 " + 6 + " " + 43 + "\n" + 43 + "\n" = 110
        assert_eq!(encoded_len(11, 7 + 44, 32), 110);
        // empty body: line + one empty line
        assert_eq!(encoded_len(1, 0, 0), 3 + 1 + 1 + 1);
        // 48-byte body: 64 chars + "\n" + empty final line "\n"
        assert_eq!(encoded_len(1, 0, 48), 3 + 1 + 1 + 64 + 2);
        // 96 bytes: 128 chars in two full lines + empty final
        assert_eq!(encoded_len(1, 0, 96), 3 + 1 + 1 + 128 + 3);
        // 49 bytes: 66 chars: one full line + 2-char final line
        assert_eq!(encoded_len(1, 0, 49), 3 + 1 + 1 + 66 + 2);
    }

    #[test]
    fn encode_stanza_shapes() {
        let mut out = [0u8; 256];
        let n = encode_stanza("t", &["a"], b"", &mut out).unwrap();
        assert_eq!(&out[..n], b"-> t a\n\n");
        let n = encode_stanza("X25519", &[], &[0u8; 48], &mut out).unwrap();
        assert_eq!(n, encoded_len(6, 0, 48));
        assert_eq!(&out[..10], b"-> X25519\n");
        assert_eq!(out[10 + 64], b'\n');
        assert_eq!(out[10 + 65], b'\n');
        let n = encode_stanza("t", &[], &[0u8; 49], &mut out).unwrap();
        assert_eq!(&out[n - 3..n], b"AA\n");
    }

    #[test]
    fn encode_stanza_rejections() {
        let mut out = [0u8; 64];
        assert_eq!(
            encode_stanza("", &[], b"", &mut out),
            Err(Error::Header(HeaderError::NoArguments))
        );
        assert_eq!(
            encode_stanza("a b", &[], b"", &mut out),
            Err(Error::Header(HeaderError::InvalidCharacter))
        );
        assert_eq!(
            encode_stanza("t", &["x\u{e9}"], b"", &mut out),
            Err(Error::Header(HeaderError::InvalidCharacter))
        );
        assert_eq!(
            encode_stanza("t", &[""], b"", &mut out),
            Err(Error::Header(HeaderError::EmptyArgument))
        );
        assert_eq!(
            encode_stanza("t", &[], &[0u8; 48], &mut out),
            Err(Error::BufferTooSmall)
        );
    }
}
