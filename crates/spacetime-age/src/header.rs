//! The age v1 header: zero-copy structural parse, stanza iteration, MAC
//! computation/verification, and canonical re-encoding.
//!
//! ```text
//! age-encryption.org/v1\n
//! -> <type> <args…>\n          ⎫ zero or more stanzas
//! <body base64, 64-col lines>\n ⎭
//! --- <base64 32-byte HMAC>\n
//! <16-byte payload nonce><STREAM payload…>
//! ```
//!
//! [`Header::parse`] is backend-free and validates the *structure* of every
//! stanza (§ grammar below) regardless of which identities the caller holds;
//! the MAC is verified separately by [`verify_mac`] once a file key is known.
//!
//! # Grammar (first failure wins)
//!
//! 1. The first 22 bytes are `age-encryption.org/v1\n`, else `BadMagic`.
//! 2. Lines up to the next `\n` (none → `Truncated`):
//!    - `---…`: the MAC line; exactly `--- ` + 43 canonical raw-base64
//!      characters, else `BadMacLine`. Done.
//!    - `-> …`: a stanza line; empty rest → `NoArguments`; an empty piece
//!      between spaces → `EmptyArgument`; a byte outside `0x21..=0x7E` →
//!      `InvalidCharacter`. Then body lines: each ≤ 64 characters
//!      (`BodyLineTooLong`), alphabet only (`BadBase64`); a 64-character
//!      line continues, a shorter (possibly empty) one ends the body, which
//!      as a whole must be canonical raw base64 (`BadBase64`). Recognised
//!      types are then shape-checked: `X25519` → one 32-byte argument and a
//!      32-byte body (`X25519Stanza`); `ssh-ed25519` → a 4-byte and a
//!      32-byte argument and a 32-byte body (`SshEd25519Stanza`); `scrypt`
//!      / `ssh-rsa` are counted; everything else is grease and counted as
//!      unknown.
//!    - anything else → `BadStanzaStart`.
//! 3. A `scrypt` stanza with any other stanza → `ScryptNotAlone`.
//! 4. Fewer than 16 bytes after the MAC line → `ShortNonce`.

use spacetime_crypto::{CryptoErrorKind, HkdfSha256, HmacSha256};

use crate::base64;
use crate::error::{Error, HeaderError};
use crate::keys::FileKey;
use crate::stanza::{Stanza, StanzaKind, BODY_LINE_LEN};
use crate::util::wipe;

/// The version line.
pub const MAGIC: &[u8; 22] = b"age-encryption.org/v1\n";
/// HKDF info for the header MAC key.
pub const MAC_INFO: &[u8] = b"header";
/// Header MAC length (HMAC-SHA-256).
pub const HEADER_MAC_LEN: usize = 32;
/// `"--- "` + 43 + `"\n"`.
pub const MAC_LINE_LEN: usize = 48;
/// Payload nonce length (the 16 bytes right after the MAC line).
pub const NONCE_LEN: usize = 16;

const fn herr(e: HeaderError) -> Error {
    Error::Header(e)
}

/// Bytes the parser has already proven ASCII; the fallback is unreachable.
fn ascii(b: &[u8]) -> &str {
    core::str::from_utf8(b).unwrap_or("")
}

/// A borrowed, structurally valid header. The MAC is **not** verified here.
/// `Debug` prints the offsets, counts and MAC, not the borrowed input (which
/// is the whole file, payload included).
#[derive(Clone, Copy)]
pub struct Header<'a> {
    input: &'a [u8],
    /// Offset of the MAC line.
    stanzas_end: usize,
    /// Through the MAC line's `\n`.
    header_len: usize,
    mac: [u8; HEADER_MAC_LEN],
    stanza_count: usize,
    x25519: usize,
    ssh_ed25519: usize,
    scrypt: usize,
    ssh_rsa: usize,
    unknown: usize,
}

impl core::fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Header")
            .field("input_len", &self.input.len())
            .field("stanzas_end", &self.stanzas_end)
            .field("header_len", &self.header_len)
            .field("mac", &self.mac)
            .field("stanza_count", &self.stanza_count)
            .field("x25519", &self.x25519)
            .field("ssh_ed25519", &self.ssh_ed25519)
            .field("scrypt", &self.scrypt)
            .field("ssh_rsa", &self.ssh_rsa)
            .field("unknown", &self.unknown)
            .finish()
    }
}

/// Offset of the next `\n` at or after `from`.
fn find_newline(input: &[u8], from: usize) -> Option<usize> {
    input
        .get(from..)?
        .iter()
        .position(|&c| c == b'\n')
        .map(|i| from + i)
}

/// Walk one stanza starting at `pos` (which points at `-> `). Returns the
/// stanza and the offset after its final body line's `\n`. With
/// `validate`, enforces the grammar; without, assumes a parsed header.
fn walk_stanza(input: &[u8], pos: usize, validate: bool) -> Result<(Stanza<'_>, usize), Error> {
    let line_end = find_newline(input, pos).ok_or(herr(HeaderError::Truncated))?;
    let rest = &input[pos + 3..line_end];
    if validate {
        if rest.is_empty() {
            return Err(herr(HeaderError::NoArguments));
        }
        for piece in rest.split(|&c| c == b' ') {
            if piece.is_empty() {
                return Err(herr(HeaderError::EmptyArgument));
            }
            if piece.iter().any(|&c| !(0x21..=0x7e).contains(&c)) {
                return Err(herr(HeaderError::InvalidCharacter));
            }
        }
    }
    let (ty, args) = match rest.iter().position(|&c| c == b' ') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &rest[rest.len()..]),
    };

    let body_start = line_end + 1;
    let mut cur = body_start;
    let body_end;
    loop {
        let le = find_newline(input, cur).ok_or(herr(HeaderError::Truncated))?;
        let line = &input[cur..le];
        if validate {
            if line.len() > BODY_LINE_LEN {
                return Err(herr(HeaderError::BodyLineTooLong));
            }
            if !line.iter().all(|&c| base64::is_alphabet(c)) {
                return Err(herr(HeaderError::BadBase64));
            }
        }
        cur = le + 1;
        if line.len() < BODY_LINE_LEN {
            body_end = le;
            break;
        }
    }
    let body = &input[body_start..body_end];
    if validate {
        base64::decode_nopad_lines_validate(body, herr(HeaderError::BadBase64))?;
    }
    Ok((Stanza::new(ascii(ty), ascii(args), body), cur))
}

impl<'a> Header<'a> {
    /// Parse the full grammar (module docs). Requires at least 16 bytes
    /// after the MAC line; everything after those is exposed as
    /// [`Header::payload`] and may be a prefix of the real payload
    /// (streaming callers).
    pub fn parse(input: &'a [u8]) -> Result<Self, Error> {
        if input.len() < MAGIC.len() || &input[..MAGIC.len()] != MAGIC {
            return Err(herr(HeaderError::BadMagic));
        }
        let mut h = Header {
            input,
            stanzas_end: 0,
            header_len: 0,
            mac: [0u8; HEADER_MAC_LEN],
            stanza_count: 0,
            x25519: 0,
            ssh_ed25519: 0,
            scrypt: 0,
            ssh_rsa: 0,
            unknown: 0,
        };
        let mut pos = MAGIC.len();
        loop {
            let line_end = find_newline(input, pos).ok_or(herr(HeaderError::Truncated))?;
            let line = &input[pos..line_end];
            if line.starts_with(b"---") {
                if line.len() != MAC_LINE_LEN - 1 || line[3] != b' ' {
                    return Err(herr(HeaderError::BadMacLine));
                }
                let n =
                    base64::decode_nopad(&line[4..], &mut h.mac, herr(HeaderError::BadMacLine))?;
                if n != HEADER_MAC_LEN {
                    return Err(herr(HeaderError::BadMacLine));
                }
                h.stanzas_end = pos;
                h.header_len = line_end + 1;
                break;
            }
            if !line.starts_with(b"-> ") {
                return Err(herr(HeaderError::BadStanzaStart));
            }
            let (st, next) = walk_stanza(input, pos, true)?;
            match st.kind() {
                StanzaKind::X25519 => {
                    let e = herr(HeaderError::X25519Stanza);
                    if st.arg_count() != 1 || st.body_len() != 32 {
                        return Err(e);
                    }
                    st.arg_bytes::<32>(0, e)?;
                    h.x25519 += 1;
                }
                StanzaKind::SshEd25519 => {
                    let e = herr(HeaderError::SshEd25519Stanza);
                    if st.arg_count() != 2 || st.body_len() != 32 {
                        return Err(e);
                    }
                    st.arg_bytes::<4>(0, e)?;
                    st.arg_bytes::<32>(1, e)?;
                    h.ssh_ed25519 += 1;
                }
                StanzaKind::Scrypt => h.scrypt += 1,
                StanzaKind::SshRsa => h.ssh_rsa += 1,
                StanzaKind::Unknown => h.unknown += 1,
            }
            h.stanza_count += 1;
            pos = next;
        }
        if h.scrypt >= 1 && h.stanza_count > 1 {
            return Err(herr(HeaderError::ScryptNotAlone));
        }
        if input.len() < h.header_len + NONCE_LEN {
            return Err(herr(HeaderError::ShortNonce));
        }
        Ok(h)
    }

    /// [`crate::armor::decode`] `armored` into `buf`, then [`Header::parse`]
    /// the decoded bytes.
    pub fn from_armored(armored: &[u8], buf: &'a mut [u8]) -> Result<Self, Error> {
        let n = crate::armor::decode(armored, buf)?;
        Self::parse(&buf[..n])
    }

    /// The stanzas, in order (re-walks the validated bytes; cannot fail).
    pub fn stanzas(&self) -> Stanzas<'a> {
        Stanzas {
            input: self.input,
            pos: MAGIC.len(),
            end: self.stanzas_end,
        }
    }

    /// Number of stanzas.
    pub const fn stanza_count(&self) -> usize {
        self.stanza_count
    }

    /// `(x25519, ssh_ed25519, scrypt, ssh_rsa, unknown)`.
    pub const fn counts(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.x25519,
            self.ssh_ed25519,
            self.scrypt,
            self.ssh_rsa,
            self.unknown,
        )
    }

    /// The MAC as encoded in the header (unverified).
    pub const fn mac(&self) -> &[u8; HEADER_MAC_LEN] {
        &self.mac
    }

    /// Bytes from offset 0 through the `---` of the MAC line inclusive —
    /// the HMAC input.
    pub fn mac_input(&self) -> &'a [u8] {
        &self.input[..self.stanzas_end + 3]
    }

    /// Header length through the MAC line's `\n`.
    pub const fn len(&self) -> usize {
        self.header_len
    }

    /// Always `false` (a parsed header has at least the magic and the MAC
    /// line); provided for the `len`/`is_empty` convention.
    pub const fn is_empty(&self) -> bool {
        self.header_len == 0
    }

    /// The 16-byte payload nonce.
    pub fn nonce(&self) -> &'a [u8; NONCE_LEN] {
        let s = &self.input[self.header_len..self.header_len + NONCE_LEN];
        // `parse` guaranteed the length.
        s.try_into().unwrap_or(&[0u8; NONCE_LEN])
    }

    /// Everything after the nonce (a prefix of the STREAM payload if the
    /// caller is streaming).
    pub fn payload(&self) -> &'a [u8] {
        &self.input[self.header_len + NONCE_LEN..]
    }

    /// Re-emit the header: `MAGIC`, every stanza, the MAC line. Byte-identical
    /// to the parsed input for every valid header — the grammar admits only
    /// the canonical body wrapping, so the raw body text is copied as is.
    /// Returns [`Header::len`]; `BufferTooSmall` if `out` is shorter.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < self.header_len {
            return Err(Error::BufferTooSmall);
        }
        let mut pos = 0usize;
        out[..MAGIC.len()].copy_from_slice(MAGIC);
        pos += MAGIC.len();
        for st in self.stanzas() {
            out[pos..pos + 3].copy_from_slice(b"-> ");
            pos += 3;
            let ty = st.stanza_type().as_bytes();
            out[pos..pos + ty.len()].copy_from_slice(ty);
            pos += ty.len();
            for a in st.args() {
                out[pos] = b' ';
                pos += 1;
                out[pos..pos + a.len()].copy_from_slice(a.as_bytes());
                pos += a.len();
            }
            out[pos] = b'\n';
            pos += 1;
            let body = st.body_text();
            out[pos..pos + body.len()].copy_from_slice(body);
            pos += body.len();
            out[pos] = b'\n';
            pos += 1;
        }
        pos += encode_mac_line(&self.mac, &mut out[pos..])?;
        Ok(pos)
    }
}

/// Iterator over a parsed header's stanzas.
#[derive(Clone, Copy, Debug)]
pub struct Stanzas<'a> {
    input: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Iterator for Stanzas<'a> {
    type Item = Stanza<'a>;

    fn next(&mut self) -> Option<Stanza<'a>> {
        if self.pos >= self.end {
            return None;
        }
        match walk_stanza(self.input, self.pos, false) {
            Ok((st, next)) => {
                self.pos = next;
                Some(st)
            }
            // Unreachable on a parsed header; stop rather than loop.
            Err(_) => {
                self.pos = self.end;
                None
            }
        }
    }
}

/// Derive the MAC key: `HKDF-SHA-256(salt = "", ikm = file_key, info = "header")`.
fn mac_key<B: HkdfSha256 + ?Sized>(b: &B, file_key: &FileKey) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    if let Err(e) = b.hkdf_sha256(&[], file_key.as_bytes(), MAC_INFO, &mut key) {
        wipe(&mut key);
        return Err(e.into());
    }
    Ok(key)
}

/// `HMAC-SHA-256(mac_key, mac_input)` (see [`Header::mac_input`]).
pub fn compute_mac<B: HkdfSha256 + HmacSha256 + ?Sized>(
    b: &B,
    file_key: &FileKey,
    mac_input: &[u8],
) -> Result<[u8; HEADER_MAC_LEN], Error> {
    let mut key = mac_key(b, file_key)?;
    let r = b.hmac_sha256(&key, mac_input);
    wipe(&mut key);
    Ok(r?)
}

/// Verify `header`'s MAC under `file_key` with the backend's constant-time
/// `hmac_sha256_verify`. `AuthenticationFailed` → [`Error::HmacMismatch`].
pub fn verify_mac<B: HkdfSha256 + HmacSha256 + ?Sized>(
    b: &B,
    file_key: &FileKey,
    header: &Header<'_>,
) -> Result<(), Error> {
    let mut key = mac_key(b, file_key)?;
    let r = b.hmac_sha256_verify(&key, header.mac_input(), header.mac());
    wipe(&mut key);
    match r {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == CryptoErrorKind::AuthenticationFailed => Err(Error::HmacMismatch),
        Err(e) => Err(e.into()),
    }
}

/// `"--- " + base64-nopad(mac) + "\n"` (48 bytes).
pub fn encode_mac_line(mac: &[u8; HEADER_MAC_LEN], out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < MAC_LINE_LEN {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(b"--- ");
    let n = base64::encode_nopad(mac, &mut out[4..])?;
    out[4 + n] = b'\n';
    Ok(4 + n + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_LINE: &str = "--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg\n";
    const X25519_STANZA: &str = "-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc\nhjabGXwSLQ9c3S6Lw2i+S2Tu2fiwQHHslbBN6B41FLE\n";
    const SSH_STANZA: &str =
        "-> ssh-ed25519 64jdUw NOQtSvXvlKB6OoQgG4idTNGnQ8snsRtqEEOKj+uOWEc\n2BYYubiSZ09zSTlnTeKpXOrVuAcD4GX1JTfFQSu4UmI\n";
    const NONCE: &[u8; 16] = &[0x11; 16];

    /// Build `MAGIC + body + MAC_LINE + nonce + tail` into a fixed buffer.
    fn build(body: &str, tail: &[u8]) -> ([u8; 1024], usize) {
        let mut buf = [0u8; 1024];
        let mut n = 0;
        for part in [
            &MAGIC[..],
            body.as_bytes(),
            MAC_LINE.as_bytes(),
            NONCE,
            tail,
        ] {
            buf[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        (buf, n)
    }

    fn parse_err(input: &[u8]) -> Error {
        Header::parse(input).map(|_| ()).unwrap_err()
    }

    #[test]
    fn empty_header_parses() {
        let (buf, n) = build("", b"payload");
        let h = Header::parse(&buf[..n]).unwrap();
        assert_eq!(h.stanza_count(), 0);
        assert_eq!(h.counts(), (0, 0, 0, 0, 0));
        assert_eq!(h.len(), 22 + 48);
        assert!(!h.is_empty());
        assert_eq!(h.nonce(), NONCE);
        assert_eq!(h.payload(), b"payload");
        assert_eq!(h.mac_input(), &buf[..22 + 3]);
        assert_eq!(h.stanzas().count(), 0);
        let mut out = [0u8; 128];
        let m = h.encode(&mut out).unwrap();
        assert_eq!(&out[..m], &buf[..h.len()]);
    }

    /// `Debug` must not dump the borrowed input (the whole file).
    #[cfg(feature = "alloc")]
    #[test]
    fn debug_prints_offsets_not_the_input() {
        let (buf, n) = build("", b"PAYLOADMARKER");
        let h = Header::parse(&buf[..n]).unwrap();
        let s = alloc::format!("{h:?}");
        assert!(s.contains(&alloc::format!("input_len: {n}")), "{s}");
        assert!(s.contains("header_len: 70"), "{s}");
        assert!(!s.contains("PAYLOADMARKER"), "{s}");
        assert!(!s.contains("0x50"), "{s}");
    }

    #[test]
    fn recognised_stanzas_are_counted_and_iterated() {
        let mut body = [0u8; 512];
        let parts = [
            X25519_STANZA,
            SSH_STANZA,
            "-> grease a b\nAAAA\n",
            "-> scrypt-ish\n\n",
        ];
        let mut n = 0;
        for p in parts {
            body[n..n + p.len()].copy_from_slice(p.as_bytes());
            n += p.len();
        }
        let (buf, len) = build(core::str::from_utf8(&body[..n]).unwrap(), b"");
        let h = Header::parse(&buf[..len]).unwrap();
        assert_eq!(h.stanza_count(), 4);
        assert_eq!(h.counts(), (1, 1, 0, 0, 2));
        let mut it = h.stanzas();
        let s = it.next().unwrap();
        assert_eq!(s.kind(), StanzaKind::X25519);
        assert_eq!(s.arg_count(), 1);
        assert_eq!(s.body_len(), 32);
        let s = it.next().unwrap();
        assert_eq!(s.kind(), StanzaKind::SshEd25519);
        assert_eq!(s.arg(0), Some("64jdUw"));
        assert_eq!(
            s.arg_bytes::<4>(0, Error::NoMatch).unwrap(),
            [0xeb, 0x88, 0xdd, 0x53]
        );
        let s = it.next().unwrap();
        assert_eq!(s.stanza_type(), "grease");
        assert_eq!(s.arg(1), Some("b"));
        assert_eq!(s.body_len(), 3);
        let s = it.next().unwrap();
        assert_eq!(s.stanza_type(), "scrypt-ish");
        assert_eq!(s.arg_count(), 0);
        assert_eq!(s.body_len(), 0);
        assert!(it.next().is_none());
        assert_eq!(h.payload(), b"");
        let mut out = [0u8; 1024];
        let m = h.encode(&mut out).unwrap();
        assert_eq!(&out[..m], &buf[..h.len()]);
        assert_eq!(h.encode(&mut [0u8; 10]), Err(Error::BufferTooSmall));
    }

    #[test]
    fn body_wrapping_round_trips() {
        // 48-byte body: a full 64-char line then an empty line.
        let mut line = [b'A'; 64];
        line[63] = b'A';
        let mut body = [0u8; 128];
        body[..3].copy_from_slice(b"-> ");
        body[3] = b't';
        body[4] = b'\n';
        body[5..69].copy_from_slice(&line);
        body[69] = b'\n';
        body[70] = b'\n';
        let (buf, n) = build(core::str::from_utf8(&body[..71]).unwrap(), b"");
        let h = Header::parse(&buf[..n]).unwrap();
        let s = h.stanzas().next().unwrap();
        assert_eq!(s.body_len(), 48);
        let mut dec = [1u8; 48];
        assert_eq!(s.body(&mut dec).unwrap(), 48);
        assert_eq!(dec, [0u8; 48]);
        let mut out = [0u8; 256];
        let m = h.encode(&mut out).unwrap();
        assert_eq!(&out[..m], &buf[..h.len()]);
        // 96-byte body: two full lines then an empty line.
        let mut body2 = [0u8; 256];
        body2[..5].copy_from_slice(b"-> t\n");
        body2[5..69].copy_from_slice(&line);
        body2[69] = b'\n';
        body2[70..134].copy_from_slice(&line);
        body2[134] = b'\n';
        body2[135] = b'\n';
        let (buf, n) = build(core::str::from_utf8(&body2[..136]).unwrap(), b"");
        let h = Header::parse(&buf[..n]).unwrap();
        assert_eq!(h.stanzas().next().unwrap().body_len(), 96);
        let m = h.encode(&mut out).unwrap();
        assert_eq!(&out[..m], &buf[..h.len()]);
    }

    #[test]
    fn every_header_error_is_reachable() {
        let e = |x| Error::Header(x);
        assert_eq!(parse_err(b""), e(HeaderError::BadMagic));
        assert_eq!(
            parse_err(b"age-encryption.org/v2\n"),
            e(HeaderError::BadMagic)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\r\n"),
            e(HeaderError::BadMagic)
        );
        assert_eq!(parse_err(MAGIC), e(HeaderError::Truncated));
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> X25519 abc"),
            e(HeaderError::Truncated)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> X25519 abc\n"),
            e(HeaderError::Truncated)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n\n"),
            e(HeaderError::BadStanzaStart)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-- x\n"),
            e(HeaderError::BadStanzaStart)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> \n"),
            e(HeaderError::NoArguments)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> a  b\n"),
            e(HeaderError::EmptyArgument)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> a b \n"),
            e(HeaderError::EmptyArgument)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> a\tb\n"),
            e(HeaderError::InvalidCharacter)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> a\r\n"),
            e(HeaderError::InvalidCharacter)
        );
        let mut long = [b'A'; 200];
        long[..27].copy_from_slice(b"age-encryption.org/v1\n-> a\n");
        long[27 + 65] = b'\n';
        assert_eq!(parse_err(&long[..27 + 66]), e(HeaderError::BodyLineTooLong));
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> a\nAA=\n"),
            e(HeaderError::BadBase64)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> a\nAAA\r\n"),
            e(HeaderError::BadBase64)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> a\nA\n"),
            e(HeaderError::BadBase64)
        );
        assert_eq!(
            parse_err(b"age-encryption.org/v1\n-> a\nAB\n"),
            e(HeaderError::BadBase64)
        );
        // a body line that is really the MAC line
        assert_eq!(
            parse_err(
                b"age-encryption.org/v1\n-> a\n--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg\n"
            ),
            e(HeaderError::BadBase64)
        );
        for bad in [
            &b"age-encryption.org/v1\n---\n"[..],
            b"age-encryption.org/v1\n--- \n",
            b"age-encryption.org/v1\n---WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg\n",
            b"age-encryption.org/v1\n---  WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg\n",
            b"age-encryption.org/v1\n--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg \n",
            b"age-encryption.org/v1\n--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNh\n",
            b"age-encryption.org/v1\n--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcN\n",
            b"age-encryption.org/v1\n--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg=\n",
            b"age-encryption.org/v1\n--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg\r\n",
        ] {
            assert_eq!(parse_err(bad), e(HeaderError::BadMacLine), "{bad:?}");
        }
        let (buf, n) = build("", b"");
        assert_eq!(parse_err(&buf[..n - 1]), e(HeaderError::ShortNonce));
        assert_eq!(parse_err(&buf[..n - 16]), e(HeaderError::ShortNonce));
        // X25519 shape
        let (buf, n) = build("-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc x\nhjabGXwSLQ9c3S6Lw2i+S2Tu2fiwQHHslbBN6B41FLE\n", b"");
        assert_eq!(parse_err(&buf[..n]), e(HeaderError::X25519Stanza));
        let (buf, n) = build("-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOC\nhjabGXwSLQ9c3S6Lw2i+S2Tu2fiwQHHslbBN6B41FLE\n", b"");
        assert_eq!(parse_err(&buf[..n]), e(HeaderError::X25519Stanza));
        let (buf, n) = build("-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCd\nhjabGXwSLQ9c3S6Lw2i+S2Tu2fiwQHHslbBN6B41FLE\n", b"");
        assert_eq!(parse_err(&buf[..n]), e(HeaderError::X25519Stanza));
        let (buf, n) = build(
            "-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc\n\n",
            b"",
        );
        assert_eq!(parse_err(&buf[..n]), e(HeaderError::X25519Stanza));
        // ssh-ed25519 shape
        let (buf, n) = build(
            "-> ssh-ed25519 64jdUw\n2BYYubiSZ09zSTlnTeKpXOrVuAcD4GX1JTfFQSu4UmI\n",
            b"",
        );
        assert_eq!(parse_err(&buf[..n]), e(HeaderError::SshEd25519Stanza));
        let (buf, n) = build("-> ssh-ed25519 64jdU NOQtSvXvlKB6OoQgG4idTNGnQ8snsRtqEEOKj+uOWEc\n2BYYubiSZ09zSTlnTeKpXOrVuAcD4GX1JTfFQSu4UmI\n", b"");
        assert_eq!(parse_err(&buf[..n]), e(HeaderError::SshEd25519Stanza));
        let (buf, n) = build(
            "-> ssh-ed25519 64jdUw NOQtSvXvlKB6OoQgG4idTNGnQ8snsRtqEEOKj+uOWEc\nAAAA\n",
            b"",
        );
        assert_eq!(parse_err(&buf[..n]), e(HeaderError::SshEd25519Stanza));
        // scrypt alone is fine structurally; with a second stanza it is not
        let (buf, n) = build("-> scrypt salt 18\nAAAA\n", b"");
        assert_eq!(Header::parse(&buf[..n]).unwrap().counts(), (0, 0, 1, 0, 0));
        let (buf, n) = build("-> scrypt salt 18\nAAAA\n-> g\n\n", b"");
        assert_eq!(parse_err(&buf[..n]), e(HeaderError::ScryptNotAlone));
        let (buf, n) = build("-> ssh-rsa tag\nAAAA\n", b"");
        assert_eq!(Header::parse(&buf[..n]).unwrap().counts(), (0, 0, 0, 1, 0));
    }

    #[test]
    fn mac_line_encoding() {
        let mut out = [0u8; 48];
        let mac = [0x5Au8; 32];
        assert_eq!(encode_mac_line(&mac, &mut out).unwrap(), 48);
        assert_eq!(&out[..4], b"--- ");
        assert_eq!(out[47], b'\n');
        let mut dec = [0u8; 32];
        assert_eq!(
            base64::decode_nopad(&out[4..47], &mut dec, Error::NoMatch).unwrap(),
            32
        );
        assert_eq!(dec, mac);
        assert_eq!(
            encode_mac_line(&mac, &mut [0u8; 47]),
            Err(Error::BufferTooSmall)
        );
    }
}
