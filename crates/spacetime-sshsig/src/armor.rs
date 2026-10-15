//! SSHSIG armor (PROTOCOL.sshsig §2) and a strict standard-alphabet base64
//! codec (RFC 4648 §4).
//!
//! The armored form is the text `ssh-keygen -Y sign` writes:
//!
//! ```text
//! -----BEGIN SSH SIGNATURE-----
//! <base64 of the blob, 70 characters per line, each line "\n"-terminated>
//! -----END SSH SIGNATURE-----
//! ```
//!
//! [`encode`] reproduces that byte for byte. [`decode`] is strict: exact
//! header, `\n` line endings only (a `\r` is a base64 error), base64 lines of
//! 1..=76 characters, canonical padding, zero unused trailing bits, and
//! nothing after the footer except one optional `\n`. Anything else fails
//! closed. Nothing here allocates; the `alloc` forms are thin wrappers.
//!
//! The base64 codec is written here rather than pulled from a crate so the
//! published dependency graph stays `spacetime-crypto` only.

use crate::error::Error;

/// Armor header line (29 bytes, no newline).
pub const HEADER: &[u8] = b"-----BEGIN SSH SIGNATURE-----";
/// Armor footer line (27 bytes, no newline).
pub const FOOTER: &[u8] = b"-----END SSH SIGNATURE-----";
/// Emitted line width — what `ssh-keygen -Y sign` writes (verified: 70).
pub const LINE_LEN: usize = 70;
/// Accepted line width (PROTOCOL.sshsig: "SHOULD be broken up by newlines
/// every 76 characters").
pub const MAX_LINE_LEN: usize = 76;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Exact armored length for a blob of `blob_len` bytes:
/// `30 (header + "\n") + b64 + ceil(b64 / 70) newlines + 28 (footer + "\n")`,
/// where `b64 = 4 * ceil(blob_len / 3)`.
pub const fn encoded_len(blob_len: usize) -> usize {
    let b64 = base64_encoded_len(blob_len);
    HEADER.len() + 1 + b64 + b64.div_ceil(LINE_LEN) + FOOTER.len() + 1
}

/// Upper bound for a [`decode`] output buffer: `armored_len / 4 * 3 + 3`.
pub const fn max_decoded_len(armored_len: usize) -> usize {
    armored_len / 4 * 3 + 3
}

/// Padded base64 length of `n` input bytes: `4 * ceil(n / 3)`.
pub const fn base64_encoded_len(n: usize) -> usize {
    4 * n.div_ceil(3)
}

/// Unpadded base64 length of `n` input bytes: `ceil(4n / 3)`.
pub const fn base64_encoded_len_nopad(n: usize) -> usize {
    (4 * n).div_ceil(3)
}

/// Value of one base64 alphabet byte, or `None` for anything else
/// (including `=`).
const fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// `true` for a base64 alphabet byte or `=`.
pub(crate) const fn is_base64_byte(c: u8) -> bool {
    c == b'=' || sextet(c).is_some()
}

// ---------------------------------------------------------------------------
// Streaming encoder
// ---------------------------------------------------------------------------

/// Streaming base64 encoder into a caller buffer, with optional line
/// wrapping. Used by [`encode`], the one-shot encoders, and the piecewise
/// public-key line / fingerprint writers (no scratch copy of the input).
pub(crate) struct Base64Encoder<'o> {
    out: &'o mut [u8],
    pos: usize,
    acc: [u8; 3],
    acc_len: usize,
    /// Characters per line; `0` disables wrapping.
    line_len: usize,
    col: usize,
}

impl<'o> Base64Encoder<'o> {
    /// Encode into `out` starting at `start`; wrap after `line_len`
    /// characters (`0` = never), emitting `\n` after every full line.
    pub(crate) fn new(out: &'o mut [u8], start: usize, line_len: usize) -> Self {
        Self {
            out,
            pos: start,
            acc: [0; 3],
            acc_len: 0,
            line_len,
            col: 0,
        }
    }

    fn put(&mut self, c: u8) -> Result<(), Error> {
        if self.pos >= self.out.len() {
            return Err(Error::BufferTooSmall);
        }
        self.out[self.pos] = c;
        self.pos += 1;
        Ok(())
    }

    fn put_char(&mut self, c: u8) -> Result<(), Error> {
        self.put(c)?;
        if self.line_len != 0 {
            self.col += 1;
            if self.col == self.line_len {
                self.put(b'\n')?;
                self.col = 0;
            }
        }
        Ok(())
    }

    fn emit(&mut self, group: &[u8], pad: bool) -> Result<(), Error> {
        let n = group.len();
        let b0 = group[0];
        let b1 = if n > 1 { group[1] } else { 0 };
        let b2 = if n > 2 { group[2] } else { 0 };
        let chars = [
            ALPHABET[(b0 >> 2) as usize],
            ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize],
            ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize],
            ALPHABET[(b2 & 0x3f) as usize],
        ];
        let keep = n + 1;
        for &c in &chars[..keep] {
            self.put_char(c)?;
        }
        if pad {
            for _ in keep..4 {
                self.put_char(b'=')?;
            }
        }
        Ok(())
    }

    /// Absorb input bytes.
    pub(crate) fn update(&mut self, mut data: &[u8]) -> Result<(), Error> {
        while !data.is_empty() {
            if self.acc_len == 0 && data.len() >= 3 {
                let (g, rest) = data.split_at(3);
                self.emit(g, true)?;
                data = rest;
                continue;
            }
            let take = (3 - self.acc_len).min(data.len());
            self.acc[self.acc_len..self.acc_len + take].copy_from_slice(&data[..take]);
            self.acc_len += take;
            data = &data[take..];
            if self.acc_len == 3 {
                let g = self.acc;
                self.emit(&g, true)?;
                self.acc_len = 0;
            }
        }
        Ok(())
    }

    /// Flush the final partial group (`pad` selects `=` padding). If
    /// wrapping is on and the last line is unterminated, emit one `\n`.
    /// Returns the end position in `out`.
    pub(crate) fn finish(mut self, pad: bool) -> Result<usize, Error> {
        if self.acc_len > 0 {
            let g = self.acc;
            let n = self.acc_len;
            self.emit(&g[..n], pad)?;
            self.acc_len = 0;
        }
        if self.line_len != 0 && self.col != 0 {
            self.put(b'\n')?;
            self.col = 0;
        }
        Ok(self.pos)
    }
}

// ---------------------------------------------------------------------------
// Streaming decoder (validation pass + write pass over the same characters)
// ---------------------------------------------------------------------------

/// Decode a stream of base64 characters strictly: total length a non-zero
/// multiple of 4, `=` only in the last one or two positions, zero unused
/// trailing bits. `sink` receives each decoded byte; the return value is the
/// decoded length. Any violation is [`Error::ArmorBadBase64`].
fn base64_stream<I, F>(chars: I, mut sink: F) -> Result<usize, Error>
where
    I: Iterator<Item = u8>,
    F: FnMut(u8) -> Result<(), Error>,
{
    let mut quad = [0u8; 4];
    let mut idx = 0usize;
    let mut pad = 0usize;
    let mut total = 0usize;
    let mut done = false;
    let mut out_len = 0usize;

    for c in chars {
        if done {
            // Nothing may follow a padded quad.
            return Err(Error::ArmorBadBase64);
        }
        total += 1;
        if c == b'=' {
            pad += 1;
            quad[idx] = 0;
        } else {
            if pad > 0 {
                // A data character after `=` inside the quad.
                return Err(Error::ArmorBadBase64);
            }
            quad[idx] = sextet(c).ok_or(Error::ArmorBadBase64)?;
        }
        idx += 1;
        if idx == 4 {
            idx = 0;
            if pad > 2 {
                return Err(Error::ArmorBadBase64);
            }
            let b0 = (quad[0] << 2) | (quad[1] >> 4);
            let b1 = (quad[1] << 4) | (quad[2] >> 2);
            let b2 = (quad[2] << 6) | quad[3];
            match pad {
                0 => {
                    sink(b0)?;
                    sink(b1)?;
                    sink(b2)?;
                    out_len += 3;
                }
                1 => {
                    if quad[2] & 0x03 != 0 {
                        return Err(Error::ArmorBadBase64);
                    }
                    sink(b0)?;
                    sink(b1)?;
                    out_len += 2;
                    done = true;
                }
                _ => {
                    if quad[1] & 0x0f != 0 {
                        return Err(Error::ArmorBadBase64);
                    }
                    sink(b0)?;
                    out_len += 1;
                    done = true;
                }
            }
        }
    }
    if total == 0 || idx != 0 {
        return Err(Error::ArmorBadBase64);
    }
    Ok(out_len)
}

/// Two-pass strict decode: validate and size, check `out`, then write.
fn base64_decode_chars<I>(chars: I, out: &mut [u8]) -> Result<usize, Error>
where
    I: Iterator<Item = u8> + Clone,
{
    let needed = base64_stream(chars.clone(), |_| Ok(()))?;
    if needed > out.len() {
        return Err(Error::BufferTooSmall);
    }
    let mut pos = 0usize;
    base64_stream(chars, |b| {
        out[pos] = b;
        pos += 1;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Public base64 API
// ---------------------------------------------------------------------------

/// Padded base64 (RFC 4648 §4) of `input` into `out`; returns bytes written
/// (`base64_encoded_len(input.len())`).
pub fn base64_encode(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < base64_encoded_len(input.len()) {
        return Err(Error::BufferTooSmall);
    }
    let mut enc = Base64Encoder::new(out, 0, 0);
    enc.update(input)?;
    enc.finish(true)
}

/// Unpadded base64 of `input` into `out`; returns bytes written
/// (`base64_encoded_len_nopad(input.len())`). Used by the fingerprint.
pub fn base64_encode_nopad(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < base64_encoded_len_nopad(input.len()) {
        return Err(Error::BufferTooSmall);
    }
    let mut enc = Base64Encoder::new(out, 0, 0);
    enc.update(input)?;
    enc.finish(false)
}

/// Strict decode of padded base64 (no line handling): total length a
/// non-zero multiple of 4, `=` only in the last one or two positions,
/// non-zero unused trailing bits rejected — any violation is
/// [`Error::ArmorBadBase64`]. The output size is checked against `out`
/// before anything is written ([`Error::BufferTooSmall`]).
pub fn base64_decode(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    base64_decode_chars(input.iter().copied(), out)
}

// ---------------------------------------------------------------------------
// Armor
// ---------------------------------------------------------------------------

/// Armor `blob` into `out`. Writes exactly `encoded_len(blob.len())` bytes:
/// `HEADER "\n"`, the base64 text in 70-character lines each followed by
/// `"\n"`, then `FOOTER "\n"` — byte for byte what `ssh-keygen -Y sign`
/// emits.
pub fn encode(blob: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let total = encoded_len(blob.len());
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    out[..HEADER.len()].copy_from_slice(HEADER);
    out[HEADER.len()] = b'\n';
    let mut enc = Base64Encoder::new(out, HEADER.len() + 1, LINE_LEN);
    enc.update(blob)?;
    let pos = enc.finish(true)?;
    out[pos..pos + FOOTER.len()].copy_from_slice(FOOTER);
    out[pos + FOOTER.len()] = b'\n';
    Ok(total)
}

/// Locate the base64 region of an armored block: returns `(start, end)` of
/// the bytes between the header line and the footer line (newlines
/// included), having enforced the line grammar (rules 1–4 of the module
/// docs).
fn scan(armored: &[u8]) -> Result<(usize, usize), Error> {
    // Rule 1: exact header line, no leading whitespace.
    if armored.len() <= HEADER.len()
        || &armored[..HEADER.len()] != HEADER
        || armored[HEADER.len()] != b'\n'
    {
        return Err(Error::ArmorMissingHeader);
    }
    let start = HEADER.len() + 1;
    let mut pos = start;
    loop {
        let rest = &armored[pos..];
        let (line, terminated) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => (&rest[..i], true),
            None => (rest, false),
        };
        // Rule 2/4: a footer line ends the block; after it EOF or one `\n`.
        if line == FOOTER {
            let after = &rest[line.len()..];
            return if after.is_empty() || after == b"\n" {
                Ok((start, pos))
            } else {
                Err(Error::ArmorTrailingData)
            };
        }
        // Rule 3: EOF before a footer line.
        if !terminated {
            return Err(Error::ArmorMissingFooter);
        }
        // Rule 2: a base64 line of 1..=76 alphabet/`=` bytes.
        if line.is_empty() {
            return Err(Error::ArmorBadBase64);
        }
        if line.len() > MAX_LINE_LEN {
            return Err(Error::ArmorLineTooLong);
        }
        if !line.iter().all(|&c| is_base64_byte(c)) {
            return Err(Error::ArmorBadBase64);
        }
        pos += line.len() + 1;
    }
}

/// Strictly decode an armored block into `out`; returns the blob length.
///
/// Grammar (fail closed):
/// 1. `HEADER` followed by `\n`, else [`Error::ArmorMissingHeader`].
/// 2. `\n`-terminated lines. A line equal to `FOOTER` ends the block. Every
///    other line is base64: length `1..=76` (`> 76` →
///    [`Error::ArmorLineTooLong`]; `0` → [`Error::ArmorBadBase64`]), every
///    byte in the alphabet or `=` (a `\r` is [`Error::ArmorBadBase64`]).
/// 3. EOF before a footer line → [`Error::ArmorMissingFooter`].
/// 4. After the footer: EOF, or exactly `\n` then EOF; else
///    [`Error::ArmorTrailingData`].
/// 5. The concatenated base64 lines decode strictly (see
///    [`base64_decode`]) — any violation [`Error::ArmorBadBase64`].
/// 6. Output longer than `out` → [`Error::BufferTooSmall`], checked before
///    anything is written.
pub fn decode(armored: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let (start, end) = scan(armored)?;
    let chars = armored[start..end].iter().copied().filter(|&c| c != b'\n');
    base64_decode_chars(chars, out)
}

// ---------------------------------------------------------------------------
// alloc forms
// ---------------------------------------------------------------------------

/// [`encode`] into a fresh `String`.
#[cfg(feature = "alloc")]
pub fn encode_string(blob: &[u8]) -> alloc::string::String {
    let mut v = alloc::vec![0u8; encoded_len(blob.len())];
    let n = encode(blob, &mut v).expect("buffer sized by encoded_len");
    v.truncate(n);
    alloc::string::String::from_utf8(v).expect("armor is ASCII")
}

/// [`decode`] into a fresh `Vec`.
#[cfg(feature = "alloc")]
pub fn decode_vec(armored: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    let mut v = alloc::vec![0u8; max_decoded_len(armored.len())];
    let n = decode(armored, &mut v)?;
    v.truncate(n);
    Ok(v)
}

/// [`base64_decode`] into a fresh `Vec`.
#[cfg(feature = "alloc")]
pub fn base64_decode_vec(input: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    let mut v = alloc::vec![0u8; max_decoded_len(input.len())];
    let n = base64_decode(input, &mut v)?;
    v.truncate(n);
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        assert_eq!(base64_encoded_len(0), 0);
        assert_eq!(base64_encoded_len(1), 4);
        assert_eq!(base64_encoded_len(3), 4);
        assert_eq!(base64_encoded_len(4), 8);
        assert_eq!(base64_encoded_len_nopad(32), 43);
        assert_eq!(base64_encoded_len_nopad(3), 4);
        // 177-byte blob → 236 base64 chars → 4 lines → 298-byte file.
        assert_eq!(encoded_len(177), 298);
        // 210-byte blob → 280 = 4 × 70 base64 chars: exactly full lines, no
        // empty line before the footer (ssh-keygen 10.2p1 observed: 29/70/
        // 70/70/70/27 for namespaces of 38–40 bytes).
        assert_eq!(encoded_len(210), 30 + 280 + 4 + 28);
        assert_eq!(encoded_len(0), 58);
        assert!(max_decoded_len(298) >= 177);
    }

    #[test]
    fn base64_round_trip_all_remainders() {
        let data: [u8; 7] = [0xfb, 0xff, 0x00, 0x10, 0x7f, 0x80, 0x01];
        let mut enc = [0u8; 4];
        assert_eq!(base64_encode(&[], &mut enc), Ok(0));
        // An empty encoding is not a valid strict input (no quad).
        assert_eq!(base64_decode(&[], &mut enc), Err(Error::ArmorBadBase64));
        for n in 1..=7 {
            let mut enc = [0u8; 12];
            let e = base64_encode(&data[..n], &mut enc).unwrap();
            assert_eq!(e, base64_encoded_len(n));
            let mut dec = [0u8; 9];
            let d = base64_decode(&enc[..e], &mut dec).unwrap();
            assert_eq!(&dec[..d], &data[..n]);
        }
    }

    #[test]
    fn base64_known_answers() {
        let mut out = [0u8; 16];
        let n = base64_encode(b"foobar", &mut out).unwrap();
        assert_eq!(&out[..n], b"Zm9vYmFy");
        let n = base64_encode(b"fooba", &mut out).unwrap();
        assert_eq!(&out[..n], b"Zm9vYmE=");
        let n = base64_encode(b"foob", &mut out).unwrap();
        assert_eq!(&out[..n], b"Zm9vYg==");
        let n = base64_encode_nopad(b"foob", &mut out).unwrap();
        assert_eq!(&out[..n], b"Zm9vYg");
        assert_eq!(
            base64_encode(b"foob", &mut out[..7]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            base64_encode_nopad(b"foob", &mut out[..5]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn base64_strict_rejections() {
        let mut out = [0u8; 16];
        let bad: &[&[u8]] = &[
            b"",             // no quad
            b"Zm9",          // length % 4 != 0
            b"Zm9vYg==Zg==", // padding in the middle
            b"Zm9=vYmE=",    // data after `=` inside a quad
            b"Zm9vYmF=",     // non-zero trailing bits (F = 000101, low 2 bits set)
            b"Zm9vYh==",     // non-zero trailing bits (h = 100001, low 4 bits set)
            b"Z===",         // three pads
            b"====",         // four pads
            b"Zm9v\r\n",     // control bytes
            b"Zm9v*A==",     // non-alphabet byte
            b"=m9v",         // pad first
        ];
        for (i, b) in bad.iter().enumerate() {
            assert_eq!(
                base64_decode(b, &mut out),
                Err(Error::ArmorBadBase64),
                "{i}"
            );
        }
        // Canonical two-byte padding decodes to a single byte.
        assert_eq!(base64_decode(b"Zg==", &mut out), Ok(1));
        assert_eq!(out[0], b'f');
        assert_eq!(
            base64_decode(b"Zm9vYmFy", &mut out[..5]),
            Err(Error::BufferTooSmall)
        );
        // Size is checked before writing: nothing lands in a short buffer.
        let mut short = [0xaau8; 2];
        assert_eq!(
            base64_decode(b"Zm9vYmFy", &mut short),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(short, [0xaa, 0xaa]);
    }

    /// A 177-byte pseudo-blob (four base64 lines like a real ssh-ed25519
    /// SSHSIG with a 7-byte namespace).
    fn blob() -> [u8; 177] {
        let mut b = [0u8; 177];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        b
    }

    #[test]
    fn armor_round_trip_and_shape() {
        let blob = blob();
        let mut armored = [0u8; 298];
        let n = encode(&blob, &mut armored).unwrap();
        assert_eq!(n, 298);
        assert!(armored.starts_with(b"-----BEGIN SSH SIGNATURE-----\n"));
        assert!(armored.ends_with(b"-----END SSH SIGNATURE-----\n"));
        let body = &armored[30..298 - 28];
        let lines = alloc_free_lines(body);
        assert_eq!(lines, [70, 70, 70, 26]);

        let mut out = [0u8; 200];
        let d = decode(&armored[..n], &mut out).unwrap();
        assert_eq!(&out[..d], &blob[..]);

        assert_eq!(
            encode(&blob, &mut armored[..297]),
            Err(Error::BufferTooSmall)
        );
    }

    /// Lengths of `\n`-terminated lines in `body`, without allocating.
    fn alloc_free_lines(body: &[u8]) -> [usize; 4] {
        let mut lens = [0usize; 4];
        let mut i = 0;
        for line in body.split(|&c| c == b'\n') {
            if line.is_empty() {
                continue;
            }
            lens[i] = line.len();
            i += 1;
        }
        lens
    }

    #[test]
    fn armor_empty_blob() {
        let mut armored = [0u8; 58];
        assert_eq!(encode(&[], &mut armored).unwrap(), 58);
        // An empty body has no base64 quad at all → rule 5 fails.
        let mut out = [0u8; 4];
        assert_eq!(decode(&armored, &mut out), Err(Error::ArmorBadBase64));
    }

    #[test]
    fn armor_full_lines_have_no_blank_line() {
        // 210 bytes → 280 base64 chars → four full 70-char lines and no
        // empty line before the footer (matches ssh-keygen byte for byte).
        let blob = [0x5au8; 210];
        let mut armored = [0u8; 342];
        assert_eq!(encode(&blob, &mut armored).unwrap(), 342);
        assert!(!armored.windows(2).any(|w| w == b"\n\n"));
        // 0x5a5a5a → "Wlpa": the last body line ends in `a`, then `\n`.
        assert_eq!(
            &armored[342 - FOOTER.len() - 3..342 - FOOTER.len() - 1],
            b"a\n"
        );
        let mut out = [0u8; 210];
        assert_eq!(decode(&armored, &mut out).unwrap(), 210);
        assert_eq!(out, blob);
    }

    #[test]
    fn armor_grammar_a1_a5() {
        let blob = blob();
        let mut good = [0u8; 298];
        encode(&blob, &mut good).unwrap();
        let mut out = [0u8; 200];

        // A1: header missing / altered / preceded by whitespace.
        assert_eq!(decode(&good[1..], &mut out), Err(Error::ArmorMissingHeader));
        assert_eq!(
            decode(&good[30..], &mut out),
            Err(Error::ArmorMissingHeader)
        );
        let mut sp = [0u8; 299];
        sp[0] = b' ';
        sp[1..].copy_from_slice(&good);
        assert_eq!(decode(&sp, &mut out), Err(Error::ArmorMissingHeader));
        assert_eq!(
            decode(b"-----BEGIN SSH SIGNATURE-----", &mut out),
            Err(Error::ArmorMissingHeader)
        );
        assert_eq!(
            decode(b"-----BEGIN SSH SIGNATURE-----\r\n", &mut out),
            Err(Error::ArmorMissingHeader)
        );

        // A2: footer missing (EOF after the last base64 line).
        assert_eq!(
            decode(&good[..298 - 28], &mut out),
            Err(Error::ArmorMissingFooter)
        );
        // ... also when the last line is unterminated.
        assert_eq!(
            decode(&good[..298 - 29], &mut out),
            Err(Error::ArmorMissingFooter)
        );
        // Header only.
        assert_eq!(
            decode(&good[..30], &mut out),
            Err(Error::ArmorMissingFooter)
        );

        // A3: a line longer than 76 characters.
        let mut long = [0u8; 298];
        long.copy_from_slice(&good);
        long[100] = b'A'; // join line 1 and line 2 (70 + 1 + 70 = 141 chars)
        assert_eq!(decode(&long, &mut out), Err(Error::ArmorLineTooLong));

        // A4: bad byte, empty line, `\r`.
        let mut bad = [0u8; 298];
        bad.copy_from_slice(&good);
        bad[31] = b'*';
        assert_eq!(decode(&bad, &mut out), Err(Error::ArmorBadBase64));
        let mut crlf = [0u8; 299];
        crlf[..100].copy_from_slice(&good[..100]);
        crlf[100] = b'\r'; // "\r\n" line ending on line 1
        crlf[101..].copy_from_slice(&good[100..]);
        assert_eq!(decode(&crlf, &mut out), Err(Error::ArmorBadBase64));
        let mut empty_line = [0u8; 299];
        empty_line[..30].copy_from_slice(&good[..30]);
        empty_line[30] = b'\n';
        empty_line[31..].copy_from_slice(&good[30..]);
        assert_eq!(decode(&empty_line, &mut out), Err(Error::ArmorBadBase64));

        // A5: text after the footer; a single `\n` is fine; EOF is fine.
        let mut trailing = [0u8; 303];
        trailing[..298].copy_from_slice(&good);
        trailing[298..].copy_from_slice(b"junk\n");
        assert_eq!(decode(&trailing, &mut out), Err(Error::ArmorTrailingData));
        let mut two_nl = [0u8; 299];
        two_nl[..298].copy_from_slice(&good);
        two_nl[298] = b'\n';
        assert_eq!(decode(&two_nl, &mut out), Err(Error::ArmorTrailingData));
        assert_eq!(decode(&good[..297], &mut out), Ok(177));

        // Rule 6: buffer too small, checked before writing.
        assert_eq!(decode(&good, &mut out[..176]), Err(Error::BufferTooSmall));
    }

    #[test]
    fn armor_accepts_76_column_lines() {
        let blob = blob();
        let mut b64 = [0u8; 236];
        base64_encode(&blob, &mut b64).unwrap();
        // 236 = 76 + 76 + 76 + 8
        let mut armored = [0u8; 30 + 236 + 4 + 28];
        let mut pos = 0;
        armored[pos..pos + 30].copy_from_slice(b"-----BEGIN SSH SIGNATURE-----\n");
        pos += 30;
        for chunk in b64.chunks(76) {
            armored[pos..pos + chunk.len()].copy_from_slice(chunk);
            pos += chunk.len();
            armored[pos] = b'\n';
            pos += 1;
        }
        armored[pos..pos + 28].copy_from_slice(b"-----END SSH SIGNATURE-----\n");
        pos += 28;
        let mut out = [0u8; 200];
        assert_eq!(decode(&armored[..pos], &mut out), Ok(177));
        assert_eq!(&out[..177], &blob[..]);
    }

    #[cfg(feature = "alloc")]
    mod with_alloc {
        use super::super::*;
        use alloc::vec::Vec;

        #[test]
        fn alloc_forms_match_buffer_forms() {
            let blob: Vec<u8> = (0u8..177).collect();
            let s = encode_string(&blob);
            let mut buf = [0u8; 298];
            let n = encode(&blob, &mut buf).unwrap();
            assert_eq!(s.as_bytes(), &buf[..n]);
            assert_eq!(decode_vec(s.as_bytes()).unwrap(), blob);
            assert_eq!(decode_vec(b"nope"), Err(Error::ArmorMissingHeader));
            assert_eq!(base64_decode_vec(b"Zm9vYmFy").unwrap(), b"foobar");
            assert_eq!(base64_decode_vec(b"Zm9"), Err(Error::ArmorBadBase64));
        }
    }
}
