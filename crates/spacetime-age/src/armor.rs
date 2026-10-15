//! ASCII armor: `-----BEGIN AGE ENCRYPTED FILE-----`, padded base64 in
//! 64-column lines, `-----END AGE ENCRYPTED FILE-----`.
//!
//! [`encode`] produces exactly what `rage -a` writes (LF line endings).
//! [`decode`] follows the CCTV corpus, first failure wins:
//!
//! - A1 Leading ASCII whitespace is skipped; then the BEGIN line followed by
//!   `\n` or `\r\n`, else `MissingBegin`.
//! - A2 Lines are read up to `\n` (EOF before an END line → `MissingEnd`);
//!   one trailing `\r` is stripped from a `\r\n` line. A line equal to END
//!   ends the block; every other line is a data line:
//!   - A3 an empty line → `LineLength` (blank lines are never allowed);
//!   - A4 longer than 64, or any line after a short (< 64) line →
//!     `LineLength`; a short line whose length is not a multiple of 4 →
//!     `BadBase64` (missing padding);
//!   - A5 every byte must be alphabet or `=`; `=` only completes the final
//!     quad of the **last** data line — anything else (`\r`, space, tab, a
//!     `=` in an earlier line) → `BadBase64`;
//!   - A6 strict padded decode: unused bits must be zero → `BadBase64`.
//! - A7 After END: `\n`, `\r\n` or EOF, then only ASCII whitespace; anything
//!   else → `TrailingData`.
//! - A8 Zero data lines are legal (decode to nothing).
//! - A9 Output longer than `out` → `BufferTooSmall`.
//!
//! rage rejects leading whitespace (`armor_whitespace_outside`); CCTV, which
//! is normative here, accepts it. Armored input is decoded in one pass over
//! a complete buffer — there is no streaming armor decoder.

use crate::base64;
use crate::error::{ArmorError, Error};

/// The BEGIN line (34 bytes, no newline).
pub const BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
/// The END line (32 bytes, no newline).
pub const END: &[u8] = b"-----END AGE ENCRYPTED FILE-----";
/// Data line width.
pub const LINE_LEN: usize = 64;

const fn aerr(e: ArmorError) -> Error {
    Error::Armor(e)
}

/// `35 + b64 + ceil(b64 / 64) + 33` with `b64 = 4·ceil(n / 3)` (68 for
/// `n = 0`).
pub const fn encoded_len(n: usize) -> usize {
    let b64 = base64::encoded_len_pad(n);
    BEGIN.len() + 1 + b64 + b64.div_ceil(LINE_LEN) + END.len() + 1
}

/// Upper bound for a [`decode`] buffer: `armored_len / 4 * 3 + 3`.
pub const fn max_decoded_len(armored_len: usize) -> usize {
    armored_len / 4 * 3 + 3
}

fn skip_whitespace(input: &[u8]) -> &[u8] {
    let n = input
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(input.len());
    &input[n..]
}

/// After skipping leading ASCII whitespace, does the input start with
/// [`BEGIN`]?
pub fn is_armored(input: &[u8]) -> bool {
    skip_whitespace(input).starts_with(BEGIN)
}

/// Armor `data` into `out`: exactly [`encoded_len`] bytes, LF endings.
pub fn encode(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let total = encoded_len(data.len());
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    let mut pos = 0usize;
    out[..BEGIN.len()].copy_from_slice(BEGIN);
    pos += BEGIN.len();
    out[pos] = b'\n';
    pos += 1;
    let b64 = base64::encoded_len_pad(data.len());
    pos += base64::encode_wrapped(data, &mut out[pos..], true, LINE_LEN)?;
    if !b64.is_multiple_of(LINE_LEN) {
        out[pos] = b'\n';
        pos += 1;
    }
    out[pos..pos + END.len()].copy_from_slice(END);
    pos += END.len();
    out[pos] = b'\n';
    pos += 1;
    debug_assert_eq!(pos, total);
    Ok(pos)
}

/// Decode an armored file into `out` (grammar in the module docs). Returns
/// the decoded length.
pub fn decode(armored: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let input = skip_whitespace(armored);
    if !input.starts_with(BEGIN) {
        return Err(aerr(ArmorError::MissingBegin));
    }
    let mut pos = BEGIN.len();
    if input.get(pos) == Some(&b'\n') {
        pos += 1;
    } else if input.get(pos) == Some(&b'\r') && input.get(pos + 1) == Some(&b'\n') {
        pos += 2;
    } else {
        return Err(aerr(ArmorError::MissingBegin));
    }

    let mut n = 0usize;
    let mut saw_short = false;
    let mut saw_pad = false;
    loop {
        if pos >= input.len() {
            return Err(aerr(ArmorError::MissingEnd));
        }
        let rest = &input[pos..];
        let (line, next) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => {
                let l = &rest[..i];
                (l.strip_suffix(b"\r").unwrap_or(l), pos + i + 1)
            }
            None => (rest, input.len()),
        };
        if line == END {
            pos = next;
            break;
        }
        if line.is_empty() || line.len() > LINE_LEN || saw_short {
            return Err(aerr(ArmorError::LineLength));
        }
        if line.len() < LINE_LEN {
            if line.len() % 4 != 0 {
                return Err(aerr(ArmorError::BadBase64));
            }
            saw_short = true;
        }
        if saw_pad {
            // `=` may only complete the last data line.
            return Err(aerr(ArmorError::BadBase64));
        }
        if line.contains(&b'=') {
            // Placement within the line is checked by the strict decoder.
            saw_pad = true;
        }
        n += base64::decode_pad(line, &mut out[n..], aerr(ArmorError::BadBase64))?;
        pos = next;
    }
    if !input[pos..].iter().all(u8::is_ascii_whitespace) {
        return Err(aerr(ArmorError::TrailingData));
    }
    Ok(n)
}

/// Owned [`encode`].
#[cfg(feature = "alloc")]
pub fn encode_string(data: &[u8]) -> alloc::string::String {
    let mut out = alloc::vec![0u8; encoded_len(data.len())];
    // Cannot fail: the buffer has exactly `encoded_len` bytes.
    let n = encode(data, &mut out).unwrap_or(0);
    out.truncate(n);
    alloc::string::String::from_utf8(out).unwrap_or_default()
}

/// Owned [`decode`].
#[cfg(feature = "alloc")]
pub fn decode_vec(armored: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    let mut out = alloc::vec![0u8; max_decoded_len(armored.len())];
    let n = decode(armored, &mut out)?;
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: &[u8] =
        b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYmFy\n-----END AGE ENCRYPTED FILE-----\n";

    fn dec(input: &[u8]) -> Result<usize, Error> {
        decode(input, &mut [0u8; 256])
    }

    #[test]
    fn lengths() {
        assert_eq!(encoded_len(0), 68);
        assert_eq!(encoded_len(1), 35 + 4 + 1 + 33);
        assert_eq!(encoded_len(48), 35 + 64 + 1 + 33);
        assert_eq!(encoded_len(49), 35 + 68 + 2 + 33);
        assert_eq!(max_decoded_len(100), 78);
    }

    #[test]
    fn encode_shapes() {
        let mut out = [0u8; 256];
        let n = encode(b"", &mut out).unwrap();
        assert_eq!(
            &out[..n],
            b"-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n"
        );
        let n = encode(b"foobar", &mut out).unwrap();
        assert_eq!(&out[..n], SMALL);
        let n = encode(&[0u8; 48], &mut out).unwrap();
        assert_eq!(n, encoded_len(48));
        assert_eq!(out[35 + 64], b'\n');
        assert_eq!(&out[35 + 65..35 + 65 + 5], b"-----");
        let n = encode(&[0u8; 49], &mut out).unwrap();
        assert_eq!(&out[35 + 65..35 + 65 + 5], b"AA==\n");
        assert_eq!(n, encoded_len(49));
        assert_eq!(
            encode(b"foobar", &mut [0u8; 10]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn decode_basics() {
        let mut out = [0u8; 16];
        assert_eq!(decode(SMALL, &mut out).unwrap(), 6);
        assert_eq!(&out[..6], b"foobar");
        // A8: no data lines
        assert_eq!(
            dec(b"-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n"),
            Ok(0)
        );
        // A1/A7: outer whitespace, CRLF, no final EOL
        assert_eq!(dec(b"\n\r \t-----BEGIN AGE ENCRYPTED FILE-----\r\nZm9vYmFy\r\n-----END AGE ENCRYPTED FILE-----\r\n \n"), Ok(6));
        assert_eq!(
            dec(b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYmFy\n-----END AGE ENCRYPTED FILE-----"),
            Ok(6)
        );
        assert!(is_armored(b"  \n-----BEGIN AGE ENCRYPTED FILE-----"));
        assert!(!is_armored(b"age-encryption.org/v1\n"));
        assert!(!is_armored(b"-----BEGIN SSH SIGNATURE-----"));
    }

    #[test]
    fn full_lines_and_short_lines() {
        let mut armored = [0u8; 256];
        let mut n = 0;
        for part in [BEGIN, b"\n", &[b'A'; 64][..], b"\n", b"AAAA\n", END, b"\n"] {
            armored[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        assert_eq!(dec(&armored[..n]), Ok(48 + 3));
        // full last line
        let mut n = 0;
        for part in [BEGIN, b"\n", &[b'A'; 64][..], b"\n", END, b"\n"] {
            armored[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        assert_eq!(dec(&armored[..n]), Ok(48));
        // full line after a short one
        let mut n = 0;
        for part in [BEGIN, b"\n", b"AAAA\n", &[b'A'; 64][..], b"\n", END, b"\n"] {
            armored[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        assert_eq!(dec(&armored[..n]), Err(aerr(ArmorError::LineLength)));
        // long line
        let mut n = 0;
        for part in [BEGIN, b"\n", &[b'A'; 68][..], b"\n", END, b"\n"] {
            armored[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        assert_eq!(dec(&armored[..n]), Err(aerr(ArmorError::LineLength)));
    }

    #[test]
    fn rejections_a1_to_a7() {
        let e = |x| Err(aerr(x));
        // A1
        assert_eq!(dec(b""), e(ArmorError::MissingBegin));
        assert_eq!(
            dec(b"garbage-----BEGIN AGE ENCRYPTED FILE-----\n"),
            e(ArmorError::MissingBegin)
        );
        assert_eq!(
            dec(b"-----BEGIN AGE ENCRYPTED FILE----- \n"),
            e(ArmorError::MissingBegin)
        );
        assert_eq!(
            dec(b"-----begin age encrypted file-----\n"),
            e(ArmorError::MissingBegin)
        );
        assert_eq!(
            dec(b"-----BEGIN AGE ENCRYPTED FILE-----"),
            e(ArmorError::MissingBegin)
        );
        // A2
        assert_eq!(
            dec(b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYmFy\n"),
            e(ArmorError::MissingEnd)
        );
        assert_eq!(
            dec(b"-----BEGIN AGE ENCRYPTED FILE-----\n"),
            e(ArmorError::MissingEnd)
        );
        // A3
        assert_eq!(dec(b"-----BEGIN AGE ENCRYPTED FILE-----\n\nZm9vYmFy\n-----END AGE ENCRYPTED FILE-----\n"), e(ArmorError::LineLength));
        assert_eq!(dec(b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYmFy\n\n-----END AGE ENCRYPTED FILE-----\n"), e(ArmorError::LineLength));
        // A4 no padding
        assert_eq!(
            dec(b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYg\n-----END AGE ENCRYPTED FILE-----\n"),
            e(ArmorError::BadBase64)
        );
        // A5
        for bad in [
            &b"-----BEGIN AGE ENCRYPTED FILE-----\n\rZm9vYmFy\n-----END AGE ENCRYPTED FILE-----\n"[..],
            b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9v\rYmFy\n-----END AGE ENCRYPTED FILE-----\n",
            b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYmFy\r\r\n-----END AGE ENCRYPTED FILE-----\n",
            b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYmFy \n-----END AGE ENCRYPTED FILE-----\n",
            b"-----BEGIN AGE ENCRYPTED FILE-----\n Zm9vYmFy\n-----END AGE ENCRYPTED FILE-----\n",
            b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9v*mFy\n-----END AGE ENCRYPTED FILE-----\n",
            b"-----BEGIN AGE ENCRYPTED FILE-----\nZm=vYmFy\n-----END AGE ENCRYPTED FILE-----\n",
            b"-----BEGIN AGE ENCRYPTED FILE-----\nComment: x\nZm9vYmFy\n-----END AGE ENCRYPTED FILE-----\n",
            b"-----BEGIN AGE ENCRYPTED FILE-----\n----- END AGE ENCRYPTED FILE-----\n",
        ] {
            assert_eq!(dec(bad), e(ArmorError::BadBase64), "{bad:?}");
        }
        // A5: `=` in a full line that is not the last data line
        let mut armored = [0u8; 256];
        let mut n = 0;
        let mut full = [b'A'; 64];
        full[62] = b'=';
        full[63] = b'=';
        for part in [BEGIN, b"\n", &full[..], b"\n", b"AAAA\n", END, b"\n"] {
            armored[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        assert_eq!(dec(&armored[..n]), e(ArmorError::BadBase64));
        // A6 not canonical
        assert_eq!(
            dec(
                b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYh==\n-----END AGE ENCRYPTED FILE-----\n"
            ),
            e(ArmorError::BadBase64)
        );
        // A7
        assert_eq!(dec(b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYmFy\n-----END AGE ENCRYPTED FILE-----\nx"), e(ArmorError::TrailingData));
        assert_eq!(
            dec(
                b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYmFy\n-----END AGE ENCRYPTED FILE-----\r"
            ),
            e(ArmorError::LineLength)
        );
        // A9
        assert_eq!(decode(SMALL, &mut [0u8; 5]), Err(Error::BufferTooSmall));
    }

    #[test]
    fn eol_between_padding_is_an_armor_failure() {
        let r = dec(
            b"-----BEGIN AGE ENCRYPTED FILE-----\nZm9vYg=\n=\n-----END AGE ENCRYPTED FILE-----\n",
        );
        assert!(matches!(r, Err(Error::Armor(_))), "{r:?}");
    }
}
