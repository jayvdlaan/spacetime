//! Strict standard-alphabet base64 (RFC 4648 §4) in the two dialects age
//! uses: raw (no padding — stanza arguments, stanza bodies, the MAC line)
//! and padded (ASCII armor).
//!
//! Both decoders are strict and *canonical*: only alphabet bytes (plus `=`
//! where the padded dialect allows it), no whitespace, and the unused
//! trailing bits of the last character must be zero — with `r = chars % 4`
//! data characters in the last quad, `r == 2` requires the low 4 bits of the
//! last value to be zero and `r == 3` the low 2 bits. The raw dialect
//! additionally rejects `chars % 4 == 1` and any `=`; the padded dialect
//! requires `chars % 4 == 0` and `=` only as the final one or two
//! characters.
//!
//! The decoders take the error the *caller* wants reported
//! (`Header(BadBase64)` from the header parser, `Armor(BadBase64)` from the
//! armor decoder) so one implementation serves both layers. Written in-crate
//! so the published dependency graph stays `spacetime-crypto` only.

use crate::error::Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Value of one alphabet byte, or `None` for anything else (including `=`).
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

/// `true` for one of the 64 alphabet bytes (`=` is **not** alphabet).
pub fn is_alphabet(b: u8) -> bool {
    sextet(b).is_some()
}

/// Raw (unpadded) length of `n` input bytes: `ceil(4n / 3)`.
pub const fn encoded_len_nopad(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Padded length of `n` input bytes: `4 * ceil(n / 3)`.
pub const fn encoded_len_pad(n: usize) -> usize {
    4 * n.div_ceil(3)
}

/// Decoded length of a raw string of `chars` characters; `None` when
/// `chars % 4 == 1` (no byte string encodes to that).
pub const fn decoded_len_nopad(chars: usize) -> Option<usize> {
    let full = chars / 4 * 3;
    match chars % 4 {
        0 => Some(full),
        2 => Some(full + 1),
        3 => Some(full + 2),
        _ => None,
    }
}

/// Encode `input` into `out`; `pad` selects `=` padding; `line_len > 0`
/// emits `\n` after every `line_len` characters (no newline is emitted
/// after a final partial line — the caller decides that). Returns the
/// number of bytes written; `BufferTooSmall` if `out` cannot hold them.
pub(crate) fn encode_wrapped(
    input: &[u8],
    out: &mut [u8],
    pad: bool,
    line_len: usize,
) -> Result<usize, Error> {
    let mut pos = 0usize;
    let mut col = 0usize;
    let mut put = |c: u8, pos: &mut usize, col: &mut usize| -> Result<(), Error> {
        if *pos >= out.len() {
            return Err(Error::BufferTooSmall);
        }
        out[*pos] = c;
        *pos += 1;
        if line_len != 0 {
            *col += 1;
            if *col == line_len {
                if *pos >= out.len() {
                    return Err(Error::BufferTooSmall);
                }
                out[*pos] = b'\n';
                *pos += 1;
                *col = 0;
            }
        }
        Ok(())
    };
    let (groups, rest) = input.as_chunks::<3>();
    for g in groups {
        put(ALPHABET[(g[0] >> 2) as usize], &mut pos, &mut col)?;
        put(
            ALPHABET[(((g[0] & 0x03) << 4) | (g[1] >> 4)) as usize],
            &mut pos,
            &mut col,
        )?;
        put(
            ALPHABET[(((g[1] & 0x0f) << 2) | (g[2] >> 6)) as usize],
            &mut pos,
            &mut col,
        )?;
        put(ALPHABET[(g[2] & 0x3f) as usize], &mut pos, &mut col)?;
    }
    match rest.len() {
        1 => {
            put(ALPHABET[(rest[0] >> 2) as usize], &mut pos, &mut col)?;
            put(
                ALPHABET[((rest[0] & 0x03) << 4) as usize],
                &mut pos,
                &mut col,
            )?;
            if pad {
                put(b'=', &mut pos, &mut col)?;
                put(b'=', &mut pos, &mut col)?;
            }
        }
        2 => {
            put(ALPHABET[(rest[0] >> 2) as usize], &mut pos, &mut col)?;
            put(
                ALPHABET[(((rest[0] & 0x03) << 4) | (rest[1] >> 4)) as usize],
                &mut pos,
                &mut col,
            )?;
            put(
                ALPHABET[((rest[1] & 0x0f) << 2) as usize],
                &mut pos,
                &mut col,
            )?;
            if pad {
                put(b'=', &mut pos, &mut col)?;
            }
        }
        _ => {}
    }
    Ok(pos)
}

/// Raw base64 of `input` into `out`; returns the number of characters
/// written (`encoded_len_nopad`). `BufferTooSmall` if `out` is too short.
pub fn encode_nopad(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    encode_wrapped(input, out, false, 0)
}

/// Padded base64 of `input` into `out`; returns `encoded_len_pad(input.len())`.
pub fn encode_pad(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    encode_wrapped(input, out, true, 0)
}

/// Strict decoder over a character stream. `out == None` validates without
/// writing. `padded` selects the dialect. Returns the decoded length.
fn decode_core<I>(
    chars: I,
    mut out: Option<&mut [u8]>,
    padded: bool,
    err: Error,
) -> Result<usize, Error>
where
    I: Iterator<Item = u8>,
{
    let mut n = 0usize;
    let mut put = |b: u8, n: &mut usize| -> Result<(), Error> {
        if let Some(o) = out.as_deref_mut() {
            if *n >= o.len() {
                return Err(Error::BufferTooSmall);
            }
            o[*n] = b;
        }
        *n += 1;
        Ok(())
    };

    let mut quad = [0u8; 4];
    let mut idx = 0usize;
    let mut pad = 0usize;
    let mut done = false;

    for c in chars {
        if done {
            // Nothing may follow a padded quad.
            return Err(err);
        }
        if c == b'=' {
            if !padded {
                return Err(err);
            }
            pad += 1;
            quad[idx] = 0;
        } else {
            if pad > 0 {
                return Err(err);
            }
            quad[idx] = sextet(c).ok_or(err)?;
        }
        idx += 1;
        if idx == 4 {
            idx = 0;
            match pad {
                0 => {
                    put((quad[0] << 2) | (quad[1] >> 4), &mut n)?;
                    put((quad[1] << 4) | (quad[2] >> 2), &mut n)?;
                    put((quad[2] << 6) | quad[3], &mut n)?;
                }
                1 => {
                    if quad[2] & 0x03 != 0 {
                        return Err(err);
                    }
                    put((quad[0] << 2) | (quad[1] >> 4), &mut n)?;
                    put((quad[1] << 4) | (quad[2] >> 2), &mut n)?;
                    done = true;
                }
                2 => {
                    if quad[1] & 0x0f != 0 {
                        return Err(err);
                    }
                    put((quad[0] << 2) | (quad[1] >> 4), &mut n)?;
                    done = true;
                }
                _ => return Err(err),
            }
        }
    }

    match idx {
        0 => {}
        1 => return Err(err),
        2 => {
            if padded || quad[1] & 0x0f != 0 {
                return Err(err);
            }
            put((quad[0] << 2) | (quad[1] >> 4), &mut n)?;
        }
        _ => {
            if padded || quad[2] & 0x03 != 0 {
                return Err(err);
            }
            put((quad[0] << 2) | (quad[1] >> 4), &mut n)?;
            put((quad[1] << 4) | (quad[2] >> 2), &mut n)?;
        }
    }
    Ok(n)
}

/// Decode raw base64: alphabet only, no `=`, `len % 4 != 1`, zero unused
/// trailing bits. A violation is `err`; a short `out` is `BufferTooSmall`.
/// Returns the decoded length.
pub fn decode_nopad(input: &[u8], out: &mut [u8], err: Error) -> Result<usize, Error> {
    decode_core(input.iter().copied(), Some(out), false, err)
}

/// [`decode_nopad`] without writing (grease bodies are validated but never
/// decoded). Returns the decoded length.
pub fn validate_nopad(input: &[u8], err: Error) -> Result<usize, Error> {
    decode_core(input.iter().copied(), None, false, err)
}

/// [`decode_nopad`] over a stanza body: the `\n` line separators are
/// skipped, every other byte is subject to the raw rules.
pub(crate) fn decode_nopad_lines(input: &[u8], out: &mut [u8], err: Error) -> Result<usize, Error> {
    decode_core(
        input.iter().copied().filter(|&c| c != b'\n'),
        Some(out),
        false,
        err,
    )
}

/// [`validate_nopad`] over a stanza body (`\n` separators skipped).
pub(crate) fn decode_nopad_lines_validate(input: &[u8], err: Error) -> Result<usize, Error> {
    decode_core(
        input.iter().copied().filter(|&c| c != b'\n'),
        None,
        false,
        err,
    )
}

/// Decode padded base64: `len % 4 == 0`, `=` only as the final one or two
/// characters, zero unused trailing bits. A violation is `err`; a short
/// `out` is `BufferTooSmall`. Returns the decoded length.
pub fn decode_pad(input: &[u8], out: &mut [u8], err: Error) -> Result<usize, Error> {
    decode_core(input.iter().copied(), Some(out), true, err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ArmorError, HeaderError};

    const HERR: Error = Error::Header(HeaderError::BadBase64);
    const AERR: Error = Error::Armor(ArmorError::BadBase64);

    #[test]
    fn lengths() {
        for (n, nopad, pad) in [
            (0, 0, 0),
            (1, 2, 4),
            (2, 3, 4),
            (3, 4, 4),
            (4, 6, 8),
            (16, 22, 24),
            (32, 43, 44),
            (48, 64, 64),
        ] {
            assert_eq!(encoded_len_nopad(n), nopad, "n = {n}");
            assert_eq!(encoded_len_pad(n), pad, "n = {n}");
            assert_eq!(decoded_len_nopad(nopad), Some(n), "n = {n}");
        }
        assert_eq!(decoded_len_nopad(1), None);
        assert_eq!(decoded_len_nopad(5), None);
    }

    #[test]
    fn rfc4648_vectors_nopad() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"f", b"Zg"),
            (b"fo", b"Zm8"),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg"),
            (b"fooba", b"Zm9vYmE"),
            (b"foobar", b"Zm9vYmFy"),
        ];
        for (raw, enc) in cases {
            let mut out = [0u8; 16];
            let n = encode_nopad(raw, &mut out).unwrap();
            assert_eq!(&out[..n], *enc);
            let mut dec = [0u8; 16];
            let m = decode_nopad(enc, &mut dec, HERR).unwrap();
            assert_eq!(&dec[..m], *raw);
            assert_eq!(validate_nopad(enc, HERR).unwrap(), raw.len());
        }
    }

    #[test]
    fn rfc4648_vectors_pad() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"f", b"Zg=="),
            (b"fo", b"Zm8="),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg=="),
            (b"fooba", b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ];
        for (raw, enc) in cases {
            let mut out = [0u8; 16];
            let n = encode_pad(raw, &mut out).unwrap();
            assert_eq!(&out[..n], *enc);
            let mut dec = [0u8; 16];
            let m = decode_pad(enc, &mut dec, AERR).unwrap();
            assert_eq!(&dec[..m], *raw);
        }
    }

    #[test]
    fn nopad_rejections() {
        let mut out = [0u8; 16];
        for bad in [
            &b"Zg=="[..],
            b"Zm8=",
            b"Z",
            b"Zm9vY",
            b"Zh",  // low 4 bits of 'h' (33 = 0b100001) non-zero
            b"Zm9", // low 2 bits of '9' (61 = 0b111101) non-zero
            b"Zm\r8",
            b"Zm 8",
            b"Zm\n8",
            b"Zm*8",
            b"====",
        ] {
            assert_eq!(decode_nopad(bad, &mut out, HERR), Err(HERR), "{bad:?}");
            assert_eq!(validate_nopad(bad, HERR), Err(HERR), "{bad:?}");
        }
    }

    #[test]
    fn pad_rejections() {
        let mut out = [0u8; 16];
        for bad in [
            &b"Zg"[..],
            b"Zm8",
            b"Zg=",
            b"Z===",
            b"Zg==Zg==",
            b"Zh==",
            b"Zm9=",
            b"Zm=8",
            b"=m9v",
            b"Zm9v\r",
            b"Zm9v\n",
            b"Zm9v ",
        ] {
            assert_eq!(decode_pad(bad, &mut out, AERR), Err(AERR), "{bad:?}");
        }
    }

    #[test]
    fn buffer_too_small_is_distinct_from_bad_base64() {
        let mut out = [0u8; 2];
        assert_eq!(
            decode_nopad(b"Zm9v", &mut out, HERR),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            decode_pad(b"Zm9v", &mut out, AERR),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(encode_nopad(b"foo", &mut out), Err(Error::BufferTooSmall));
        assert_eq!(encode_pad(b"f", &mut out), Err(Error::BufferTooSmall));
    }

    #[test]
    fn lines_variant_skips_newlines_only() {
        let mut out = [0u8; 16];
        let n = decode_nopad_lines(b"Zm9v\nYmFy\n", &mut out, HERR).unwrap();
        assert_eq!(&out[..n], b"foobar");
        assert_eq!(
            decode_nopad_lines(b"Zm9v\r\nYmFy", &mut out, HERR),
            Err(HERR)
        );
    }

    #[test]
    fn wrapped_encoding_breaks_after_full_lines_only() {
        let mut out = [0u8; 80];
        let n = encode_wrapped(&[0u8; 48], &mut out, false, 64).unwrap();
        assert_eq!(n, 65);
        assert_eq!(out[64], b'\n');
        let n = encode_wrapped(&[0u8; 3], &mut out, false, 64).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&out[..4], b"AAAA");
    }

    #[test]
    fn alphabet() {
        assert!(is_alphabet(b'A'));
        assert!(is_alphabet(b'/'));
        assert!(!is_alphabet(b'='));
        assert!(!is_alphabet(b'-'));
        assert!(!is_alphabet(b' '));
    }
}
