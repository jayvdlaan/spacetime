//! Bech32 (BIP-173, **not** bech32m) for the age key strings `age1…` and
//! `AGE-SECRET-KEY-1…`.
//!
//! No 90-character limit is enforced (age does not enforce one either); the
//! payload is fixed-size by the callers in `keys.rs`. Written in-crate so the
//! published dependency graph stays `spacetime-crypto` only.

use crate::error::{Error, KeyError};

/// The bech32 data alphabet.
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

const fn bech32_err() -> Error {
    Error::Key(KeyError::Bech32)
}

/// Streaming BIP-173 polymod.
struct Polymod(u32);

impl Polymod {
    const fn new() -> Self {
        Self(1)
    }

    fn feed(&mut self, v: u8) {
        let b = self.0 >> 25;
        self.0 = ((self.0 & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GENERATOR.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                self.0 ^= g;
            }
        }
    }

    /// Feed the HRP expansion of `hrp` (already lowercase).
    fn feed_hrp<I: Iterator<Item = u8> + Clone>(&mut self, hrp: I) {
        for c in hrp.clone() {
            self.feed(c >> 5);
        }
        self.feed(0);
        for c in hrp {
            self.feed(c & 31);
        }
    }
}

/// Value of one data character (case-insensitive), or `None`.
fn char_value(c: u8) -> Option<u8> {
    let lc = c.to_ascii_lowercase();
    CHARSET.iter().position(|&x| x == lc).map(|p| p as u8)
}

/// Encoded length: `hrp + 1 + ceil(8 * data / 5) + 6`.
pub const fn encoded_len(hrp_len: usize, data_len: usize) -> usize {
    hrp_len + 1 + (8 * data_len).div_ceil(5) + 6
}

/// Encode `data` (any length) as lowercase `hrp || '1' || data || checksum`
/// into `out`. `hrp` must be lowercase ASCII in `0x21..=0x7E` (the callers
/// pass constants; a violation is `Key(Bech32)`). Returns the length
/// written; `BufferTooSmall` if `out` is too short.
pub fn encode(hrp: &str, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let hrp = hrp.as_bytes();
    if hrp.is_empty()
        || hrp
            .iter()
            .any(|&c| !(0x21..=0x7e).contains(&c) || c.is_ascii_uppercase())
    {
        return Err(bech32_err());
    }
    let total = encoded_len(hrp.len(), data.len());
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    let mut pos = 0usize;
    out[..hrp.len()].copy_from_slice(hrp);
    pos += hrp.len();
    out[pos] = b'1';
    pos += 1;

    let mut chk = Polymod::new();
    chk.feed_hrp(hrp.iter().copied());

    // 8 -> 5 bit regrouping, padded with zero bits.
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let v = ((acc >> bits) & 31) as u8;
            chk.feed(v);
            out[pos] = CHARSET[v as usize];
            pos += 1;
        }
    }
    if bits > 0 {
        let v = ((acc << (5 - bits)) & 31) as u8;
        chk.feed(v);
        out[pos] = CHARSET[v as usize];
        pos += 1;
    }
    for _ in 0..6 {
        chk.feed(0);
    }
    let pm = chk.0 ^ 1;
    for i in 0..6 {
        let v = ((pm >> (5 * (5 - i))) & 31) as u8;
        out[pos] = CHARSET[v as usize];
        pos += 1;
    }
    debug_assert_eq!(pos, total);
    Ok(pos)
}

/// Decode `s` into `out`: all-lowercase or all-uppercase (else
/// `Key(Bech32)`); the last `1` is the separator (≥ 1 HRP character, ≥ 6
/// data characters); the checksum must verify; leftover bits must be fewer
/// than 5 and zero. Returns `(hrp_len, decoded_len)`; the HRP is
/// `&s[..hrp_len]` (compare it ASCII-lowercased). `BufferTooSmall` if `out`
/// cannot hold the payload.
pub fn decode(s: &str, out: &mut [u8]) -> Result<(usize, usize), Error> {
    let b = s.as_bytes();
    let has_lower = b.iter().any(u8::is_ascii_lowercase);
    let has_upper = b.iter().any(u8::is_ascii_uppercase);
    if has_lower && has_upper {
        return Err(bech32_err());
    }
    let sep = b.iter().rposition(|&c| c == b'1').ok_or(bech32_err())?;
    if sep < 1 || b.len() - sep - 1 < 6 {
        return Err(bech32_err());
    }
    let hrp = &b[..sep];
    if hrp.iter().any(|&c| !(0x21..=0x7e).contains(&c)) {
        return Err(bech32_err());
    }
    let data = &b[sep + 1..];

    let mut chk = Polymod::new();
    chk.feed_hrp(hrp.iter().map(u8::to_ascii_lowercase));
    for &c in data {
        chk.feed(char_value(c).ok_or(bech32_err())?);
    }
    if chk.0 != 1 {
        return Err(bech32_err());
    }

    // 5 -> 8 bit regrouping without padding.
    let payload = &data[..data.len() - 6];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut n = 0usize;
    for &c in payload {
        // Validated above; `0` can never be reached.
        let v = char_value(c).unwrap_or(0);
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if n >= out.len() {
                return Err(Error::BufferTooSmall);
            }
            out[n] = ((acc >> bits) & 0xff) as u8;
            n += 1;
        }
    }
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return Err(bech32_err());
    }
    Ok((sep, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [
        0x21, 0x8b, 0x82, 0x33, 0x44, 0xbf, 0x92, 0xd0, 0x80, 0xa6, 0x30, 0x6b, 0x95, 0x2d, 0x7e,
        0x5e, 0x8d, 0x09, 0x38, 0x1a, 0xf6, 0x3e, 0xcc, 0xd7, 0x13, 0x45, 0x09, 0x81, 0x51, 0xa5,
        0x9f, 0xbc,
    ];
    const PUBLIC: [u8; 32] = [
        0xa3, 0xb3, 0x2e, 0xd0, 0x10, 0x64, 0x18, 0x5e, 0x2c, 0x60, 0x25, 0xb3, 0x49, 0x8b, 0xaf,
        0x3b, 0x37, 0xdf, 0xc1, 0x5f, 0x27, 0xe1, 0xe8, 0xce, 0x8c, 0xf5, 0xfe, 0xb4, 0xda, 0xba,
        0xde, 0x01,
    ];
    const IDENTITY: &str =
        "AGE-SECRET-KEY-1YX9CYV6YH7FDPQ9XXP4E2TT7T6XSJWQ67CLVE4CNG5YCZ5D9N77QZ8EEGV";
    const RECIPIENT: &str = "age15weja5qsvsv9utrqyke5nza08vmals2lyls73n5v7hltfk46mcqsy3c60l";

    #[test]
    fn encoded_len_matches_the_key_strings() {
        assert_eq!(encoded_len(3, 32), 62);
        assert_eq!(encoded_len(15, 32), 74);
    }

    #[test]
    fn encode_known_keys() {
        let mut out = [0u8; 80];
        let n = encode("age", &PUBLIC, &mut out).unwrap();
        assert_eq!(&out[..n], RECIPIENT.as_bytes());
        let n = encode("age-secret-key-", &SECRET, &mut out).unwrap();
        out[..n].make_ascii_uppercase();
        assert_eq!(&out[..n], IDENTITY.as_bytes());
    }

    #[test]
    fn decode_known_keys_both_cases() {
        let mut out = [0u8; 32];
        let (h, n) = decode(RECIPIENT, &mut out).unwrap();
        assert_eq!((h, n), (3, 32));
        assert_eq!(out, PUBLIC);
        let (h, n) = decode(IDENTITY, &mut out).unwrap();
        assert_eq!((h, n), (15, 32));
        assert_eq!(out, SECRET);
        let upper = RECIPIENT.to_ascii_uppercase();
        assert_eq!(decode(&upper, &mut out).unwrap(), (3, 32));
        assert_eq!(out, PUBLIC);
    }

    #[test]
    fn rejections() {
        let mut out = [0u8; 32];
        let err = Error::Key(KeyError::Bech32);
        // mixed case
        let mut s = alloc_free_copy(RECIPIENT);
        s[5] = s[5].to_ascii_uppercase();
        assert_eq!(
            decode(core::str::from_utf8(&s).unwrap(), &mut out),
            Err(err)
        );
        // bad checksum
        let mut s = alloc_free_copy(RECIPIENT);
        s[61] = if s[61] == b'l' { b'q' } else { b'l' };
        assert_eq!(
            decode(core::str::from_utf8(&s).unwrap(), &mut out),
            Err(err)
        );
        // no separator / too short
        assert_eq!(decode("age", &mut out), Err(err));
        assert_eq!(decode("1qqqqqq", &mut out), Err(err));
        assert_eq!(decode("age1qqq", &mut out), Err(err));
        // non-charset byte
        let mut s = alloc_free_copy(RECIPIENT);
        s[10] = b'b';
        assert_eq!(
            decode(core::str::from_utf8(&s).unwrap(), &mut out),
            Err(err)
        );
        // uppercase HRP on encode
        assert_eq!(encode("AGE", &PUBLIC, &mut [0u8; 80]), Err(err));
        // short buffer
        assert_eq!(
            encode("age", &PUBLIC, &mut [0u8; 61]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            decode(RECIPIENT, &mut [0u8; 31]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn bip173_reference_strings() {
        // Valid strings from BIP-173 (checksum only; payloads are not 32 bytes).
        let mut out = [0u8; 64];
        assert!(decode("A12UEL5L", &mut out).is_ok());
        assert!(decode("a12uel5l", &mut out).is_ok());
        assert!(decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", &mut out).is_ok());
        // Invalid: bad padding / non-zero padding bits.
        assert!(decode("A1G7SGD8", &mut out).is_err());
    }

    #[test]
    fn round_trip_odd_lengths() {
        for len in [0usize, 1, 2, 5, 31, 33] {
            let data = [0x5Au8; 33];
            let mut enc = [0u8; 80];
            let n = encode("t", &data[..len], &mut enc).unwrap();
            let s = core::str::from_utf8(&enc[..n]).unwrap();
            let mut dec = [0u8; 33];
            let (h, m) = decode(s, &mut dec).unwrap();
            assert_eq!((h, m), (1, len));
            assert_eq!(&dec[..m], &data[..len]);
        }
    }

    fn alloc_free_copy(s: &str) -> [u8; 62] {
        let mut b = [0u8; 62];
        b.copy_from_slice(s.as_bytes());
        b
    }
}
