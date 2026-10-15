//! RFC test vectors as data (feature `conformance`).
//!
//! Everything in this module is a literal transcribed from the cited RFC
//! (or, for the Ed25519 negatives, derived from RFC 8032 data by the
//! construction documented on each entry). No cryptography runs here and no
//! cryptography crate was used to generate or check any value: the vectors
//! are hex strings decoded at compile time by the zero-dependency
//! [`hex`] helper, so a transcription typo of the wrong length or with a
//! non-hex character is a build error rather than a silently wrong vector.
//!
//! Each vector carries a `name` (used in harness error messages) and, where
//! it comes straight from a specification, a `source` naming the section.

use crate::kdf::Argon2Params;

/// Decode a hex string into a fixed-size byte array at compile time.
///
/// Panics (at compile time, when used in a `const`/`static` initializer) if
/// `s` is not exactly `2 * N` hex digits.
pub const fn hex<const N: usize>(s: &str) -> [u8; N] {
    let bytes = s.as_bytes();
    assert!(
        bytes.len() == 2 * N,
        "hex literal has the wrong length for its declared size"
    );
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("hex literal contains a non-hex character"),
    }
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/// A one-message digest vector with an `N`-byte digest.
#[derive(Debug)]
pub struct DigestVector<const N: usize> {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// Specification section the vector comes from.
    pub source: &'static str,
    /// Message to digest.
    pub message: &'static [u8],
    /// Expected digest.
    pub digest: [u8; N],
}

/// SHA-256 vectors: the FIPS 180-4 / RFC 6234 examples for `""`, `"abc"`
/// and the 56-byte two-block message. (The one-million-`a` example is
/// omitted: it is too slow for the embedded targets this harness must run
/// on.)
pub static SHA256: &[DigestVector<32>] = &[
    DigestVector {
        name: "SHA-256 empty message",
        source: "RFC 6234 §8.5 / FIPS 180-4",
        message: b"",
        digest: hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    },
    DigestVector {
        name: "SHA-256 \"abc\"",
        source: "FIPS 180-4 example (RFC 6234 §8.5)",
        message: b"abc",
        digest: hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    },
    DigestVector {
        name: "SHA-256 56-byte two-block message",
        source: "FIPS 180-4 example (RFC 6234 §8.5)",
        message: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        digest: hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    },
];

/// SHA-512 vectors: the FIPS 180-4 examples for `""`, `"abc"` and the
/// 112-byte two-block message. `SHA-512("abc")` is also the message of the
/// RFC 8032 §7.1 "TEST SHA(abc)" Ed25519 vector.
pub static SHA512: &[DigestVector<64>] = &[
    DigestVector {
        name: "SHA-512 empty message",
        source: "FIPS 180-4",
        message: b"",
        digest: hex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
    },
    DigestVector {
        name: "SHA-512 \"abc\"",
        source: "FIPS 180-4 example",
        message: b"abc",
        digest: hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    },
    DigestVector {
        name: "SHA-512 112-byte two-block message",
        source: "FIPS 180-4 example",
        message: b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                   ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        digest: hex(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
    },
];

// ---------------------------------------------------------------------------
// HMAC-SHA-256 (RFC 4231)
// ---------------------------------------------------------------------------

/// An HMAC-SHA-256 vector.
#[derive(Debug)]
pub struct HmacSha256Vector {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// Specification section the vector comes from.
    pub source: &'static str,
    /// MAC key (any length).
    pub key: &'static [u8],
    /// Message.
    pub data: &'static [u8],
    /// Expected full-length tag.
    pub mac: [u8; 32],
}

/// RFC 4231 test cases 1–4, 6 and 7 (the SHA-256 column). Test case 5 is a
/// truncated-tag case and does not apply to this facade.
pub static HMAC_SHA256: &[HmacSha256Vector] = &[
    HmacSha256Vector {
        name: "HMAC-SHA-256 RFC 4231 test case 1",
        source: "RFC 4231 §4.2",
        key: &[0x0b; 20],
        data: b"Hi There",
        mac: hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    },
    HmacSha256Vector {
        name: "HMAC-SHA-256 RFC 4231 test case 2",
        source: "RFC 4231 §4.3",
        key: b"Jefe",
        data: b"what do ya want for nothing?",
        mac: hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    },
    HmacSha256Vector {
        name: "HMAC-SHA-256 RFC 4231 test case 3",
        source: "RFC 4231 §4.4",
        key: &[0xaa; 20],
        data: &[0xdd; 50],
        mac: hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    },
    HmacSha256Vector {
        name: "HMAC-SHA-256 RFC 4231 test case 4",
        source: "RFC 4231 §4.5",
        key: &hex::<25>("0102030405060708090a0b0c0d0e0f10111213141516171819"),
        data: &[0xcd; 50],
        mac: hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    },
    HmacSha256Vector {
        name: "HMAC-SHA-256 RFC 4231 test case 6",
        source: "RFC 4231 §4.7",
        key: &[0xaa; 131],
        data: b"Test Using Larger Than Block-Size Key - Hash Key First",
        mac: hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    },
    HmacSha256Vector {
        name: "HMAC-SHA-256 RFC 4231 test case 7",
        source: "RFC 4231 §4.8",
        key: &[0xaa; 131],
        data: b"This is a test using a larger than block-size key and a larger than \
                block-size data. The key needs to be hashed before being used by \
                the HMAC algorithm.",
        mac: hex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    },
];

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032)
// ---------------------------------------------------------------------------

/// An RFC 8032 Ed25519 (pure, no context) positive vector.
#[derive(Debug)]
pub struct Ed25519Vector {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// Specification section the vector comes from.
    pub source: &'static str,
    /// 32-byte private seed.
    pub seed: [u8; 32],
    /// Public key derived from `seed`.
    pub public_key: [u8; 32],
    /// Signed message.
    pub message: &'static [u8],
    /// `R || S` signature of `message` under `seed`.
    pub signature: [u8; 64],
}

/// RFC 8032 §7.1 TEST 1, TEST 2, TEST 3 and TEST SHA(abc).
pub static ED25519: &[Ed25519Vector] = &[
    Ed25519Vector {
        name: "Ed25519 RFC 8032 TEST 1",
        source: "RFC 8032 §7.1",
        seed: hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        public_key: hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        message: b"",
        signature: hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
    },
    Ed25519Vector {
        name: "Ed25519 RFC 8032 TEST 2",
        source: "RFC 8032 §7.1",
        seed: hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
        public_key: hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        message: &[0x72],
        signature: hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    },
    Ed25519Vector {
        name: "Ed25519 RFC 8032 TEST 3",
        source: "RFC 8032 §7.1",
        seed: hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
        public_key: hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
        message: &[0xaf, 0x82],
        signature: hex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    },
    Ed25519Vector {
        name: "Ed25519 RFC 8032 TEST SHA(abc)",
        source: "RFC 8032 §7.1",
        seed: hex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"),
        public_key: hex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
        // The message is SHA-512("abc"); see `SHA512[1]`.
        message: &hex::<64>(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        signature: hex(
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
             09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    },
];

/// An `(A, message, signature)` triple that a strict verifier MUST reject
/// with `AuthenticationFailed`.
#[derive(Debug)]
pub struct Ed25519RejectVector {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// Why a strict verifier rejects it, and which lax verifiers accept it.
    pub reason: &'static str,
    /// Public key (possibly malformed on purpose).
    pub public_key: [u8; 32],
    /// Message.
    pub message: &'static [u8],
    /// `R || S` (possibly malformed on purpose).
    pub signature: [u8; 64],
}

/// The order-8 torsion point `T8` (libsodium's blocklist entry), canonical
/// encoding.
const T8: [u8; 32] = hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");

/// The public key of RFC 8032 §7.1 TEST 1 (`A₁`).
const A1: [u8; 32] = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

/// `A₁ + T8`: canonical and not small-order, but not torsion-free (mixed
/// order). Rejected at import; used by NEG-6 to isolate the small-order
/// check on `R`.
const A1_PLUS_T8: [u8; 32] =
    hex("9158312a9a8d6e3b34c891d6d61444f8b8211c5117ebad15bdb0bd68b07e0245");

/// Negative Ed25519 vectors separating a strict verifier (the facade
/// contract: `ed25519-dalek`'s `verify_strict`) from lax ones.
///
/// Notation: `L` is the group order, `A₁`/`a₁` the RFC 8032 TEST 1 public
/// key / clamped secret scalar, `T8` the order-8 point above, `B` the base
/// point. Every derived value can be recomputed with the RFC 8032 §6
/// reference code; the constructions are spelled out per entry.
pub static ED25519_REJECT: &[Ed25519RejectVector] = &[
    // A = R = T8 (both small-order), S = 0, message = 0x0a. The message was
    // chosen so that k = SHA-512(R || A || msg) mod L satisfies
    // k + 1 ≡ 0 (mod 8); then [0]B = O = T8 + [k]T8 = [k+1]T8 and the
    // equation holds for any verifier that skips the small-order check
    // (dalek's non-strict `verify` and cofactored verifiers accept it).
    Ed25519RejectVector {
        name: "Ed25519 NEG-1 small-order A and R",
        reason: "small-order public key and R point (rule V4)",
        public_key: T8,
        message: &[0x0a],
        signature: hex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a\
             0000000000000000000000000000000000000000000000000000000000000000",
        ),
    },
    // TEST 1 with S' = S + L. The top three bits of S' are still clear, so
    // the legacy `s[31] & 0xe0` check passes; any verifier that reduces S
    // mod L before use accepts it.
    Ed25519RejectVector {
        name: "Ed25519 NEG-2 non-canonical S = S + L",
        reason: "S >= L (rule V1)",
        public_key: A1,
        message: b"",
        signature: hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             4c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b",
        ),
    },
    // R' = ee ff..ff ff: y = p + 1 with the sign bit set — an RFC 8032
    // §5.1.3 decoding failure (y >= p, and x = 0 with sign bit 1) that a lax
    // decoder reduces to the identity. S = k · a₁ mod L with
    // k = SHA-512(R' || A₁ || "") mod L, so [S]B = O + [k]A₁ holds for any
    // decoder that reduces R'. Also rejected by V4 (identity is small-order).
    Ed25519RejectVector {
        name: "Ed25519 NEG-3 non-canonical R, sign bit set",
        reason: "non-canonical R encoding, y = p + 1 with sign bit set (rule V2; also V4)",
        public_key: A1,
        message: b"",
        signature: hex(
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             004280bc94ccbf33ae57c0ca637b326bb3c77fe5fd5dac48f8f091ca7820b408",
        ),
    },
    // Same construction with R' = ee ff..ff 7f (y = p + 1, sign bit clear).
    Ed25519RejectVector {
        name: "Ed25519 NEG-3b non-canonical R, sign bit clear",
        reason: "non-canonical R encoding, y = p + 1 (rule V2; also V4)",
        public_key: A1,
        message: b"",
        signature: hex(
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f\
             3fdd9411ef77c7b937c975b1193128983db0482a002663080c0dd63cf3466c06",
        ),
    },
    // A' = ee ff..ff 7f (y = p + 1, reduces to the identity under a lax
    // decoder), R = B, S = 1: [1]B = B + [k]O for any decoder that reduces
    // A'. dalek's non-strict `verify` accepts it. Also rejected by V4.
    Ed25519RejectVector {
        name: "Ed25519 NEG-4 non-canonical A",
        reason: "non-canonical public key encoding, y = p + 1 (rule V3; also V4)",
        public_key: hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        message: b"",
        signature: hex(
            "5866666666666666666666666666666666666666666666666666666666666666\
             0100000000000000000000000000000000000000000000000000000000000000",
        ),
    },
    // TEST 2's key and signature over TEST 3's message: canonical inputs,
    // the equation simply does not hold.
    Ed25519RejectVector {
        name: "Ed25519 NEG-5 equation failure with canonical inputs",
        reason: "valid encodings, wrong message (rule V6)",
        public_key: hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        message: &[0xaf, 0x82],
        signature: hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    },
    // Isolates the small-order check on R. With an honest (prime-order) A a
    // small-order R is already killed by the cofactorless equation, so the
    // only way to observe V4-on-R is a mixed-order key: A' = A₁ + T8
    // (canonical, not small-order — the `ED25519_INVALID_PUBLIC_KEYS`
    // mixed-order row), R = T8, message = 0x08 chosen so that
    // k = SHA-512(R || A' || msg) mod L satisfies k ≡ 7 (mod 8), and
    // S = k · a₁ mod L. Then [S]B = [k]A₁ = R + [k]A' because
    // [k+1]T8 = O, so a verifier that applies the small-order check to A
    // only accepts it, as does a cofactored (ZIP-215-style) verifier; a
    // strict verifier rejects R = T8 outright.
    Ed25519RejectVector {
        name: "Ed25519 NEG-6 small-order R with mixed-order A",
        reason: "small-order R point under a mixed-order public key (rule V4 on R)",
        public_key: A1_PLUS_T8,
        message: &[0x08],
        signature: hex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a\
             0e92a1e23fae5a4011d6ea494d698cf56026bea8225f9a059772a7f0d8a6650c",
        ),
    },
];

/// A 32-byte key with a documented property.
#[derive(Debug)]
pub struct KeyVector {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// The property that makes this key interesting.
    pub property: &'static str,
    /// The key bytes.
    pub key: [u8; 32],
}

/// Public keys that `Ed25519Verify::ed25519_validate_public_key` MUST reject
/// with `InvalidParameter`: the eight canonical torsion encodings (identity,
/// the order-2 point, two order-4 and four order-8 points — the complete
/// set), four non-canonical encodings, and one canonical mixed-order point.
/// Little-endian compressed encodings; the sign bit is bit 255.
pub static ED25519_INVALID_PUBLIC_KEYS: &[KeyVector] = &[
    KeyVector {
        name: "Ed25519 identity point",
        property: "identity (order 1)",
        key: hex("0100000000000000000000000000000000000000000000000000000000000000"),
    },
    KeyVector {
        name: "Ed25519 order-2 point (y = -1)",
        property: "y = -1, order 2",
        key: hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    },
    KeyVector {
        name: "Ed25519 order-4 point (y = 0)",
        property: "y = 0, order 4",
        key: hex("0000000000000000000000000000000000000000000000000000000000000000"),
    },
    KeyVector {
        name: "Ed25519 order-4 point (y = 0, negated x)",
        property: "y = 0, negated x, order 4",
        key: hex("0000000000000000000000000000000000000000000000000000000000000080"),
    },
    KeyVector {
        name: "Ed25519 order-8 point T8",
        property: "order 8 (libsodium blocklist entry)",
        key: T8,
    },
    KeyVector {
        name: "Ed25519 order-8 point -T8",
        property: "order 8",
        key: hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    },
    KeyVector {
        name: "Ed25519 order-8 point (second pair, positive x)",
        property: "order 8",
        key: hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    },
    KeyVector {
        name: "Ed25519 order-8 point (second pair, negative x)",
        property: "order 8",
        key: hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    },
    KeyVector {
        name: "Ed25519 non-canonical y = p",
        property: "y = p (non-canonical; a lax decoder reduces it to an order-4 point)",
        key: hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    },
    KeyVector {
        name: "Ed25519 non-canonical y = p, sign bit set",
        property: "y = p with sign bit set (non-canonical; reduces to an order-4 point)",
        key: hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    },
    KeyVector {
        name: "Ed25519 non-canonical y = p + 1",
        property: "y = p + 1 (non-canonical identity)",
        key: hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    },
    KeyVector {
        name: "Ed25519 non-canonical y = p + 1, sign bit set",
        property: "y = p + 1 with x = 0 and the sign bit set (RFC 8032 §5.1.3 decoding failure)",
        key: hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    },
    KeyVector {
        name: "Ed25519 mixed-order point A1 + T8",
        property: "canonical, not small-order, NOT torsion-free (prime-order part plus T8)",
        key: A1_PLUS_T8,
    },
];

/// An Ed25519 public key with its X25519 (Montgomery `u`) form.
#[derive(Debug)]
pub struct Ed25519ToX25519Vector {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// Where the key comes from and how `u` was computed.
    pub source: &'static str,
    /// The compressed Edwards public key `A`.
    pub public_key: [u8; 32],
    /// The little-endian Montgomery `u`-coordinate of the same point.
    pub x25519_public: [u8; 32],
}

/// RFC 8032 §7.1 public keys and their Montgomery `u = (1+y)/(1−y) mod p`.
/// Each `u` was computed two independent ways by the contract author
/// (pure-integer field arithmetic on the decoded `y`, and
/// `X25519(clamp(SHA-512(seed)[0..32]), 9)` with a pure-Python RFC 7748 ladder).
pub static ED25519_TO_X25519: &[Ed25519ToX25519Vector] = &[
    Ed25519ToX25519Vector {
        name: "Ed25519→X25519 RFC 8032 TEST 1",
        source: "RFC 8032 §7.1 TEST 1 public key; u computed per RFC 7748 §4.1",
        public_key: hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        x25519_public: hex("d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e"),
    },
    Ed25519ToX25519Vector {
        name: "Ed25519→X25519 RFC 8032 TEST 2",
        source: "RFC 8032 §7.1 TEST 2",
        public_key: hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        x25519_public: hex("25c704c594b88afc00a76b69d1ed2b984d7e22550f3ed0802d04fbcd07d38d47"),
    },
    Ed25519ToX25519Vector {
        name: "Ed25519→X25519 RFC 8032 TEST 3",
        source: "RFC 8032 §7.1 TEST 3",
        public_key: hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
        x25519_public: hex("cbb22fc9f790bd3eba9b84680c157ca4950a9894362601701f89c3c4d9fda23a"),
    },
    Ed25519ToX25519Vector {
        name: "Ed25519→X25519 RFC 8032 TEST SHA(abc)",
        source: "RFC 8032 §7.1 TEST SHA(abc)",
        public_key: hex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
        x25519_public: hex("d5948dca7a9ad7175303dc6881c34aa7881fb946ee34dfd8fab126ed6db8da69"),
    },
];

// ---------------------------------------------------------------------------
// AEAD (RFC 8439 / draft-irtf-cfrg-xchacha-03)
// ---------------------------------------------------------------------------

/// An AEAD vector with an `NONCE_LEN`-byte nonce.
#[derive(Debug)]
pub struct AeadVector<const NONCE_LEN: usize> {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// Specification section the vector comes from.
    pub source: &'static str,
    /// 32-byte key.
    pub key: [u8; 32],
    /// Nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Additional authenticated data.
    pub aad: &'static [u8],
    /// Plaintext.
    pub plaintext: &'static [u8],
    /// Ciphertext (same length as `plaintext`).
    pub ciphertext: &'static [u8],
    /// 16-byte authentication tag.
    pub tag: [u8; 16],
}

/// Key shared by the RFC 8439 §2.8.2 and draft-irtf-cfrg-xchacha-03 §A.3.1
/// vectors: the bytes `0x80..=0x9f`.
const AEAD_KEY: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");

/// AAD shared by both AEAD vectors.
const AEAD_AAD: [u8; 12] = hex("50515253c0c1c2c3c4c5c6c7");

/// The 114-byte plaintext shared by both AEAD vectors.
const AEAD_PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                                only one tip for the future, sunscreen would be it.";

/// RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 vector.
pub static CHACHA20POLY1305: &[AeadVector<12>] = &[AeadVector {
    name: "ChaCha20-Poly1305 RFC 8439 §2.8.2",
    source: "RFC 8439 §2.8.2",
    key: AEAD_KEY,
    nonce: hex("070000004041424344454647"),
    aad: &AEAD_AAD,
    plaintext: AEAD_PLAINTEXT,
    ciphertext: &hex::<114>(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116",
    ),
    tag: hex("1ae10b594f09e26a7e902ecbd0600691"),
}];

/// draft-irtf-cfrg-xchacha-03 §A.3.1 AEAD_XCHACHA20_POLY1305 vector (same
/// key, AAD and plaintext as RFC 8439 §2.8.2; 24-byte nonce).
pub static XCHACHA20POLY1305: &[AeadVector<24>] = &[AeadVector {
    name: "XChaCha20-Poly1305 draft-irtf-cfrg-xchacha-03 §A.3.1",
    source: "draft-irtf-cfrg-xchacha-03 §A.3.1",
    key: AEAD_KEY,
    nonce: hex("404142434445464748494a4b4c4d4e4f5051525354555657"),
    aad: &AEAD_AAD,
    plaintext: AEAD_PLAINTEXT,
    ciphertext: &hex::<114>(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
         21f9664c97637da9768812f615c68b13b52e",
    ),
    tag: hex("c0875924c1c7987947deafd8780acf49"),
}];

// ---------------------------------------------------------------------------
// HKDF-SHA-256 (RFC 5869)
// ---------------------------------------------------------------------------

/// An HKDF-SHA-256 vector.
#[derive(Debug)]
pub struct HkdfSha256Vector {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// Specification section the vector comes from.
    pub source: &'static str,
    /// Input keying material.
    pub ikm: &'static [u8],
    /// Salt (empty = "not provided").
    pub salt: &'static [u8],
    /// Context/application info.
    pub info: &'static [u8],
    /// Expected pseudorandom key from `extract`.
    pub prk: [u8; 32],
    /// Expected output keying material from `expand` (its length is `L`).
    pub okm: &'static [u8],
}

/// RFC 5869 Appendix A test cases 1–3 (the SHA-256 cases).
pub static HKDF_SHA256: &[HkdfSha256Vector] = &[
    HkdfSha256Vector {
        name: "HKDF-SHA-256 RFC 5869 A.1",
        source: "RFC 5869 A.1",
        ikm: &[0x0b; 22],
        salt: &hex::<13>("000102030405060708090a0b0c"),
        info: &hex::<10>("f0f1f2f3f4f5f6f7f8f9"),
        prk: hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        okm: &hex::<42>(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        ),
    },
    HkdfSha256Vector {
        name: "HKDF-SHA-256 RFC 5869 A.2",
        source: "RFC 5869 A.2",
        ikm: &hex::<80>(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        ),
        salt: &hex::<80>(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        ),
        info: &hex::<80>(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ),
        prk: hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
        okm: &hex::<82>(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
    },
    HkdfSha256Vector {
        name: "HKDF-SHA-256 RFC 5869 A.3",
        source: "RFC 5869 A.3",
        ikm: &[0x0b; 22],
        salt: b"",
        info: b"",
        prk: hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
        okm: &hex::<42>(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        ),
    },
];

// ---------------------------------------------------------------------------
// X25519 (RFC 7748)
// ---------------------------------------------------------------------------

/// An X25519 Diffie–Hellman vector.
#[derive(Debug)]
pub struct X25519Vector {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// Specification section the vector comes from.
    pub source: &'static str,
    /// Alice's private key.
    pub alice_secret: [u8; 32],
    /// Alice's public key (`X25519(alice_secret, 9)`).
    pub alice_public: [u8; 32],
    /// Bob's private key.
    pub bob_secret: [u8; 32],
    /// Bob's public key.
    pub bob_public: [u8; 32],
    /// The shared secret both sides compute.
    pub shared: [u8; 32],
}

/// RFC 7748 §6.1 Diffie–Hellman vector.
pub static X25519: &[X25519Vector] = &[X25519Vector {
    name: "X25519 RFC 7748 §6.1",
    source: "RFC 7748 §6.1",
    alice_secret: hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
    alice_public: hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
    bob_secret: hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
    bob_public: hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
    shared: hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
}];

/// Peer `u`-coordinates of order dividing 8: `X25519(k, u)` is all-zero for
/// every clamped scalar `k`, so the facade MUST reject them with
/// `InvalidParameter` and leave the shared buffer zeroed. The list covers
/// the canonical low-order points and their non-canonical (`u >= p`)
/// aliases.
pub static X25519_LOW_ORDER_PEERS: &[KeyVector] = &[
    KeyVector {
        name: "X25519 low-order peer u = 0",
        property: "u = 0 (order 2)",
        key: [0u8; 32],
    },
    KeyVector {
        name: "X25519 low-order peer u = 1",
        property: "u = 1 (order 1 on the twist / identity image)",
        key: hex("0100000000000000000000000000000000000000000000000000000000000000"),
    },
    KeyVector {
        name: "X25519 low-order peer (order 8, first)",
        property: "order 8",
        key: hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    },
    KeyVector {
        name: "X25519 low-order peer (order 8, second)",
        property: "order 8",
        key: hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    },
    KeyVector {
        name: "X25519 low-order peer u = p - 1",
        property: "u = p - 1 (order 4)",
        key: hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    },
    KeyVector {
        name: "X25519 low-order peer u = p",
        property: "u = p (non-canonical alias of u = 0)",
        key: hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    },
    KeyVector {
        name: "X25519 low-order peer u = p + 1",
        property: "u = p + 1 (non-canonical alias of u = 1)",
        key: hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    },
];

// ---------------------------------------------------------------------------
// Argon2id (RFC 9106)
// ---------------------------------------------------------------------------

/// An Argon2id vector with secret key `K` and associated data `X`.
#[derive(Debug)]
pub struct Argon2idVector {
    /// Human-readable name used in harness messages.
    pub name: &'static str,
    /// Specification section the vector comes from.
    pub source: &'static str,
    /// Cost parameters.
    pub params: Argon2Params,
    /// Password `P`.
    pub password: &'static [u8],
    /// Salt `S`.
    pub salt: &'static [u8],
    /// Secret key `K`.
    pub secret: &'static [u8],
    /// Associated data `X`.
    pub ad: &'static [u8],
    /// Expected 32-byte tag.
    pub tag: [u8; 32],
}

/// RFC 9106 §5.3 Argon2id vector: version 0x13, `m = 32` KiB, `t = 3`,
/// `p = 4`, tag length 32, with the RFC's secret key and associated data.
/// Note the memory size: the RFC vector uses 32 **KiB** (exactly the domain
/// floor `8 · p`), not 32 MiB — a backend that enforces a policy floor
/// inside `argon2id` cannot pass this vector.
pub static ARGON2ID: &[Argon2idVector] = &[Argon2idVector {
    name: "Argon2id RFC 9106 §5.3",
    source: "RFC 9106 §5.3",
    params: Argon2Params::new(32, 3, 4),
    password: &[0x01; 32],
    salt: &[0x02; 16],
    secret: &[0x03; 8],
    ad: &[0x04; 12],
    tag: hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"),
}];

#[cfg(test)]
mod tests {
    use super::*;

    /// The Ed25519 base point `B`, compressed (RFC 8032 §5.1).
    const B_COMPRESSED: [u8; 32] =
        hex("5866666666666666666666666666666666666666666666666666666666666666");

    #[test]
    fn hex_decodes_both_cases() {
        assert_eq!(hex::<4>("deadBEEF"), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(hex::<0>(""), [0u8; 0]);
    }

    #[test]
    fn shared_aead_inputs_have_the_rfc_lengths() {
        assert_eq!(AEAD_PLAINTEXT.len(), 114);
        for v in CHACHA20POLY1305 {
            assert_eq!(v.plaintext.len(), v.ciphertext.len());
        }
        for v in XCHACHA20POLY1305 {
            assert_eq!(v.plaintext.len(), v.ciphertext.len());
        }
    }

    #[test]
    fn sha_abc_message_is_the_sha512_abc_digest() {
        assert_eq!(ED25519[3].message, &SHA512[1].digest[..]);
    }

    #[test]
    fn neg5_is_test2_key_and_signature_over_test3_message() {
        let neg5 = &ED25519_REJECT[5];
        assert_eq!(neg5.public_key, ED25519[1].public_key);
        assert_eq!(neg5.signature, ED25519[1].signature);
        assert_eq!(neg5.message, ED25519[2].message);
    }

    #[test]
    fn neg6_uses_t8_as_r_under_the_mixed_order_key() {
        let neg6 = &ED25519_REJECT[6];
        assert_eq!(neg6.signature[..32], T8);
        assert_eq!(neg6.public_key, ED25519_INVALID_PUBLIC_KEYS[12].key);
        assert_eq!(ED25519_REJECT.len(), 7);
    }

    #[test]
    fn neg2_shares_r_with_test1_and_neg4_r_is_the_base_point() {
        assert_eq!(
            ED25519_REJECT[1].signature[..32],
            ED25519[0].signature[..32]
        );
        assert_eq!(ED25519_REJECT[4].signature[..32], B_COMPRESSED);
        assert_eq!(ED25519_REJECT[4].signature[32], 1);
        assert!(ED25519_REJECT[4].signature[33..].iter().all(|b| *b == 0));
    }

    #[test]
    fn hkdf_okm_lengths_match_the_rfc() {
        assert_eq!(HKDF_SHA256[0].okm.len(), 42);
        assert_eq!(HKDF_SHA256[1].okm.len(), 82);
        assert_eq!(HKDF_SHA256[2].okm.len(), 42);
    }

    #[test]
    fn argon2id_params_are_in_the_rfc_domain() {
        assert!(ARGON2ID[0].params.validate().is_ok());
    }

    #[test]
    fn ed25519_to_x25519_keys_are_the_ed25519_vector_keys() {
        assert_eq!(ED25519_TO_X25519.len(), 4);
        for (conv, sig) in ED25519_TO_X25519.iter().zip(ED25519) {
            assert_eq!(conv.public_key, sig.public_key, "{}", conv.name);
        }
    }

    #[test]
    fn the_eight_torsion_rows_come_first_and_are_distinct() {
        let torsion = &ED25519_INVALID_PUBLIC_KEYS[..8];
        for (i, a) in torsion.iter().enumerate() {
            for b in &torsion[i + 1..] {
                assert_ne!(a.key, b.key);
            }
        }
    }
}
