//! Error types: one variant per parse, predicate or backend failure, grouped
//! by the layer that produced it.
//!
//! [`Error`] is `Copy` and carries no heap data under any feature, so it is
//! usable from the pure `no_std` build. [`Error::class`] maps every variant
//! onto the C2SP CCTV expectation classes (`armor failure`, `header
//! failure`, `no match`, `HMAC failure`, `payload failure`), which is what the
//! vendored test corpus asserts against.

use spacetime_crypto::{CryptoError, CryptoErrorKind};

/// ASCII armor failures (`armor.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArmorError {
    /// After leading whitespace the input does not start with the BEGIN line.
    MissingBegin,
    /// A data line is empty, longer than 64 characters, or a full line
    /// follows a short one (or a second short line appears).
    LineLength,
    /// A data line is not strict padded base64 (bad byte, `=` in the wrong
    /// place, missing padding, non-zero unused bits).
    BadBase64,
    /// End of input before the END line.
    MissingEnd,
    /// Non-whitespace bytes after the END line.
    TrailingData,
}

/// Header failures (`header.rs`, `stanza.rs`, the unwrap step).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderError {
    /// The first 22 bytes are not `age-encryption.org/v1\n` (covers empty
    /// input, other versions and CRLF).
    BadMagic,
    /// Input ended before the MAC line (or inside a line).
    Truncated,
    /// A header line that starts neither with `-> ` nor with `---`.
    BadStanzaStart,
    /// `-> ` with nothing after it.
    NoArguments,
    /// Two consecutive spaces, or a trailing space, in a stanza line.
    EmptyArgument,
    /// A stanza-line byte outside `0x21..=0x7E`.
    InvalidCharacter,
    /// A body line longer than 64 characters.
    BodyLineTooLong,
    /// Body: a non-alphabet byte (including `=` and `\r`), `len % 4 == 1`,
    /// or non-zero unused bits.
    BadBase64,
    /// The `---` line is not exactly `--- ` + 43 canonical base64 characters.
    BadMacLine,
    /// Fewer than 16 bytes after the MAC line.
    ShortNonce,
    /// X25519 stanza: argument count, share or body length, or
    /// canonicality violated.
    X25519Stanza,
    /// ssh-ed25519 stanza: argument count, tag/share/body length, or
    /// canonicality violated.
    SshEd25519Stanza,
    /// A scrypt stanza together with any other stanza.
    ScryptNotAlone,
    /// X25519 produced an all-zero shared secret while unwrapping (the
    /// facade's `InvalidParameter`).
    LowOrderShare,
}

/// STREAM payload failures (`stream.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PayloadError {
    /// Input ended before a final chunk (also: no chunk at all).
    Truncated,
    /// A final chunk of 1..=15 bytes (shorter than a tag).
    ChunkTooShort,
    /// A 16-byte final chunk after at least one other chunk (or
    /// `write_last(&[])` after a chunk).
    EmptyFinalChunk,
    /// ChaCha20-Poly1305 tag failure (both nonce variants for a full chunk).
    Authentication,
    /// Bytes after the final chunk.
    TrailingData,
    /// The 11-byte chunk counter wrapped.
    CounterOverflow,
    /// API misuse: wrong slice length for `next_chunk` / `last_chunk` /
    /// `write_chunk` / `write_last`.
    ChunkLength,
}

/// Stanza types that are recognised, counted, and refused — never treated
/// as grease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedStanza {
    /// `scrypt` (passphrase) stanza.
    Scrypt,
    /// `ssh-rsa` stanza.
    SshRsa,
}

/// Key string failures (`keys.rs`, `bech32.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// Charset, mixed case, checksum, separator or bit padding.
    Bech32,
    /// The HRP is not `age` / `age-secret-key-` (compared after ASCII
    /// lowercasing).
    Hrp,
    /// The decoded payload is not 32 bytes (or the string is not exactly
    /// 62 / 74 characters).
    Length,
    /// `Ed25519ToX25519` / `X25519` rejected a recipient key
    /// (`InvalidParameter`).
    InvalidPublicKey,
    /// `encode_age` on an ssh-ed25519 key (age has no string form for it).
    NotEncodable,
}

/// One variant per failure. `Copy`; carries no heap data under any feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// ASCII armor did not parse.
    Armor(ArmorError),
    /// The header did not parse (or a share was low-order at unwrap time).
    Header(HeaderError),
    /// No identity unwrapped any stanza.
    NoMatch,
    /// A file key unwrapped but the header MAC did not verify.
    HmacMismatch,
    /// The STREAM payload did not decrypt cleanly to EOF.
    Payload(PayloadError),
    /// Only stanzas of an unsupported (but recognised) type could match.
    Unsupported(UnsupportedStanza),
    /// A key string or key value was rejected.
    Key(KeyError),
    /// `encrypt_header` with an empty recipient list.
    NoRecipients,
    /// The caller-provided output buffer is too small.
    BufferTooSmall,
    /// A backend failure not attributable to the inputs.
    Backend(CryptoErrorKind),
}

/// The CCTV expectation classes (`tests/vectors/cctv/README.md`), plus one
/// class per [`Error`] variant the corpus never produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// `armor failure`.
    ArmorFailure,
    /// `header failure`.
    HeaderFailure,
    /// `no match`.
    NoMatch,
    /// `HMAC failure`.
    HmacFailure,
    /// `payload failure`.
    PayloadFailure,
    /// [`Error::Unsupported`].
    Unsupported,
    /// [`Error::Key`].
    Key,
    /// [`Error::NoRecipients`].
    NoRecipients,
    /// [`Error::BufferTooSmall`].
    Buffer,
    /// [`Error::Backend`].
    Backend,
}

impl Error {
    /// Stable identifier: `"Armor(MissingBegin)"`, `"Header(BadMagic)"`,
    /// `"NoMatch"`, `"HmacMismatch"`, `"Payload(Truncated)"`,
    /// `"Unsupported(Scrypt)"`, `"Key(Bech32)"`, `"NoRecipients"`,
    /// `"BufferTooSmall"`, `"Backend"`.
    pub const fn name(&self) -> &'static str {
        match self {
            Error::Armor(ArmorError::MissingBegin) => "Armor(MissingBegin)",
            Error::Armor(ArmorError::LineLength) => "Armor(LineLength)",
            Error::Armor(ArmorError::BadBase64) => "Armor(BadBase64)",
            Error::Armor(ArmorError::MissingEnd) => "Armor(MissingEnd)",
            Error::Armor(ArmorError::TrailingData) => "Armor(TrailingData)",
            Error::Header(HeaderError::BadMagic) => "Header(BadMagic)",
            Error::Header(HeaderError::Truncated) => "Header(Truncated)",
            Error::Header(HeaderError::BadStanzaStart) => "Header(BadStanzaStart)",
            Error::Header(HeaderError::NoArguments) => "Header(NoArguments)",
            Error::Header(HeaderError::EmptyArgument) => "Header(EmptyArgument)",
            Error::Header(HeaderError::InvalidCharacter) => "Header(InvalidCharacter)",
            Error::Header(HeaderError::BodyLineTooLong) => "Header(BodyLineTooLong)",
            Error::Header(HeaderError::BadBase64) => "Header(BadBase64)",
            Error::Header(HeaderError::BadMacLine) => "Header(BadMacLine)",
            Error::Header(HeaderError::ShortNonce) => "Header(ShortNonce)",
            Error::Header(HeaderError::X25519Stanza) => "Header(X25519Stanza)",
            Error::Header(HeaderError::SshEd25519Stanza) => "Header(SshEd25519Stanza)",
            Error::Header(HeaderError::ScryptNotAlone) => "Header(ScryptNotAlone)",
            Error::Header(HeaderError::LowOrderShare) => "Header(LowOrderShare)",
            Error::NoMatch => "NoMatch",
            Error::HmacMismatch => "HmacMismatch",
            Error::Payload(PayloadError::Truncated) => "Payload(Truncated)",
            Error::Payload(PayloadError::ChunkTooShort) => "Payload(ChunkTooShort)",
            Error::Payload(PayloadError::EmptyFinalChunk) => "Payload(EmptyFinalChunk)",
            Error::Payload(PayloadError::Authentication) => "Payload(Authentication)",
            Error::Payload(PayloadError::TrailingData) => "Payload(TrailingData)",
            Error::Payload(PayloadError::CounterOverflow) => "Payload(CounterOverflow)",
            Error::Payload(PayloadError::ChunkLength) => "Payload(ChunkLength)",
            Error::Unsupported(UnsupportedStanza::Scrypt) => "Unsupported(Scrypt)",
            Error::Unsupported(UnsupportedStanza::SshRsa) => "Unsupported(SshRsa)",
            Error::Key(KeyError::Bech32) => "Key(Bech32)",
            Error::Key(KeyError::Hrp) => "Key(Hrp)",
            Error::Key(KeyError::Length) => "Key(Length)",
            Error::Key(KeyError::InvalidPublicKey) => "Key(InvalidPublicKey)",
            Error::Key(KeyError::NotEncodable) => "Key(NotEncodable)",
            Error::NoRecipients => "NoRecipients",
            Error::BufferTooSmall => "BufferTooSmall",
            Error::Backend(_) => "Backend",
        }
    }

    /// The expectation class of this error.
    pub const fn class(&self) -> Class {
        match self {
            Error::Armor(_) => Class::ArmorFailure,
            Error::Header(_) => Class::HeaderFailure,
            Error::NoMatch => Class::NoMatch,
            Error::HmacMismatch => Class::HmacFailure,
            Error::Payload(_) => Class::PayloadFailure,
            Error::Unsupported(_) => Class::Unsupported,
            Error::Key(_) => Class::Key,
            Error::NoRecipients => Class::NoRecipients,
            Error::BufferTooSmall => Class::Buffer,
            Error::Backend(_) => Class::Backend,
        }
    }
}

impl Class {
    /// The CCTV `expect:` value for this class: `"armor failure"`,
    /// `"header failure"`, `"no match"`, `"HMAC failure"`,
    /// `"payload failure"`; `None` for the classes the corpus never names.
    pub const fn cctv_name(&self) -> Option<&'static str> {
        match self {
            Class::ArmorFailure => Some("armor failure"),
            Class::HeaderFailure => Some("header failure"),
            Class::NoMatch => Some("no match"),
            Class::HmacFailure => Some("HMAC failure"),
            Class::PayloadFailure => Some("payload failure"),
            Class::Unsupported
            | Class::Key
            | Class::NoRecipients
            | Class::Buffer
            | Class::Backend => None,
        }
    }
}

impl core::fmt::Display for ArmorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ArmorError::MissingBegin => "armor: missing BEGIN line",
            ArmorError::LineLength => {
                "armor: line not 64 characters (or empty / second short line)"
            }
            ArmorError::BadBase64 => "armor: invalid base64",
            ArmorError::MissingEnd => "armor: missing END line",
            ArmorError::TrailingData => "armor: data after END line",
        })
    }
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            HeaderError::BadMagic => "header: bad magic (expected age-encryption.org/v1)",
            HeaderError::Truncated => "header: truncated",
            HeaderError::BadStanzaStart => "header: line is not a stanza or the MAC line",
            HeaderError::NoArguments => "header: stanza without a type",
            HeaderError::EmptyArgument => "header: empty stanza argument",
            HeaderError::InvalidCharacter => {
                "header: stanza argument contains an invalid character"
            }
            HeaderError::BodyLineTooLong => "header: stanza body line longer than 64 characters",
            HeaderError::BadBase64 => "header: stanza body is not canonical base64",
            HeaderError::BadMacLine => "header: malformed MAC line",
            HeaderError::ShortNonce => "header: payload nonce missing or short",
            HeaderError::X25519Stanza => "header: malformed X25519 stanza",
            HeaderError::SshEd25519Stanza => "header: malformed ssh-ed25519 stanza",
            HeaderError::ScryptNotAlone => "header: scrypt stanza must be the only stanza",
            HeaderError::LowOrderShare => "header: X25519 share is low-order",
        })
    }
}

impl core::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            PayloadError::Truncated => "payload: truncated before the final chunk",
            PayloadError::ChunkTooShort => "payload: chunk shorter than a tag",
            PayloadError::EmptyFinalChunk => "payload: empty final chunk after other chunks",
            PayloadError::Authentication => "payload: chunk authentication failed",
            PayloadError::TrailingData => "payload: data after the final chunk",
            PayloadError::CounterOverflow => "payload: chunk counter overflow",
            PayloadError::ChunkLength => "payload: wrong chunk length",
        })
    }
}

impl core::fmt::Display for UnsupportedStanza {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            UnsupportedStanza::Scrypt => "scrypt",
            UnsupportedStanza::SshRsa => "ssh-rsa",
        })
    }
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            KeyError::Bech32 => "key: invalid bech32",
            KeyError::Hrp => "key: wrong bech32 prefix",
            KeyError::Length => "key: wrong length",
            KeyError::InvalidPublicKey => "key: invalid public key",
            KeyError::NotEncodable => "key: no age string form",
        })
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Armor(e) => core::fmt::Display::fmt(e, f),
            Error::Header(e) => core::fmt::Display::fmt(e, f),
            Error::NoMatch => f.write_str("no identity matched any stanza"),
            Error::HmacMismatch => f.write_str("header MAC mismatch"),
            Error::Payload(e) => core::fmt::Display::fmt(e, f),
            Error::Unsupported(s) => write!(f, "unsupported stanza type: {s}"),
            Error::Key(e) => core::fmt::Display::fmt(e, f),
            Error::NoRecipients => f.write_str("no recipients"),
            Error::BufferTooSmall => f.write_str("output buffer too small"),
            Error::Backend(k) => write!(f, "backend error: {k}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<CryptoError> for Error {
    /// The generic fallback: every kind becomes [`Error::Backend`]`(kind)`.
    /// Call sites that can attribute a kind to an input (`AuthenticationFailed`
    /// on an AEAD open, `InvalidParameter` on a low-order share) map it
    /// themselves before this conversion is reached.
    fn from(e: CryptoError) -> Self {
        Error::Backend(e.kind())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant once, paired with its stable name, class and display text.
    const ALL: &[(Error, &str, Class, &str)] = &[
        (
            Error::Armor(ArmorError::MissingBegin),
            "Armor(MissingBegin)",
            Class::ArmorFailure,
            "armor: missing BEGIN line",
        ),
        (
            Error::Armor(ArmorError::LineLength),
            "Armor(LineLength)",
            Class::ArmorFailure,
            "armor: line not 64 characters (or empty / second short line)",
        ),
        (
            Error::Armor(ArmorError::BadBase64),
            "Armor(BadBase64)",
            Class::ArmorFailure,
            "armor: invalid base64",
        ),
        (
            Error::Armor(ArmorError::MissingEnd),
            "Armor(MissingEnd)",
            Class::ArmorFailure,
            "armor: missing END line",
        ),
        (
            Error::Armor(ArmorError::TrailingData),
            "Armor(TrailingData)",
            Class::ArmorFailure,
            "armor: data after END line",
        ),
        (
            Error::Header(HeaderError::BadMagic),
            "Header(BadMagic)",
            Class::HeaderFailure,
            "header: bad magic (expected age-encryption.org/v1)",
        ),
        (
            Error::Header(HeaderError::Truncated),
            "Header(Truncated)",
            Class::HeaderFailure,
            "header: truncated",
        ),
        (
            Error::Header(HeaderError::BadStanzaStart),
            "Header(BadStanzaStart)",
            Class::HeaderFailure,
            "header: line is not a stanza or the MAC line",
        ),
        (
            Error::Header(HeaderError::NoArguments),
            "Header(NoArguments)",
            Class::HeaderFailure,
            "header: stanza without a type",
        ),
        (
            Error::Header(HeaderError::EmptyArgument),
            "Header(EmptyArgument)",
            Class::HeaderFailure,
            "header: empty stanza argument",
        ),
        (
            Error::Header(HeaderError::InvalidCharacter),
            "Header(InvalidCharacter)",
            Class::HeaderFailure,
            "header: stanza argument contains an invalid character",
        ),
        (
            Error::Header(HeaderError::BodyLineTooLong),
            "Header(BodyLineTooLong)",
            Class::HeaderFailure,
            "header: stanza body line longer than 64 characters",
        ),
        (
            Error::Header(HeaderError::BadBase64),
            "Header(BadBase64)",
            Class::HeaderFailure,
            "header: stanza body is not canonical base64",
        ),
        (
            Error::Header(HeaderError::BadMacLine),
            "Header(BadMacLine)",
            Class::HeaderFailure,
            "header: malformed MAC line",
        ),
        (
            Error::Header(HeaderError::ShortNonce),
            "Header(ShortNonce)",
            Class::HeaderFailure,
            "header: payload nonce missing or short",
        ),
        (
            Error::Header(HeaderError::X25519Stanza),
            "Header(X25519Stanza)",
            Class::HeaderFailure,
            "header: malformed X25519 stanza",
        ),
        (
            Error::Header(HeaderError::SshEd25519Stanza),
            "Header(SshEd25519Stanza)",
            Class::HeaderFailure,
            "header: malformed ssh-ed25519 stanza",
        ),
        (
            Error::Header(HeaderError::ScryptNotAlone),
            "Header(ScryptNotAlone)",
            Class::HeaderFailure,
            "header: scrypt stanza must be the only stanza",
        ),
        (
            Error::Header(HeaderError::LowOrderShare),
            "Header(LowOrderShare)",
            Class::HeaderFailure,
            "header: X25519 share is low-order",
        ),
        (
            Error::NoMatch,
            "NoMatch",
            Class::NoMatch,
            "no identity matched any stanza",
        ),
        (
            Error::HmacMismatch,
            "HmacMismatch",
            Class::HmacFailure,
            "header MAC mismatch",
        ),
        (
            Error::Payload(PayloadError::Truncated),
            "Payload(Truncated)",
            Class::PayloadFailure,
            "payload: truncated before the final chunk",
        ),
        (
            Error::Payload(PayloadError::ChunkTooShort),
            "Payload(ChunkTooShort)",
            Class::PayloadFailure,
            "payload: chunk shorter than a tag",
        ),
        (
            Error::Payload(PayloadError::EmptyFinalChunk),
            "Payload(EmptyFinalChunk)",
            Class::PayloadFailure,
            "payload: empty final chunk after other chunks",
        ),
        (
            Error::Payload(PayloadError::Authentication),
            "Payload(Authentication)",
            Class::PayloadFailure,
            "payload: chunk authentication failed",
        ),
        (
            Error::Payload(PayloadError::TrailingData),
            "Payload(TrailingData)",
            Class::PayloadFailure,
            "payload: data after the final chunk",
        ),
        (
            Error::Payload(PayloadError::CounterOverflow),
            "Payload(CounterOverflow)",
            Class::PayloadFailure,
            "payload: chunk counter overflow",
        ),
        (
            Error::Payload(PayloadError::ChunkLength),
            "Payload(ChunkLength)",
            Class::PayloadFailure,
            "payload: wrong chunk length",
        ),
        (
            Error::Unsupported(UnsupportedStanza::Scrypt),
            "Unsupported(Scrypt)",
            Class::Unsupported,
            "unsupported stanza type: scrypt",
        ),
        (
            Error::Unsupported(UnsupportedStanza::SshRsa),
            "Unsupported(SshRsa)",
            Class::Unsupported,
            "unsupported stanza type: ssh-rsa",
        ),
        (
            Error::Key(KeyError::Bech32),
            "Key(Bech32)",
            Class::Key,
            "key: invalid bech32",
        ),
        (
            Error::Key(KeyError::Hrp),
            "Key(Hrp)",
            Class::Key,
            "key: wrong bech32 prefix",
        ),
        (
            Error::Key(KeyError::Length),
            "Key(Length)",
            Class::Key,
            "key: wrong length",
        ),
        (
            Error::Key(KeyError::InvalidPublicKey),
            "Key(InvalidPublicKey)",
            Class::Key,
            "key: invalid public key",
        ),
        (
            Error::Key(KeyError::NotEncodable),
            "Key(NotEncodable)",
            Class::Key,
            "key: no age string form",
        ),
        (
            Error::NoRecipients,
            "NoRecipients",
            Class::NoRecipients,
            "no recipients",
        ),
        (
            Error::BufferTooSmall,
            "BufferTooSmall",
            Class::Buffer,
            "output buffer too small",
        ),
        (
            Error::Backend(CryptoErrorKind::Failed),
            "Backend",
            Class::Backend,
            "backend error: crypto operation failed",
        ),
    ];

    #[test]
    fn names_and_classes_are_stable() {
        for (e, name, class, _) in ALL {
            assert_eq!(e.name(), *name);
            assert_eq!(e.class(), *class, "{name}");
        }
    }

    /// Writes `Display` output into a fixed buffer without allocating.
    struct Buf {
        data: [u8; 96],
        len: usize,
    }

    impl core::fmt::Write for Buf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.len + s.len();
            if end > self.data.len() {
                return Err(core::fmt::Error);
            }
            self.data[self.len..end].copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    #[test]
    fn display_texts_are_exact() {
        use core::fmt::Write;
        for (e, _, _, text) in ALL {
            let mut b = Buf {
                data: [0; 96],
                len: 0,
            };
            write!(b, "{e}").unwrap();
            assert_eq!(&b.data[..b.len], text.as_bytes(), "{}", e.name());
        }
    }

    #[test]
    fn cctv_names() {
        assert_eq!(Class::ArmorFailure.cctv_name(), Some("armor failure"));
        assert_eq!(Class::HeaderFailure.cctv_name(), Some("header failure"));
        assert_eq!(Class::NoMatch.cctv_name(), Some("no match"));
        assert_eq!(Class::HmacFailure.cctv_name(), Some("HMAC failure"));
        assert_eq!(Class::PayloadFailure.cctv_name(), Some("payload failure"));
        for c in [
            Class::Unsupported,
            Class::Key,
            Class::NoRecipients,
            Class::Buffer,
            Class::Backend,
        ] {
            assert_eq!(c.cctv_name(), None);
        }
    }

    #[test]
    fn crypto_error_mapping_is_the_generic_fallback() {
        for kind in [
            CryptoErrorKind::AuthenticationFailed,
            CryptoErrorKind::InvalidParameter,
            CryptoErrorKind::Unavailable,
            CryptoErrorKind::Unsupported,
            CryptoErrorKind::Failed,
        ] {
            assert_eq!(Error::from(CryptoError::new(kind)), Error::Backend(kind));
        }
    }

    #[test]
    fn is_core_error() {
        fn assert_error<E: core::error::Error>(_: &E) {}
        assert_error(&Error::NoMatch);
    }
}
