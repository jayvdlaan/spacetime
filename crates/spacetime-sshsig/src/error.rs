//! Error type: one variant per parse or predicate failure.
//!
//! [`Error`] is `Copy` and carries no heap data under any feature, so it is
//! usable from the pure `no_std` build. The Ed25519 facade's rejection of an
//! input-caused kind is collapsed into a single [`Error::SignatureInvalid`]
//! (no reason oracle — see `spacetime_crypto::Ed25519Verify`); only backend
//! kinds that are not attributable to the inputs surface as
//! [`Error::Backend`].

use spacetime_crypto::{CryptoError, CryptoErrorKind};

/// Which wire section had bytes left over after its last field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// The SSHSIG blob itself (after the `signature` string).
    Outer,
    /// The public-key blob inside the `publickey` string.
    PublicKey,
    /// The signature blob inside the `signature` string.
    Signature,
}

/// One variant per predicate or parse failure. `Copy`; carries no heap data
/// under any feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // -- armor (armor.rs) --
    /// Input does not start with `-----BEGIN SSH SIGNATURE-----` + `\n`.
    ArmorMissingHeader,
    /// End of input before a `-----END SSH SIGNATURE-----` line.
    ArmorMissingFooter,
    /// A base64 line is longer than 76 characters.
    ArmorLineTooLong,
    /// A byte outside the base64 alphabet, an empty line, bad padding or
    /// non-zero unused trailing bits.
    ArmorBadBase64,
    /// Bytes after the END footer (other than one `\n`).
    ArmorTrailingData,
    // -- buffers / lengths --
    /// The caller-provided output buffer is too small.
    BufferTooSmall,
    /// A length does not fit an SSH `uint32`.
    TooLong,
    // -- blob structure (blob.rs, pubkey.rs, wire.rs) --
    /// The first six bytes are not `SSHSIG`.
    BadMagic,
    /// The version field is not 1.
    UnsupportedVersion,
    /// A read ran past the end of its buffer.
    Truncated,
    /// A section had bytes left after its last field.
    TrailingBytes(Section),
    /// Key type is neither `ssh-ed25519` nor `sk-ssh-ed25519@openssh.com`.
    UnknownKeyType,
    /// Signature type is neither `ssh-ed25519` nor `sk-ssh-ed25519@openssh.com`.
    UnknownSignatureType,
    /// Key family and signature family disagree.
    KeyTypeMismatch,
    /// The public-key string is not 32 bytes.
    BadKeyLength,
    /// The signature string is not 64 bytes.
    BadSignatureLength,
    // -- predicate (verify.rs) --
    /// The caller's expected namespace is empty.
    EmptyNamespace,
    /// The caller's expected namespace exceeds [`crate::MAX_NAMESPACE_LEN`].
    NamespaceTooLong,
    /// The blob's `reserved` string is not empty.
    ReservedNotEmpty,
    /// The blob's `hash_algorithm` is not `sha512`.
    HashAlgorithmNotSha512,
    /// The blob's namespace differs from the caller's expected namespace.
    NamespaceMismatch,
    /// The embedded key differs from the caller's expected signer.
    SignerMismatch,
    /// sk: the user-presence flag (`0x01`) is not set.
    SkUserPresenceMissing,
    /// sk: the user-verification flag (`0x04`) is required by policy but not set.
    SkUserVerificationMissing,
    /// Strict Ed25519 verification failed (any input-caused reason).
    SignatureInvalid,
    /// `ed25519_validate_public_key` rejected the key.
    InvalidPublicKey,
    /// A backend failure not attributable to the inputs.
    Backend(CryptoErrorKind),
    // -- text formats (pubkey.rs, allowed_signers.rs) --
    /// A public-key line has too few tokens or undecodable base64.
    PublicKeyLineInvalid,
    /// A public-key line's type token differs from the blob's type.
    PublicKeyTypeMismatch,
    /// An `allowed_signers` line is malformed.
    AllowedSignersLineInvalid,
    /// An `allowed_signers` option name is not recognised.
    AllowedSignersUnknownOption,
}

impl Error {
    /// Stable identifier, equal to the `expect.*` strings in
    /// `tests/vectors/manifest.json`. `TrailingBytes(s)` →
    /// `"TrailingBytes(Outer)"` / `"TrailingBytes(PublicKey)"` /
    /// `"TrailingBytes(Signature)"`; `Backend(_)` → `"Backend"`; every other
    /// variant → its own name.
    pub const fn name(&self) -> &'static str {
        match self {
            Error::ArmorMissingHeader => "ArmorMissingHeader",
            Error::ArmorMissingFooter => "ArmorMissingFooter",
            Error::ArmorLineTooLong => "ArmorLineTooLong",
            Error::ArmorBadBase64 => "ArmorBadBase64",
            Error::ArmorTrailingData => "ArmorTrailingData",
            Error::BufferTooSmall => "BufferTooSmall",
            Error::TooLong => "TooLong",
            Error::BadMagic => "BadMagic",
            Error::UnsupportedVersion => "UnsupportedVersion",
            Error::Truncated => "Truncated",
            Error::TrailingBytes(Section::Outer) => "TrailingBytes(Outer)",
            Error::TrailingBytes(Section::PublicKey) => "TrailingBytes(PublicKey)",
            Error::TrailingBytes(Section::Signature) => "TrailingBytes(Signature)",
            Error::UnknownKeyType => "UnknownKeyType",
            Error::UnknownSignatureType => "UnknownSignatureType",
            Error::KeyTypeMismatch => "KeyTypeMismatch",
            Error::BadKeyLength => "BadKeyLength",
            Error::BadSignatureLength => "BadSignatureLength",
            Error::EmptyNamespace => "EmptyNamespace",
            Error::NamespaceTooLong => "NamespaceTooLong",
            Error::ReservedNotEmpty => "ReservedNotEmpty",
            Error::HashAlgorithmNotSha512 => "HashAlgorithmNotSha512",
            Error::NamespaceMismatch => "NamespaceMismatch",
            Error::SignerMismatch => "SignerMismatch",
            Error::SkUserPresenceMissing => "SkUserPresenceMissing",
            Error::SkUserVerificationMissing => "SkUserVerificationMissing",
            Error::SignatureInvalid => "SignatureInvalid",
            Error::InvalidPublicKey => "InvalidPublicKey",
            Error::Backend(_) => "Backend",
            Error::PublicKeyLineInvalid => "PublicKeyLineInvalid",
            Error::PublicKeyTypeMismatch => "PublicKeyTypeMismatch",
            Error::AllowedSignersLineInvalid => "AllowedSignersLineInvalid",
            Error::AllowedSignersUnknownOption => "AllowedSignersUnknownOption",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::ArmorMissingHeader => f.write_str("armor: missing BEGIN header"),
            Error::ArmorMissingFooter => f.write_str("armor: missing END footer"),
            Error::ArmorLineTooLong => f.write_str("armor: base64 line longer than 76 characters"),
            Error::ArmorBadBase64 => f.write_str("armor: invalid base64"),
            Error::ArmorTrailingData => f.write_str("armor: data after END footer"),
            Error::BufferTooSmall => f.write_str("output buffer too small"),
            Error::TooLong => f.write_str("length does not fit an SSH uint32"),
            Error::BadMagic => f.write_str("blob: bad SSHSIG magic"),
            Error::UnsupportedVersion => f.write_str("blob: unsupported version (expected 1)"),
            Error::Truncated => f.write_str("blob: truncated"),
            Error::TrailingBytes(Section::Outer) => {
                f.write_str("blob: trailing bytes after outer fields")
            }
            Error::TrailingBytes(Section::PublicKey) => {
                f.write_str("blob: trailing bytes in public key")
            }
            Error::TrailingBytes(Section::Signature) => {
                f.write_str("blob: trailing bytes in signature")
            }
            Error::UnknownKeyType => f.write_str("unsupported key type"),
            Error::UnknownSignatureType => f.write_str("unsupported signature type"),
            Error::KeyTypeMismatch => f.write_str("signature type does not match key type"),
            Error::BadKeyLength => f.write_str("public key is not 32 bytes"),
            Error::BadSignatureLength => f.write_str("signature is not 64 bytes"),
            Error::EmptyNamespace => f.write_str("namespace must not be empty"),
            Error::NamespaceTooLong => f.write_str("namespace longer than 255 bytes"),
            Error::ReservedNotEmpty => f.write_str("reserved field must be empty"),
            Error::HashAlgorithmNotSha512 => f.write_str("hash_algorithm must be sha512"),
            Error::NamespaceMismatch => f.write_str("namespace mismatch"),
            Error::SignerMismatch => f.write_str("signature made by a different key"),
            Error::SkUserPresenceMissing => f.write_str("sk: user-presence flag not set"),
            Error::SkUserVerificationMissing => {
                f.write_str("sk: user-verification flag required but not set")
            }
            Error::SignatureInvalid => f.write_str("signature verification failed"),
            Error::InvalidPublicKey => f.write_str("public key failed validation"),
            Error::Backend(k) => write!(f, "backend error: {k}"),
            Error::PublicKeyLineInvalid => f.write_str("public key line: invalid"),
            Error::PublicKeyTypeMismatch => {
                f.write_str("public key line: type does not match blob")
            }
            Error::AllowedSignersLineInvalid => f.write_str("allowed_signers: invalid line"),
            Error::AllowedSignersUnknownOption => f.write_str("allowed_signers: unknown option"),
        }
    }
}

impl core::error::Error for Error {}

impl From<CryptoError> for Error {
    /// `AuthenticationFailed` → [`Error::SignatureInvalid`];
    /// `InvalidParameter` → [`Error::InvalidPublicKey`]; any other kind →
    /// [`Error::Backend`]`(kind)`.
    fn from(e: CryptoError) -> Self {
        match e.kind() {
            CryptoErrorKind::AuthenticationFailed => Error::SignatureInvalid,
            CryptoErrorKind::InvalidParameter => Error::InvalidPublicKey,
            kind => Error::Backend(kind),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant once, paired with its stable name and display text.
    const ALL: &[(Error, &str, &str)] = &[
        (
            Error::ArmorMissingHeader,
            "ArmorMissingHeader",
            "armor: missing BEGIN header",
        ),
        (
            Error::ArmorMissingFooter,
            "ArmorMissingFooter",
            "armor: missing END footer",
        ),
        (
            Error::ArmorLineTooLong,
            "ArmorLineTooLong",
            "armor: base64 line longer than 76 characters",
        ),
        (
            Error::ArmorBadBase64,
            "ArmorBadBase64",
            "armor: invalid base64",
        ),
        (
            Error::ArmorTrailingData,
            "ArmorTrailingData",
            "armor: data after END footer",
        ),
        (
            Error::BufferTooSmall,
            "BufferTooSmall",
            "output buffer too small",
        ),
        (
            Error::TooLong,
            "TooLong",
            "length does not fit an SSH uint32",
        ),
        (Error::BadMagic, "BadMagic", "blob: bad SSHSIG magic"),
        (
            Error::UnsupportedVersion,
            "UnsupportedVersion",
            "blob: unsupported version (expected 1)",
        ),
        (Error::Truncated, "Truncated", "blob: truncated"),
        (
            Error::TrailingBytes(Section::Outer),
            "TrailingBytes(Outer)",
            "blob: trailing bytes after outer fields",
        ),
        (
            Error::TrailingBytes(Section::PublicKey),
            "TrailingBytes(PublicKey)",
            "blob: trailing bytes in public key",
        ),
        (
            Error::TrailingBytes(Section::Signature),
            "TrailingBytes(Signature)",
            "blob: trailing bytes in signature",
        ),
        (
            Error::UnknownKeyType,
            "UnknownKeyType",
            "unsupported key type",
        ),
        (
            Error::UnknownSignatureType,
            "UnknownSignatureType",
            "unsupported signature type",
        ),
        (
            Error::KeyTypeMismatch,
            "KeyTypeMismatch",
            "signature type does not match key type",
        ),
        (
            Error::BadKeyLength,
            "BadKeyLength",
            "public key is not 32 bytes",
        ),
        (
            Error::BadSignatureLength,
            "BadSignatureLength",
            "signature is not 64 bytes",
        ),
        (
            Error::EmptyNamespace,
            "EmptyNamespace",
            "namespace must not be empty",
        ),
        (
            Error::NamespaceTooLong,
            "NamespaceTooLong",
            "namespace longer than 255 bytes",
        ),
        (
            Error::ReservedNotEmpty,
            "ReservedNotEmpty",
            "reserved field must be empty",
        ),
        (
            Error::HashAlgorithmNotSha512,
            "HashAlgorithmNotSha512",
            "hash_algorithm must be sha512",
        ),
        (
            Error::NamespaceMismatch,
            "NamespaceMismatch",
            "namespace mismatch",
        ),
        (
            Error::SignerMismatch,
            "SignerMismatch",
            "signature made by a different key",
        ),
        (
            Error::SkUserPresenceMissing,
            "SkUserPresenceMissing",
            "sk: user-presence flag not set",
        ),
        (
            Error::SkUserVerificationMissing,
            "SkUserVerificationMissing",
            "sk: user-verification flag required but not set",
        ),
        (
            Error::SignatureInvalid,
            "SignatureInvalid",
            "signature verification failed",
        ),
        (
            Error::InvalidPublicKey,
            "InvalidPublicKey",
            "public key failed validation",
        ),
        (
            Error::Backend(CryptoErrorKind::Failed),
            "Backend",
            "backend error: crypto operation failed",
        ),
        (
            Error::PublicKeyLineInvalid,
            "PublicKeyLineInvalid",
            "public key line: invalid",
        ),
        (
            Error::PublicKeyTypeMismatch,
            "PublicKeyTypeMismatch",
            "public key line: type does not match blob",
        ),
        (
            Error::AllowedSignersLineInvalid,
            "AllowedSignersLineInvalid",
            "allowed_signers: invalid line",
        ),
        (
            Error::AllowedSignersUnknownOption,
            "AllowedSignersUnknownOption",
            "allowed_signers: unknown option",
        ),
    ];

    #[test]
    fn names_are_stable() {
        for (e, name, _) in ALL {
            assert_eq!(e.name(), *name);
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
        for (e, _, text) in ALL {
            let mut b = Buf {
                data: [0; 96],
                len: 0,
            };
            write!(b, "{e}").unwrap();
            assert_eq!(&b.data[..b.len], text.as_bytes(), "{}", e.name());
        }
    }

    #[test]
    fn crypto_error_mapping() {
        assert_eq!(
            Error::from(CryptoError::new(CryptoErrorKind::AuthenticationFailed)),
            Error::SignatureInvalid
        );
        assert_eq!(
            Error::from(CryptoError::new(CryptoErrorKind::InvalidParameter)),
            Error::InvalidPublicKey
        );
        assert_eq!(
            Error::from(CryptoError::new(CryptoErrorKind::Unavailable)),
            Error::Backend(CryptoErrorKind::Unavailable)
        );
        assert_eq!(
            Error::from(CryptoError::new(CryptoErrorKind::Unsupported)),
            Error::Backend(CryptoErrorKind::Unsupported)
        );
        assert_eq!(
            Error::from(CryptoError::new(CryptoErrorKind::Failed)),
            Error::Backend(CryptoErrorKind::Failed)
        );
    }

    #[test]
    fn is_core_error() {
        fn assert_error<E: core::error::Error>(_: &E) {}
        assert_error(&Error::Truncated);
    }
}
