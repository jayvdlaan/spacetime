//! The SSHSIG blob (PROTOCOL.sshsig §3) and the signature blobs it carries
//! (RFC 8709 §6, PROTOCOL.u2f).
//!
//! ```text
//! "SSHSIG"                     6 bytes, no length prefix
//! uint32   version             must be 1
//! string   publickey           an OpenSSH public-key blob (crate::pubkey)
//! string   namespace
//! string   reserved
//! string   hash_algorithm
//! string   signature           an OpenSSH signature blob (Signature)
//! ```
//!
//! [`SshSig::parse`] is **structural only**: it checks the magic, the
//! version, the nesting, and that every section is consumed exactly. The
//! pinned predicate (reserved empty, `sha512`, namespace, the curve
//! operation) is applied by [`crate::verify()`]. `reserved` and
//! `hash_algorithm` are exposed verbatim so a caller can inspect a signature
//! that `verify` will reject. Parsing is zero-copy.

use crate::armor;
use crate::error::{Error, Section};
use crate::pubkey::{PublicKey, KEY_TYPE_ED25519, KEY_TYPE_SK_ED25519};
use crate::wire::{string_len, Reader, Writer};

/// The six-byte magic preamble (no length prefix).
pub const MAGIC: &[u8; 6] = b"SSHSIG";
/// The only supported SSHSIG version.
pub const SSHSIG_VERSION: u32 = 1;
/// The only accepted `hash_algorithm` value.
pub const HASH_ALGORITHM_SHA512: &[u8] = b"sha512";

/// Length of an `ssh-ed25519` SSHSIG blob with a namespace of
/// `namespace_len` bytes: `170 + namespace_len` (10 magic + version, 55 key
/// string, 4 + ns, 4 reserved, 10 hash_algorithm, 87 signature string).
pub const fn ed25519_sshsig_len(namespace_len: usize) -> usize {
    170 + namespace_len
}

/// Borrowed view of an OpenSSH signature blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signature<'a> {
    /// `string "ssh-ed25519" || string sig[64]`
    Ed25519 {
        /// `R || S`.
        sig: &'a [u8; 64],
    },
    /// `string "sk-ssh-ed25519@openssh.com" || string sig[64] || byte flags || uint32 counter`
    SkEd25519 {
        /// `R || S`.
        sig: &'a [u8; 64],
        /// Authenticator flags (`0x01` user presence, `0x04` user
        /// verification).
        flags: u8,
        /// Authenticator signature counter (big-endian on the wire).
        counter: u32,
    },
}

impl<'a> Signature<'a> {
    /// The signature type string.
    pub const fn sig_type(&self) -> &'static str {
        match self {
            Signature::Ed25519 { .. } => KEY_TYPE_ED25519,
            Signature::SkEd25519 { .. } => KEY_TYPE_SK_ED25519,
        }
    }

    /// The 64-byte Ed25519 signature `R || S`.
    pub const fn sig(&self) -> &'a [u8; 64] {
        match self {
            Signature::Ed25519 { sig } | Signature::SkEd25519 { sig, .. } => sig,
        }
    }

    /// Parse a whole signature blob; it must be consumed exactly
    /// ([`Error::TrailingBytes`]`(`[`Section::Signature`]`)`). Unknown type
    /// → [`Error::UnknownSignatureType`]; a sig string that is not 64 bytes
    /// → [`Error::BadSignatureLength`].
    pub fn parse_blob(blob: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(blob);
        let sig_type = r.string()?;
        let is_sk = if sig_type == KEY_TYPE_ED25519.as_bytes() {
            false
        } else if sig_type == KEY_TYPE_SK_ED25519.as_bytes() {
            true
        } else {
            return Err(Error::UnknownSignatureType);
        };
        let sig = <&[u8; 64]>::try_from(r.string()?).map_err(|_| Error::BadSignatureLength)?;
        let s = if is_sk {
            let flags = r.u8()?;
            let counter = r.u32()?;
            Signature::SkEd25519 {
                sig,
                flags,
                counter,
            }
        } else {
            Signature::Ed25519 { sig }
        };
        r.finish(Section::Signature)?;
        Ok(s)
    }

    /// Encoded blob length: 83 for `ssh-ed25519`, 103 for
    /// `sk-ssh-ed25519@openssh.com`.
    pub const fn blob_len(&self) -> usize {
        match self {
            Signature::Ed25519 { .. } => string_len(KEY_TYPE_ED25519.len()) + string_len(64),
            Signature::SkEd25519 { .. } => {
                string_len(KEY_TYPE_SK_ED25519.len()) + string_len(64) + 1 + 4
            }
        }
    }

    /// Write the blob fields through `w`.
    pub(crate) fn write_to(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.put_string(self.sig_type().as_bytes())?;
        w.put_string(self.sig())?;
        if let Signature::SkEd25519 { flags, counter, .. } = self {
            w.put_u8(*flags)?;
            w.put_u32(*counter)?;
        }
        Ok(())
    }

    /// Encode the blob into `out`; returns bytes written
    /// ([`Signature::blob_len`]).
    pub fn encode_blob(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        self.write_to(&mut w)?;
        Ok(w.finish())
    }
}

/// Borrowed, structurally valid SSHSIG blob. Structural only — the
/// predicate is applied by [`crate::verify()`]. `reserved` and
/// `hash_algorithm` are exposed verbatim so a caller can inspect a
/// signature that `verify` will reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SshSig<'a> {
    /// The embedded signer key.
    pub public_key: PublicKey<'a>,
    /// The namespace the signer claimed. `verify` only *compares* it; the
    /// signed data is rebuilt from the verifier's expected constant.
    pub namespace: &'a [u8],
    /// Must be empty for `verify` to accept.
    pub reserved: &'a [u8],
    /// Must be `sha512` for `verify` to accept.
    pub hash_algorithm: &'a [u8],
    /// The signature blob.
    pub signature: Signature<'a>,
}

impl<'a> SshSig<'a> {
    /// Parse a raw blob.
    ///
    /// Order and errors: 6 bytes magic ([`Error::Truncated`] /
    /// [`Error::BadMagic`]); `uint32` version `!= 1` →
    /// [`Error::UnsupportedVersion`]; string publickey →
    /// [`PublicKey::parse_blob`]; string namespace; string reserved; string
    /// hash_algorithm; string signature → [`Signature::parse_blob`]; then
    /// the outer buffer must be consumed exactly
    /// ([`Error::TrailingBytes`]`(`[`Section::Outer`]`)`); finally the key
    /// and signature families must agree (`Ed25519`↔`Ed25519`,
    /// `SkEd25519`↔`SkEd25519`) else [`Error::KeyTypeMismatch`].
    pub fn parse(blob: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(blob);
        if r.bytes(MAGIC.len())? != MAGIC {
            return Err(Error::BadMagic);
        }
        if r.u32()? != SSHSIG_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let public_key = PublicKey::parse_blob(r.string()?)?;
        let namespace = r.string()?;
        let reserved = r.string()?;
        let hash_algorithm = r.string()?;
        let signature = Signature::parse_blob(r.string()?)?;
        r.finish(Section::Outer)?;
        if public_key.is_sk() != matches!(signature, Signature::SkEd25519 { .. }) {
            return Err(Error::KeyTypeMismatch);
        }
        Ok(Self {
            public_key,
            namespace,
            reserved,
            hash_algorithm,
            signature,
        })
    }

    /// [`armor::decode`] into `buf`, then [`SshSig::parse`] the decoded
    /// prefix. `buf` should hold
    /// [`armor::max_decoded_len`]`(armored.len())` bytes.
    pub fn from_armored(armored: &[u8], buf: &'a mut [u8]) -> Result<Self, Error> {
        let n = armor::decode(armored, buf)?;
        let blob: &'a [u8] = &buf[..n];
        Self::parse(blob)
    }

    /// Length [`SshSig::encode`] will write.
    pub fn encoded_len(&self) -> usize {
        MAGIC.len()
            + 4
            + string_len(self.public_key.blob_len())
            + string_len(self.namespace.len())
            + string_len(self.reserved.len())
            + string_len(self.hash_algorithm.len())
            + string_len(self.signature.blob_len())
    }

    /// Encode the raw blob into `out`; returns bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.put_bytes(MAGIC)?;
        w.put_u32(SSHSIG_VERSION)?;
        let pk_len = u32::try_from(self.public_key.blob_len()).map_err(|_| Error::TooLong)?;
        w.put_u32(pk_len)?;
        self.public_key.write_to(&mut w)?;
        w.put_string(self.namespace)?;
        w.put_string(self.reserved)?;
        w.put_string(self.hash_algorithm)?;
        let sig_len = u32::try_from(self.signature.blob_len()).map_err(|_| Error::TooLong)?;
        w.put_u32(sig_len)?;
        self.signature.write_to(&mut w)?;
        Ok(w.finish())
    }

    /// [`SshSig::encode`] into a fresh `Vec`.
    ///
    /// # Panics
    /// If a field exceeds `u32::MAX` bytes (the SSH `string` limit; the
    /// buffer API returns [`Error::TooLong`] instead).
    #[cfg(feature = "alloc")]
    pub fn encode_vec(&self) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![0u8; self.encoded_len()];
        let n = self.encode(&mut v).expect("buffer sized by encoded_len");
        v.truncate(n);
        v
    }

    /// [`SshSig::encode_vec`] then [`armor::encode_string`]; panics under
    /// the same condition.
    #[cfg(feature = "alloc")]
    pub fn encode_armored(&self) -> alloc::string::String {
        armor::encode_string(&self.encode_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x22; 32];
    const SIG: [u8; 64] = [0x33; 64];
    const NS: &[u8] = b"test-ns";

    fn sample() -> SshSig<'static> {
        SshSig {
            public_key: PublicKey::Ed25519 { key: &KEY },
            namespace: NS,
            reserved: b"",
            hash_algorithm: HASH_ALGORITHM_SHA512,
            signature: Signature::Ed25519 { sig: &SIG },
        }
    }

    fn sample_sk() -> SshSig<'static> {
        SshSig {
            public_key: PublicKey::SkEd25519 {
                key: &KEY,
                application: b"ssh:",
            },
            namespace: NS,
            reserved: b"",
            hash_algorithm: HASH_ALGORITHM_SHA512,
            signature: Signature::SkEd25519 {
                sig: &SIG,
                flags: 0x05,
                counter: 0x0102_0304,
            },
        }
    }

    #[test]
    fn lengths() {
        assert_eq!(ed25519_sshsig_len(NS.len()), 177);
        assert_eq!(sample().encoded_len(), 177);
        assert_eq!(Signature::Ed25519 { sig: &SIG }.blob_len(), 83);
        assert_eq!(
            Signature::SkEd25519 {
                sig: &SIG,
                flags: 1,
                counter: 1
            }
            .blob_len(),
            103
        );
        // 10 + (4+74) + (4+7) + 4 + 10 + (4+103)
        assert_eq!(sample_sk().encoded_len(), 220);
    }

    #[test]
    fn encode_parse_round_trip() {
        for s in [sample(), sample_sk()] {
            let mut buf = [0u8; 256];
            let n = s.encode(&mut buf).unwrap();
            assert_eq!(n, s.encoded_len());
            assert_eq!(&buf[..6], MAGIC);
            assert_eq!(&buf[6..10], &[0, 0, 0, 1]);
            let parsed = SshSig::parse(&buf[..n]).unwrap();
            assert_eq!(parsed, s);
            assert_eq!(s.encode(&mut buf[..n - 1]), Err(Error::BufferTooSmall));
        }
    }

    #[test]
    fn signature_blob_round_trip_and_errors() {
        let s = Signature::SkEd25519 {
            sig: &SIG,
            flags: 0x01,
            counter: 7,
        };
        let mut out = [0u8; 103];
        assert_eq!(s.encode_blob(&mut out), Ok(103));
        assert_eq!(out[98], 0x01);
        assert_eq!(&out[99..], &[0, 0, 0, 7]);
        assert_eq!(Signature::parse_blob(&out), Ok(s));
        assert_eq!(s.sig_type(), KEY_TYPE_SK_ED25519);
        assert_eq!(s.sig(), &SIG);

        // Truncated flags/counter.
        assert_eq!(Signature::parse_blob(&out[..100]), Err(Error::Truncated));
        // Trailing byte.
        let mut long = [0u8; 104];
        long[..103].copy_from_slice(&out);
        assert_eq!(
            Signature::parse_blob(&long),
            Err(Error::TrailingBytes(Section::Signature))
        );
        // Unknown type.
        let mut bad = out;
        bad[4] = b'x';
        assert_eq!(
            Signature::parse_blob(&bad),
            Err(Error::UnknownSignatureType)
        );
        // 63-byte signature.
        let e = Signature::Ed25519 { sig: &SIG };
        let mut out = [0u8; 83];
        e.encode_blob(&mut out).unwrap();
        out[18] = 63;
        assert_eq!(
            Signature::parse_blob(&out[..82]),
            Err(Error::BadSignatureLength)
        );
        assert_eq!(Signature::parse_blob(&[]), Err(Error::Truncated));
    }

    #[test]
    fn parse_errors() {
        let s = sample();
        let mut buf = [0u8; 200];
        let n = s.encode(&mut buf).unwrap();

        assert_eq!(SshSig::parse(&buf[..5]), Err(Error::Truncated));
        let mut m = buf;
        m[5] = b'H';
        assert_eq!(SshSig::parse(&m[..n]), Err(Error::BadMagic));
        let mut v = buf;
        v[9] = 2;
        assert_eq!(SshSig::parse(&v[..n]), Err(Error::UnsupportedVersion));
        assert_eq!(SshSig::parse(&buf[..n - 10]), Err(Error::Truncated));
        assert_eq!(
            SshSig::parse(&buf[..n + 1]),
            Err(Error::TrailingBytes(Section::Outer))
        );
        // Key-family / signature-family disagreement: ssh-ed25519 key with
        // an sk-layout signature.
        let mixed = SshSig {
            signature: Signature::SkEd25519 {
                sig: &SIG,
                flags: 1,
                counter: 1,
            },
            ..sample()
        };
        let n = mixed.encode(&mut buf).unwrap();
        assert_eq!(SshSig::parse(&buf[..n]), Err(Error::KeyTypeMismatch));
        let mixed = SshSig {
            public_key: PublicKey::SkEd25519 {
                key: &KEY,
                application: b"ssh:",
            },
            ..sample()
        };
        let n = mixed.encode(&mut buf).unwrap();
        assert_eq!(SshSig::parse(&buf[..n]), Err(Error::KeyTypeMismatch));
    }

    #[test]
    fn from_armored_round_trip() {
        let s = sample();
        let mut raw = [0u8; 177];
        s.encode(&mut raw).unwrap();
        let mut armored = [0u8; 298];
        armor::encode(&raw, &mut armored).unwrap();
        let mut buf = [0u8; 256];
        let parsed = SshSig::from_armored(&armored, &mut buf).unwrap();
        assert_eq!(parsed, s);
        let mut buf = [0u8; 256];
        assert_eq!(
            SshSig::from_armored(&armored[1..], &mut buf),
            Err(Error::ArmorMissingHeader)
        );
    }

    #[cfg(feature = "alloc")]
    mod with_alloc {
        use super::super::*;
        use super::sample;

        #[test]
        fn alloc_encoders_match() {
            let s = sample();
            let mut raw = [0u8; 177];
            s.encode(&mut raw).unwrap();
            assert_eq!(s.encode_vec(), &raw[..]);
            assert_eq!(s.encode_armored(), armor::encode_string(&raw));
        }
    }
}
