//! File keys, recipients and identities.
//!
//! [`Recipient`] is public data (`Copy`, public fields). [`FileKey`] and
//! [`Identity`] are owned secrets with private fields: they never
//! `Debug`-print their bytes, are compared only where the caller explicitly
//! asks for the bytes, and are wiped on drop (best effort, see
//! `crate::util::wipe`).
//!
//! String forms (bech32, BIP-173): `age1…` is an X25519 public key,
//! `AGE-SECRET-KEY-1…` an X25519 scalar (uppercase by convention; both cases
//! parse). An ssh-ed25519 key has no age string form; it is the raw 32-byte
//! Ed25519 public key or seed, and the SSH wire form is built in-crate.

use spacetime_crypto::{Ed25519Sign, Rng, Sha256, X25519};

use crate::bech32;
use crate::error::{Error, KeyError};
use crate::ssh_ed25519;
use crate::util::wipe;

/// age file key length.
pub const FILE_KEY_LEN: usize = 16;
/// `age1` + 52 data characters + 6 checksum characters.
pub const RECIPIENT_STR_LEN: usize = 62;
/// `AGE-SECRET-KEY-1` + 52 + 6.
pub const IDENTITY_STR_LEN: usize = 74;
/// Recipient HRP.
pub const RECIPIENT_HRP: &str = "age";
/// Identity HRP (lowercase; the string form is uppercased).
pub const IDENTITY_HRP: &str = "age-secret-key-";

/// The 16-byte age file key. Wiped on drop (best effort). `Debug` prints
/// `FileKey(<redacted>)`. `==` is a plain short-circuit comparison, kept
/// for known-answer tests; nothing in this crate compares file keys (the
/// header MAC and the AEAD tags authenticate — a file key is never matched
/// against another), so unlike [`Identity`] it needs no constant-time
/// equality.
#[derive(Clone, PartialEq, Eq)]
pub struct FileKey([u8; FILE_KEY_LEN]);

impl FileKey {
    /// Wrap 16 bytes.
    pub const fn from_bytes(bytes: [u8; FILE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Draw 16 bytes from `rng`. An `Rng` error is `Backend(kind)`.
    pub fn generate<R: Rng + ?Sized>(rng: &mut R) -> Result<Self, Error> {
        let mut k = [0u8; FILE_KEY_LEN];
        rng.fill_bytes(&mut k)?;
        Ok(Self(k))
    }

    /// The raw key.
    pub const fn as_bytes(&self) -> &[u8; FILE_KEY_LEN] {
        &self.0
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl core::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FileKey(<redacted>)")
    }
}

/// A recipient: public data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    /// `age1…` — an X25519 public key.
    X25519 {
        /// The Montgomery `u`-coordinate, little-endian.
        public_key: [u8; 32],
    },
    /// An OpenSSH `ssh-ed25519` public key (raw 32 bytes; the SSH wire form
    /// is built in-crate).
    SshEd25519 {
        /// The compressed Edwards point.
        public_key: [u8; 32],
    },
}

/// Split `s` at its bech32 separator and check the HRP (case-insensitively)
/// and the total length; returns nothing but the errors of the contract
/// (`Key(Bech32)` for no separator, `Key(Hrp)`, `Key(Length)`).
fn check_hrp_and_len(s: &str, hrp: &str, total_len: usize) -> Result<(), Error> {
    let sep = s
        .as_bytes()
        .iter()
        .rposition(|&c| c == b'1')
        .ok_or(Error::Key(KeyError::Bech32))?;
    if !s.as_bytes()[..sep].eq_ignore_ascii_case(hrp.as_bytes()) {
        return Err(Error::Key(KeyError::Hrp));
    }
    if s.len() != total_len {
        return Err(Error::Key(KeyError::Length));
    }
    Ok(())
}

/// Decode a 32-byte bech32 key string with the given HRP.
fn decode_key(s: &str, hrp: &str, total_len: usize) -> Result<[u8; 32], Error> {
    check_hrp_and_len(s, hrp, total_len)?;
    let mut out = [0u8; 32];
    let (_, n) = bech32::decode(s, &mut out)?;
    if n != 32 {
        wipe(&mut out);
        return Err(Error::Key(KeyError::Length));
    }
    Ok(out)
}

impl Recipient {
    /// Parse `age1…` (lowercase or uppercase bech32, HRP `age`, 32 bytes,
    /// exactly 62 characters).
    pub fn from_age_str(s: &str) -> Result<Self, Error> {
        let public_key = decode_key(s, RECIPIENT_HRP, RECIPIENT_STR_LEN)?;
        Ok(Recipient::X25519 { public_key })
    }

    /// `age1…` for X25519; ssh-ed25519 → `Key(NotEncodable)`.
    pub fn encode_age<'o>(&self, out: &'o mut [u8; RECIPIENT_STR_LEN]) -> Result<&'o str, Error> {
        match self {
            Recipient::X25519 { public_key } => {
                let n = bech32::encode(RECIPIENT_HRP, public_key, out)?;
                core::str::from_utf8(&out[..n])
                    .map_err(|_| Error::Backend(spacetime_crypto::CryptoErrorKind::Failed))
            }
            Recipient::SshEd25519 { .. } => Err(Error::Key(KeyError::NotEncodable)),
        }
    }

    /// Owned [`Recipient::encode_age`].
    #[cfg(feature = "alloc")]
    pub fn to_age_string(&self) -> Result<alloc::string::String, Error> {
        let mut buf = [0u8; RECIPIENT_STR_LEN];
        self.encode_age(&mut buf).map(alloc::string::String::from)
    }

    /// SSH wire form `string "ssh-ed25519" || string key` (51 bytes) —
    /// ssh-ed25519 only.
    pub fn ssh_wire(&self) -> Option<[u8; ssh_ed25519::WIRE_LEN]> {
        match self {
            Recipient::SshEd25519 { public_key } => Some(ssh_ed25519::ssh_wire(public_key)),
            Recipient::X25519 { .. } => None,
        }
    }

    /// `SHA-256(ssh_wire)[0..4]` — ssh-ed25519 only (`None` for X25519).
    pub fn ssh_tag<H: Sha256 + ?Sized>(&self, h: &H) -> Result<Option<[u8; 4]>, Error> {
        match self {
            Recipient::SshEd25519 { public_key } => ssh_ed25519::tag(h, public_key).map(Some),
            Recipient::X25519 { .. } => Ok(None),
        }
    }
}

/// Which secret an [`Identity`] holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityKind {
    /// An X25519 scalar (`AGE-SECRET-KEY-1…`).
    X25519,
    /// An Ed25519 seed (OpenSSH `ssh-ed25519` key).
    SshEd25519,
}

/// An owned secret: an X25519 scalar or an Ed25519 seed. Wiped on drop
/// (best effort). `Debug` is redacted. `PartialEq` is deliberately not
/// implemented (no timing-visible secret comparison); compare
/// [`Identity::secret`] explicitly where a test needs to.
#[derive(Clone)]
pub struct Identity {
    kind: IdentityKind,
    secret: [u8; 32],
}

impl Identity {
    /// An X25519 identity from its scalar.
    pub const fn x25519(secret: [u8; 32]) -> Self {
        Self {
            kind: IdentityKind::X25519,
            secret,
        }
    }

    /// An ssh-ed25519 identity from the Ed25519 seed.
    pub const fn ssh_ed25519(seed: [u8; 32]) -> Self {
        Self {
            kind: IdentityKind::SshEd25519,
            secret: seed,
        }
    }

    /// Which secret this is.
    pub const fn kind(&self) -> IdentityKind {
        self.kind
    }

    /// The raw secret bytes.
    pub const fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Parse `AGE-SECRET-KEY-1…` (lower or upper case, HRP `age-secret-key-`,
    /// 32 bytes, exactly 74 characters). `AGE-SECRET-KEY-PQ-…` and
    /// `AGE-PLUGIN-…` fail with `Key(Hrp)`.
    pub fn from_age_str(s: &str) -> Result<Self, Error> {
        let secret = decode_key(s, IDENTITY_HRP, IDENTITY_STR_LEN)?;
        Ok(Self::x25519(secret))
    }

    /// Uppercase `AGE-SECRET-KEY-1…`; ssh-ed25519 → `Key(NotEncodable)`.
    pub fn encode_age<'o>(&self, out: &'o mut [u8; IDENTITY_STR_LEN]) -> Result<&'o str, Error> {
        match self.kind {
            IdentityKind::X25519 => {
                let n = bech32::encode(IDENTITY_HRP, &self.secret, out)?;
                out[..n].make_ascii_uppercase();
                core::str::from_utf8(&out[..n])
                    .map_err(|_| Error::Backend(spacetime_crypto::CryptoErrorKind::Failed))
            }
            IdentityKind::SshEd25519 => Err(Error::Key(KeyError::NotEncodable)),
        }
    }

    /// Owned [`Identity::encode_age`].
    #[cfg(feature = "alloc")]
    pub fn to_age_string(&self) -> Result<alloc::string::String, Error> {
        let mut buf = [0u8; IDENTITY_STR_LEN];
        let s = self.encode_age(&mut buf).map(alloc::string::String::from);
        wipe(&mut buf);
        s
    }

    /// The matching recipient: X25519 → `x25519_public_key(secret)`;
    /// ssh-ed25519 → `ed25519_public_key(seed)`.
    pub fn recipient<B: X25519 + Ed25519Sign + ?Sized>(&self, b: &B) -> Result<Recipient, Error> {
        match self.kind {
            IdentityKind::X25519 => Ok(Recipient::X25519 {
                public_key: b.x25519_public_key(&self.secret)?,
            }),
            IdentityKind::SshEd25519 => Ok(Recipient::SshEd25519 {
                public_key: b.ed25519_public_key(&self.secret)?,
            }),
        }
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity({:?}, <redacted>)", self.kind)
    }
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

    /// Writes `Debug` output into a fixed buffer without allocating.
    struct Buf {
        data: [u8; 64],
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

    fn debug_of(v: &dyn core::fmt::Debug) -> Buf {
        use core::fmt::Write;
        let mut b = Buf {
            data: [0; 64],
            len: 0,
        };
        write!(b, "{v:?}").unwrap();
        b
    }

    #[test]
    fn recipient_round_trip() {
        let r = Recipient::from_age_str(RECIPIENT).unwrap();
        assert_eq!(r, Recipient::X25519 { public_key: PUBLIC });
        let mut out = [0u8; RECIPIENT_STR_LEN];
        assert_eq!(r.encode_age(&mut out).unwrap(), RECIPIENT);
        let upper = RECIPIENT.to_ascii_uppercase();
        assert_eq!(Recipient::from_age_str(&upper).unwrap(), r);
    }

    #[test]
    fn identity_round_trip() {
        let id = Identity::from_age_str(IDENTITY).unwrap();
        assert_eq!(id.kind(), IdentityKind::X25519);
        assert_eq!(id.secret(), &SECRET);
        let mut out = [0u8; IDENTITY_STR_LEN];
        assert_eq!(id.encode_age(&mut out).unwrap(), IDENTITY);
        let lower = IDENTITY.to_ascii_lowercase();
        assert_eq!(Identity::from_age_str(&lower).unwrap().secret(), &SECRET);
    }

    #[test]
    fn wrong_hrp_and_lengths() {
        assert_eq!(
            Recipient::from_age_str(IDENTITY),
            Err(Error::Key(KeyError::Hrp))
        );
        assert_eq!(
            Identity::from_age_str(RECIPIENT).map(|_| ()),
            Err(Error::Key(KeyError::Hrp))
        );
        assert_eq!(
            Identity::from_age_str("AGE-SECRET-KEY-PQ-1QQQQQQQ").map(|_| ()),
            Err(Error::Key(KeyError::Hrp))
        );
        assert_eq!(
            Identity::from_age_str("AGE-PLUGIN-YUBIKEY-1QQQQQQQ").map(|_| ()),
            Err(Error::Key(KeyError::Hrp))
        );
        assert_eq!(
            Recipient::from_age_str("noseparator"),
            Err(Error::Key(KeyError::Bech32))
        );
        // A 31-byte payload has a different total length.
        let mut buf = [0u8; 80];
        let n = bech32::encode("age", &PUBLIC[..31], &mut buf).unwrap();
        let s = core::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(
            Recipient::from_age_str(s),
            Err(Error::Key(KeyError::Length))
        );
        // Right length, bad checksum.
        let mut bad = [0u8; 62];
        bad.copy_from_slice(RECIPIENT.as_bytes());
        bad[61] = b'q';
        assert_eq!(
            Recipient::from_age_str(core::str::from_utf8(&bad).unwrap()),
            Err(Error::Key(KeyError::Bech32))
        );
    }

    #[test]
    fn ssh_keys_have_no_string_form() {
        let r = Recipient::SshEd25519 {
            public_key: [7; 32],
        };
        assert_eq!(
            r.encode_age(&mut [0u8; RECIPIENT_STR_LEN]),
            Err(Error::Key(KeyError::NotEncodable))
        );
        let id = Identity::ssh_ed25519([7; 32]);
        assert_eq!(
            id.encode_age(&mut [0u8; IDENTITY_STR_LEN]),
            Err(Error::Key(KeyError::NotEncodable))
        );
        assert_eq!(id.kind(), IdentityKind::SshEd25519);
        let wire = r.ssh_wire().unwrap();
        assert_eq!(&wire[..15], b"\x00\x00\x00\x0bssh-ed25519");
        assert_eq!(&wire[15..19], &[0, 0, 0, 32]);
        assert_eq!(&wire[19..], &[7u8; 32]);
        assert!(Recipient::X25519 {
            public_key: [0; 32]
        }
        .ssh_wire()
        .is_none());
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let fk = FileKey::from_bytes([0xAB; 16]);
        let d = debug_of(&fk);
        assert_eq!(&d.data[..d.len], b"FileKey(<redacted>)");
        let id = Identity::x25519([0xAB; 32]);
        let d = debug_of(&id);
        assert_eq!(&d.data[..d.len], b"Identity(X25519, <redacted>)");
        assert!(!d.data.contains(&0xAB));
    }

    #[test]
    fn file_key_accessors() {
        let fk = FileKey::from_bytes([1; 16]);
        assert_eq!(fk.as_bytes(), &[1; 16]);
        assert_eq!(fk.clone(), fk);
    }
}
