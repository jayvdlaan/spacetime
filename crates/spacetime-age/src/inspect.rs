//! Header-only inspection: what a file is addressed to, without any key.
//!
//! This is pre-authentication data — the header MAC is **not** checked, so
//! the counts and the tag are exactly as trustworthy as the bytes on disk.
//! A typical ingest predicate ("exactly one ssh-ed25519 stanza whose tag is
//! ours, no scrypt, no ssh-rsa, grease ignored") is
//! [`Inspection::is_single_ssh_ed25519`].

use crate::error::{Error, HeaderError};
use crate::header::Header;
#[cfg(feature = "alloc")]
use crate::stanza::StanzaKind;

/// A parsed header with its stanza counts.
#[derive(Clone, Copy, Debug)]
pub struct Inspection<'a> {
    /// The parsed header.
    pub header: Header<'a>,
    /// Number of `X25519` stanzas.
    pub x25519: usize,
    /// Number of `ssh-ed25519` stanzas.
    pub ssh_ed25519: usize,
    /// Number of `scrypt` stanzas.
    pub scrypt: usize,
    /// Number of `ssh-rsa` stanzas.
    pub ssh_rsa: usize,
    /// Number of unrecognised (grease) stanzas.
    pub unknown: usize,
    /// `Some(tag)` iff exactly one ssh-ed25519 stanza is present.
    pub ssh_ed25519_tag: Option<[u8; 4]>,
}

impl<'a> Inspection<'a> {
    fn of(header: Header<'a>) -> Result<Self, Error> {
        let (x25519, ssh_ed25519, scrypt, ssh_rsa, unknown) = header.counts();
        let ssh_ed25519_tag = if ssh_ed25519 == 1 {
            let st = header
                .stanzas()
                .find(|s| s.kind() == crate::stanza::StanzaKind::SshEd25519)
                .ok_or(Error::Header(HeaderError::SshEd25519Stanza))?;
            Some(st.arg_bytes::<4>(0, Error::Header(HeaderError::SshEd25519Stanza))?)
        } else {
            None
        };
        Ok(Self {
            header,
            x25519,
            ssh_ed25519,
            scrypt,
            ssh_rsa,
            unknown,
            ssh_ed25519_tag,
        })
    }

    /// `ssh_ed25519 == 1 && scrypt == 0 && ssh_rsa == 0 && ssh_ed25519_tag
    /// == Some(*tag)`.
    ///
    /// Deliberately silent on the other counts: `X25519` co-recipients and
    /// grease stanzas alongside the single ssh-ed25519 stanza satisfy the
    /// predicate ("addressed to us", not "addressed only to us"). A caller
    /// that must refuse co-recipients adds `&& inspection.x25519 == 0`
    /// (and `unknown == 0`). Pre-authentication data: a header can carry
    /// our tag without being decryptable by us.
    pub fn is_single_ssh_ed25519(&self, tag: &[u8; 4]) -> bool {
        self.ssh_ed25519 == 1
            && self.scrypt == 0
            && self.ssh_rsa == 0
            && self.ssh_ed25519_tag.as_ref() == Some(tag)
    }

    /// Owned copy with every stanza materialised.
    #[cfg(feature = "alloc")]
    pub fn to_buf(&self) -> InspectionBuf {
        use alloc::string::String;
        use alloc::vec::Vec;
        let stanzas = self
            .header
            .stanzas()
            .map(|s| {
                let mut body = alloc::vec![0u8; s.body_len()];
                // Cannot fail: the buffer has exactly `body_len` bytes.
                let n = s.body(&mut body).unwrap_or(0);
                body.truncate(n);
                StanzaBuf {
                    kind: s.kind(),
                    stanza_type: String::from(s.stanza_type()),
                    args: s.args().map(String::from).collect::<Vec<_>>(),
                    body,
                }
            })
            .collect();
        InspectionBuf {
            stanzas,
            x25519: self.x25519,
            ssh_ed25519: self.ssh_ed25519,
            scrypt: self.scrypt,
            ssh_rsa: self.ssh_rsa,
            unknown: self.unknown,
            ssh_ed25519_tag: self.ssh_ed25519_tag,
            header_len: self.header.len(),
        }
    }
}

/// [`Header::parse`] plus counts.
pub fn inspect(input: &[u8]) -> Result<Inspection<'_>, Error> {
    Inspection::of(Header::parse(input)?)
}

/// [`Header::from_armored`] plus counts.
pub fn inspect_armored<'b>(armored: &[u8], buf: &'b mut [u8]) -> Result<Inspection<'b>, Error> {
    Inspection::of(Header::from_armored(armored, buf)?)
}

/// An owned stanza.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StanzaBuf {
    /// Classification of the type.
    pub kind: StanzaKind,
    /// The type string.
    pub stanza_type: alloc::string::String,
    /// The arguments.
    pub args: alloc::vec::Vec<alloc::string::String>,
    /// The decoded body.
    pub body: alloc::vec::Vec<u8>,
}

/// An owned [`Inspection`].
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectionBuf {
    /// Every stanza, in order.
    pub stanzas: alloc::vec::Vec<StanzaBuf>,
    /// Number of `X25519` stanzas.
    pub x25519: usize,
    /// Number of `ssh-ed25519` stanzas.
    pub ssh_ed25519: usize,
    /// Number of `scrypt` stanzas.
    pub scrypt: usize,
    /// Number of `ssh-rsa` stanzas.
    pub ssh_rsa: usize,
    /// Number of unrecognised (grease) stanzas.
    pub unknown: usize,
    /// `Some(tag)` iff exactly one ssh-ed25519 stanza is present.
    pub ssh_ed25519_tag: Option<[u8; 4]>,
    /// Header length through the MAC line.
    pub header_len: usize,
}

#[cfg(feature = "alloc")]
impl InspectionBuf {
    /// The same predicate as [`Inspection::is_single_ssh_ed25519`].
    pub fn is_single_ssh_ed25519(&self, tag: &[u8; 4]) -> bool {
        self.ssh_ed25519 == 1
            && self.scrypt == 0
            && self.ssh_rsa == 0
            && self.ssh_ed25519_tag.as_ref() == Some(tag)
    }
}

/// Inspect either form: [`crate::armor::is_armored`] ? decode then inspect
/// : inspect as is.
#[cfg(feature = "alloc")]
pub fn inspect_auto(input: &[u8]) -> Result<InspectionBuf, Error> {
    if crate::armor::is_armored(input) {
        let v = crate::armor::decode_vec(input)?;
        Ok(inspect(&v)?.to_buf())
    } else {
        Ok(inspect(input)?.to_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &[u8] = b"age-encryption.org/v1\n-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc\nhjabGXwSLQ9c3S6Lw2i+S2Tu2fiwQHHslbBN6B41FLE\n-> ssh-ed25519 64jdUw NOQtSvXvlKB6OoQgG4idTNGnQ8snsRtqEEOKj+uOWEc\n2BYYubiSZ09zSTlnTeKpXOrVuAcD4GX1JTfFQSu4UmI\n-> grease\nAAAA\n--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg\n0123456789abcdef";
    const TAG: [u8; 4] = [0xeb, 0x88, 0xdd, 0x53];

    #[test]
    fn counts_and_tag() {
        let i = inspect(HEADER).unwrap();
        assert_eq!(
            (i.x25519, i.ssh_ed25519, i.scrypt, i.ssh_rsa, i.unknown),
            (1, 1, 0, 0, 1)
        );
        assert_eq!(i.ssh_ed25519_tag, Some(TAG));
        assert!(i.is_single_ssh_ed25519(&TAG));
        assert!(!i.is_single_ssh_ed25519(&[0; 4]));
        assert_eq!(i.header.stanza_count(), 3);
    }

    #[test]
    fn two_ssh_stanzas_have_no_single_tag() {
        let mut buf = [0u8; 512];
        let ssh = b"-> ssh-ed25519 64jdUw NOQtSvXvlKB6OoQgG4idTNGnQ8snsRtqEEOKj+uOWEc\n2BYYubiSZ09zSTlnTeKpXOrVuAcD4GX1JTfFQSu4UmI\n";
        let mac = b"--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg\n0123456789abcdef";
        let mut n = 0;
        for part in [&crate::header::MAGIC[..], ssh, ssh, mac] {
            buf[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        let i = inspect(&buf[..n]).unwrap();
        assert_eq!(i.ssh_ed25519, 2);
        assert_eq!(i.ssh_ed25519_tag, None);
        assert!(!i.is_single_ssh_ed25519(&TAG));
    }

    #[test]
    fn scrypt_blocks_the_predicate() {
        let input = b"age-encryption.org/v1\n-> scrypt salt 18\nAAAA\n--- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg\n0123456789abcdef";
        let i = inspect(input).unwrap();
        assert_eq!(i.scrypt, 1);
        assert!(!i.is_single_ssh_ed25519(&TAG));
    }

    #[test]
    fn armored_inspection() {
        let mut armored = [0u8; 1024];
        let n = crate::armor::encode(HEADER, &mut armored).unwrap();
        let mut buf = [0u8; 1024];
        let i = inspect_armored(&armored[..n], &mut buf).unwrap();
        assert!(i.is_single_ssh_ed25519(&TAG));
        assert_eq!(
            inspect_armored(b"nope", &mut buf).map(|_| ()),
            Err(Error::Armor(crate::error::ArmorError::MissingBegin))
        );
    }

    #[test]
    fn errors_propagate() {
        assert_eq!(
            inspect(b"age-encryption.org/v2\n").map(|_| ()),
            Err(Error::Header(HeaderError::BadMagic))
        );
    }
}
