//! OpenSSH `allowed_signers` roster (ssh-keygen(1) "ALLOWED SIGNERS"),
//! parsed zero-copy.
//!
//! Line grammar (exact): strip one trailing `"\r\n"`/`"\n"`; trim leading
//! spaces/tabs; empty or `#` first → not an entry. Fields are separated by
//! runs of spaces/tabs:
//!
//! ```text
//! principals [options] key-type base64 [comment]
//! ```
//!
//! Field 2 is the **options** field iff it starts with `"`, contains `=`,
//! or equals `cert-authority` (ASCII case-insensitive); otherwise it is the
//! key type. Options are comma-separated `name` or `name="value"`; a value
//! **must** be double-quoted, exactly as ssh-keygen requires (`opt_dequote`:
//! an unquoted value is "missing start quote" there), and runs to the next
//! `"` (commas inside are literal; backslashes are not interpreted) — no
//! whitespace is allowed inside the field. Names are ASCII
//! case-insensitive: `cert-authority` (no value), `namespaces`,
//! `valid-after`, `valid-before` (value required, non-empty). Any other
//! name → [`Error::AllowedSignersUnknownOption`]; a repeated option, a
//! missing/empty/unquoted value, a value on `cert-authority`, an
//! unterminated quote → [`Error::AllowedSignersLineInvalid`]. The key type
//! must be one of the two constants (else [`Error::UnknownKeyType`]), the
//! base64 token non-empty with alphabet/`=` bytes only (else
//! [`Error::AllowedSignersLineInvalid`]); the remainder, trimmed, is the
//! comment.
//!
//! Principal and namespace matching is **exact**: no glob (`*`, `?`), no
//! negation (`!`). ssh-keygen's pattern syntax is unsupported, and a list
//! item containing any of those three bytes is rejected at parse time
//! ([`Error::AllowedSignersLineInvalid`]) rather than matched literally —
//! otherwise `alice,!alice` would match here and not there. That is
//! stricter than ssh-keygen, which is the permitted direction.
//!
//! `valid-after` / `valid-before` are carried as raw strings. An entry that
//! has either never satisfies [`AllowedSigner::accepts`], which knows no
//! clock; [`AllowedSigner::accepts_at`] takes the verification time and
//! applies ssh-keygen's window (`valid-after <= now <= valid-before`). Only
//! the UTC forms (`YYYYMMDDZ`, `YYYYMMDDHHMM[SS]Z`) are interpreted: without
//! the `Z` ssh-keygen reads local time, which a `no_std` crate cannot know,
//! so such a window — like any malformed one — fails closed.
//!
//! A `cert-authority` entry names a certificate CA. ssh-keygen never matches
//! a plain (non-certificate) SSHSIG against such a line, and certificates are
//! a non-goal of this crate, so a CA entry can never legitimately match a
//! signature here: use [`AllowedSigner::accepts`], which excludes them.

use crate::armor;
use crate::error::Error;
use crate::pubkey::{next_token, strip_newline, PublicKey, KEY_TYPE_ED25519, KEY_TYPE_SK_ED25519};

/// One non-comment line of an `allowed_signers` file, borrowed from the
/// text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowedSigner<'a> {
    /// Raw comma-separated pattern list, as written.
    pub principals: &'a str,
    /// `cert-authority` option present: the entry names a certificate CA,
    /// not a signer. ssh-keygen never matches a plain SSHSIG against it and
    /// this crate has no certificate support, so such an entry MUST NOT be
    /// used to accept a signature ([`AllowedSigner::accepts`] returns
    /// `false` for it).
    pub cert_authority: bool,
    /// `namespaces=` raw value, quotes removed.
    pub namespaces: Option<&'a str>,
    /// `valid-after=` raw value (`YYYYMMDD[Z]` | `YYYYMMDDHHMM[SS][Z]`);
    /// evaluated only by [`AllowedSigner::accepts_at`].
    pub valid_after: Option<&'a str>,
    /// `valid-before=` raw value; evaluated only by
    /// [`AllowedSigner::accepts_at`].
    pub valid_before: Option<&'a str>,
    /// One of [`KEY_TYPE_ED25519`] / [`KEY_TYPE_SK_ED25519`] (validated).
    pub key_type: &'a str,
    /// Base64 of the key blob; alphabet validated, decoded on demand.
    pub key_base64: &'a str,
    /// Trailing comment, trimmed.
    pub comment: Option<&'a str>,
}

/// Parsed options field.
#[derive(Default)]
struct Options<'a> {
    cert_authority: bool,
    namespaces: Option<&'a str>,
    valid_after: Option<&'a str>,
    valid_before: Option<&'a str>,
}

/// `true` iff `field` is an options field rather than a key type.
fn is_options_field(field: &str) -> bool {
    field.starts_with('"') || field.contains('=') || field.eq_ignore_ascii_case("cert-authority")
}

/// The value part of one option.
enum OptValue<'a> {
    /// `name` alone.
    Absent,
    /// `name="value"`, quotes removed.
    Quoted(&'a str),
    /// `name=value` without the opening quote — always invalid, but
    /// reported after the name lookup so an unknown name still yields
    /// [`Error::AllowedSignersUnknownOption`] (ssh-keygen's order).
    Unquoted,
}

/// Split `name[="value"]` off the front of `s`. Returns `(name, value,
/// rest)` where `rest` starts after the separating comma (or is empty).
fn next_option(s: &str) -> Result<(&str, OptValue<'_>, &str), Error> {
    let name_end = s.find(['=', ',']).unwrap_or(s.len());
    let name = &s[..name_end];
    if name.is_empty() {
        return Err(Error::AllowedSignersLineInvalid);
    }
    let after = &s[name_end..];
    if let Some(after_eq) = after.strip_prefix('=') {
        let Some(quoted) = after_eq.strip_prefix('"') else {
            // Skip to the next comma so the caller can still name the option.
            let end = after_eq.find(',').unwrap_or(after_eq.len());
            let rest = after_eq[end..].strip_prefix(',').unwrap_or("");
            return Ok((name, OptValue::Unquoted, rest));
        };
        let close = quoted.find('"').ok_or(Error::AllowedSignersLineInvalid)?;
        let value = &quoted[..close];
        let rest = &quoted[close + 1..];
        let rest = if rest.is_empty() {
            rest
        } else {
            rest.strip_prefix(',')
                .ok_or(Error::AllowedSignersLineInvalid)?
        };
        Ok((name, OptValue::Quoted(value), rest))
    } else {
        let rest = after.strip_prefix(',').unwrap_or(after);
        Ok((name, OptValue::Absent, rest))
    }
}

fn parse_options(field: &str) -> Result<Options<'_>, Error> {
    let mut opts = Options::default();
    let mut rest = field;
    while !rest.is_empty() {
        let (name, value, tail) = next_option(rest)?;
        // A trailing comma (`a=b,`) leaves an empty tail; that is fine, but
        // an empty *name* (`,,`) is caught by `next_option`.
        if name.eq_ignore_ascii_case("cert-authority") {
            if !matches!(value, OptValue::Absent) || opts.cert_authority {
                return Err(Error::AllowedSignersLineInvalid);
            }
            opts.cert_authority = true;
        } else {
            let slot = if name.eq_ignore_ascii_case("namespaces") {
                &mut opts.namespaces
            } else if name.eq_ignore_ascii_case("valid-after") {
                &mut opts.valid_after
            } else if name.eq_ignore_ascii_case("valid-before") {
                &mut opts.valid_before
            } else {
                return Err(Error::AllowedSignersUnknownOption);
            };
            match value {
                OptValue::Quoted(v) if !v.is_empty() && slot.is_none() => *slot = Some(v),
                _ => return Err(Error::AllowedSignersLineInvalid),
            }
        }
        rest = tail;
    }
    Ok(opts)
}

/// `true` iff no comma-separated item of `list` uses ssh-keygen pattern
/// syntax (`!` negation, `*` / `?` glob), which this crate does not
/// interpret.
fn is_literal_list(list: &str) -> bool {
    !list.contains(['!', '*', '?'])
}

/// Days from 1970-01-01 to the proleptic-Gregorian date `y-m-d`
/// (`y >= 1970`, `m` in 1..=12).
fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// An ssh-keygen absolute time in its UTC form — `YYYYMMDDZ` or
/// `YYYYMMDDHHMM[SS]Z` (`Z` either case) — as Unix seconds. `None` for the
/// local-time form (no `Z`), any malformed value, or a date before 1970.
fn parse_utc_time(s: &str) -> Option<u64> {
    let digits = s.strip_suffix(['Z', 'z'])?.as_bytes();
    if !matches!(digits.len(), 8 | 12 | 14) || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let num = |at: usize, len: usize| {
        digits[at..at + len]
            .iter()
            .fold(0u64, |n, &b| n * 10 + u64::from(b - b'0'))
    };
    let (year, month, day) = (num(0, 4), num(4, 2), num(6, 2));
    let (hour, min, sec) = match digits.len() {
        8 => (0, 0, 0),
        12 => (num(8, 2), num(10, 2), 0),
        _ => (num(8, 2), num(10, 2), num(12, 2)),
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if year < 1970 || day == 0 || day > month_days || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + min * 60 + sec)
}

/// ssh-keygen's validity rule at `now` (Unix seconds): `valid_after <= now`
/// and `now <= valid_before`, each only when present. A bound that cannot be
/// interpreted ([`parse_utc_time`]) fails closed.
fn window_admits(valid_after: Option<&str>, valid_before: Option<&str>, now: u64) -> bool {
    valid_after.is_none_or(|s| parse_utc_time(s).is_some_and(|t| t <= now))
        && valid_before.is_none_or(|s| parse_utc_time(s).is_some_and(|t| now <= t))
}

impl<'a> AllowedSigner<'a> {
    /// Parse one line. `Ok(None)` for an empty line or one whose first
    /// non-blank byte is `#`.
    pub fn parse_line(line: &'a str) -> Result<Option<Self>, Error> {
        let line = strip_newline(line);
        let line = line.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            return Ok(None);
        }
        let (principals, rest) = next_token(line).ok_or(Error::AllowedSignersLineInvalid)?;
        if !is_literal_list(principals) {
            return Err(Error::AllowedSignersLineInvalid);
        }
        let (field, rest) = next_token(rest).ok_or(Error::AllowedSignersLineInvalid)?;
        let (opts, key_type, rest) = if is_options_field(field) {
            let opts = parse_options(field)?;
            if !opts.namespaces.is_none_or(is_literal_list) {
                return Err(Error::AllowedSignersLineInvalid);
            }
            let (key_type, rest) = next_token(rest).ok_or(Error::AllowedSignersLineInvalid)?;
            (opts, key_type, rest)
        } else {
            (Options::default(), field, rest)
        };
        if key_type != KEY_TYPE_ED25519 && key_type != KEY_TYPE_SK_ED25519 {
            return Err(Error::UnknownKeyType);
        }
        let (key_base64, rest) = next_token(rest).ok_or(Error::AllowedSignersLineInvalid)?;
        if !key_base64.bytes().all(armor::is_base64_byte) {
            return Err(Error::AllowedSignersLineInvalid);
        }
        let comment = rest.trim_end_matches(|c: char| c.is_ascii_whitespace());
        let comment = if comment.is_empty() {
            None
        } else {
            Some(comment)
        };
        Ok(Some(Self {
            principals,
            cert_authority: opts.cert_authority,
            namespaces: opts.namespaces,
            valid_after: opts.valid_after,
            valid_before: opts.valid_before,
            key_type,
            key_base64,
            comment,
        }))
    }

    /// The principal patterns, split on `,`.
    pub fn principals(&self) -> impl Iterator<Item = &'a str> {
        self.principals.split(',')
    }

    /// Exact match of `name` against any principal item (no glob).
    pub fn has_principal(&self, name: &str) -> bool {
        self.principals().any(|p| p == name)
    }

    /// The `namespaces=` items, split on `,`; empty when the option is
    /// absent.
    pub fn namespace_list(&self) -> impl Iterator<Item = &'a str> {
        self.namespaces.into_iter().flat_map(|s| s.split(','))
    }

    /// `None` → `true` (any namespace); `Some` → exact membership. No glob,
    /// no negation.
    pub fn allows_namespace(&self, namespace: &str) -> bool {
        match self.namespaces {
            None => true,
            Some(_) => self.namespace_list().any(|n| n == namespace),
        }
    }

    /// `true` iff this entry may vouch for a plain SSHSIG by `principal` in
    /// `namespace`: not a `cert-authority` entry (a CA never matches a
    /// signature made directly with its key — ssh-keygen agrees), and
    /// [`has_principal`](Self::has_principal) and
    /// [`allows_namespace`](Self::allows_namespace) both hold. Use this,
    /// not the two predicates alone, to pick the roster key to pin with
    /// `Expected::with_signer`. An entry with `valid-after` or
    /// `valid-before` never accepts here — there is no clock to check the
    /// window against; use [`accepts_at`](Self::accepts_at).
    pub fn accepts(&self, principal: &str, namespace: &str) -> bool {
        self.valid_after.is_none()
            && self.valid_before.is_none()
            && self.accepts_ignoring_window(principal, namespace)
    }

    /// [`accepts`](Self::accepts) at verification time `now` (Unix
    /// seconds): the entry's `valid-after` / `valid-before` window, when
    /// present, must also admit `now` under ssh-keygen's rule. A window in
    /// local-time form or otherwise uninterpretable rejects (see the module
    /// docs).
    pub fn accepts_at(&self, principal: &str, namespace: &str, now: u64) -> bool {
        window_admits(self.valid_after, self.valid_before, now)
            && self.accepts_ignoring_window(principal, namespace)
    }

    fn accepts_ignoring_window(&self, principal: &str, namespace: &str) -> bool {
        !self.cert_authority && self.has_principal(principal) && self.allows_namespace(namespace)
    }

    /// base64-decode into `buf`, [`PublicKey::parse_blob`], then require
    /// `key.key_type() == self.key_type` ([`Error::PublicKeyTypeMismatch`]).
    /// Structurally bad base64 is [`Error::AllowedSignersLineInvalid`].
    pub fn decode_key<'b>(&self, buf: &'b mut [u8]) -> Result<PublicKey<'b>, Error> {
        let n = match armor::base64_decode(self.key_base64.as_bytes(), buf) {
            Ok(n) => n,
            Err(Error::ArmorBadBase64) => return Err(Error::AllowedSignersLineInvalid),
            Err(e) => return Err(e),
        };
        let blob: &'b [u8] = &buf[..n];
        let key = PublicKey::parse_blob(blob)?;
        if key.key_type() != self.key_type {
            return Err(Error::PublicKeyTypeMismatch);
        }
        Ok(key)
    }

    /// Owned copy; decodes the key.
    #[cfg(feature = "alloc")]
    pub fn to_buf(&self) -> Result<AllowedSignerBuf, Error> {
        use alloc::string::String;
        use alloc::vec::Vec;
        let mut buf = alloc::vec![0u8; armor::max_decoded_len(self.key_base64.len())];
        let key = self.decode_key(&mut buf)?.to_buf();
        Ok(AllowedSignerBuf {
            principals: self.principals().map(String::from).collect(),
            cert_authority: self.cert_authority,
            namespaces: self
                .namespaces
                .map(|_| self.namespace_list().map(String::from).collect::<Vec<_>>()),
            valid_after: self.valid_after.map(String::from),
            valid_before: self.valid_before.map(String::from),
            key,
            comment: self.comment.map(String::from),
        })
    }
}

/// A parse failure with its 1-based line number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineError {
    /// 1-based line number in the file text.
    pub line: usize,
    /// The failure.
    pub error: Error,
}

impl core::fmt::Display for LineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "line {}: {}", self.line, self.error)
    }
}

impl core::error::Error for LineError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Iterator over all entries of a file's text; comment/blank lines are
/// skipped, not yielded.
pub struct AllowedSigners<'a> {
    lines: core::str::Lines<'a>,
    line_no: usize,
}

impl<'a> AllowedSigners<'a> {
    /// Iterate the entries of `text`.
    pub fn new(text: &'a str) -> Self {
        Self {
            lines: text.lines(),
            line_no: 0,
        }
    }
}

impl<'a> Iterator for AllowedSigners<'a> {
    type Item = Result<AllowedSigner<'a>, LineError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line = self.lines.next()?;
            self.line_no += 1;
            match AllowedSigner::parse_line(line) {
                Ok(Some(entry)) => return Some(Ok(entry)),
                Ok(None) => continue,
                Err(error) => {
                    return Some(Err(LineError {
                        line: self.line_no,
                        error,
                    }))
                }
            }
        }
    }
}

/// Owned [`AllowedSigner`] with the key decoded and the lists split.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedSignerBuf {
    /// Principal patterns.
    pub principals: alloc::vec::Vec<alloc::string::String>,
    /// `cert-authority` option present — a certificate CA, never a signer
    /// to match a plain SSHSIG against (see [`AllowedSigner::cert_authority`]).
    pub cert_authority: bool,
    /// `namespaces=` items; `None` when the option is absent.
    pub namespaces: Option<alloc::vec::Vec<alloc::string::String>>,
    /// `valid-after=` raw value.
    pub valid_after: Option<alloc::string::String>,
    /// `valid-before=` raw value.
    pub valid_before: Option<alloc::string::String>,
    /// The decoded key.
    pub key: crate::pubkey::PublicKeyBuf,
    /// Trailing comment.
    pub comment: Option<alloc::string::String>,
}

#[cfg(feature = "alloc")]
impl AllowedSignerBuf {
    /// Exact match of `name` against any principal item (no glob).
    pub fn has_principal(&self, name: &str) -> bool {
        self.principals.iter().any(|p| p == name)
    }

    /// `None` → `true` (any namespace); `Some` → exact membership.
    pub fn allows_namespace(&self, namespace: &str) -> bool {
        self.namespaces
            .as_ref()
            .is_none_or(|list| list.iter().any(|n| n == namespace))
    }

    /// Same rule as [`AllowedSigner::accepts`]: no validity window, not a
    /// `cert-authority` entry, principal listed, namespace allowed.
    pub fn accepts(&self, principal: &str, namespace: &str) -> bool {
        self.valid_after.is_none()
            && self.valid_before.is_none()
            && self.accepts_ignoring_window(principal, namespace)
    }

    /// Same rule as [`AllowedSigner::accepts_at`].
    pub fn accepts_at(&self, principal: &str, namespace: &str, now: u64) -> bool {
        window_admits(
            self.valid_after.as_deref(),
            self.valid_before.as_deref(),
            now,
        ) && self.accepts_ignoring_window(principal, namespace)
    }

    fn accepts_ignoring_window(&self, principal: &str, namespace: &str) -> bool {
        !self.cert_authority && self.has_principal(principal) && self.allows_namespace(namespace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIC+V33GKxm11791ic1JG3vEwyzyPjkqBhAfusScVAqW7";
    const C: &str = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAILVWgS9TDP4YxZBVJsIRIr8754uTJj07ROVp4DqU+RvJAAAABHNzaDo=";

    #[test]
    fn plain_line() {
        let mut line = [0u8; 128];
        let text = concat_line(&mut line, &["alice ssh-ed25519 ", A, " a comment \r\n"]);
        let e = AllowedSigner::parse_line(text).unwrap().unwrap();
        assert_eq!(e.principals, "alice");
        assert!(!e.cert_authority);
        assert_eq!(e.namespaces, None);
        assert_eq!(e.valid_after, None);
        assert_eq!(e.valid_before, None);
        assert_eq!(e.key_type, KEY_TYPE_ED25519);
        assert_eq!(e.key_base64, A);
        assert_eq!(e.comment, Some("a comment"));
        assert!(e.has_principal("alice"));
        assert!(!e.has_principal("alic"));
        assert!(e.allows_namespace("anything"));
        assert_eq!(e.namespace_list().count(), 0);
        let mut buf = [0u8; 64];
        let key = e.decode_key(&mut buf).unwrap();
        assert_eq!(key.key_type(), KEY_TYPE_ED25519);
        assert_eq!(key.key()[0], 0x2f);
    }

    /// Concatenate string pieces into `buf` and return the `&str`.
    fn concat_line<'b>(buf: &'b mut [u8], parts: &[&str]) -> &'b str {
        let mut n = 0;
        for p in parts {
            buf[n..n + p.len()].copy_from_slice(p.as_bytes());
            n += p.len();
        }
        core::str::from_utf8(&buf[..n]).unwrap()
    }

    #[test]
    fn options_line() {
        let mut line = [0u8; 256];
        let text = concat_line(
            &mut line,
            &[
                "\t bob,carol Cert-Authority,NAMESPACES=\"ns-a,ns-b\",valid-after=\"20260101Z\",valid-before=\"20301231235959Z\" ssh-ed25519 ",
                A,
            ],
        );
        let e = AllowedSigner::parse_line(text).unwrap().unwrap();
        assert_eq!(e.principals, "bob,carol");
        assert!(e.has_principal("bob"));
        assert!(e.has_principal("carol"));
        assert!(!e.has_principal("bob,carol"));
        assert!(e.cert_authority);
        assert_eq!(e.namespaces, Some("ns-a,ns-b"));
        assert!(e.allows_namespace("ns-a"));
        assert!(e.allows_namespace("ns-b"));
        assert!(!e.allows_namespace("ns-a,ns-b"));
        assert!(!e.allows_namespace("ns"));
        assert_eq!(e.valid_after, Some("20260101Z"));
        assert_eq!(e.valid_before, Some("20301231235959Z"));
        assert_eq!(e.comment, None);
        // A cert-authority entry never accepts a plain signature.
        assert!(!e.accepts("bob", "ns-a"));
    }

    #[test]
    fn accepts_requires_principal_namespace_and_no_ca() {
        let mut line = [0u8; 256];
        let text = concat_line(
            &mut line,
            &["bob,carol namespaces=\"ns-a\" ssh-ed25519 ", A],
        );
        let e = AllowedSigner::parse_line(text).unwrap().unwrap();
        assert!(e.accepts("bob", "ns-a"));
        assert!(e.accepts("carol", "ns-a"));
        assert!(!e.accepts("bob", "ns-b"));
        assert!(!e.accepts("dave", "ns-a"));
        let text = concat_line(&mut line, &["bob ssh-ed25519 ", A]);
        let e = AllowedSigner::parse_line(text).unwrap().unwrap();
        assert!(e.accepts("bob", "anything"));
        let text = concat_line(&mut line, &["bob cert-authority ssh-ed25519 ", A]);
        let e = AllowedSigner::parse_line(text).unwrap().unwrap();
        assert!(e.has_principal("bob") && e.allows_namespace("anything"));
        assert!(!e.accepts("bob", "anything"));
    }

    #[test]
    fn pattern_syntax_is_rejected() {
        let inv = Err(Error::AllowedSignersLineInvalid);
        assert_eq!(AllowedSigner::parse_line("* ssh-ed25519 AAAA"), inv);
        assert_eq!(
            AllowedSigner::parse_line("alice,!alice ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(AllowedSigner::parse_line("a?ice ssh-ed25519 AAAA"), inv);
        assert_eq!(
            AllowedSigner::parse_line("alice namespaces=\"git*\" ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line("alice namespaces=\"a,!b\" ssh-ed25519 AAAA"),
            inv
        );
        // The bytes are fine in a value that is not a pattern list.
        let e = AllowedSigner::parse_line("alice valid-after=\"*\" ssh-ed25519 AAAA")
            .unwrap()
            .unwrap();
        assert_eq!(e.valid_after, Some("*"));
    }

    #[test]
    fn sk_line_and_type_mismatch() {
        let mut line = [0u8; 256];
        let text = concat_line(
            &mut line,
            &[
                "sk1 namespaces=\"x\" sk-ssh-ed25519@openssh.com ",
                C,
                " yubikey",
            ],
        );
        let e = AllowedSigner::parse_line(text).unwrap().unwrap();
        assert_eq!(e.key_type, KEY_TYPE_SK_ED25519);
        assert_eq!(e.comment, Some("yubikey"));
        let mut buf = [0u8; 128];
        let key = e.decode_key(&mut buf).unwrap();
        assert!(key.is_sk());

        let mut line = [0u8; 256];
        let text = concat_line(&mut line, &["dave sk-ssh-ed25519@openssh.com ", A]);
        let e = AllowedSigner::parse_line(text).unwrap().unwrap();
        let mut buf = [0u8; 128];
        assert_eq!(e.decode_key(&mut buf), Err(Error::PublicKeyTypeMismatch));

        // Alphabet-valid but structurally bad base64 surfaces at decode.
        let e = AllowedSigner::parse_line("dave ssh-ed25519 AAA")
            .unwrap()
            .unwrap();
        let mut buf = [0u8; 128];
        assert_eq!(
            e.decode_key(&mut buf),
            Err(Error::AllowedSignersLineInvalid)
        );
        // Decode buffer too small.
        let mut line = [0u8; 256];
        let text = concat_line(&mut line, &["dave ssh-ed25519 ", A]);
        let e = AllowedSigner::parse_line(text).unwrap().unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(e.decode_key(&mut buf), Err(Error::BufferTooSmall));
    }

    #[test]
    fn blank_and_comment_lines() {
        assert_eq!(AllowedSigner::parse_line(""), Ok(None));
        assert_eq!(AllowedSigner::parse_line("\n"), Ok(None));
        assert_eq!(AllowedSigner::parse_line("  \t \r\n"), Ok(None));
        assert_eq!(AllowedSigner::parse_line("# c"), Ok(None));
        assert_eq!(AllowedSigner::parse_line("\t # c"), Ok(None));
    }

    #[test]
    fn parse_utc_time_forms() {
        assert_eq!(parse_utc_time("19700101Z"), Some(0));
        assert_eq!(parse_utc_time("20260101Z"), Some(1_767_225_600));
        assert_eq!(parse_utc_time("20260101z"), Some(1_767_225_600));
        assert_eq!(parse_utc_time("202402291230Z"), Some(1_709_209_800));
        assert_eq!(parse_utc_time("20301231235959Z"), Some(1_924_991_999));
        for bad in [
            "20260101",     // local time: not interpretable here
            "202601011200", // local time
            "Z",
            "2026011Z",    // 7 digits
            "2026010100Z", // 10 digits
            "2026-01-01Z",
            "20230229Z", // not a leap year
            "20261301Z",
            "20260100Z",
            "202601012400Z",
            "202601011260Z",
            "20260101235960Z",
            "19691231Z",
            "*",
        ] {
            assert_eq!(parse_utc_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn validity_window_fails_closed() {
        let after = 1_767_225_600; // 20260101Z
        let before = 1_924_991_999; // 20301231235959Z
        let mut line = [0u8; 256];
        let text = concat_line(
            &mut line,
            &[
                "bob valid-after=\"20260101Z\",valid-before=\"20301231235959Z\" ssh-ed25519 ",
                A,
            ],
        );
        let e = AllowedSigner::parse_line(text).unwrap().unwrap();
        // No clock: a windowed entry never accepts.
        assert!(!e.accepts("bob", "ns"));
        // ssh-keygen's bounds are inclusive at both ends.
        assert!(!e.accepts_at("bob", "ns", after - 1));
        assert!(e.accepts_at("bob", "ns", after));
        assert!(e.accepts_at("bob", "ns", before));
        assert!(!e.accepts_at("bob", "ns", before + 1));
        // The window adds to, never replaces, the principal check.
        assert!(!e.accepts_at("carol", "ns", after));

        let open_ended = AllowedSigner::parse_line(concat_line(
            &mut line,
            &["bob valid-after=\"20260101Z\" ssh-ed25519 ", A],
        ))
        .unwrap()
        .unwrap();
        assert!(!open_ended.accepts("bob", "ns"));
        assert!(open_ended.accepts_at("bob", "ns", u64::MAX));
        assert!(!open_ended.accepts_at("bob", "ns", after - 1));

        // Local-time and wildcard windows cannot be evaluated: reject.
        for window in ["valid-before=\"20301231\"", "valid-after=\"*\""] {
            let mut buf = [0u8; 256];
            let text = concat_line(&mut buf, &["bob ", window, " ssh-ed25519 ", A]);
            let e = AllowedSigner::parse_line(text).unwrap().unwrap();
            assert!(!e.accepts("bob", "ns"), "{window}");
            assert!(!e.accepts_at("bob", "ns", after), "{window}");
        }

        // Entries without a window are unaffected.
        let plain = AllowedSigner::parse_line(concat_line(&mut line, &["bob ssh-ed25519 ", A]))
            .unwrap()
            .unwrap();
        assert!(plain.accepts("bob", "ns"));
        assert!(plain.accepts_at("bob", "ns", 0));
    }

    #[test]
    fn invalid_lines() {
        let inv = Err(Error::AllowedSignersLineInvalid);
        let unk = Err(Error::AllowedSignersUnknownOption);
        assert_eq!(AllowedSigner::parse_line("dave"), inv);
        assert_eq!(AllowedSigner::parse_line("dave ssh-ed25519"), inv);
        assert_eq!(AllowedSigner::parse_line("dave ssh-ed25519 "), inv);
        assert_eq!(AllowedSigner::parse_line("dave ssh-ed25519 AAA*"), inv);
        assert_eq!(
            AllowedSigner::parse_line("dave ssh-rsa AAAAB3NzaC1yc2E="),
            Err(Error::UnknownKeyType)
        );
        assert_eq!(
            AllowedSigner::parse_line("dave namespaces=\"x\" ssh-rsa AAAA"),
            Err(Error::UnknownKeyType)
        );
        // Options field present but no key type after it.
        assert_eq!(AllowedSigner::parse_line("dave cert-authority"), inv);
        // Unknown option.
        assert_eq!(
            AllowedSigner::parse_line("dave foo=1 ssh-ed25519 AAAA"),
            unk
        );
        assert_eq!(
            AllowedSigner::parse_line("dave foo ssh-ed25519 AAAA"),
            Err(Error::UnknownKeyType)
        );
        // No `=`, not exactly `cert-authority`: field 2 is read as a key type.
        assert_eq!(
            AllowedSigner::parse_line("dave cert-authority,foo ssh-ed25519 AAAA"),
            Err(Error::UnknownKeyType)
        );
        assert_eq!(
            AllowedSigner::parse_line("dave cert-authority,foo=1 ssh-ed25519 AAAA"),
            unk
        );
        // Unquoted values (ssh-keygen: "missing start quote"); the name is
        // still looked up first, so an unknown one stays UnknownOption.
        assert_eq!(
            AllowedSigner::parse_line("dave namespaces=x ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line(
                "dave valid-after=20260101Z,valid-before=\"x\" ssh-ed25519 AAAA"
            ),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line("dave cert-authority,namespaces=x\" ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line("dave foo=1,namespaces=x ssh-ed25519 AAAA"),
            unk
        );
        // Unterminated quote.
        assert_eq!(
            AllowedSigner::parse_line("dave namespaces=\"x ssh-ed25519 AAAA"),
            inv
        );
        // Text after a closing quote that is not a comma.
        assert_eq!(
            AllowedSigner::parse_line("dave namespaces=\"x\"y ssh-ed25519 AAAA"),
            inv
        );
        // Value on cert-authority.
        assert_eq!(
            AllowedSigner::parse_line("dave cert-authority=yes ssh-ed25519 AAAA"),
            inv
        );
        // Missing / empty values.
        assert_eq!(
            AllowedSigner::parse_line("dave namespaces ssh-ed25519 AAAA"),
            Err(Error::UnknownKeyType)
        );
        assert_eq!(
            AllowedSigner::parse_line("dave namespaces=,cert-authority ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line("dave namespaces=\"\" ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line("dave valid-after= ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line("dave valid-before,namespaces=\"x\" ssh-ed25519 AAAA"),
            inv
        );
        // Repeated options.
        assert_eq!(
            AllowedSigner::parse_line("dave namespaces=\"a\",namespaces=\"b\" ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line(
                "dave cert-authority,cert-authority,namespaces=\"x\" ssh-ed25519 AAAA"
            ),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line("dave valid-after=\"1\",valid-after=\"2\" ssh-ed25519 AAAA"),
            inv
        );
        // Empty option names.
        assert_eq!(
            AllowedSigner::parse_line("dave ,namespaces=\"x\" ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(
            AllowedSigner::parse_line("dave cert-authority,,namespaces=\"x\" ssh-ed25519 AAAA"),
            inv
        );
        assert_eq!(AllowedSigner::parse_line("dave =x ssh-ed25519 AAAA"), inv);
        // A trailing comma is tolerated.
        let e = AllowedSigner::parse_line("dave namespaces=\"x\", ssh-ed25519 AAAA")
            .unwrap()
            .unwrap();
        assert_eq!(e.namespaces, Some("x"));
        // Case-insensitive names; quoted values with commas.
        let e =
            AllowedSigner::parse_line("dave CERT-AUTHORITY,Valid-After=\"1,2\" ssh-ed25519 AAAA")
                .unwrap()
                .unwrap();
        assert!(e.cert_authority);
        assert_eq!(e.valid_after, Some("1,2"));
        // Options field recognised by a leading quote.
        assert_eq!(
            AllowedSigner::parse_line("dave \"x\" ssh-ed25519 AAAA"),
            Err(Error::AllowedSignersUnknownOption)
        );
    }

    #[test]
    fn file_iterator_skips_comments_and_numbers_lines() {
        let mut text = [0u8; 512];
        let t = concat_line(
            &mut text,
            &[
                "# header\n",
                "\n",
                "alice ssh-ed25519 ",
                A,
                " one\r\n",
                "bad\n",
                "bob ssh-ed25519 ",
                A,
                "\n",
            ],
        );
        let mut it = AllowedSigners::new(t);
        let e = it.next().unwrap().unwrap();
        assert_eq!(e.principals, "alice");
        let err = it.next().unwrap().unwrap_err();
        assert_eq!(
            err,
            LineError {
                line: 4,
                error: Error::AllowedSignersLineInvalid
            }
        );
        let e = it.next().unwrap().unwrap();
        assert_eq!(e.principals, "bob");
        assert!(it.next().is_none());
    }

    #[test]
    fn line_error_display() {
        use core::fmt::Write;
        struct Buf([u8; 64], usize);
        impl Write for Buf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                self.0[self.1..self.1 + s.len()].copy_from_slice(s.as_bytes());
                self.1 += s.len();
                Ok(())
            }
        }
        let mut b = Buf([0; 64], 0);
        write!(
            b,
            "{}",
            LineError {
                line: 3,
                error: Error::UnknownKeyType
            }
        )
        .unwrap();
        assert_eq!(&b.0[..b.1], b"line 3: unsupported key type");
    }

    #[cfg(feature = "alloc")]
    mod with_alloc {
        use super::super::*;
        use super::{concat_line, A, C};
        use alloc::string::String;
        use alloc::vec;

        #[test]
        fn to_buf() {
            let mut line = [0u8; 256];
            let text = concat_line(
                &mut line,
                &[
                    "bob,carol namespaces=\"n1,n2\",valid-after=\"x\" ssh-ed25519 ",
                    A,
                    " two",
                ],
            );
            let e = AllowedSigner::parse_line(text).unwrap().unwrap();
            let b = e.to_buf().unwrap();
            assert_eq!(
                b.principals,
                vec![String::from("bob"), String::from("carol")]
            );
            assert!(!b.cert_authority);
            assert_eq!(
                b.namespaces,
                Some(vec![String::from("n1"), String::from("n2")])
            );
            assert_eq!(b.valid_after, Some(String::from("x")));
            assert_eq!(b.valid_before, None);
            assert_eq!(b.key.as_key().key_type(), KEY_TYPE_ED25519);
            assert_eq!(b.comment, Some(String::from("two")));
            assert!(b.has_principal("carol") && !b.has_principal("dave"));
            assert!(b.allows_namespace("n2") && !b.allows_namespace("n3"));
            // `valid-after="x"` cannot be evaluated: the entry never accepts.
            assert!(!b.accepts("bob", "n1"));
            assert!(!b.accepts_at("bob", "n1", u64::MAX));
            let open = AllowedSignerBuf {
                valid_after: None,
                ..b.clone()
            };
            assert!(open.accepts("bob", "n1") && !open.accepts("bob", "n3"));
            let windowed = AllowedSignerBuf {
                valid_after: Some(String::from("20260101Z")),
                ..open.clone()
            };
            assert!(!windowed.accepts("bob", "n1"));
            assert!(!windowed.accepts_at("bob", "n1", 1_767_225_599));
            assert!(windowed.accepts_at("bob", "n1", 1_767_225_600));
            let ca = AllowedSignerBuf {
                cert_authority: true,
                ..open.clone()
            };
            assert!(!ca.accepts("bob", "n1"));

            let mut line = [0u8; 256];
            let text = concat_line(&mut line, &["sk1 sk-ssh-ed25519@openssh.com ", C]);
            let e = AllowedSigner::parse_line(text).unwrap().unwrap();
            let b = e.to_buf().unwrap();
            assert_eq!(b.namespaces, None);
            assert!(b.key.as_key().is_sk());

            let mut line = [0u8; 256];
            let text = concat_line(&mut line, &["sk1 sk-ssh-ed25519@openssh.com ", A]);
            let e = AllowedSigner::parse_line(text).unwrap().unwrap();
            assert_eq!(e.to_buf(), Err(Error::PublicKeyTypeMismatch));
        }
    }
}
