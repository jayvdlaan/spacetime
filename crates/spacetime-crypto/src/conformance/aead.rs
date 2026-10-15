//! Conformance checks for [`ChaCha20Poly1305`] and [`XChaCha20Poly1305`].

use super::vectors::{AeadVector, CHACHA20POLY1305, XCHACHA20POLY1305};
use super::Case;
use crate::{
    ChaCha20Poly1305, CryptoErrorKind, CryptoResult, XChaCha20Poly1305, AEAD_KEY_LEN, AEAD_TAG_LEN,
};

/// Longest plaintext the harness buffers hold (the RFC 8439 message).
const MAX_BODY: usize = 114;
/// Longest AAD the tamper cases can copy.
const MAX_AAD: usize = 16;
/// Stack buffer for `ciphertext || tag`.
const SEALED_LEN: usize = MAX_BODY + AEAD_TAG_LEN;

/// Run the RFC 8439 §2.8.2 vector against `a`.
///
/// For every vector in [`CHACHA20POLY1305`]:
/// - seal in place → ciphertext and tag equal the vector; open in place →
///   plaintext;
/// - tamper cases — ciphertext byte 0 flipped, tag byte 15 flipped, last
///   AAD byte flipped, nonce byte 0 flipped — must each fail with exactly
///   `AuthenticationFailed`, and afterwards the buffer must hold either
///   exactly the bytes passed in or all zeros (no plaintext on failure);
/// - `_seal_into` yields `ciphertext || tag` and returns `len + 16`;
///   `_open_into` returns `len` and the plaintext; an output buffer one byte
///   short (either direction) and a 15-byte `sealed` are `InvalidParameter`;
///   `_open_into` with the tag flipped is `AuthenticationFailed` with
///   `out[..len]` all zero;
/// - an empty plaintext with empty AAD round-trips through seal/open and
///   `_seal_into`/`_open_into` (self-consistency; no RFC vector exists).
pub fn check_chacha20poly1305<A: ChaCha20Poly1305 + ?Sized>(a: &A) -> CryptoResult<()> {
    run("check_chacha20poly1305", CHACHA20POLY1305, &ChaChaApi(a))
}

/// Run the draft-irtf-cfrg-xchacha-03 §A.3.1 vector against `a`; same
/// procedure as [`check_chacha20poly1305`] over [`XCHACHA20POLY1305`].
pub fn check_xchacha20poly1305<A: XChaCha20Poly1305 + ?Sized>(a: &A) -> CryptoResult<()> {
    run("check_xchacha20poly1305", XCHACHA20POLY1305, &XChaChaApi(a))
}

/// Uniform view of the two AEAD traits so one runner serves both.
trait AeadApi<const NONCE_LEN: usize> {
    fn seal(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; AEAD_TAG_LEN]>;
    fn open(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> CryptoResult<()>;
    fn seal_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize>;
    fn open_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        sealed: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize>;
}

struct ChaChaApi<'a, A: ?Sized>(&'a A);

impl<A: ChaCha20Poly1305 + ?Sized> AeadApi<12> for ChaChaApi<'_, A> {
    fn seal(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; AEAD_TAG_LEN]> {
        self.0.chacha20poly1305_seal(key, nonce, aad, buf)
    }
    fn open(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> CryptoResult<()> {
        self.0.chacha20poly1305_open(key, nonce, aad, buf, tag)
    }
    fn seal_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        self.0
            .chacha20poly1305_seal_into(key, nonce, aad, plaintext, out)
    }
    fn open_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        self.0
            .chacha20poly1305_open_into(key, nonce, aad, sealed, out)
    }
}

struct XChaChaApi<'a, A: ?Sized>(&'a A);

impl<A: XChaCha20Poly1305 + ?Sized> AeadApi<24> for XChaChaApi<'_, A> {
    fn seal(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
    ) -> CryptoResult<[u8; AEAD_TAG_LEN]> {
        self.0.xchacha20poly1305_seal(key, nonce, aad, buf)
    }
    fn open(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; 24],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> CryptoResult<()> {
        self.0.xchacha20poly1305_open(key, nonce, aad, buf, tag)
    }
    fn seal_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; 24],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        self.0
            .xchacha20poly1305_seal_into(key, nonce, aad, plaintext, out)
    }
    fn open_into(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; 24],
        aad: &[u8],
        sealed: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        self.0
            .xchacha20poly1305_open_into(key, nonce, aad, sealed, out)
    }
}

/// Copy `ct` into a fresh buffer, open it with the given inputs, and demand
/// exactly `AuthenticationFailed` **and** a buffer that afterwards holds
/// either the bytes passed in or all zeros.
#[allow(clippy::too_many_arguments)]
fn open_must_fail<const NONCE_LEN: usize, A: AeadApi<NONCE_LEN>>(
    case: Case,
    api: &A,
    step: &'static str,
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; AEAD_TAG_LEN],
) -> CryptoResult<()> {
    let mut work = [0u8; MAX_BODY];
    let work = &mut work[..ct.len()];
    work.copy_from_slice(ct);
    case.kind(
        step,
        api.open(key, nonce, aad, work, tag),
        CryptoErrorKind::AuthenticationFailed,
    )?;
    case.ensure(
        work == ct || work.iter().all(|b| *b == 0),
        "buffer holds neither the input bytes nor zeros after a failed open (plaintext exposure)",
    )
}

fn run<const NONCE_LEN: usize, A: AeadApi<NONCE_LEN>>(
    check: &'static str,
    vectors: &[AeadVector<NONCE_LEN>],
    api: &A,
) -> CryptoResult<()> {
    for v in vectors {
        let case = Case::new(check, v.name);
        let n = v.plaintext.len();
        case.ensure(
            n > 0 && n <= MAX_BODY && v.ciphertext.len() == n,
            "vector does not fit the harness buffer",
        )?;
        case.ensure(
            !v.aad.is_empty() && v.aad.len() <= MAX_AAD,
            "vector AAD must be 1..=16 bytes for the tamper cases",
        )?;

        // Seal in place.
        let mut buf = [0u8; MAX_BODY];
        let body = &mut buf[..n];
        body.copy_from_slice(v.plaintext);
        let tag = case.ok(api.seal(&v.key, &v.nonce, v.aad, body))?;
        case.eq("ciphertext", body, v.ciphertext)?;
        case.eq("tag", &tag, &v.tag)?;

        // Open in place.
        case.ok(api.open(&v.key, &v.nonce, v.aad, body, &v.tag))?;
        case.eq("plaintext", body, v.plaintext)?;

        // Tamper: ciphertext byte 0.
        let mut ct = [0u8; MAX_BODY];
        let ct = &mut ct[..n];
        ct.copy_from_slice(v.ciphertext);
        ct[0] ^= 0x01;
        open_must_fail(
            case,
            api,
            "open with ciphertext byte 0 flipped",
            &v.key,
            &v.nonce,
            v.aad,
            ct,
            &v.tag,
        )?;

        // Tamper: tag byte 15.
        let mut bad_tag = v.tag;
        bad_tag[15] ^= 0x01;
        open_must_fail(
            case,
            api,
            "open with tag byte 15 flipped",
            &v.key,
            &v.nonce,
            v.aad,
            v.ciphertext,
            &bad_tag,
        )?;

        // Tamper: last AAD byte.
        let mut aad = [0u8; MAX_AAD];
        let aad = &mut aad[..v.aad.len()];
        aad.copy_from_slice(v.aad);
        aad[v.aad.len() - 1] ^= 0x01;
        open_must_fail(
            case,
            api,
            "open with the last AAD byte flipped",
            &v.key,
            &v.nonce,
            aad,
            v.ciphertext,
            &v.tag,
        )?;

        // Tamper: nonce byte 0.
        let mut nonce = v.nonce;
        nonce[0] ^= 0x01;
        open_must_fail(
            case,
            api,
            "open with nonce byte 0 flipped",
            &v.key,
            &nonce,
            v.aad,
            v.ciphertext,
            &v.tag,
        )?;

        // seal_into: layout and length.
        let mut sealed = [0u8; SEALED_LEN];
        let written = case.ok(api.seal_into(
            &v.key,
            &v.nonce,
            v.aad,
            v.plaintext,
            &mut sealed[..n + AEAD_TAG_LEN],
        ))?;
        case.ensure(
            written == n + AEAD_TAG_LEN,
            "seal_into returned a length other than plaintext.len() + 16",
        )?;
        case.eq("seal_into ciphertext", &sealed[..n], v.ciphertext)?;
        case.eq("seal_into tag", &sealed[n..n + AEAD_TAG_LEN], &v.tag)?;

        // seal_into: output one byte short.
        let mut short = [0u8; SEALED_LEN];
        case.kind(
            "seal_into with an output buffer one byte short",
            api.seal_into(
                &v.key,
                &v.nonce,
                v.aad,
                v.plaintext,
                &mut short[..n + AEAD_TAG_LEN - 1],
            ),
            CryptoErrorKind::InvalidParameter,
        )?;

        // open_into: happy path.
        let mut pt = [0u8; MAX_BODY];
        let got = case.ok(api.open_into(
            &v.key,
            &v.nonce,
            v.aad,
            &sealed[..n + AEAD_TAG_LEN],
            &mut pt[..n],
        ))?;
        case.ensure(
            got == n,
            "open_into returned a length other than the plaintext length",
        )?;
        case.eq("open_into plaintext", &pt[..n], v.plaintext)?;

        // open_into: output one byte short.
        case.kind(
            "open_into with an output buffer one byte short",
            api.open_into(
                &v.key,
                &v.nonce,
                v.aad,
                &sealed[..n + AEAD_TAG_LEN],
                &mut pt[..n - 1],
            ),
            CryptoErrorKind::InvalidParameter,
        )?;

        // open_into: sealed shorter than a tag.
        case.kind(
            "open_into with a 15-byte sealed input",
            api.open_into(&v.key, &v.nonce, v.aad, &sealed[..15], &mut pt[..n]),
            CryptoErrorKind::InvalidParameter,
        )?;

        // open_into: tag flipped → AuthenticationFailed, out zeroed.
        let mut bad = sealed;
        bad[n + AEAD_TAG_LEN - 1] ^= 0x01;
        let mut pt = [0xAAu8; MAX_BODY];
        case.kind(
            "open_into with the tag flipped",
            api.open_into(
                &v.key,
                &v.nonce,
                v.aad,
                &bad[..n + AEAD_TAG_LEN],
                &mut pt[..n],
            ),
            CryptoErrorKind::AuthenticationFailed,
        )?;
        case.ensure(
            pt[..n].iter().all(|b| *b == 0),
            "open_into left non-zero bytes in the output after an authentication failure",
        )?;

        // Empty plaintext + empty AAD: in-place and two-buffer round trips.
        let mut empty: [u8; 0] = [];
        let empty_tag = case.ok(api.seal(&v.key, &v.nonce, &[], &mut empty))?;
        case.ok(api.open(&v.key, &v.nonce, &[], &mut empty, &empty_tag))?;

        let mut sealed_empty = [0u8; AEAD_TAG_LEN];
        let written = case.ok(api.seal_into(&v.key, &v.nonce, &[], &[], &mut sealed_empty))?;
        case.ensure(
            written == AEAD_TAG_LEN,
            "seal_into of an empty plaintext must write 16 bytes",
        )?;
        case.eq(
            "empty-plaintext tag (seal_into vs seal)",
            &sealed_empty,
            &empty_tag,
        )?;
        let got = case.ok(api.open_into(&v.key, &v.nonce, &[], &sealed_empty, &mut empty))?;
        case.ensure(got == 0, "open_into of an empty plaintext must return 0")?;
    }
    Ok(())
}
