//! Conformance checks for [`Sha256`] and [`Sha512`].

use super::vectors::{DigestVector, SHA256, SHA512};
use super::Case;
use crate::{CryptoResult, Sha256, Sha256State, Sha512, Sha512State};

/// Run the SHA-256 vectors against `d`.
///
/// For every vector in [`SHA256`]: the provided one-shot `sha256`; the
/// streaming API with the whole message in one `update`, one byte per
/// `update`, and (for the two-block message) the chunking `[1, 7, rest]`;
/// for the empty message, zero `update` calls and one empty `update`. A
/// single state object is reused across all vectors, so the "`finalize`
/// resets" contract is exercised as well.
pub fn check_sha256<D: Sha256 + ?Sized>(d: &D) -> CryptoResult<()> {
    run("check_sha256", SHA256, &Sha256Api(d))
}

/// Run the SHA-512 vectors against `d`; same procedure as [`check_sha256`]
/// over [`SHA512`].
pub fn check_sha512<D: Sha512 + ?Sized>(d: &D) -> CryptoResult<()> {
    run("check_sha512", SHA512, &Sha512Api(d))
}

/// Uniform view of the two digest trait families so one runner serves both.
trait DigestApi<const N: usize> {
    type State;
    fn init(&self) -> CryptoResult<Self::State>;
    fn update(&self, st: &mut Self::State, data: &[u8]) -> CryptoResult<()>;
    fn finalize(&self, st: &mut Self::State) -> CryptoResult<[u8; N]>;
    fn one_shot(&self, data: &[u8]) -> CryptoResult<[u8; N]>;
}

struct Sha256Api<'a, D: ?Sized>(&'a D);

impl<D: Sha256 + ?Sized> DigestApi<32> for Sha256Api<'_, D> {
    type State = D::State;
    fn init(&self) -> CryptoResult<Self::State> {
        self.0.sha256_init()
    }
    fn update(&self, st: &mut Self::State, data: &[u8]) -> CryptoResult<()> {
        st.update(data)
    }
    fn finalize(&self, st: &mut Self::State) -> CryptoResult<[u8; 32]> {
        st.finalize()
    }
    fn one_shot(&self, data: &[u8]) -> CryptoResult<[u8; 32]> {
        self.0.sha256(data)
    }
}

struct Sha512Api<'a, D: ?Sized>(&'a D);

impl<D: Sha512 + ?Sized> DigestApi<64> for Sha512Api<'_, D> {
    type State = D::State;
    fn init(&self) -> CryptoResult<Self::State> {
        self.0.sha512_init()
    }
    fn update(&self, st: &mut Self::State, data: &[u8]) -> CryptoResult<()> {
        st.update(data)
    }
    fn finalize(&self, st: &mut Self::State) -> CryptoResult<[u8; 64]> {
        st.finalize()
    }
    fn one_shot(&self, data: &[u8]) -> CryptoResult<[u8; 64]> {
        self.0.sha512(data)
    }
}

fn run<const N: usize, A: DigestApi<N>>(
    check: &'static str,
    vectors: &[DigestVector<N>],
    api: &A,
) -> CryptoResult<()> {
    let first = match vectors.first() {
        Some(v) => v,
        None => return Ok(()),
    };
    // One state for the whole run: every `finalize` must reset it.
    let mut st = Case::new(check, first.name).ok(api.init())?;

    for v in vectors {
        let case = Case::new(check, v.name);
        let msg = v.message;

        // One-shot.
        let got = case.ok(api.one_shot(msg))?;
        case.eq("one-shot digest", &got, &v.digest)?;

        if msg.is_empty() {
            // Zero updates.
            let got = case.ok(api.finalize(&mut st))?;
            case.eq("streaming digest (no update)", &got, &v.digest)?;
            // One empty update.
            case.ok(api.update(&mut st, &[]))?;
            let got = case.ok(api.finalize(&mut st))?;
            case.eq("streaming digest (empty update)", &got, &v.digest)?;
            continue;
        }

        // Whole message in one update.
        case.ok(api.update(&mut st, msg))?;
        let got = case.ok(api.finalize(&mut st))?;
        case.eq("streaming digest (single update)", &got, &v.digest)?;

        // One byte per update.
        for b in msg {
            case.ok(api.update(&mut st, core::slice::from_ref(b)))?;
        }
        let got = case.ok(api.finalize(&mut st))?;
        case.eq("streaming digest (byte-wise updates)", &got, &v.digest)?;

        // [1, 7, rest] chunking for messages long enough to have a "rest".
        if msg.len() > 8 {
            case.ok(api.update(&mut st, &msg[..1]))?;
            case.ok(api.update(&mut st, &msg[1..8]))?;
            case.ok(api.update(&mut st, &msg[8..]))?;
            let got = case.ok(api.finalize(&mut st))?;
            case.eq("streaming digest ([1, 7, rest] updates)", &got, &v.digest)?;
        }
    }
    Ok(())
}
