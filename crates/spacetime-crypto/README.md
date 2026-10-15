spacetime-crypto
================

No_std-first trait facades for cryptographic primitives (RNG/entropy, SHA-2,
HMAC, Ed25519 and its Edwards→Montgomery public-key conversion,
ChaCha20-Poly1305/XChaCha20-Poly1305, HKDF, Argon2id, X25519) plus an
RFC-vector conformance harness.

Overview
--------

This crate defines the seam, not the backend: it contains **no concrete
cryptographic implementation and no cryptographic randomness**. It fixes the
trait shapes, buffer conventions, and error contracts so that a portable
registry verifier, an appliance/Android reader, and a pure-Rust or
hardware-backed implementation crate can all program against (or against a
common interface with) the same types.

Traits:
- [`Rng`], [`EntropySource`] — random bytes / entropy (pre-existing).
- [`Sha256`]/[`Sha256State`], [`Sha512`]/[`Sha512State`] — digest (FIPS
  180-4).
- [`HmacSha256`] — MAC (RFC 2104/4231).
- [`Ed25519Verify`], [`Ed25519Sign`] — signatures (RFC 8032).
  `ed25519_verify` implements the **strict** verification profile (canonical
  `S`/`R`/`A`, no small-order points, cofactorless equation — see the trait
  docs for the full normative statement; this is *not* the ZIP-215 profile).
- [`Ed25519ToX25519`] — Edwards→Montgomery public-key conversion for X25519
  use of an Ed25519 key (domain = keys passing `ed25519_validate_public_key`).
- `ChaCha20Poly1305`, `XChaCha20Poly1305` — AEAD (RFC 8439 /
  draft-irtf-cfrg-xchacha).
- `HkdfSha256`, `Argon2id` — key derivation (RFC 5869 / RFC 9106).
- `X25519` — Diffie-Hellman (RFC 7748); an all-zero shared secret (low-order
  peer) is rejected.

Every trait method is fallible and, where an allocator is not required, uses
caller-provided buffers or fixed-size arrays rather than `Vec`/`Box` — see
each trait's `# Object safety` and `# Errors` doc sections.

Dependencies
------------

None. Zero runtime dependencies, by design — this is a facade, not a
cryptography crate.

Usage
-----

```bash
cargo build -p spacetime-crypto                       # pure no_std, no features
cargo build -p spacetime-crypto --features alloc      # no_std + allocator
cargo build -p spacetime-crypto --features std        # std
cargo build -p spacetime-crypto --features conformance
cargo build -p spacetime-crypto --no-default-features --target riscv32imac-unknown-none-elf
cargo test -p spacetime-crypto                        # inline unit tests + object_safety + smoke
cargo test -p spacetime-crypto --features std
cargo test -p spacetime-crypto --features std,conformance
cargo clippy -p spacetime-crypto --all-targets --all-features -- -D warnings
```

A backend crate implements the traits it supports on its own type:

```rust
use spacetime_crypto::{CryptoResult, Sha256, Sha256State};

struct MyBackend;
struct MyState { /* ... */ }

impl Sha256State for MyState {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> { /* ... */ Ok(()) }
    fn finalize(&mut self) -> CryptoResult<[u8; 32]> { /* ... */ Ok([0; 32]) }
}

impl Sha256 for MyBackend {
    type State = MyState;
    fn sha256_init(&self) -> CryptoResult<Self::State> { Ok(MyState {}) }
}
```

API sketch
----------

| Trait | Key methods | Object-safe |
|---|---|---|
| `Sha256` / `Sha256State` | `sha256_init`, `update`, `finalize`, `sha256` (provided) | yes, as `&dyn Sha256<State = S>` |
| `Sha512` / `Sha512State` | same shape, 64-byte output | yes |
| `HmacSha256` | `hmac_sha256`, `hmac_sha256_verify` | yes |
| `Ed25519Verify` | `ed25519_validate_public_key`, `ed25519_verify` | yes |
| `Ed25519Sign` | `ed25519_public_key`, `ed25519_sign` | yes |
| `Ed25519ToX25519` | `ed25519_public_to_x25519` | yes |
| `ChaCha20Poly1305` / `XChaCha20Poly1305` | `*_seal`, `*_open`, `*_seal_into`/`*_open_into` (provided) | yes |
| `HkdfSha256` | `hkdf_sha256_extract`, `hkdf_sha256_expand`, `hkdf_sha256` (provided) | yes |
| `Argon2id` | `argon2id` | yes |
| `X25519` | `x25519_public_key`, `x25519` | yes |
| `Rng` / `EntropySource` | `fill_bytes`, `try_read` | yes |

All traits above are usable as trait objects (`&dyn Trait`); see each
trait's `# Object safety` doc section for the specific caveat (the digest
traits need their associated `State` type named at the use site).
`tests/object_safety.rs` asserts every row of this table under the default
feature set — a unit struct implements all twelve traits without `alloc`,
is coerced to each `&dyn Trait`, and every provided method is called
through the trait object — so `cargo test --workspace` compiles the table
on every gate run.

Conformance
-----------

Behind the `conformance` feature, `spacetime_crypto::conformance` provides
the RFC test vectors as data (`conformance::vectors`) and generic
`check_*<T: Trait + ?Sized>(t: &T) -> CryptoResult<()>` functions — plus
`check_all` — that a downstream backend crate calls from its own tests to
prove it agrees with the RFCs:

| Check | Vectors |
|---|---|
| `check_sha256`, `check_sha512` | FIPS 180-4 examples (`""`, `"abc"`, two-block message), one-shot and several streaming chunkings |
| `check_hmac_sha256` | RFC 4231 test cases 1–4, 6, 7; `verify` accepts the tag and rejects two tampered tags |
| `check_ed25519_verify` | RFC 8032 §7.1 TEST 1–3 and SHA(abc); strict-profile negatives NEG-1…NEG-6 (small-order `A` and `R`, `S + L`, non-canonical `R`/`A`, equation failure, small-order `R` under a mixed-order `A`); `validate_public_key` against the eight torsion encodings, four non-canonical encodings and a mixed-order key |
| `check_ed25519_sign`, `check_ed25519_roundtrip` | RFC 8032 §7.1 key derivation and signatures |
| `check_ed25519_to_x25519` | RFC 8032 §7.1 TEST 1–3 and SHA(abc) public keys → Montgomery `u`; the 13 `ED25519_INVALID_PUBLIC_KEYS` rejected |
| `check_chacha20poly1305`, `check_xchacha20poly1305` | RFC 8439 §2.8.2 / draft-irtf-cfrg-xchacha-03 §A.3.1, tamper cases, the `_seal_into`/`_open_into` layout and the no-plaintext-on-failure rule |
| `check_hkdf_sha256` | RFC 5869 A.1–A.3 |
| `check_argon2id` | RFC 9106 §5.3 (m = 32 KiB, t = 3, p = 4, with secret and associated data) and the parameter-domain rejections |
| `check_x25519` | RFC 7748 §6.1 and seven low-order peers (all-zero shared secret must be rejected and zeroed) |

```rust
// in the backend crate, with spacetime-crypto's `conformance` feature on
#[test]
fn conforms_to_the_rfcs() {
    spacetime_crypto::conformance::check_all(&MyBackend).unwrap();
}
```

`check_*` never returns the backend's own error kind — a failed check is
always `CryptoErrorKind::InvalidParameter`, with a detail message under
`alloc` naming the check, the first failed vector and what mismatched.
Negative cases demand the exact error kind the trait contract names, and
`Unsupported` anywhere is a failure. The harness needs no allocator (fixed
stack buffers, `&'static` data), so it also runs on an embedded target; one
HKDF sub-check (expand into 8161 bytes) runs only under `alloc`. Budget the
stack, not just the heap: the AEAD and digest runners keep several
100-plus-byte scratch buffers live at once, so their frames measure about
5 KiB each in a debug build (x86_64, rustc 1.98; about 1.2 KiB in release,
other checks under 2 KiB / 0.5 KiB) before the backend's own frames — run
the harness on target as a release build.

```bash
cargo test -p spacetime-crypto --features std,conformance   # harness + doubles
```

This crate's own tests (`tests/conformance_doubles.rs`) exercise the harness
only with lookup-table and constant-returning test doubles, to prove it
compiles generically (including against `&dyn Trait`), passes a backend
that returns the tabled answers, and rejects a wrong answer, a wrong error
kind, or a plaintext leak — the real cryptographic run of the harness happens
in the downstream backend crate that implements these traits against actual
SHA-256/Ed25519/etc. A transcription error in a vector would surface there,
not here.

Status
------

The facade traits, `Argon2Params`, the constants and the `conformance`
module are new public API on top of the released workspace version; nothing
that existed before (`CryptoError`, `CryptoErrorKind`, `CryptoResult`,
`Rng`, `EntropySource`, the feature set) changed shape. Whether the next
workspace release takes a minor bump for them is an owner decision, not
part of this crate. No backend has yet run the conformance harness
cryptographically; until one does, the vectors are transcriptions checked
only against the RFC text and out-of-tree tooling, and this crate's own
tests exercise the harness with lookup-table doubles only.

License
-------

MIT OR Apache-2.0 — see the workspace [`LICENSE-MIT`](../../LICENSE-MIT) and [`LICENSE-APACHE`](../../LICENSE-APACHE).
