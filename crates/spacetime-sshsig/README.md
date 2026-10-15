# spacetime-sshsig

OpenSSH SSHSIG (PROTOCOL.sshsig) codec for `no_std`: parse, pinned-predicate
verify, deterministic sign (`ssh-ed25519`), `sk-ssh-ed25519@openssh.com`
verify, armor, public-key lines, fingerprints and `allowed_signers` — generic
over the `spacetime-crypto` facades.

## Overview

SSHSIG is the detached-signature format behind `ssh-keygen -Y sign` /
`-Y verify`. This crate is the codec and the verification predicate; it holds
**no cryptography** of its own. Every hash and every signature goes through
the `spacetime-crypto` trait facades (`Sha256`, `Sha512`, `Ed25519Verify`,
`Ed25519Sign`) supplied by the caller's backend, so the same code verifies a
registry entry on a server, an appliance and an embedded reader. It is
`no_std` by default, allocates nothing in any core path (borrowed slices in,
caller buffers out), and offers owned conveniences under the `alloc` feature.

`SshSig::parse` is structural; `verify` applies the pinned predicate. A
signature is accepted iff **all** of the following hold, in this order:

| # | Check | `Error` |
|---|---|---|
| A | armor: exact header/footer, `\n` endings, lines ≤ 76, strict base64, nothing after the footer | `ArmorMissingHeader`, `ArmorMissingFooter`, `ArmorLineTooLong`, `ArmorBadBase64`, `ArmorTrailingData` |
| P | magic `SSHSIG`; version 1; every section consumed exactly; key/signature types known and of the same family; 32-byte key; 64-byte signature | `BadMagic`, `UnsupportedVersion`, `Truncated`, `TrailingBytes(_)`, `UnknownKeyType`, `UnknownSignatureType`, `KeyTypeMismatch`, `BadKeyLength`, `BadSignatureLength` |
| V1 | caller namespace non-empty and ≤ 255 bytes | `EmptyNamespace`, `NamespaceTooLong` |
| V2 | `reserved` empty | `ReservedNotEmpty` |
| V3 | `hash_algorithm == "sha512"` | `HashAlgorithmNotSha512` |
| V4 | blob namespace == caller namespace | `NamespaceMismatch` |
| V5 | embedded key == expected signer (when one is given) | `SignerMismatch` |
| V6 | sk: user presence (`0x01`) always; user verification (`0x04`) when `SkPolicy` requires it | `SkUserPresenceMissing`, `SkUserVerificationMissing` |
| V7 | strict Ed25519 (canonical `A`/`R`, `S < L`, no small-order points, cofactorless) over the signed data rebuilt from the **caller's** namespace | `SignatureInvalid` |

The signed data is `"SSHSIG" ‖ string(expected namespace) ‖ string("") ‖
string("sha512") ‖ string(SHA-512(message))`. The blob's namespace is only
ever *compared* (V4); it never enters the reconstruction.

For `sk-ssh-ed25519@openssh.com` the Ed25519 message is (PROTOCOL.u2f, no
extensions)

```text
SHA-256(application) ‖ flags ‖ counter (uint32 big-endian) ‖ SHA-256(signed data)
```

with `application` taken from the key blob. sk keys are verify-only.

Streaming rule: `H(message)` is SHA-512 over the whole message; use
`verify_digest` / `sign_digest` with a `Sha512State` for large inputs — the
`verify` / `sign` forms hash a `&[u8]` in one shot.

## Dependencies

`spacetime-crypto` only. Dev-only: `ed25519-dalek`, `sha2`, `serde_json` for
the vector suite (`tests/vectors.rs`); they are not in the published graph and
`src/` never names a concrete primitive.

## Usage

```bash
cargo build -p spacetime-sshsig                       # pure no_std, no features
cargo build -p spacetime-sshsig --features alloc      # no_std + allocator
cargo build -p spacetime-sshsig --features std        # std
cargo build -p spacetime-sshsig --no-default-features --target riscv32imac-unknown-none-elf
cargo test -p spacetime-sshsig                        # unit tests + the vector suite (buffer API only)
cargo test -p spacetime-sshsig --features std         # + tests/alloc_api.rs
cargo clippy -p spacetime-sshsig --all-targets --all-features -- -D warnings
```

Verify a signature without an allocator (`backend` implements
`Ed25519Verify + Sha256 + Sha512`):

```rust
use spacetime_sshsig::{Expected, PublicKey, SshSig};

fn check<B>(backend: &B, armored: &[u8], message: &[u8], roster_key: &PublicKey<'_>)
    -> Result<(), spacetime_sshsig::Error>
where
    B: spacetime_crypto::Ed25519Verify + spacetime_crypto::Sha256 + spacetime_crypto::Sha512,
{
    let mut blob = [0u8; 512];
    let sig = SshSig::from_armored(armored, &mut blob)?;
    let expected = Expected::new("example-entry-v1").with_signer(roster_key);
    let verified = spacetime_sshsig::verify(backend, &sig, &expected, message)?;
    assert_eq!(verified.public_key(), roster_key);
    Ok(())
}
```

Sign (`backend` implements `Ed25519Sign + Sha512`); the output is
byte-identical to `ssh-keygen -Y sign -n example-entry-v1` for the same seed:

```rust
use spacetime_sshsig::{armor, ed25519_sshsig_len, sign_armored};

const NS: &str = "example-entry-v1";
const OUT_LEN: usize = armor::encoded_len(ed25519_sshsig_len(NS.len()));

fn make<B: spacetime_crypto::Ed25519Sign + spacetime_crypto::Sha512>(
    backend: &B, seed: &[u8; 32], message: &[u8],
) -> Result<[u8; OUT_LEN], spacetime_sshsig::Error> {
    let mut out = [0u8; OUT_LEN];
    let n = sign_armored(backend, seed, NS, message, &mut out)?;
    debug_assert_eq!(n, OUT_LEN);
    Ok(out)
}
```

Public-key lines and rosters: `pubkey::parse_public_key_line`,
`PublicKey::fingerprint` (`SHA256:…`, what `ssh-keygen -lf` prints),
`AllowedSigners::new(text)` iterating `AllowedSigner` entries with exact
principal / namespace matching. Option values must be double-quoted
(`namespaces="a,b"`), as ssh-keygen requires; a principal or namespace item
containing `!`, `*` or `?` (ssh-keygen pattern syntax, unsupported) is a
parse error. Pick the roster key with `AllowedSigner::accepts(principal,
namespace)`: it returns `false` for `cert-authority` entries, which name a
certificate CA and never match a plain SSHSIG (ssh-keygen agrees; certificates
are a non-goal), so they MUST NOT be used to pin a signer.

## Divergence from ssh-keygen

The crate is the normative verifier; `ssh-keygen` (10.2p1 / OpenSSL 3.5.8,
observed) is strictly more permissive. The crate rejects, ssh-keygen accepts:

| Case | Crate |
|---|---|
| `S + L` (non-canonical scalar) | `SignatureInvalid` (V7) |
| non-empty `reserved` (signature made over an empty one; ssh-keygen ignores the field) | `ReservedNotEmpty` (V2) |
| `hash_algorithm = sha256` | `HashAlgorithmNotSha512` (V3) |
| sk `flags = 0`; sk without UV when required (ssh-keygen ignores flags) | `SkUserPresenceMissing` / `SkUserVerificationMissing` (V6) |
| armor lines longer than 76 characters | `ArmorLineTooLong` (A) |
| text after the END footer | `ArmorTrailingData` (A) |
| `\r\n` line endings in the armor (ssh-keygen's base64 reader skips whitespace) | `ArmorMissingHeader` (header line) / `ArmorBadBase64` (body lines) (A) |
| a blank or whitespace-only line inside the base64 body | `ArmorBadBase64` (A) |
| more than one newline after the END footer | `ArmorTrailingData` (A) |
| the identity-key universal forgery `A = R = identity, S = 0`, and its non-canonical-`A` variant | `SignatureInvalid` (V7) |

The reverse never occurs: every signature the crate accepts, ssh-keygen
accepts (asserted by the vector generator).

## Test vectors

`tests/vectors/` holds a committed, deterministic corpus generated by the
local `ssh-keygen` plus a pure-Python RFC 8032 reference (see
[`tests/vectors/README.md`](tests/vectors/README.md)): 8 positive and 32
negative vectors, three keys, an `allowed_signers` fixture and
`manifest.json`. `tests/vectors.rs` runs every vector through the real
`parse` / `verify` / `sign` with a dev-only `ed25519-dalek` + `sha2` backend,
including the byte-identity proof against `ssh-keygen -Y sign`. The suite
never shells out; `ssh-keygen` is not needed to run it.

## Non-goals

OpenSSH private-key file parsing (`openssh-key-v1`, encrypted or not);
certificates (`ssh-ed25519-cert-v01@openssh.com`, `sk-…-cert-…`) —
`UnknownKeyType`; RSA / ECDSA / DSA key types — `UnknownKeyType` /
`UnknownSignatureType` (an explicit parse error, never a silent accept); the
ssh-agent protocol; sk signing; `hash_algorithm = "sha256"` signatures;
glob/negation semantics in `allowed_signers` pattern lists; local-time (no
`Z`) `valid-after` / `valid-before` values — an entry using one never
accepts; KRL/revocation files; webauthn-sk.

## Status

Stable API as of 1.0.1; sk signing out of scope.

## License

MIT OR Apache-2.0 — see [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
