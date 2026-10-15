# spacetime-age

age-encryption.org/v1 file format for `no_std`: header/stanza codec with
grease tolerance, header MAC, STREAM payload, X25519 and ssh-ed25519
recipients, bech32 keys, ASCII armor and header-only inspection — generic
over the `spacetime-crypto` facades.

## Overview

[age](https://age-encryption.org/v1) is the small-file encryption format
behind the `age` and `rage` tools. This crate is the codec and the key
agreement recipes; it holds **no cryptography** of its own. Every hash, MAC,
KDF, AEAD and Diffie-Hellman goes through a `spacetime-crypto` trait facade
(`Sha256`, `Sha512`, `HmacSha256`, `HkdfSha256`, `ChaCha20Poly1305`, `X25519`,
`Ed25519Sign`, `Ed25519ToX25519`, `Rng`) supplied by the caller's backend, so
the same code runs on a server, an appliance and an embedded reader. It is
`no_std` by default, allocates nothing in any core path (borrowed slices in,
caller buffers out), and offers owned conveniences under the `alloc` feature.

The format in one screen:

```text
age-encryption.org/v1\n
-> <type> <args…>\n                        zero or more stanzas; body is raw base64
<body, 64-column lines, last line < 64>\n   (the last line may be empty)
--- <base64 HMAC-SHA-256 (32 bytes)>\n      key = HKDF-SHA-256(salt = "", ikm = file key, info = "header"),
                                             over every header byte through the three dashes
<16-byte nonce><STREAM chunks…>             key = HKDF-SHA-256(salt = nonce, ikm = file key, info = "payload")
```

STREAM: ChaCha20-Poly1305 over 64 KiB plaintext chunks; chunk nonce =
11-byte big-endian counter ‖ 1-byte last-chunk flag. The final chunk holds
1..=64 KiB, or 0 bytes only when the whole plaintext is empty; a plaintext
that is an exact multiple of 64 KiB ends with a *full* final chunk.

Recipient recipes (both verified against `rage` 0.12.1 in both directions;
`HKDF(salt, ikm, info)` = HKDF-SHA-256 to 32 bytes; `SEAL` = ChaCha20-Poly1305
with an all-zero nonce and no AAD over the 16-byte file key):

| Stanza | Key agreement | Wrap key |
|---|---|---|
| `-> X25519 b64(eph)` | `eph = X25519(e, 9)`, `shared = X25519(e, pk)` | `HKDF(salt = eph ‖ pk, ikm = shared, info = "age-encryption.org/v1/X25519")` |
| `-> ssh-ed25519 b64(tag) b64(eph)` | `wire = SSH blob of pk` (51 bytes), `tag = SHA-256(wire)[..4]`, `tweak = HKDF(salt = wire, ikm = "", info = LABEL)`, `pk_mont = Edwards→Montgomery(pk)`, `shared = X25519(tweak, X25519(e, pk_mont))` | `HKDF(salt = eph ‖ pk_mont, ikm = shared, info = LABEL)` with `LABEL = "age-encryption.org/v1/ssh-ed25519"` — the salt uses the **untweaked** `pk_mont` |

On decrypt an ssh-ed25519 identity is the 32-byte Ed25519 seed:
`a = SHA-512(seed)[..32]` (the facade clamps), `pk_mont = X25519(a, 9)`,
`shared = X25519(tweak, X25519(a, eph))`.

Policy, all pinned by the vendored test corpora:

- **Grease / unsupported.** Unknown stanza types are grease: validated
  structurally, then ignored. `scrypt` and `ssh-rsa` are *recognised*,
  counted, and reported as `Unsupported(Scrypt)` / `Unsupported(SshRsa)` when
  nothing else unwraps — never silently skipped. A `scrypt` stanza must be the
  only stanza (`Header(ScryptNotAlone)`). `X25519` and `ssh-ed25519` stanzas
  are shape-checked at parse time regardless of the identities held.
- **Unwrap order** (Go's): identities outer, stanzas inner, first success
  wins; a low-order share is fatal (`Header(LowOrderShare)`); an ssh-ed25519
  tag mismatch or AEAD failure is a skip. The header MAC is verified before a
  file key is returned.
- **Release rule.** The reader hands out the plaintext of every successfully
  opened chunk before a later trailing-data / truncation error is detected;
  a full 65 552-byte chunk is opened with `last = 0` first and re-opened
  with `last = 1` on failure. CCTV hashes the released plaintext even on
  `payload failure`, so this is normative.
- **Randomness.** Every encrypt entry point takes an `rng: &mut R`
  (`R: spacetime_crypto::Rng`). Draw order: 16 bytes file key, 32 bytes per
  recipient in recipient order, 16 bytes payload nonce — a deterministic
  `Rng` gives byte-deterministic output (the `pyref_*` known-answer vectors).
  No facade method draws randomness.

## Dependencies

`spacetime-crypto` only. Dev-only: `ed25519-dalek`, `x25519-dalek`, `sha2`,
`hmac`, `hkdf`, `chacha20poly1305` (the test backend in `tests/common/`),
`serde_json` (manifests) and `miniz_oxide` (the 22 zlib-compressed CCTV
vectors). None is in the published graph; `src/` never names a concrete
primitive.

## Usage

```bash
cargo build -p spacetime-age                          # pure no_std, no features
cargo build -p spacetime-age --features alloc         # no_std + allocator
cargo build -p spacetime-age --features std           # std
cargo build -p spacetime-age --no-default-features --target riscv32imac-unknown-none-elf
cargo test -p spacetime-age                           # unit tests + CCTV + rage suites (buffer API only)
cargo test -p spacetime-age --features std            # + tests/alloc_api.rs
cargo clippy -p spacetime-age --all-targets --all-features -- -D warnings
```

Decrypt without an allocator (`backend` implements the `DecryptBackend`
facades; `file` is the whole binary age file):

```rust
use spacetime_age::{unwrap_file_key, DecryptBackend, Error, Header, Identity, StreamReader};
use spacetime_age::{CHUNK_LEN, CHUNK_SEALED_LEN};

fn decrypt<B: DecryptBackend>(
    backend: &B, file: &[u8], identity: &Identity, out: &mut [u8; CHUNK_LEN],
    mut sink: impl FnMut(&[u8]),
) -> Result<(), Error> {
    let header = Header::parse(file)?;
    let file_key = unwrap_file_key(backend, &header, core::slice::from_ref(identity))?;
    let mut reader = StreamReader::new(backend, &file_key, header.nonce())?;
    let mut payload = header.payload();
    while payload.len() >= CHUNK_SEALED_LEN {
        let (chunk, rest) = payload.split_at(CHUNK_SEALED_LEN);
        let n = reader.next_chunk(chunk, out)?;
        sink(&out[..n]);
        payload = rest;
        if reader.is_finished() { break; }
    }
    let n = reader.last_chunk(payload, out)?;
    sink(&out[..n]);
    Ok(())
}
```

Encrypt with an allocator (`backend` implements the `EncryptBackend`
facades; `rng` is the backend's `Rng`):

```rust
use spacetime_age::{encrypt_vec, EncryptBackend, Error, Recipient};

fn encrypt<B: EncryptBackend, R: spacetime_crypto::Rng>(
    backend: &B, rng: &mut R, ssh_public_key: [u8; 32], plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let recipients = [
        Recipient::from_age_str("age15weja5qsvsv9utrqyke5nza08vmals2lyls73n5v7hltfk46mcqsy3c60l")?,
        Recipient::SshEd25519 { public_key: ssh_public_key },
    ];
    encrypt_vec(backend, rng, &recipients, plaintext)
}
```

Header inspection for an ingest predicate (no key, no MAC check):
`inspect(file)?.is_single_ssh_ed25519(&tag)` with `tag =
Recipient::SshEd25519 { .. }.ssh_tag(backend)`. The predicate ignores
`X25519` co-recipients and grease; add `&& inspection.x25519 == 0` to
require "addressed only to us".

## Conformance

`tests/cctv.rs` runs the vendored [C2SP CCTV](https://github.com/C2SP/CCTV)
age corpus (147 vectors) through the buffer API: 103 vectors are asserted
strictly against their `expect` class and, for `success` / `payload
failure`, the SHA-256 of every released byte; 44 exercise features this
crate does not implement and run in an explicit "unsupported" mode (must
fail, must release nothing), counted by reason and asserted so the totals
cannot drift:

| Class | Count |
|---|---|
| strict: header failure | 34 |
| strict: armor failure | 26 |
| strict: success | 19 |
| strict: payload failure | 19 |
| strict: no match | 4 |
| strict: HMAC failure | 1 |
| skipped (passphrase / scrypt) | 26 |
| skipped (hybrid-only identities) | 18 |

`compressed: zlib` vectors (22) are inflated, never skipped. The same file
also proves armor, header and payload round trips over the corpus.
`tests/rage_vectors.rs` runs 31 `rage`-encrypted files (X25519, ssh-ed25519,
both; armored and not; five payload sizes) as decrypt oracles and reproduces
8 deterministic `pyref_*` files byte for byte through `encrypt_header` +
`StreamWriter` under a counter RNG. `tests/backend_conformance.rs` proves the
dev-only backend with the `spacetime-crypto` harness before any of that.

Divergences (CCTV is normative; rage 0.12.1 is an interop oracle only):

| Vector / case | CCTV / this crate | rage 0.12.1 |
|---|---|---|
| `armor_whitespace_outside` (whitespace before BEGIN / after END) | success | rejects |
| `stanza_missing_body`, `stanza_missing_final_line` | header failure | accepts |
| hybrid `mlkem768x25519` / `AGE-SECRET-KEY-PQ-` | no match / `Key(Hrp)` | unsupported |
| `=` in a non-final armor data line | `Armor(BadBase64)` | decodes lines independently |
| ssh-ed25519 tag match with AEAD failure | skip (Go semantics) | fatal |
| `AGE1…` uppercase recipients | accepted (bech32 permits) | — |
| malformed `X25519` / `ssh-ed25519` stanza (arg count, base64, lengths) alongside a stanza we can unwrap | header failure (validated at parse time, whatever identities are held) | decrypts (Go and rage validate a stanza only when an identity tries it) |

## Test vectors

`tests/vectors/cctv/` is the vendored C2SP corpus with its license
([`tests/vectors/cctv/README.md`](tests/vectors/cctv/README.md));
`tests/vectors/rage/` holds the rage oracles, the deterministic `pyref_*`
files, the fixed throwaway keys and the generator
([`tests/vectors/rage/README.md`](tests/vectors/rage/README.md)). The suite
never shells out: `rage`, `rage-keygen`, `ssh-keygen` and `python3` are not
needed to run it.

## Non-goals

scrypt/passphrase stanzas (recognised, reported `Unsupported(Scrypt)`);
`ssh-rsa` (recognised, `Unsupported(SshRsa)`); hybrid `mlkem768x25519` and
any plugin stanza (treated as grease, so a file addressed only to them is
`NoMatch`); age plugins; `AGE-SECRET-KEY-PQ-…` / `AGE-PLUGIN-…` identity
strings (`Key(Hrp)`); OpenSSH private-key files (`openssh-key-v1`, encrypted
or not); passphrase-protected age identity files; multi-file archives; grease
emission on encrypt (we never emit grease); header versions other than
`age-encryption.org/v1`; streaming armor decode (armored input is buffered).

## Status

API new in 1.0.1; scrypt / ssh-rsa / hybrid stanzas are reported, not
implemented.

## License

MIT OR Apache-2.0 — see [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
