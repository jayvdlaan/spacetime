# spacetime-sshsig test vectors

What this is: a committed, deterministic corpus of OpenSSH SSHSIG (PROTOCOL.sshsig) fixtures — 8
positive and 32 negative vectors, three ed25519 keys (two with private material, one verify-only
sk-ssh-ed25519@openssh.com key), an `allowed_signers` fixture, and a `manifest.json` that ties it
all together. `tests/vectors.rs` (in the crate proper) and `airframe_crypt`'s
`tests/sshsig_vectors.rs` both run their real parse/verify/sign code against this manifest. Neither
test needs `ssh-keygen` on PATH — everything here is already generated and cross-checked.

## Regenerating

```
./gen.sh
```

Requires `python3` (3.9+, stdlib only — no pip packages) and `ssh-keygen` (OpenSSH ≥ 8.2; developed
and verified against `OpenSSH_10.2p1, OpenSSL 3.5.8`) on PATH. Deterministic and idempotent: two runs
produce byte-identical files (no timestamps, no randomness, fixed seeds and fixed sk counters), and
`git diff` after a run should be empty unless `gen.py` / `ed25519_ref.py` themselves changed.

`gen.sh` just checks the two prerequisites, prints the `ssh` version banner, and runs `gen.py`.
`gen.py` does everything: writes `keys/`, `msgs/`, `sigs/`, `allowed_signers` and `manifest.json`;
asserts the pinned seed/pubkey/fingerprint/SHA-512 values below; signs every positive vector twice
with `ssh-keygen -Y sign` to prove determinism; builds every ssh-keygen-produced blob a second time
with the pure-Python `ed25519_ref.py` reference and asserts byte-for-byte equality (the byte-identity
proof the crate's own `sign_is_byte_identical_to_ssh_keygen` test relies on); cross-checks **every**
vector with `ssh-keygen -Y verify` (or, for `find-principals`, records that check separately) and
**fails loudly, naming the vector**, if the observed accept/reject disagrees with the manifest's
`ssh_keygen` field — it never silently drops or "fixes" a vector to make the run go green.

`gen.py` never shells out to Rust and is never invoked by the Rust test suite.

## Layout

```
README.md            this file
gen.sh                entry point: checks prerequisites, runs gen.py
gen.py                the generator (stdlib only + ed25519_ref.py)
ed25519_ref.py         pure-integer RFC 8032 §6 Ed25519 reference (point arithmetic, sign, a
                       from-scratch strict verifier) + SSH wire helpers + an openssh-key-v1 writer +
                       SSHSIG blob/armor builders — the second, independent oracle next to ssh-keygen
manifest.json         see "manifest.json shape" below
keys/a, keys/a.pub     seed A, comment spacetime-sshsig-a (unencrypted openssh-key-v1, mode 0600)
keys/b, keys/b.pub     seed B, comment spacetime-sshsig-b
keys/c.pub             seed C, sk-ssh-ed25519@openssh.com, application "ssh:" — NO private file;
                       sk keys are verify-only (contract D4/R2), so "signing" with seed C below means
                       building the raw Ed25519 signature by hand over the sk message formula, exactly
                       as real authenticator firmware would, not anything ssh-keygen can do for sk-
                       keys without real hardware
msgs/hello.txt         b"spacetime-sshsig test message\n" (30 bytes)
msgs/empty.bin          0 bytes
msgs/large.bin          262144 bytes = concat of SHA256(b"spacetime-sshsig large " + i.to_bytes(4,
                       "big")) for i in 0..8192 — deterministic filler with no external dependency
sigs/<name>.sig        one armored SSHSIG file per vector
allowed_signers        fixture for the allowed_signers parser (§5.5)
```

`keys/a` and `keys/b` must be mode `0600` for `ssh-keygen -Y sign` to accept them ("No private key
found" otherwise) — git does not preserve file mode, so `gen.py` chmods them on every run; this only
matters for regeneration, the committed test suite never invokes `ssh-keygen`.

## Fixed seeds and derived values

| key | seed (SHA-256 of the literal) | public key | fingerprint |
|---|---|---|---|
| a | `SHA256(b"spacetime-sshsig vector key A")` = `a7c884c52f11deb9f8fe0e803ad3229aa7e974dda980afe5aa815b8ee7ce2c65` | `2f95df718ac66d75efdd62735246def130cb3c8f8e4a818407eeb1271502a5bb` | `SHA256:5FxuSKuU4+XupSaJNmRMPpy+07DhkxvYrylShCh0GVM` |
| b | `SHA256(b"spacetime-sshsig vector key B")` = `bb6b36fb48b77829b69428f3d7be483e614e6ca5bb0150a05aa5727a1a04e958` | `a240be8bf1dad5a485dd35dcade841d2ca9087b1513afd07dc971b4d6f61bb0d` | `SHA256:9QyLndDsouyFRirdn58g4s8u+ogYRpU3rRtE18LnlE8` |
| c (sk, application `ssh:`) | `SHA256(b"spacetime-sshsig vector key C")` = `08d5e9d838e4188e1cf4ff655b18f83b1f402eb5f380a6f724cd9d877003a417` | `b556812f530cfe18c5905526c21122bf3be78b93263d3b44e569e03a94f91bc9` | `SHA256:78wb2B6GDw5YYHb3bz4ntk7FezhZoFkodDoFj5iDh7g` |

Namespaces: `NS = "spacetime-sshsig-test-v1"`, `NS_OTHER = "spacetime-sshsig-other-v1"`.
`SHA512(msgs/hello.txt)` = `9df41151eda3c4f4b0837ccfbfaffa4e4fed9b4d8c218892925ec8522597ffc02ffc6dcd60d1e0f0128efdcc1ae8b05ea10bbd5b5c761e4b6c569c7ab2eb6bd0`.

**Determinism proof (D9 / R2):** `ssh-keygen -Y sign -f keys/a -n spacetime-sshsig-test-v1
msgs/hello.txt` was run twice; the two `.sig` outputs are byte-identical, and the pure-Python
`ed25519_ref.sign_ed25519_sshsig(seed_a, ...)` build of the same blob is also byte-identical to both
— proving both that Ed25519 signing here is deterministic and that the reference builder matches
ssh-keygen exactly. This is the byte-identity the crate's implementer test
(`sign_is_byte_identical_to_ssh_keygen`) checks for every `deterministic_sign: true` vector. Fixed
determinism seed (key a, hex, for the implementer's byte-identity test):
`a7c884c52f11deb9f8fe0e803ad3229aa7e974dda980afe5aa815b8ee7ce2c65`.

## Special point encodings (curve-math negatives)

Built and sanity-checked in `ed25519_ref.py` at import time (module-level asserts):
- **Identity** (order 1): `01` followed by 31 zero bytes (little-endian y=1, sign bit 0).
- **Non-canonical identity**: y = p+1 (`p = 2^255-19`) encoded as 32 little-endian bytes with the top
  bit clear — `ee ff×30 7f`. Reduces to the identity mod p.
- **Order-4 point**: the all-zero encoding (y=0, sign bit 0) — `[8]P == identity`, `P != identity`.

## manifest.json shape

```json
{
  "schema": 1,
  "generator": "gen.sh -> gen.py ... ; ssh-keygen <version> for provenance",
  "namespace": "spacetime-sshsig-test-v1",
  "other_namespace": "spacetime-sshsig-other-v1",
  "keys": { "a": {...}, "b": {...}, "c": {...} },
  "messages": { "hello": "msgs/hello.txt", "empty": "msgs/empty.bin", "large": "msgs/large.bin" },
  "vectors": [
    {
      "name": "ok_ed25519_hello",
      "kind": "positive",
      "key": "a",
      "message": "hello",
      "sig": "sigs/ok_ed25519_hello.sig",
      "expected_namespace": "spacetime-sshsig-test-v1",
      "policy": { "require_user_verification": false },
      "expect": { "parse": "ok", "verify": "ok" },
      "ssh_keygen": "accept",
      "allowed_signers_line": "v ssh-ed25519 AAAA...",
      "deterministic_sign": true,
      "provenance": "ssh-keygen -Y sign -f keys/a -n spacetime-sshsig-test-v1 msgs/hello.txt"
    }
  ],
  "allowed_signers": { "file": "allowed_signers", "entries": [...], "bad_lines": [...], "find_principals_check": {...} }
}
```

`expect.parse` and `expect.verify` are `spacetime_sshsig::Error::name()` strings (or `null` /
absent-verify when parsing itself fails, so verify is never attempted). `key: null` means the
signature's embedded public key is forged/synthetic and there is no manifest key entry to compare
against — the test passes no `Expected::with_signer`. `sig` sometimes points at another vector's file
(`neg_wrong_message`, `neg_signer_mismatch`, `neg_sk_uv_missing`) — those three negatives are the
*same bytes* as a positive vector, verified under a different message / expected signer / policy;
this is deliberate (contract §5.4), not a mistake.

## Divergence from ssh-keygen (crate rejects, ssh-keygen accepts)

Every one of these was *observed* on this machine (`OpenSSH_10.2p1, OpenSSL 3.5.8`) by `gen.py`'s
cross-check pass, not merely asserted — see the `ssh_keygen: "accept"` field on the named vector(s).
The reverse never occurs: everything the crate accepts, ssh-keygen accepts too (also asserted, for
every positive vector).

| What | Vector(s) | Why ssh-keygen doesn't care |
|---|---|---|
| `S + L` (non-canonical scalar) | `neg_s_plus_l` | `ssh-keygen -Y verify` reduces mod the group order rather than requiring `S < L` |
| Non-empty `reserved` over an empty-reserved signature | `neg_reserved_nonempty` | the field is accepted but never fed into anything ssh-keygen checks |
| `hash_algorithm = "sha256"` | `neg_hash_sha256` | ssh-keygen accepts any algorithm it recognizes, not just sha512 |
| sk `flags = 0` (no UP) / UV required but missing | `neg_sk_flags_zero`, `neg_sk_uv_missing` | ssh-keygen's sshsig verifier does not interpret sk flags at all |
| Armor lines > 76 characters | `neg_armor_line_too_long` | ssh-keygen's base64 reader has no line-length limit |
| Text after the END footer | `neg_armor_trailing_text` | ssh-keygen stops scanning at the footer and never checks for extra text |
| Universal identity forgery (`A = R = identity`, `S = 0`) | `neg_small_order_a` | no small-order / identity check on `A` in ssh-keygen's verifier |
| Non-canonical encoding of the identity as `A` (paired with `R = identity`, `S = 0`) | `neg_noncanonical_a` | **empirically confirmed here, beyond the contract's original list (§9.3 V12 predicted "reject")**: reducing this specific `A` mod p lands in the same identity-forgery class as `neg_small_order_a` above, and ssh-keygen accepts it for the same reason. A non-canonical encoding of a genuine large-order point paired with an otherwise-honest signature was not separately tested — the contract's construction (§5.2/§5.4) pins the identity-based encoding, and that specific vector *does* diverge from the contract's own table. This is reported, not silently corrected. |

`neg_noncanonical_r`, `neg_small_order_r`, `neg_s_zero`, `neg_sk_wrong_application`,
`neg_wrong_message`, `neg_wrong_namespace`, `neg_signer_mismatch`, and every structural/armor-grammar
negative not listed above are ordinary rejects for ssh-keygen too (`ssh_keygen: "reject"` in the
manifest) — the crate is never *more* permissive than ssh-keygen, only ever equal or stricter.

`ssh-keygen -Y find-principals -s sigs/ok_ed25519_hello.sig -f allowed_signers` reports only `alice`,
not `root`, even though both lines carry key `a` — a `cert-authority` allowed_signers entry (the
`root` line) is for verifying *certificates* signed by that key, not for matching a plain (non-cert)
SSHSIG signature made directly with the key, so it is correctly excluded. The contract's §5.5
anticipated both names; this is the actual, verified behaviour and is what `manifest.allowed_signers.
find_principals_check` records. This check is informational only — no Rust test asserts it; the
crate mirrors it with `AllowedSigner::accepts`, which is `false` for the `root` line (asserted).

Every option value in the fixture is double-quoted. The contract's §5.5 text wrote lines 5 and 6
with unquoted values (`valid-after=20260101Z`, `namespaces=spacetime-sshsig-test-v1`); ssh-keygen
rejects those (`allowed_signers:5: bad options: missing start quote`, verified with OpenSSH_10.2p1),
so the fixture quotes them and an unquoted line sits in `bad_lines` instead.

`neg_empty_namespace_in_sig`'s `ssh_keygen` field is `"n/a"`: `ssh-keygen -Y sign -n ""` refuses to
run at all (verified: nonzero exit), so there is no oracle-signed equivalent for a signature whose
blob namespace is empty; the vector is built entirely by `ed25519_ref.py` instead.

## Non-goals

See the crate's own README (`../../README.md`) §"Non-goals" — this corpus does not cover OpenSSH
private-key file *parsing* (only writing, for the oracle's benefit), certificates, RSA/ECDSA/DSA,
the ssh-agent protocol, sk *signing*, `allowed_signers` glob/negation semantics, or
`valid-after`/`valid-before` interpretation. Every place those would apply, the corresponding
construction is an explicit parse-time reject (`UnknownKeyType` etc.), never a silent accept.

## Rule for anyone touching this directory

Never hand-edit a vector file to make a test pass. If a test disagrees with a vector, or `gen.py`'s
cross-check disagrees with this README's divergence table, the fix is either in the crate's code or
in `gen.py`/this README (with the reasoning written down, as above) — never a quiet edit to
`sigs/*.sig` or `manifest.json`.
