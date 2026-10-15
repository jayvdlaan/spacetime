# rage-oracle vectors

39 age files this directory generates itself, used as a second oracle alongside
the vendored CCTV corpus (`../cctv/`) — CCTV is normative for parsing edge cases;
these exist because CCTV has no `ssh-ed25519` recipient vectors and no
deterministic known-answer test for the encrypt direction (contract §0 D3, §5.3).

## What's here

- `age_ref.py` — a self-contained, pure-stdlib (Python 3.9+) age reference:
  X25519 (RFC 7748 ladder), ChaCha20-Poly1305 (RFC 8439), HKDF-SHA-256
  (RFC 5869), bech32 (BIP-173), the age header/STREAM wire format, both age
  recipient recipes, and ASCII armor. Also carries the handful of RFC 8032
  Ed25519 / SSH-wire-format primitives it needs (point arithmetic, key
  derivation, an `openssh-key-v1` writer) — copied in from
  `spacetime-sshsig/tests/vectors/ed25519_ref.py` so this crate's test
  fixtures never cross-import another crate's test helpers (contract §5.1).
  This file is a generator/oracle, not shipped code; it is **not** trusted by
  itself — every value it produces is cross-checked against `rage -d` in
  `gen.py`, and its ssh-ed25519 recipe (contract §3.3) was itself derived by
  reading `age-0.12.1`/`age-core-0.12.0` source after a first attempt failed
  to interoperate with rage (contract §9.4).
- `gen.py` — the generator. Deterministic except for the `rage_*` vectors
  (rage's own output is randomised — those are decrypt-only oracles, not
  known-answer tests). Regenerating replaces those files' bytes but never
  their recorded expectations (which identity/passphrase combinations should
  and shouldn't decrypt them, and to what payload hash).
- `gen.sh` — thin wrapper: checks `rage`/`rage-keygen`/`python3` are on PATH
  and prints their versions, then runs `gen.py`. Idempotent — safe to re-run;
  a re-run reads nothing it wrote before, only the fixed seeds baked into
  `gen.py`, so `pyref_*` output and all derived keys/hashes/JSON are
  byte-identical run to run (the `rage_*` ciphertexts are not, since `rage`
  injects fresh ephemeral scalars/nonces/grease each time — that's fine, they
  are oracles, not KATs).
- `manifest.json` — one entry per vector: kind (`rage` decrypt-only oracle vs.
  `pyref` deterministic KAT), recipient kinds, armored flag, payload/plaintext,
  which identities should and shouldn't unwrap it, sha256, and the exact
  provenance (the `rage` command line, or "age_ref.encrypt (deterministic)").
- `ed25519_to_x25519.json` — RFC 8032 §7.1 TEST 1-3 / SHA(abc) public keys and
  this directory's ssh key, each with its Montgomery `u`; plus 5 keys that
  `Ed25519ToX25519::ed25519_public_to_x25519` must reject with
  `InvalidParameter` (identity, order-2, order-4, and two non-canonical
  encodings of `p + 1` — the same set spacetime-crypto's
  `ED25519_INVALID_PUBLIC_KEYS` uses for the first five entries).
- `keys/` — the two fixed, committed, throwaway key pairs these vectors use.
  **Never** regenerate these with `rage-keygen`/`ssh-keygen`; `gen.py` derives
  them from fixed seeds and asserts every resulting byte string against the
  values pinned in the spacetime-age implementation contract §5.3, so a
  mismatch here is a bug in the generator, not something to "fix" by
  re-deriving.
- `payloads/` — `p0.bin` … `p200k.bin`, deterministic filler
  (`SHA-256("spacetime-age payload " ‖ BE32(i))` repeated and truncated).
- `vectors/` — the 39 `.age` files (31 `rage_*`, 8 `pyref_*`).

## Fixed keys (throwaway; committed on purpose)

| | value |
|---|---|
| X25519 identity | `AGE-SECRET-KEY-1YX9CYV6YH7FDPQ9XXP4E2TT7T6XSJWQ67CLVE4CNG5YCZ5D9N77QZ8EEGV` |
| X25519 recipient | `age15weja5qsvsv9utrqyke5nza08vmals2lyls73n5v7hltfk46mcqsy3c60l` |
| ssh-ed25519 public line | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDmjTStv9rjz6dfYVA9C4CD/dcvPnbRcarldbcpezIbC spacetime-age-ssh` |
| ssh-ed25519 stanza tag | `eb88dd53` (base64 `64jdUw`) |

`keys/x25519.txt` is a plain `rage -i`-compatible identity file (no comments).
`keys/ssh_ed25519` is an unencrypted `openssh-key-v1` private key (mode 0600,
written by `age_ref.openssh_key_v1`, accepted by both `rage -i` and
`ssh-keygen -lf`); `keys/ssh_ed25519.pub` is its public-key line.

There is also an `other` X25519 recipient (`SHA-256("spacetime-age vector other
identity")`) whose secret is **never** written to disk or used to decrypt
anything — it exists only so `rage_other_p1` has a recipient that every held
identity correctly reports as "no match".

## Vector naming

- `rage_{x25519,ssh,both}_{p0,p1,p64k,p64k1,p200k}[_armored]` (30) — encrypted
  by `rage` itself with fixed recipients, decrypt-only oracles.
- `rage_other_p1` (1) — encrypted to the unrecoverable `other` recipient.
- `pyref_x25519_p1`, `pyref_ssh_p1`, `pyref_both_p1`, `pyref_both_p0`,
  `pyref_x25519_p64k`, `pyref_both_p64k1`, `pyref_x25519_p1_armored`,
  `pyref_both_det` (8) — built by `age_ref.encrypt` with `CounterRng(0)`
  (fill_bytes emits `0x00, 0x01, 0x02, …` wrapping mod 256, consumed in the
  draw order of contract §4: file key, then each recipient's ephemeral scalar
  in recipient order `[x25519, ssh_ed25519]`, then the STREAM nonce) — these
  are byte-exact known-answer tests. `pyref_both_det` is the contract's own
  worked example (plaintext `det\n`, recipient order `[x25519, ssh]`): 314
  bytes, sha256 `9750c165…`, armored 495 bytes, sha256 `1fc65fff…`, with the
  exact stanza lines pinned in the contract — `gen.py` asserts all of it, which
  is what proves this vendored reference — independently rewritten here,
  without importing the experiment's copy — still agrees byte-for-byte with
  the one that was verified against `rage` in both directions (contract §9.4).

## Regenerating

```
./gen.sh
```

Requires `rage`/`rage-keygen` 0.12.1 and `python3` 3.9+ on PATH; `ssh-keygen`
is optional (used only to cross-check the ssh key's SHA256 fingerprint, and
the check is skipped, not required, if it isn't present or its flags differ
across OpenSSH versions).
