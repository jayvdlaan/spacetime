# CCTV age test vectors (vendored)

Source: https://github.com/C2SP/CCTV, subdirectory `age/testdata`.
Commit: `4448f2097b2daa812c91a26141f9f36c2096b9ca` (2026-08-29).
License: 0BSD / CC0 1.0 / Unlicense, at the vendor's choice (see `LICENSE`); vendoring
without attribution is explicitly permitted by the upstream README, but the license
text is reproduced here anyway (contract §5.1).

`testdata/` holds the 147 vector files, byte-identical to upstream (verified with
`diff -rq` against the clone at vendor time; re-verify the same way after a re-vendor).

## Re-vendoring

```
git clone https://github.com/C2SP/CCTV /tmp/cctv-src
cd /path/to/spacetime-age/tests/vectors/cctv
rm -rf testdata
cp -r /tmp/cctv-src/age/testdata .
diff -rq /tmp/cctv-src/age/testdata testdata   # must print nothing
```

Update the commit hash above and in `LICENSE`, and re-run the vector count / class
totals in `tests/cctv.rs` (spacetime-age D14/§5.2) — a new upstream commit may add,
remove, or reclassify vectors.

## File format (from the upstream README)

Each file is a textual header (`key: value` lines), a blank line, then an age-encrypted
file (possibly zlib-compressed). Unknown header keys are ignored.

- `expect` — one of `success`, `no match`, `HMAC failure`, `header failure`,
  `payload failure`, `armor failure`.
  - `success`: decrypts correctly to EOF; payload matches the hash.
  - `no match`: header parses; no recipient stanza unwraps.
  - `HMAC failure`: header parses, a file key unwraps, but the header HMAC is wrong.
  - `header failure`: the header fails to parse.
  - `payload failure`: header parses, a file key unwraps, but the STREAM payload
    does not decrypt cleanly to EOF. **Whatever plaintext was released before the
    error must still match the payload hash.**
  - `armor failure`: the ASCII armor fails to parse.
- `compressed: zlib` — the encrypted file is zlib-compressed (22 vectors here);
  inflate before further processing.
- `payload` — hex SHA-256 of *all* plaintext ever released to the caller, even on
  a `payload failure` (this key is present only for `success` and `payload failure`).
- `identity` — one or more Bech32 X25519 or hybrid identities to attempt.
- `passphrase` — one or more passphrases, for `scrypt` stanzas.
- `armored: yes` — the file is ASCII-armored.
- `file key` — hex file key, for round-trip re-encryption checks; may be absent.
- `comment` — human-readable, ignored by the driver.

## Skip policy (spacetime-age contract §5.2, D14)

`spacetime-age` does not implement passphrase (`scrypt`) recipients or hybrid
(`AGE-SECRET-KEY-PQ-…` / `mlkem768x25519`) recipients. Vectors that exercise only
those are **not** silently ignored: the runner (`tests/cctv.rs`) puts them in an
explicit "unsupported" mode (never plain skip) and counts them separately from the
147:

- **103** strict vectors, checked exactly against `expect`: 34 header failure,
  26 armor failure, 19 success, 19 payload failure, 4 no match, 1 HMAC failure.
- **26** `skipped_passphrase` — every vector carrying a `passphrase:` line.
- **18** `skipped_hybrid` — every vector whose *only* identities are hybrid
  (`AGE-SECRET-KEY-PQ-…`, which fails `Identity::from_age_str`) and that has no
  usable X25519/ssh-ed25519 identity to fall back to.

`compressed: zlib` (22 of the above, distributed across classes) is inflated with
`miniz_oxide` — never skipped.

In "unsupported" mode the runner still requires the outcome to be an `Err` whose
class matches the vector's declared `expect` (or `NoMatch` / `Unsupported(Scrypt)`,
since an implementation without the feature may legitimately fail earlier), that
`released` is empty, and it counts (without asserting the hash) whenever the class
matched anyway (`matched_anyway`). "Never silently ignored as grease" (contract R4)
means: every one of the 147 files is read, classified into strict or
skipped_passphrase/skipped_hybrid, and contributes to the printed summary line —
none is dropped by a directory filter or a name pattern.

Never edit a vector file. If a byte in `testdata/` needs to change, that means a
re-vendor from a newer upstream commit, not a hand edit.
