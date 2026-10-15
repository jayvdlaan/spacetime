# Changelog

## 2.0.0

Now dual-licensed **MIT OR Apache-2.0** (1.x was MIT only).

Every crate moves to 2.0.0 together (one workspace version). Code that mixes spacetime 1.x and
2.x types sees two distinct types per name; upgrade every spacetime dependency at once.

### Breaking

- **spacetime-storage**: `StorageError` gains `HashMismatch` and `Digest(CryptoErrorKind)` and is
  now `#[non_exhaustive]`; exhaustive matches need a wildcard arm.

No other crate changes a 1.x public API; their 2.0.0 is the shared workspace version.

### Added

- **spacetime-crypto**: `no_std` trait facades for SHA-256/512, HMAC-SHA-256, Ed25519 (strict
  verification profile), Ed25519→X25519, ChaCha20-Poly1305 and XChaCha20-Poly1305, HKDF-SHA-256,
  Argon2id and X25519 (all-zero shared secret rejected), plus an RFC conformance harness
  (`conformance` feature) that a backend runs against itself.
- **spacetime-sshsig** (new crate): `no_std` OpenSSH SSHSIG (`ssh-keygen -Y sign` / `-Y verify`)
  over the facades — Ed25519 and sk-Ed25519, SHA-512, strict verification, armor, public-key lines,
  fingerprints and `allowed_signers` parsing. Stricter than ssh-keygen where the two differ; the
  README lists every divergence.
  - `AllowedSigner::accepts` rejects an entry that carries `valid-after` / `valid-before`;
    `accepts_at(principal, namespace, now)` applies ssh-keygen's window. Only the UTC forms
    (`…Z`) are interpreted; a local-time or malformed bound rejects.
- **spacetime-age** (new crate): `no_std` age-encryption.org/v1 codec over the facades — X25519
  and ssh-ed25519 recipients, STREAM payload, armor, header-only inspection. Follows the CCTV test
  vectors; the README lists where it differs from rage.
- **spacetime-storage**: a content-addressed streaming `BlobStore` seam with `MemBlobStore` and
  `FsBlobStore` (SHA-256 ids computed by the store, fsync + atomic rename, verified reads).
  `FsBlobStore` is Unix-only.

### Fixed

- **spacetime-macros**: clippy 1.98 `collapsible_match`.
