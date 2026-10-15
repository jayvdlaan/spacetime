//! age-encryption.org/v1 file format for `no_std`: header/stanza codec with
//! grease tolerance, header MAC, STREAM payload, X25519 and ssh-ed25519
//! recipients, bech32 keys, ASCII armor and header-only inspection —
//! generic over the [`spacetime_crypto`] facades.
//!
//! This crate contains **no cryptography**: every hash, MAC, KDF, AEAD and
//! Diffie-Hellman goes through a facade trait supplied by the caller's
//! backend. It is `no_std` by default, allocates nothing in any core path
//! (borrowed slices in, caller buffers out), and offers owned conveniences
//! under the `alloc` feature.
//!
//! # The format in one screen
//!
//! ```text
//! age-encryption.org/v1\n
//! -> <type> <args…>\n                       zero or more stanzas; body is raw base64
//! <body, 64-column lines, last line < 64>\n  (the last line may be empty)
//! --- <base64 HMAC-SHA-256 (32 bytes)>\n     MAC key = HKDF(salt = "", ikm = file key, info = "header")
//!                                             over every header byte through the three dashes
//! <16-byte nonce><STREAM chunks…>            key = HKDF(salt = nonce, ikm = file key, info = "payload")
//! ```
//!
//! STREAM: ChaCha20-Poly1305 over 64 KiB plaintext chunks, chunk nonce =
//! 11-byte big-endian counter ‖ 1-byte last-chunk flag; the final chunk is
//! 1..=64 KiB, or empty only for an empty plaintext (see [`stream`]).
//!
//! Recipient stanzas (the exact HKDF roles are normative; both verified
//! against `rage` 0.12 and Go `age`):
//!
//! | Stanza | Key agreement | Wrap key |
//! |---|---|---|
//! | `-> X25519 b64(eph)` | `shared = X25519(e, pk)` | `HKDF(salt = eph ‖ pk, ikm = shared, info = "age-encryption.org/v1/X25519")` |
//! | `-> ssh-ed25519 b64(SHA-256(wire)[..4]) b64(eph)` | `tweak = HKDF(salt = wire, ikm = "", info = LABEL)`; `shared = X25519(tweak, X25519(e, pk_mont))` | `HKDF(salt = eph ‖ pk_mont, ikm = shared, info = LABEL)` |
//!
//! where `wire` is the 51-byte SSH public-key blob, `pk_mont` the
//! Edwards→Montgomery form of the Ed25519 key
//! ([`spacetime_crypto::Ed25519ToX25519`] on encrypt;
//! `X25519(clamp(SHA-512(seed)[..32]), 9)` on decrypt), and the body is the
//! 16-byte file key sealed with ChaCha20-Poly1305 under an all-zero nonce.
//!
//! # Grease and unsupported stanzas
//!
//! Unknown stanza types are grease: their structure is validated, then they
//! are ignored. `scrypt` and `ssh-rsa` are *recognised*, counted, and
//! reported as [`Error::Unsupported`] when nothing else unwraps — never
//! silently skipped. A `scrypt` stanza must be the only stanza. Recognised
//! recipient stanzas (`X25519`, `ssh-ed25519`) are shape-checked at parse
//! time regardless of the identities held.
//!
//! # Unwrap order and the release rule
//!
//! Identities outer, stanzas inner, first success wins; a low-order share
//! is fatal (`Header(LowOrderShare)`); the MAC is verified before a file
//! key is returned. On decrypt, the plaintext of every successfully opened
//! chunk is released before a later error is detected (Go semantics — the
//! CCTV corpus hashes released plaintext even on `payload failure`); the
//! `alloc` convenience `decrypt_vec` releases nothing on `Err`.
//!
//! # Randomness
//!
//! Every encrypt entry point takes an `rng: &mut R` (`R:`
//! [`spacetime_crypto::Rng`]). Draw order: 16 bytes file key, 32 bytes per
//! recipient in order, 16 bytes payload nonce — so a deterministic `Rng`
//! yields byte-deterministic output. No facade method draws randomness.
//!
//! # Non-goals
//!
//! scrypt/passphrase stanzas (reported `Unsupported(Scrypt)`); `ssh-rsa`
//! (`Unsupported(SshRsa)`); hybrid `mlkem768x25519` and plugin stanzas
//! (grease, so a file addressed only to them is `NoMatch`); age plugins;
//! `AGE-SECRET-KEY-PQ-…` / `AGE-PLUGIN-…` identity strings (`Key(Hrp)`);
//! OpenSSH private-key files; passphrase-protected identity files;
//! multi-file archives; grease emission on encrypt; header versions other
//! than `age-encryption.org/v1`; streaming armor decode (armored input is
//! buffered).
//!
//! # Entry points
//!
//! Every entry point is a generic function over the facade traits
//! ([`EncryptBackend`] / [`DecryptBackend`] are blanket-implemented
//! bounds, not traits to implement); the backend may be a `&dyn` facade
//! where the facade allows it.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod util;

pub mod armor;
pub mod base64;
pub mod bech32;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod header;
pub mod inspect;
pub mod keys;
pub mod ssh_ed25519;
pub mod stanza;
pub mod stream;
pub mod x25519;

#[cfg(feature = "alloc")]
pub use decrypt::{decrypt_armored_vec, decrypt_vec};
pub use decrypt::{unwrap_file_key, DecryptBackend};
#[cfg(feature = "alloc")]
pub use encrypt::{encrypt_armored_string, encrypt_vec};
pub use encrypt::{
    encrypt_header, encrypt_header_len, encrypted_len, header_len_for, EncryptBackend,
};
pub use error::{ArmorError, Class, Error, HeaderError, KeyError, PayloadError, UnsupportedStanza};
pub use header::{Header, Stanzas, HEADER_MAC_LEN, MAC_INFO, MAC_LINE_LEN, MAGIC};
pub use inspect::{inspect, inspect_armored, Inspection};
#[cfg(feature = "alloc")]
pub use inspect::{inspect_auto, InspectionBuf, StanzaBuf};
pub use keys::{
    FileKey, Identity, IdentityKind, Recipient, FILE_KEY_LEN, IDENTITY_STR_LEN, RECIPIENT_STR_LEN,
};
pub use stanza::{
    Args, Stanza, StanzaKind, STANZA_TYPE_SCRYPT, STANZA_TYPE_SSH_ED25519, STANZA_TYPE_SSH_RSA,
    STANZA_TYPE_X25519,
};
pub use stream::{
    sealed_payload_len, StreamReader, StreamWriter, CHUNK_LEN, CHUNK_SEALED_LEN, CHUNK_TAG_LEN,
    PAYLOAD_INFO, PAYLOAD_NONCE_LEN,
};
