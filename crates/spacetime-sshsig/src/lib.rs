//! OpenSSH SSHSIG (PROTOCOL.sshsig) codec for `no_std`: parse,
//! pinned-predicate verify, deterministic sign (`ssh-ed25519`),
//! `sk-ssh-ed25519@openssh.com` verify, armor, public-key lines,
//! fingerprints and `allowed_signers` — generic over the `spacetime-crypto`
//! facades.
//!
//! SSHSIG is the detached-signature format behind `ssh-keygen -Y sign` /
//! `-Y verify`. A signature is an armored blob:
//!
//! ```text
//! "SSHSIG" ‖ uint32 1 ‖ string publickey ‖ string namespace ‖ string reserved
//!          ‖ string hash_algorithm ‖ string signature
//! ```
//!
//! and the Ed25519 message is the *signed data*
//!
//! ```text
//! "SSHSIG" ‖ string namespace ‖ string reserved ‖ string hash_algorithm ‖ string H(message)
//! ```
//!
//! This crate contains **no cryptography**: every hash and signature goes
//! through [`spacetime_crypto::Sha256`], [`spacetime_crypto::Sha512`],
//! [`spacetime_crypto::Ed25519Verify`] and [`spacetime_crypto::Ed25519Sign`],
//! supplied by the caller's backend. It is `no_std` by default, allocates
//! nothing in any core path (borrowed slices in, caller buffers out), and
//! offers owned conveniences under the `alloc` feature.
//!
//! # The pinned predicate
//!
//! [`verify()`] accepts a signature iff **all** of the following hold, in this
//! order (first failure wins):
//!
//! | # | Check | Error |
//! |---|---|---|
//! | A | armor: exact header/footer, lines ≤ 76, strict base64, nothing after the footer | `Armor*` |
//! | P | magic `SSHSIG`, version 1, every section consumed exactly, key/signature types known and of the same family, 32-byte key, 64-byte signature | `BadMagic`, `UnsupportedVersion`, `Truncated`, `TrailingBytes(_)`, `UnknownKeyType`, `UnknownSignatureType`, `KeyTypeMismatch`, `BadKeyLength`, `BadSignatureLength` |
//! | V1 | caller namespace non-empty, ≤ 255 bytes | `EmptyNamespace`, `NamespaceTooLong` |
//! | V2 | `reserved` empty | `ReservedNotEmpty` |
//! | V3 | `hash_algorithm == "sha512"` | `HashAlgorithmNotSha512` |
//! | V4 | blob namespace == caller namespace | `NamespaceMismatch` |
//! | V5 | embedded key == expected signer (when given) | `SignerMismatch` |
//! | V6 | sk: user presence (`0x01`) always; user verification (`0x04`) per [`SkPolicy`] | `SkUserPresenceMissing`, `SkUserVerificationMissing` |
//! | V7 | strict Ed25519 over the signed data rebuilt from the **caller's** namespace | `SignatureInvalid` |
//!
//! "Strict Ed25519" is the facade's profile: canonical `A`, `R`, `S < L`,
//! no small-order points, cofactorless equation — see
//! [`spacetime_crypto::Ed25519Verify`]. The blob's namespace is only ever
//! *compared*; the signed data is reconstructed from the verifier's
//! expected constant.
//!
//! # sk-ssh-ed25519@openssh.com
//!
//! The Ed25519 message for an sk signature (PROTOCOL.u2f) is
//!
//! ```text
//! SHA-256(application) ‖ flags ‖ counter (uint32 be) ‖ SHA-256(signed data)
//! ```
//!
//! with `application` taken from the key blob. sk keys are verify-only.
//!
//! # Streaming rule
//!
//! `H(message)` is SHA-512 over the **whole** message. [`verify()`] and
//! [`sign()`] hash a `&[u8]` in one shot; [`verify_digest`], [`sign_digest`]
//! and [`sign_armored_digest`] take a precomputed `[u8; 64]` so a std
//! layer can stream a large file through
//! [`spacetime_crypto::Sha512State`].
//!
//! # Non-goals
//!
//! OpenSSH private-key files (`openssh-key-v1`); certificates
//! (`*-cert-v01@openssh.com`) — `UnknownKeyType`; RSA / ECDSA / DSA —
//! `UnknownKeyType` / `UnknownSignatureType` (an explicit parse error, never
//! a silent accept); the ssh-agent protocol; sk signing; `hash_algorithm =
//! "sha256"`; glob/negation in `allowed_signers` pattern lists; local-time
//! (no `Z`) `valid-after` / `valid-before` values — an entry using one never
//! accepts; KRLs; webauthn-sk.
//!
//! # Entry points
//!
//! Every entry point is a generic function over the facade traits (there is
//! no trait of this crate's own to be object-safe); the backend may be a
//! `&dyn` facade where the facade allows it.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod allowed_signers;
pub mod armor;
pub mod blob;
pub mod error;
pub mod pubkey;
pub mod sign;
pub mod verify;
pub mod wire;

#[cfg(feature = "alloc")]
pub use allowed_signers::AllowedSignerBuf;
pub use allowed_signers::{AllowedSigner, AllowedSigners, LineError};
pub use blob::{
    ed25519_sshsig_len, Signature, SshSig, HASH_ALGORITHM_SHA512, MAGIC, SSHSIG_VERSION,
};
pub use error::{Error, Section};
#[cfg(feature = "alloc")]
pub use pubkey::PublicKeyBuf;
pub use pubkey::{PublicKey, FINGERPRINT_LEN, KEY_TYPE_ED25519, KEY_TYPE_SK_ED25519};
pub use sign::{sign, sign_armored, sign_armored_digest, sign_digest};
#[cfg(feature = "alloc")]
pub use sign::{sign_armored_string, sign_vec};
#[cfg(feature = "alloc")]
pub use verify::VerifiedBuf;
pub use verify::{
    verify, verify_digest, Expected, SkAttestation, SkPolicy, Verified, MAX_NAMESPACE_LEN,
    SK_FLAG_USER_PRESENCE, SK_FLAG_USER_VERIFICATION,
};
