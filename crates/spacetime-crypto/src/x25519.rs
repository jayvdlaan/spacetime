//! X25519 Diffie-Hellman facade (RFC 7748 §5/§6.1).

use crate::CryptoResult;

/// X25519 secret/public key length in bytes.
pub const X25519_KEY_LEN: usize = 32;

/// X25519 Diffie-Hellman (RFC 7748 §5/§6.1).
///
/// # Errors
/// [`crate::CryptoErrorKind::InvalidParameter`] from
/// [`X25519::x25519`] when the peer's public key is low-order (all-zero
/// shared secret); otherwise only `Unavailable`/`Failed`.
///
/// # Object safety
/// Object-safe: `&self`, array parameters, no generics.
///
/// # Conformance
/// See `check_x25519` (feature `conformance`).
pub trait X25519 {
    /// Clamp `secret` per RFC 7748 §5 and multiply the base point `u = 9`.
    fn x25519_public_key(
        &self,
        secret: &[u8; X25519_KEY_LEN],
    ) -> CryptoResult<[u8; X25519_KEY_LEN]>;

    /// `shared = X25519(clamp(secret), peer_public)`, writing the result
    /// into the caller-provided `shared` buffer.
    ///
    /// Bit 255 of `peer_public` is masked per RFC 7748 §5; no canonicality
    /// check is performed on the peer's `u`-coordinate (RFC 7748 explicitly
    /// accepts `u >= p`, reducing it mod `p`).
    ///
    /// If the result is all-zero — which, since the clamped scalar is
    /// always a multiple of 8, only happens when `peer_public` encodes a
    /// point of order dividing 8 (a low-order peer) — `shared` is left
    /// **all-zero** and [`crate::CryptoErrorKind::InvalidParameter`] is
    /// returned rather than silently handing back a degenerate secret. This
    /// mirrors `airframe_crypt`'s manual OR-fold check and `x25519-dalek`'s
    /// `SharedSecret::was_contributory`. The all-zero check itself must be
    /// constant time (an OR-fold over the output bytes, not an early-exit
    /// comparison).
    ///
    /// A backend that instead blocklists known low-order peer encodings
    /// *before* multiplying must still zero `shared` on that rejection path,
    /// so callers can rely on "`Err` implies `shared` is all-zero"
    /// unconditionally.
    fn x25519(
        &self,
        secret: &[u8; X25519_KEY_LEN],
        peer_public: &[u8; X25519_KEY_LEN],
        shared: &mut [u8; X25519_KEY_LEN],
    ) -> CryptoResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CryptoError, CryptoErrorKind};

    /// A fake: "public key" is the secret unchanged, "shared secret" is the
    /// XOR of the two 32-byte inputs (commutative, so both directions
    /// agree) -- except that a designated low-order peer list is honored so
    /// the all-zero-on-failure contract can be tested. Not cryptography.
    struct XorDh {
        low_order_peers: [[u8; X25519_KEY_LEN]; 1],
    }

    impl XorDh {
        fn new() -> Self {
            Self {
                low_order_peers: [[0u8; X25519_KEY_LEN]],
            }
        }
    }

    impl X25519 for XorDh {
        fn x25519_public_key(
            &self,
            secret: &[u8; X25519_KEY_LEN],
        ) -> CryptoResult<[u8; X25519_KEY_LEN]> {
            Ok(*secret)
        }

        fn x25519(
            &self,
            secret: &[u8; X25519_KEY_LEN],
            peer_public: &[u8; X25519_KEY_LEN],
            shared: &mut [u8; X25519_KEY_LEN],
        ) -> CryptoResult<()> {
            if self.low_order_peers.contains(peer_public) {
                *shared = [0u8; X25519_KEY_LEN];
                return Err(CryptoError::new(CryptoErrorKind::InvalidParameter));
            }
            for i in 0..X25519_KEY_LEN {
                shared[i] = secret[i] ^ peer_public[i];
            }
            Ok(())
        }
    }

    #[test]
    fn dh_agrees_both_directions() {
        let alice_secret = [1u8; X25519_KEY_LEN];
        let bob_secret = [2u8; X25519_KEY_LEN];
        let dh = XorDh::new();
        let alice_pub = dh.x25519_public_key(&alice_secret).unwrap();
        let bob_pub = dh.x25519_public_key(&bob_secret).unwrap();

        let mut shared_a = [0u8; X25519_KEY_LEN];
        dh.x25519(&alice_secret, &bob_pub, &mut shared_a).unwrap();
        let mut shared_b = [0u8; X25519_KEY_LEN];
        dh.x25519(&bob_secret, &alice_pub, &mut shared_b).unwrap();
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn low_order_peer_is_rejected_and_zeroed() {
        let dh = XorDh::new();
        let secret = [7u8; X25519_KEY_LEN];
        let mut shared = [0xAAu8; X25519_KEY_LEN];
        let err = dh
            .x25519(&secret, &[0u8; X25519_KEY_LEN], &mut shared)
            .unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::InvalidParameter);
        assert_eq!(shared, [0u8; X25519_KEY_LEN]);
    }
}
