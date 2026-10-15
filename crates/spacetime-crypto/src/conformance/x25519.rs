//! Conformance check for [`X25519`].

use super::vectors::{X25519 as X25519_VECTORS, X25519_LOW_ORDER_PEERS};
use super::Case;
use crate::{CryptoErrorKind, CryptoResult, X25519, X25519_KEY_LEN};

/// Run the RFC 7748 §6.1 vector and the low-order-peer rejections against
/// `x`.
///
/// For every vector in [`X25519_VECTORS`](super::vectors::X25519):
/// `x25519_public_key` must derive both public keys; `x25519` must produce
/// the shared secret in both directions. Then, for every entry of
/// [`X25519_LOW_ORDER_PEERS`] with Alice's secret: `x25519` must fail with
/// exactly `InvalidParameter` and leave the shared buffer — pre-filled with
/// `0xAA` by the harness — all zero.
pub fn check_x25519<X: X25519 + ?Sized>(x: &X) -> CryptoResult<()> {
    const CHECK: &str = "check_x25519";

    for v in X25519_VECTORS {
        let case = Case::new(CHECK, v.name);

        let pk = case.ok(x.x25519_public_key(&v.alice_secret))?;
        case.eq("Alice's public key", &pk, &v.alice_public)?;
        let pk = case.ok(x.x25519_public_key(&v.bob_secret))?;
        case.eq("Bob's public key", &pk, &v.bob_public)?;

        let mut shared = [0u8; X25519_KEY_LEN];
        case.ok(x.x25519(&v.alice_secret, &v.bob_public, &mut shared))?;
        case.eq("shared secret (Alice's side)", &shared, &v.shared)?;
        let mut shared = [0u8; X25519_KEY_LEN];
        case.ok(x.x25519(&v.bob_secret, &v.alice_public, &mut shared))?;
        case.eq("shared secret (Bob's side)", &shared, &v.shared)?;

        for peer in X25519_LOW_ORDER_PEERS {
            let case = Case::new(CHECK, peer.name);
            let mut shared = [0xAAu8; X25519_KEY_LEN];
            case.kind(
                "x25519 with a low-order peer",
                x.x25519(&v.alice_secret, &peer.key, &mut shared),
                CryptoErrorKind::InvalidParameter,
            )?;
            case.ensure(
                shared.iter().all(|b| *b == 0),
                "shared buffer not all-zero after a low-order peer was rejected",
            )?;
        }
    }
    Ok(())
}
