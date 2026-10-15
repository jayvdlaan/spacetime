//! Deterministic `Rng` double for the encrypt-side test binaries (included
//! with `#[path = "common/rng.rs"]`; the decrypt-only binaries never draw
//! randomness).

use spacetime_crypto::{CryptoResult, Rng};

/// Writes `n, n+1, n+2, …` (wrapping), exactly as `spacetime_crypto`'s own
/// test double.
pub struct CounterRng(pub u8);

impl Rng for CounterRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> CryptoResult<()> {
        for b in out.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}
