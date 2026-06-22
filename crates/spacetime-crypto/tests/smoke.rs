use spacetime_crypto as sc;
use spacetime_crypto::Rng;

struct Counter(u8);
impl sc::Rng for Counter {
    fn fill_bytes(&mut self, out: &mut [u8]) -> sc::CryptoResult<()> {
        for b in out.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

#[test]
fn rng_fills_buffer() {
    let mut r = Counter(1);
    let mut buf = [0u8; 4];
    r.fill_bytes(&mut buf).unwrap();
    assert_eq!(&buf, &[1, 2, 3, 4]);
}
