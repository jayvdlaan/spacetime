//! Crate-private helpers.

/// Best-effort zeroing of a secret buffer.
///
/// A plain zero loop followed by `core::hint::black_box` on the buffer so
/// the optimiser cannot prove the stores dead. `black_box` is a hint, not a
/// guarantee — this crate is `#![forbid(unsafe_code)]`, so `write_volatile`
/// is unavailable. The facade backend wipes its own expanded state; this
/// crate never holds a secret longer than the call that needs it except
/// [`crate::FileKey`], [`crate::Identity`] and the STREAM keys, which are
/// wiped on drop through this function.
pub(crate) fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(&*buf);
}

#[cfg(test)]
mod tests {
    use super::wipe;

    #[test]
    fn wipe_zeroes_every_byte() {
        let mut b = [0xAAu8; 40];
        wipe(&mut b);
        assert!(b.iter().all(|&x| x == 0));
    }

    #[test]
    fn wipe_of_empty_is_fine() {
        wipe(&mut []);
    }
}
