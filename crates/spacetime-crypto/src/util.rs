//! Internal helpers shared by the facade traits.
//!
//! Nothing here is cryptography: this module wipes the crate's own transient
//! buffers (e.g. an HKDF PRK, or a caller buffer after a failed AEAD open) so
//! secret material does not linger on the stack longer than necessary.

/// Overwrite `buf` with zeros in a way the optimizer cannot elide, even
/// though the buffer's final value is otherwise unobserved.
///
/// This is the crate's only `unsafe` code. A safe `for b in buf { *b = 0 }`
/// loop is a valid target for dead-store elimination once the compiler can
/// prove `buf` is not read again; a volatile write per byte, followed by a
/// compiler fence, forbids that optimization without pulling in the `zeroize`
/// crate (out of scope for a zero-dependency trait facade).
pub(crate) fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned `&mut u8` derived from the caller's
        // slice, so a volatile write of a `u8` to it is defined behavior. The
        // fence prevents the compiler from reordering or eliding the writes
        // relative to any later (or earlier) accesses to `buf`.
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::wipe;

    #[test]
    fn wipe_zeroes_buffer() {
        let mut buf = [0xAAu8; 16];
        wipe(&mut buf);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn wipe_handles_empty_buffer() {
        let mut buf: [u8; 0] = [];
        wipe(&mut buf);
        assert_eq!(buf.len(), 0);
    }
}
