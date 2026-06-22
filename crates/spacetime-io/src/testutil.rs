//! Shared test utilities for spacetime-io tests.
//!
//! This module is gated on `feature = "std"` and hidden from documentation.
//! It provides a simple fixed-capacity byte sink implementing [`Write`] for
//! use in both unit tests and integration tests.

use crate::{IoError, IoResult, Write};

/// A fixed-capacity in-memory byte buffer that implements [`Write`].
///
/// Writes succeed until the buffer is full, then return [`IoError::Other`].
pub struct Sink<const N: usize> {
    pub buf: [u8; N],
    pub len: usize,
}

impl<const N: usize> Sink<N> {
    pub fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }
}

impl<const N: usize> Default for Sink<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Write for Sink<N> {
    fn write(&mut self, data: &[u8]) -> IoResult<usize> {
        if self.len >= N {
            return Err(IoError::Other);
        }
        let space = N - self.len;
        let n = core::cmp::min(space, data.len());
        self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
        self.len += n;
        Ok(n)
    }
}
