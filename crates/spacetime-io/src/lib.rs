#![no_std]

//! Spacetime I/O traits: minimal, no_std-friendly facades.
//!
//! These traits mirror a subset of embedded-io/core2::io to avoid a hard
//! dependency while keeping the API surface tiny and portable. Platform
//! adapters can implement these traits for concrete transports (UART, TCP,
//! files, etc.).

/// Error type for I/O operations in no_std contexts.
///
/// Variants mirror common `std::io::ErrorKind` values so that platform
/// adapters can provide meaningful diagnostics without pulling in `std`.
/// The enum is intentionally `#[non_exhaustive]` so that new variants can
/// be added in future releases without breaking downstream match arms.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum IoError {
    /// Operation would block (non-blocking mode or lack of readiness).
    WouldBlock,
    /// The operation timed out before completing.
    TimedOut,
    /// An unexpected end-of-file / end-of-stream was reached.
    UnexpectedEof,
    /// A parameter or input was invalid.
    InvalidInput,
    /// The caller lacks the required permissions.
    PermissionDenied,
    /// The connection was refused by the remote host.
    ConnectionRefused,
    /// The connection was reset by the remote host.
    ConnectionReset,
    /// The requested resource was not found.
    NotFound,
    /// Input/output error of unspecified kind.
    Other,
}

impl core::fmt::Display for IoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[allow(unreachable_patterns)] // wildcard needed for #[non_exhaustive]
        match self {
            IoError::WouldBlock => f.write_str("operation would block"),
            IoError::TimedOut => f.write_str("operation timed out"),
            IoError::UnexpectedEof => f.write_str("unexpected end of file"),
            IoError::InvalidInput => f.write_str("invalid input"),
            IoError::PermissionDenied => f.write_str("permission denied"),
            IoError::ConnectionRefused => f.write_str("connection refused"),
            IoError::ConnectionReset => f.write_str("connection reset"),
            IoError::NotFound => f.write_str("not found"),
            IoError::Other => f.write_str("other I/O error"),
            _ => f.write_str("unknown I/O error"),
        }
    }
}

pub type IoResult<T> = core::result::Result<T, IoError>;

/// Minimal blocking read trait.
pub trait Read {
    /// Read some bytes into `buf`, returning the number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize>;
}

/// Minimal blocking write trait.
pub trait Write {
    /// Write some bytes from `buf`, returning the number of bytes written.
    fn write(&mut self, buf: &[u8]) -> IoResult<usize>;
}

/// Flush buffered output, if any.
pub trait Flush {
    fn flush(&mut self) -> IoResult<()>;
}

/// Shared test utilities (`Sink`, etc.) for I/O tests.
///
/// Available only when the `std` feature is enabled.
#[cfg(feature = "std")]
#[doc(hidden)]
pub mod testutil;

/// Convenience helper: write all bytes, looping until complete or error.
///
/// Returns `Err(IoError::WouldBlock)` immediately if the underlying writer
/// is not ready, letting the caller decide how to handle back-pressure
/// (e.g. yield, sleep, or retry). This avoids a busy-spin in `no_std`
/// environments where there is no way to yield the thread.
///
/// On success, `buf` has been fully written. On `WouldBlock`, some prefix
/// of `buf` may already have been written; callers that need to resume
/// should track progress externally.
pub fn write_all<W: Write>(w: &mut W, mut buf: &[u8]) -> IoResult<()> {
    while !buf.is_empty() {
        match w.write(buf) {
            Ok(0) => return Err(IoError::Other), // prevent infinite loop
            Ok(n) => buf = &buf[n..],
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;
    use crate::testutil::Sink;
    use std::format;

    #[test]
    fn write_all_writes_everything() {
        let mut s = Sink::<16>::new();
        let msg = b"hello world";
        write_all(&mut s, msg).unwrap();
        assert_eq!(&s.buf[..s.len], &msg[..]);
    }

    #[test]
    fn write_all_error_on_full() {
        let mut s = Sink::<4>::new();
        let msg = b"too long for buffer";
        let result = write_all(&mut s, msg);
        assert!(result.is_err());
    }

    #[test]
    fn io_error_equality() {
        assert_eq!(IoError::WouldBlock, IoError::WouldBlock);
        assert_eq!(IoError::Other, IoError::Other);
        assert_ne!(IoError::WouldBlock, IoError::Other);
    }

    #[test]
    fn io_error_debug() {
        let e = IoError::WouldBlock;
        let cloned = e;
        assert_eq!(format!("{:?}", e), "WouldBlock");
        assert_eq!(e, cloned);
    }

    /// Writer that returns WouldBlock on first call, then succeeds.
    struct WouldBlockOnceWriter {
        calls: usize,
        buf: [u8; 32],
        len: usize,
    }

    impl WouldBlockOnceWriter {
        fn new() -> Self {
            Self {
                calls: 0,
                buf: [0u8; 32],
                len: 0,
            }
        }
    }

    impl Write for WouldBlockOnceWriter {
        fn write(&mut self, data: &[u8]) -> IoResult<usize> {
            self.calls += 1;
            if self.calls == 1 {
                return Err(IoError::WouldBlock);
            }
            let n = core::cmp::min(self.buf.len() - self.len, data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            Ok(n)
        }
    }

    #[test]
    fn write_all_propagates_would_block() {
        let mut w = WouldBlockOnceWriter::new();
        let msg = b"hello";
        // write_all should now propagate WouldBlock instead of busy-spinning
        let result = write_all(&mut w, msg);
        assert!(matches!(result, Err(IoError::WouldBlock)));
        // Nothing should have been written yet
        assert_eq!(w.len, 0);
        assert_eq!(w.calls, 1);

        // Caller can retry after handling back-pressure (e.g. yielding)
        let result = write_all(&mut w, msg);
        assert!(result.is_ok());
        assert_eq!(&w.buf[..w.len], msg);
    }

    /// Writer that always returns 0 bytes written (no progress)
    struct ZeroWriter;

    impl Write for ZeroWriter {
        fn write(&mut self, _data: &[u8]) -> IoResult<usize> {
            Ok(0)
        }
    }

    #[test]
    fn write_all_error_on_zero_bytes() {
        let mut w = ZeroWriter;
        let result = write_all(&mut w, b"data");
        assert!(matches!(result, Err(IoError::Other)));
    }

    #[test]
    fn io_error_display_all_variants() {
        assert_eq!(format!("{}", IoError::WouldBlock), "operation would block");
        assert_eq!(format!("{}", IoError::TimedOut), "operation timed out");
        assert_eq!(
            format!("{}", IoError::UnexpectedEof),
            "unexpected end of file"
        );
        assert_eq!(format!("{}", IoError::InvalidInput), "invalid input");
        assert_eq!(
            format!("{}", IoError::PermissionDenied),
            "permission denied"
        );
        assert_eq!(
            format!("{}", IoError::ConnectionRefused),
            "connection refused"
        );
        assert_eq!(format!("{}", IoError::ConnectionReset), "connection reset");
        assert_eq!(format!("{}", IoError::NotFound), "not found");
        assert_eq!(format!("{}", IoError::Other), "other I/O error");
    }

    #[test]
    fn io_result_type_alias() {
        let ok: IoResult<usize> = Ok(42);
        assert!(ok.is_ok());
        let err: IoResult<usize> = Err(IoError::TimedOut);
        assert!(err.is_err());
    }

    #[test]
    fn sink_default_trait() {
        let s = Sink::<8>::default();
        assert_eq!(s.len, 0);
    }

    #[test]
    fn write_all_empty_buf_succeeds() {
        let mut s = Sink::<4>::new();
        write_all(&mut s, b"").unwrap();
        assert_eq!(s.len, 0);
    }

    #[test]
    fn read_trait_object_safety() {
        struct SliceReader<'a>(&'a [u8]);
        impl Read for SliceReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
                let n = core::cmp::min(buf.len(), self.0.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let data = b"hello";
        let mut reader = SliceReader(data);
        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }
}
