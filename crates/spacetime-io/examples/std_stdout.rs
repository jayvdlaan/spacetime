// Run with: cargo run -p spacetime-io --example std_stdout --features std

#![cfg(feature = "std")]

use spacetime_io::{write_all, Flush, IoError, IoResult, Write};
use std::io::Write as _; // bring std::io::Write trait for Stdout::write

struct StdoutWriter(std::io::Stdout);

/// Map a [`std::io::ErrorKind`] to the corresponding [`IoError`] variant.
fn map_std_io_error(e: &std::io::Error) -> IoError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock => IoError::WouldBlock,
        std::io::ErrorKind::TimedOut => IoError::TimedOut,
        std::io::ErrorKind::UnexpectedEof => IoError::UnexpectedEof,
        std::io::ErrorKind::InvalidInput => IoError::InvalidInput,
        std::io::ErrorKind::PermissionDenied => IoError::PermissionDenied,
        std::io::ErrorKind::ConnectionRefused => IoError::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset => IoError::ConnectionReset,
        std::io::ErrorKind::NotFound => IoError::NotFound,
        _ => IoError::Other,
    }
}

impl Write for StdoutWriter {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // Delegate to std::io::Write
        match self.0.write(buf) {
            Ok(n) => Ok(n),
            Err(e) => Err(map_std_io_error(&e)),
        }
    }
}

impl Flush for StdoutWriter {
    fn flush(&mut self) -> IoResult<()> {
        self.0.flush().map_err(|e| map_std_io_error(&e))
    }
}

fn main() {
    let mut w = StdoutWriter(std::io::stdout());
    write_all(&mut w, b"Hello from spacetime-io!\n").unwrap();
    w.flush().unwrap();
}
