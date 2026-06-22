#![no_std]

//! Platform-agnostic IPC abstractions for inter-process communication.
//!
//! Provides no_std-compatible traits for shared memory regions, IPC channels,
//! and child process handles. Concrete implementations live in `airframe_ipc`.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Error type for IPC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// The shared memory region could not be created or opened.
    RegionCreateFailed,
    /// The shared memory region could not be mapped.
    RegionMapFailed,
    /// A send operation failed.
    SendFailed,
    /// A receive operation failed.
    RecvFailed,
    /// The connection was closed by the remote end.
    ConnectionClosed,
    /// The child process could not be spawned.
    SpawnFailed,
    /// The child process could not be killed.
    KillFailed,
    /// The operation timed out.
    Timeout,
    /// An invalid argument was provided.
    InvalidArgument,
    /// The region name or path was too long.
    NameTooLong,
}

impl core::fmt::Display for IpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RegionCreateFailed => write!(f, "shared region creation failed"),
            Self::RegionMapFailed => write!(f, "shared region mapping failed"),
            Self::SendFailed => write!(f, "send failed"),
            Self::RecvFailed => write!(f, "receive failed"),
            Self::ConnectionClosed => write!(f, "connection closed"),
            Self::SpawnFailed => write!(f, "child process spawn failed"),
            Self::KillFailed => write!(f, "child process kill failed"),
            Self::Timeout => write!(f, "operation timed out"),
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::NameTooLong => write!(f, "name too long"),
        }
    }
}

/// A named shared memory region accessible by multiple processes.
///
/// # Safety
///
/// Implementations must ensure that the returned pointers are valid for the
/// lifetime of the region and that the length accurately reflects the mapped
/// size. Callers must ensure proper synchronization when accessing the region
/// concurrently from multiple processes.
pub trait SharedRegion {
    /// Returns a pointer to the start of the shared memory region.
    fn as_ptr(&self) -> *const u8;

    /// Returns a mutable pointer to the start of the shared memory region.
    fn as_mut_ptr(&mut self) -> *mut u8;

    /// Returns the total size of the shared memory region in bytes.
    fn len(&self) -> usize;

    /// Returns true if the region has zero length.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A bidirectional IPC channel for sending and receiving byte messages.
///
/// Messages are discrete (not streaming) — each `send` produces exactly
/// one `recv` on the other end.
pub trait IpcChannel {
    /// Send a message. Blocks until the message is fully written.
    fn send(&mut self, data: &[u8]) -> Result<(), IpcError>;

    /// Receive a message into the provided buffer. Returns the number
    /// of bytes written.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, IpcError>;

    /// Returns true if there is data available to read without blocking.
    fn poll(&self) -> bool;
}

/// Handle to a child process spawned by the current process.
pub trait ChildHandle {
    /// Returns true if the child process is still running.
    fn is_alive(&self) -> bool;

    /// Returns the OS process ID of the child.
    fn pid(&self) -> u64;

    /// Terminate the child process.
    fn kill(&mut self) -> Result<(), IpcError>;
}
