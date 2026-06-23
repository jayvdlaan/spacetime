# spacetime-ipc

Platform-agnostic, `no_std`-first IPC trait and error definitions for inter-process communication.

## Overview

`spacetime-ipc` is a minimal facade crate that declares the abstractions used
for inter-process communication across the Spacetime/Airframe stack. It contains
no platform-specific code and pulls in no dependencies — only the shared error
type and the traits that concrete backends implement.

The crate exposes:

- `IpcError` — a `Copy` error enum covering shared-region, channel, and child-process failure modes, with a `core::fmt::Display` implementation.
- `SharedRegion` — a trait for a named shared memory region accessible by multiple processes.
- `IpcChannel` — a trait for a bidirectional, message-oriented (non-streaming) byte channel.
- `ChildHandle` — a trait for a handle to a spawned child process.

Concrete implementations of these traits live in `airframe_ipc`; this crate
provides only the contract so that downstream code can be written against a
stable, portable interface.

## Feature flags

The crate is `#![no_std]` and builds with no features by default.

- *(default — none)* — pure `no_std`; only `core` is used.
- `alloc` — pulls in `extern crate alloc` for builds that target `no_std` with an allocator.
- `std` — enables `extern crate std` (implies `alloc`).

The public API surface is identical across all feature combinations; the flags
only control which standard facilities are linked in for downstream consumers.

## Dependencies

None. The crate depends solely on `core` (and optionally `alloc`/`std` via the
feature flags above).

## Usage

Implement the traits over your platform's IPC primitives, then program against
the trait objects:

```rust
use spacetime_ipc::{ChildHandle, IpcChannel, IpcError, SharedRegion};

/// A toy in-memory region backed by a byte slice.
struct SliceRegion<'a>(&'a mut [u8]);

impl SharedRegion for SliceRegion<'_> {
    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
    // `is_empty` is provided by the trait's default implementation.
}

/// Send a message over any channel, surfacing a typed error on failure.
fn forward<C: IpcChannel>(chan: &mut C, msg: &[u8]) -> Result<(), IpcError> {
    if !chan.poll() {
        // No data pending; carry on with the send.
    }
    chan.send(msg)
}

/// Stop a child, then confirm it is no longer alive.
fn stop<H: ChildHandle>(child: &mut H) -> Result<u64, IpcError> {
    let pid = child.pid();
    child.kill()?;
    debug_assert!(!child.is_alive());
    Ok(pid)
}
```

Every fallible operation returns `Result<_, IpcError>`, and `IpcError`
implements `Display`, so failures can be reported in `no_std` contexts without
an allocator:

```rust
use spacetime_ipc::IpcError;

let err = IpcError::Timeout;
// Renders as: "operation timed out"
let _ = err == IpcError::Timeout; // IpcError is Copy + Eq
```
