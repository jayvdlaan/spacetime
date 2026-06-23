# spacetime-capabilities

Minimal capability identity and metadata types for Spacetime runtimes.

## Overview

This crate provides lightweight, `no_std`-first types for identifying and describing capabilities in a module system. It focuses solely on identity and simple descriptors - resolution logic and semver range matching are left to higher-level runtimes like Airframe.

## Features

| Feature | Description |
|---------|-------------|
| `alloc` | Enables owned metadata types (`CapabilityMeta` with `Cow<str>`) |
| `serde` | Enables serialization support for capability types |
| `std` | Enables standard library (implies `alloc`) |

## Types

### `CapabilityId`

A stable identifier for a capability, typically a reverse-DNS or namespaced string.

```rust
use spacetime_capabilities::CapabilityId;

const SCHEDULER: CapabilityId = CapabilityId::new("airframe:scheduler");
const HEALTH: CapabilityId = CapabilityId::new("airframe:health");
```

### `Capability`

A capability with its provider information.

```rust
use spacetime_capabilities::{Capability, CapabilityId};
use spacetime_core::Version;

let cap = Capability::new(
    CapabilityId::new("airframe:kv"),
    "airframe_kv",
    Version::new(0, 1, 0),
);
```

### `ModuleCapabilities`

Describes what capabilities a module provides and requires.

```rust
use spacetime_capabilities::{ModuleCapabilities, CapabilityId};

const PROVIDES: &[CapabilityId] = &[CapabilityId::new("myapp:auth")];
const REQUIRES: &[CapabilityId] = &[
    CapabilityId::new("airframe:http"),
    CapabilityId::new("airframe:secrets"),
];

let caps = ModuleCapabilities {
    provides: PROVIDES,
    requires: REQUIRES,
};
```

### `CapabilityMeta` (requires `alloc`)

Key-value metadata for capabilities.

```rust
use spacetime_capabilities::CapabilityMeta;
use std::borrow::Cow;

let meta = CapabilityMeta {
    key: Cow::Borrowed("description"),
    value: Cow::Borrowed("Provides key-value storage"),
};
```

## Design Notes

- **Identity-only**: This crate defines identifiers and descriptors but does not implement capability resolution, version matching, or dependency graphs
- **no_std-first**: Works in embedded and WASM environments without allocation
- **Optional alloc**: Enable `alloc` feature for owned string metadata
- **Serde support**: Enable `serde` feature for JSON/config serialization

## Dependencies

- `spacetime-core` - For `Version` type

## License

Licensed under the MIT License.
