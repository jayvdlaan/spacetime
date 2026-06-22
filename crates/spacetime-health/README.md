spacetime-health
=================

Portable health snapshot types shared across runtimes. Designed no_std-first with optional alloc and serde features.

Features
- default = []: no_std compatible, minimal types only
- alloc: enables notes: Vec<...> on HealthSnapshot
- std: convenience feature enabling alloc and std support in dependencies
- serde: enables Serialize/Deserialize for HealthStatus and HealthSnapshot
  - Instant and Duration are encoded as u64 millis
  - When both alloc and serde are enabled, notes use Cow<'a, str> to allow zero-copy deserialization

Types
- HealthStatus: Healthy | Degraded | Unhealthy
- HealthSnapshot<'a>:
  - status: HealthStatus
  - since: spacetime_core::Instant
  - uptime: spacetime_core::Duration
  - notes: Vec<Note<'a>> (alloc-gated); Note is &'a str normally, or Cow<'a, str> with serde

Helpers
- HealthSnapshot::healthy(since, uptime)
- HealthSnapshot::degraded(since, uptime)
- HealthSnapshot::unhealthy(since, uptime)
- HealthSnapshot::degraded_with_notes(...)
- HealthSnapshot::unhealthy_with_notes(...)

Examples
```rust,no_run
use spacetime_health::{HealthSnapshot, HealthStatus};
use spacetime_core::{Instant, Duration};

let snap = HealthSnapshot::healthy(
    Instant::from_millis_since_epoch(1),
    Duration::from_secs(2),
);
assert!(matches!(snap.status, HealthStatus::Healthy));
```

Serde example (alloc + serde + std):
```rust,no_run
use spacetime_health::HealthSnapshot;
use spacetime_core::{Instant, Duration};

let snap = HealthSnapshot::unhealthy_with_notes(
    Instant::from_millis_since_epoch(42),
    Duration::from_secs(1),
    vec!["network".into(), "timeout".into()], // Cow<'_, str>
);
let json = serde_json::to_string(&snap).unwrap();
let round: HealthSnapshot = serde_json::from_str(&json).unwrap();
assert_eq!(round.notes.len(), 2);
```

Testing
- Run unit tests with serde + alloc + std:
  cargo test -p spacetime-health --features "alloc,serde,std"
- Build no_std (wasm):
  cargo build -p spacetime-health --no-default-features --target wasm32-unknown-unknown

License: MIT
