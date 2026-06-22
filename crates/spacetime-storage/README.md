spacetime-storage
=================

No_std-first key/value storage facades for Spacetime.

Badges
- Docs: https://docs.rs/spacetime-storage

Highlights
- No allocations in core traits.
- Caller-provided buffers for reads; optional alloc helpers.
- Prefix-scan iterator API without allocation.
- Lightweight namespacing via key prefixing.

Features
- default: no_std
- alloc: enable convenience helpers returning Vec
- std: enables std-only examples/tests and the in-memory MemStore

Quickstart
- Build (std):
  - cargo check -p spacetime-storage --features std
- Run examples:
  - Basic usage: cargo run -p spacetime-storage --example memstore_basic --features std,alloc
  - Prefix scan: cargo run -p spacetime-storage --example prefix_scan --features std
 - Run tests (std): cargo test -p spacetime-storage --features std

API sketch
- trait KvStore:
  - get(&self, key, out) -> Result<usize>
  - put(&mut self, key, value) -> Result<()>
  - delete(&mut self, key) -> Result<()>
  - len(&self, key) -> Result<usize>
  - contains(&self, key) -> bool
- trait KvScan:
  - scan_prefix(&self, prefix) -> Iter that fills caller-provided key/value buffers
- struct Namespaced<S>:
  - wraps a store and prefixes keys; methods: get_ns, put_ns, delete_ns, len_ns, contains_ns

Transactions
- Traits TxnStore and Txn provide begin/commit/rollback.
- A std-only prototype transaction (MemTxn) is implemented for the in-memory MemStore with read-your-writes and commit/rollback semantics. See unit tests for usage.

Notes
- The std MemStore is for development and testing only; it does not guarantee iteration order for prefix scans.
