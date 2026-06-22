// Run with: cargo run -p spacetime-storage --example memstore_basic --features std,alloc

#![cfg(all(feature = "std", feature = "alloc"))]

use spacetime_storage::alloc_helpers::get_alloc;
use spacetime_storage::std_impl::MemStore;
use spacetime_storage::KvStore;

fn main() {
    let mut store = MemStore::new();

    // Basic put/get
    store.put(b"hello", b"world").unwrap();
    let mut buf = [0u8; 16];
    let n = store.get(b"hello", &mut buf).unwrap();
    println!(
        "hello -> {} ({} bytes)",
        core::str::from_utf8(&buf[..n]).unwrap(),
        n
    );

    // Alloc convenience helper
    let v = get_alloc(&store, b"hello").unwrap();
    println!(
        "get_alloc -> {} ({} bytes)",
        core::str::from_utf8(&v).unwrap(),
        v.len()
    );

    // Delete and observe NotFound on next get
    store.delete(b"hello").unwrap();
    let err = store.get(b"hello", &mut buf).unwrap_err();
    println!("post-delete get error: {:?}", err);
}
