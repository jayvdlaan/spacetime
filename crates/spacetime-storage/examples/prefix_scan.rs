// Run with: cargo run -p spacetime-storage --example prefix_scan --features std

#![cfg(feature = "std")]

use spacetime_storage::std_impl::MemStore;
use spacetime_storage::{KvScan, KvStore, PrefixScanIter};

fn main() {
    let mut s = MemStore::new();
    s.put(b"cfg/a", b"alpha").unwrap();
    s.put(b"cfg/b", b"beta").unwrap();
    s.put(b"data/x", b"xxx").unwrap();

    let mut it = s.scan_prefix(b"cfg/");
    let mut key = [0u8; 16];
    let mut val = [0u8; 16];
    println!("Entries with prefix 'cfg/':");
    while let Some(res) = it.next(&mut key, &mut val) {
        let (kl, vl) = res.unwrap();
        println!(
            "  {} -> {}",
            core::str::from_utf8(&key[..kl]).unwrap(),
            core::str::from_utf8(&val[..vl]).unwrap()
        );
    }
}
