#![cfg(feature = "std")]

use spacetime_storage::std_impl::MemStore;
use spacetime_storage::KvStore;

#[test]
fn memstore_put_get_delete_smoke() {
    let mut s = MemStore::new();
    s.put(b"k", b"v").unwrap();
    let mut buf = [0u8; 8];
    let n = s.get(b"k", &mut buf).unwrap();
    assert_eq!(&buf[..n], b"v");
    s.delete(b"k").unwrap();
    assert!(s.get(b"k", &mut buf).is_err());
}
