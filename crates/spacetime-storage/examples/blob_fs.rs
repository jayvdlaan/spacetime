// Run with: cargo run -p spacetime-storage --example blob_fs --features std

#![cfg(feature = "std")]

use spacetime_crypto::{self as st, CryptoResult};
use spacetime_storage::alloc_helpers::{get_blob, list_blobs, put_blob};
use spacetime_storage::{BlobStore, FsBlobStore};

/// The RustCrypto SHA-256 primitive viewed through the `spacetime_crypto::Sha256` facade. Dev
/// dependency only (`sha2`); this pattern is not something `spacetime-storage`'s `src/` ships.
#[derive(Clone, Copy, Default)]
struct DevSha256;

struct DevSha256State(sha2::Sha256);

impl st::Sha256State for DevSha256State {
    fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        use sha2::Digest;
        Digest::update(&mut self.0, data);
        Ok(())
    }
    fn finalize(&mut self) -> CryptoResult<[u8; st::SHA256_LEN]> {
        use sha2::Digest;
        Ok(self.0.finalize_reset().into())
    }
}

impl st::Sha256 for DevSha256 {
    type State = DevSha256State;
    fn sha256_init(&self) -> CryptoResult<Self::State> {
        use sha2::Digest as _;
        Ok(DevSha256State(sha2::Sha256::new()))
    }
}

fn main() {
    let root =
        std::env::temp_dir().join(format!("spacetime-storage-example-{}", std::process::id()));

    // Class partitioning: one FsBlobStore per class directory builds
    // `blobs/<class>/sha256/<aa>/<hex64>` — here the class is "tool".
    let mut store = FsBlobStore::new(root.join("blobs").join("tool"), DevSha256)
        .expect("create the filesystem blob store");

    let id = put_blob(&mut store, b"hello, blob").expect("put the blob");
    println!("put id: {id}");
    println!("blob path: {}", store.blob_path(&id).display());

    let bytes = get_blob(&store, &id).expect("read the blob back, verified");
    println!(
        "read back: {}",
        core::str::from_utf8(&bytes).expect("the example blob is valid UTF-8")
    );

    let ids = list_blobs(&store).expect("list the store");
    println!("store now holds {} blob(s)", ids.len());

    store.remove(&id).expect("remove the blob");
    println!("contains after remove: {}", store.contains(&id));

    match store.open(&id) {
        Ok(_) => panic!("the blob was just removed; open should have failed"),
        Err(err) => println!("open after remove: {err:?}"),
    }

    std::fs::remove_dir_all(&root).expect("clean up the example's temp directory");
}
