// Run with: cargo run -p spacetime-async-core --example tokio_spawner --features std

#![cfg(feature = "std")]

use spacetime_async_core::Spawner;

struct TokioSpawner;

impl Spawner for TokioSpawner {
    fn spawn<F>(&self, fut: F)
    where
        F: core::future::Future<Output = ()> + 'static,
    {
        // For a current_thread runtime, use spawn_local to avoid Send bound.
        tokio::task::spawn_local(fut);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // LocalSet is required for spawn_local
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let sp = TokioSpawner;
            let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
            sp.spawn(async move {
                tx.send(42).ok();
            });
            let v = rx.await.expect("oneshot should complete");
            println!("TokioSpawner worked: {}", v);
        })
        .await;
}
