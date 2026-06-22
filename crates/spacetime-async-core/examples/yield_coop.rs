// Run with: cargo run -p spacetime-async-core --example yield_coop --features std

#![cfg(feature = "std")]

use spacetime_async_core::YieldNow;

struct StdYielder;
impl YieldNow for StdYielder {
    fn yield_now(&self) {
        std::thread::yield_now();
    }
}

fn main() {
    let y = StdYielder;
    // Simulate cooperative progress between two loops by yielding
    for i in 0..3 {
        println!("producer step {}", i);
        y.yield_now();
        println!("consumer observes step {}", i);
    }
}
