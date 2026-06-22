#![no_std]

//! Spacetime async core: executor-agnostic async traits for no_std.
//!
//! This crate defines the canonical async Spacetime module interface in a
//! no_std-first manner using associated future types. For ergonomic use in
//! std environments, enable the `async-trait` feature to get an `async fn`
//! version of the trait under `easy`.

use core::future::Future;
use spacetime_core::{InitCtx, InitError, Runtime, StartError, Version};

// Legacy/basic async runtime helper traits retained to keep examples compiling.
// These are runtime-agnostic and intentionally minimal.
/// A handle capable of spawning fire-and-forget tasks.
pub trait Spawner {
    fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + 'static;
}

/// An executor capable of driving a future to completion in the current context.
pub trait Executor {
    fn block_on<F>(&self, fut: F) -> F::Output
    where
        F: Future;
}

/// A minimal cancellation token interface.
pub trait CancellationToken {
    /// Request cancellation for all parties observing this token.
    fn cancel(&self);
    /// Returns true if cancellation has been requested.
    fn is_cancelled(&self) -> bool;
}

/// A cooperative yielding interface for executors that support it.
pub trait YieldNow {
    /// Hint to the executor/scheduler to yield execution.
    fn yield_now(&self);
}

/// Canonical no_std-first async Spacetime module interface.
///
/// Uses associated future types to avoid depending on allocation or macros.
pub trait AsyncModule {
    const NAME: &'static str;
    const VERSION: Version;

    type Deps<'a>
    where
        Self: 'a;

    type InitFut<'a>: Future<Output = Result<Self, InitError>> + 'a
    where
        Self: 'a,
        Self: Sized;
    fn init_async<'a>(ctx: &'a mut InitCtx, deps: Self::Deps<'a>) -> Self::InitFut<'a>
    where
        Self: Sized;

    type StartFut<'a>: Future<Output = Result<(), StartError>> + 'a
    where
        Self: 'a;
    fn start_async<'a>(&'a mut self, rt: &'a dyn Runtime) -> Self::StartFut<'a>;

    type ShutdownFut<'a>: Future<Output = ()> + 'a
    where
        Self: 'a;
    fn shutdown_async<'a>(&'a mut self) -> Self::ShutdownFut<'a>;
}

/// Ergonomic `async fn` version of the trait using the async-trait macro.
#[cfg(feature = "async-trait")]
pub mod easy {
    use super::*;
    use async_trait::async_trait;
    // Bring Box into scope for async-trait generated code.
    use std::boxed::Box;

    #[async_trait]
    pub trait AsyncModule {
        const NAME: &'static str;
        const VERSION: Version;
        type Deps<'a>
        where
            Self: 'a;
        async fn init_async(ctx: &mut InitCtx, deps: Self::Deps<'_>) -> Result<Self, InitError>
        where
            Self: Sized;
        async fn start_async(&mut self, rt: &dyn Runtime) -> Result<(), StartError>;
        async fn shutdown_async(&mut self) {}
    }
}

// Link std when feature enabled (tests/examples under std)
#[cfg(feature = "std")]
extern crate std;

// ---------------------------------------------------------------------------
// Async storage traits (parallel to spacetime-storage)
// ---------------------------------------------------------------------------
pub mod storage;
pub use storage::{
    AsyncKvScan, AsyncKvStore, AsyncPrefixScanIter, AsyncTxn, AsyncTxnStore, StorageError,
    StorageResult,
};

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use spacetime_std_runtime::StdRuntime;

    // Concrete future structs for associated types below.
    pub struct InitReady<T>(Option<T>);
    impl<T> InitReady<T> {
        pub fn new(val: T) -> Self {
            Self(Some(val))
        }
    }
    impl<T> Future for InitReady<T> {
        type Output = Result<T, InitError>;
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            // Safety: InitReady<T> does not move the inner T after it has been pinned;
            // we only access the Option to take the value, which does not rely on pinning.
            let this = unsafe { self.get_unchecked_mut() };
            Poll::Ready(Ok(this.0.take().expect("polled after completion")))
        }
    }

    pub struct StartReady;
    impl Future for StartReady {
        type Output = Result<(), StartError>;
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(Ok(()))
        }
    }

    pub struct ShutdownReady;
    impl Future for ShutdownReady {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(())
        }
    }

    struct Greeter;
    impl AsyncModule for Greeter {
        const NAME: &'static str = "greeter";
        const VERSION: Version = Version::new(0, 1, 0);
        type Deps<'a> = ();

        type InitFut<'a>
            = InitReady<Self>
        where
            Self: 'a;
        fn init_async<'a>(_ctx: &'a mut InitCtx, _deps: Self::Deps<'a>) -> Self::InitFut<'a>
        where
            Self: Sized,
        {
            InitReady::new(Greeter)
        }

        type StartFut<'a>
            = StartReady
        where
            Self: 'a;
        fn start_async<'a>(&'a mut self, _rt: &'a dyn Runtime) -> Self::StartFut<'a> {
            StartReady
        }

        type ShutdownFut<'a>
            = ShutdownReady
        where
            Self: 'a;
        fn shutdown_async<'a>(&'a mut self) -> Self::ShutdownFut<'a> {
            ShutdownReady
        }
    }

    // A tiny helper to create a no-op waker so we can poll futures directly if needed
    fn noop_waker() -> Waker {
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    #[test]
    fn core_async_module_runs() {
        let rt = StdRuntime::new();
        let mut ctx = InitCtx;
        // Drive init future to completion via direct poll
        let mut fut = Greeter::init_async(&mut ctx, ());
        let w = noop_waker();
        let mut cx = Context::from_waker(&w);
        let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
        let mut m = match Future::poll(fut.as_mut(), &mut cx) {
            Poll::Ready(Ok(m)) => m,
            _ => panic!("init not ready"),
        };

        // Start
        let mut start = m.start_async(&rt);
        let mut start = unsafe { Pin::new_unchecked(&mut start) };
        match Future::poll(start.as_mut(), &mut cx) {
            Poll::Ready(Ok(())) => {}
            _ => panic!("start not ready"),
        }

        // Shutdown
        let mut sd = m.shutdown_async();
        let mut sd = unsafe { Pin::new_unchecked(&mut sd) };
        match Future::poll(sd.as_mut(), &mut cx) {
            Poll::Ready(()) => {}
            _ => panic!("shutdown not ready"),
        }
    }

    #[cfg(feature = "async-trait")]
    mod easy_tests {
        use super::*;
        use crate::easy::AsyncModule as EasyModule;
        use std::boxed::Box; // required by async-trait expansion in this module

        struct Hello;

        #[async_trait::async_trait]
        impl EasyModule for Hello {
            const NAME: &'static str = "hello";
            const VERSION: Version = Version::new(0, 1, 0);
            type Deps<'a> = ();
            async fn init_async(
                _ctx: &mut InitCtx,
                _deps: Self::Deps<'_>,
            ) -> Result<Self, InitError> {
                Ok(Hello)
            }
            async fn start_async(&mut self, _rt: &dyn Runtime) -> Result<(), StartError> {
                Ok(())
            }
            async fn shutdown_async(&mut self) {}
        }

        #[tokio::test]
        async fn easy_trait_runs() {
            let rt = StdRuntime::new();
            let mut ctx = InitCtx;
            let mut m = Hello::init_async(&mut ctx, ()).await.unwrap();
            m.start_async(&rt).await.unwrap();
            m.shutdown_async().await;
        }
    }
}
