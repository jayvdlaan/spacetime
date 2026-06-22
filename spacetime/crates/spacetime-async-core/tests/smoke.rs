#![cfg(all(feature = "std", feature = "async-trait"))]

use spacetime_async_core::easy::AsyncModule;
use spacetime_core::{InitCtx, Runtime, Version};
use spacetime_std_runtime::StdRuntime;

struct demo;

#[allow(non_camel_case_types)]
struct DemoMod;

#[async_trait::async_trait]
impl AsyncModule for DemoMod {
    const NAME: &'static str = "demo_mod";
    const VERSION: Version = Version::new(0, 1, 0);
    type Deps<'a> = ();

    async fn init_async(_ctx: &mut InitCtx, _deps: Self::Deps<'_>) -> Result<Self, spacetime_core::InitError>
    where
        Self: Sized,
    {
        Ok(DemoMod)
    }

    async fn start_async(&mut self, _rt: &dyn Runtime) -> Result<(), spacetime_core::StartError> {
        Ok(())
    }

    async fn shutdown_async(&mut self) { }
}

#[test]
fn easy_async_module_smoke() {
    let rt = StdRuntime::new();
    let mut ctx = InitCtx;
    let mut m = futures::executor::block_on(<DemoMod as AsyncModule>::init_async(&mut ctx, ()) ).unwrap();
    futures::executor::block_on(m.start_async(&rt)).unwrap();
    futures::executor::block_on(m.shutdown_async());
}
