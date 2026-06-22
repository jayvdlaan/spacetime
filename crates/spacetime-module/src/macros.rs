//! Declarative macros for reducing boilerplate in Spacetime module development.

/// Create a `ModuleNode` with the given name, version, dependencies, and init function.
///
/// # Examples
///
/// Basic usage with init only:
/// ```ignore
/// use spacetime_module::{node, ModuleNode};
/// use spacetime_core::{InitCtx, InitError, Version};
///
/// fn my_init(_ctx: &mut InitCtx) -> Result<(), InitError> {
///     Ok(())
/// }
///
/// let node: ModuleNode = node!("my_module", Version::new(1, 0, 0), [], my_init);
/// ```
///
/// With dependencies:
/// ```ignore
/// let node = node!("child", Version::new(1, 0, 0), ["parent"], my_init);
/// ```
///
/// With start hook:
/// ```ignore
/// fn my_start(_rt: &dyn Runtime) -> Result<(), StartError> {
///     Ok(())
/// }
///
/// let node = node!("my_module", Version::new(1, 0, 0), [], my_init, my_start);
/// ```
#[macro_export]
macro_rules! node {
    ($name:expr, $version:expr, [$($dep:expr),* $(,)?], $init:expr) => {
        $crate::ModuleNode {
            descriptor: $crate::ModuleDescriptor::new($name, $version),
            init: $init,
            deps: &[$($dep),*],
            start: None,
        }
    };
    ($name:expr, $version:expr, [$($dep:expr),* $(,)?], $init:expr, $start:expr) => {
        $crate::ModuleNode {
            descriptor: $crate::ModuleDescriptor::new($name, $version),
            init: $init,
            deps: &[$($dep),*],
            start: Some($start),
        }
    };
}

/// Implement the `Runtime` trait for a struct with clock and timer fields.
///
/// # Examples
///
/// ```ignore
/// use spacetime_module::impl_runtime;
///
/// impl_runtime!(MyRuntime { clock: MyClock, timer: MyTimer });
/// ```
///
/// This expands to:
/// ```ignore
/// pub struct MyRuntime {
///     clock: MyClock,
///     timer: MyTimer,
/// }
///
/// impl MyRuntime {
///     pub fn new(clock: MyClock, timer: MyTimer) -> Self {
///         Self { clock, timer }
///     }
/// }
///
/// impl spacetime_core::Runtime for MyRuntime {
///     fn clock(&self) -> &dyn spacetime_core::Clock { &self.clock }
///     fn timer(&self) -> &dyn spacetime_core::Timer { &self.timer }
/// }
/// ```
#[macro_export]
macro_rules! impl_runtime {
    ($name:ident { clock: $clock:ty, timer: $timer:ty $(,)? }) => {
        pub struct $name {
            clock: $clock,
            timer: $timer,
        }

        impl $name {
            pub fn new(clock: $clock, timer: $timer) -> Self {
                Self { clock, timer }
            }
        }

        impl $crate::core::Runtime for $name {
            fn clock(&self) -> &dyn $crate::core::Clock {
                &self.clock
            }
            fn timer(&self) -> &dyn $crate::core::Timer {
                &self.timer
            }
        }
    };
}

/// Generate a `From<Status>` implementation for a custom error type.
///
/// This macro maps `spacetime_core::Status` variants to expressions of your error type.
///
/// # Examples
///
/// ```ignore
/// use spacetime_module::status_conversion;
///
/// #[derive(Debug)]
/// enum MyError {
///     NotSupported,
///     NotAvailable,
///     AccessDenied,
///     BadInput,
///     OperationFailed,
/// }
///
/// status_conversion!(MyError {
///     Ok => MyError::OperationFailed,
///     Unsupported => MyError::NotSupported,
///     Unavailable => MyError::NotAvailable,
///     Denied => MyError::AccessDenied,
///     Invalid => MyError::BadInput,
///     Failed => MyError::OperationFailed,
/// });
/// ```
#[macro_export]
macro_rules! status_conversion {
    ($target:ty { $($status:ident => $err:expr),* $(,)? }) => {
        impl From<$crate::core::Status> for $target {
            fn from(s: $crate::core::Status) -> Self {
                match s {
                    $($crate::core::Status::$status => $err,)*
                }
            }
        }
    };
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use crate::core::{InitCtx, InitError, Runtime, StartError, Version};
    use crate::ModuleNode;

    fn noop_init(_ctx: &mut InitCtx) -> Result<(), InitError> {
        Ok(())
    }

    fn noop_start(_rt: &dyn Runtime) -> Result<(), StartError> {
        Ok(())
    }

    #[test]
    fn node_macro_without_start() {
        let n: ModuleNode = node!("test", Version::new(1, 2, 3), [], noop_init);
        assert_eq!(n.descriptor.name, "test");
        assert_eq!(n.descriptor.version, Version::new(1, 2, 3));
        assert!(n.deps.is_empty());
        assert!(n.start.is_none());
    }

    #[test]
    fn node_macro_with_deps() {
        let n: ModuleNode = node!(
            "child",
            Version::new(0, 1, 0),
            ["parent", "other"],
            noop_init
        );
        assert_eq!(n.descriptor.name, "child");
        assert_eq!(n.deps, &["parent", "other"]);
        assert!(n.start.is_none());
    }

    #[test]
    fn node_macro_with_start() {
        let n: ModuleNode = node!(
            "full",
            Version::new(2, 0, 0),
            ["dep"],
            noop_init,
            noop_start
        );
        assert_eq!(n.descriptor.name, "full");
        assert_eq!(n.deps, &["dep"]);
        assert!(n.start.is_some());
    }

    #[test]
    fn status_conversion_macro() {
        use crate::core::Status;

        #[derive(Debug, PartialEq)]
        enum TestError {
            Ok,
            Unsupported,
            Unavailable,
            Denied,
            Invalid,
            Failed,
        }

        status_conversion!(TestError {
            Ok => TestError::Ok,
            Unsupported => TestError::Unsupported,
            Unavailable => TestError::Unavailable,
            Denied => TestError::Denied,
            Invalid => TestError::Invalid,
            Failed => TestError::Failed,
        });

        assert_eq!(TestError::from(Status::Ok), TestError::Ok);
        assert_eq!(TestError::from(Status::Unsupported), TestError::Unsupported);
        assert_eq!(TestError::from(Status::Unavailable), TestError::Unavailable);
        assert_eq!(TestError::from(Status::Denied), TestError::Denied);
        assert_eq!(TestError::from(Status::Invalid), TestError::Invalid);
        assert_eq!(TestError::from(Status::Failed), TestError::Failed);
    }
}
