//! Centralized Tokio runtime management for consistent async handling
//! 
//! This module provides a unified approach to handle async-to-sync bridging
//! for PyO3 bindings, ensuring all async operations use the same Tokio runtime.

use once_cell::sync::Lazy;
use std::future::Future;
use tokio::runtime::{Handle, Runtime};

/// Global Tokio runtime for the entire library
/// This ensures consistent async execution across all operations
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)  // Small thread pool for database operations
        .thread_name("signal-protocol-worker")
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
});

/// Execute an async operation in the global runtime
/// 
/// This is the primary function to use when bridging async Rust code to sync Python APIs.
/// It handles both cases:
/// - When called from within a Tokio context (e.g., during tests)
/// - When called from Python without any async context
pub fn block_on<F: Future>(future: F) -> F::Output {
    // First, check if we're already in a Tokio runtime
    match Handle::try_current() {
        Ok(_) => {
            // We're in a Tokio runtime, use block_in_place to avoid blocking the runtime
            tokio::task::block_in_place(|| {
                Handle::current().block_on(future)
            })
        }
        Err(_) => {
            // No runtime context, use our global runtime
            RUNTIME.block_on(future)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_on_simple() {
        let result = block_on(async { 42 });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_block_on_with_async_operation() {
        let result = block_on(async {
            // Simulate an async operation
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            "completed"
        });
        assert_eq!(result, "completed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_block_on_from_tokio_context() {
        // This tests that block_on works when called from within a Tokio runtime
        let result = block_on(async { 100 });
        assert_eq!(result, 100);
    }
}