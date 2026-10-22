// Test-only crash hooks may never ship in an optimized build: they force
// hard process exits from production code paths.
#[cfg(all(feature = "backup-test-hooks", not(debug_assertions)))]
compile_error!("backup-test-hooks is a debug-only test feature");

pub mod composition;
pub mod native_adapters;
