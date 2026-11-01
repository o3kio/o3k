use std::env;

fn main() -> Result<(), std::io::Error> {
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=OPT_LEVEL");
    println!("cargo:rerun-if-env-changed=DEBUG");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    if env::var_os("CARGO_FEATURE_A10_PROCESS_TEST_HOOKS").is_none() {
        return Ok(());
    }

    let profile = env::var("PROFILE").unwrap_or_default();
    let opt_level = env::var("OPT_LEVEL").unwrap_or_default();
    let debug = env::var("DEBUG").unwrap_or_default();
    // rustc flags can override Cargo's profile metadata (for example, a debug
    // profile with `RUSTFLAGS='-C opt-level=3'`). Reject custom flags whenever
    // qualification hooks are enabled so the metadata check cannot be bypassed.
    let rustflags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if profile == "release" || opt_level != "0" || debug != "true" || !rustflags.is_empty() {
        return Err(std::io::Error::other(
            "a10-process-test-hooks is a debug-only qualification feature",
        ));
    }
    Ok(())
}
