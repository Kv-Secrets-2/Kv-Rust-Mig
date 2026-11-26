//! Cargo exposes the effective target rustflags to build scripts in
//! CARGO_ENCODED_RUSTFLAGS. This probe writes that exact encoding to a path
//! selected by the packaging script.

use std::env;
use std::fs;

fn main() {
    let output = env::var("KV_RUSTFLAGS_PROBE_OUT")
        .expect("KV_RUSTFLAGS_PROBE_OUT must name the probe output file");
    let rustflags = env::var_os("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    fs::write(&output, rustflags.as_encoded_bytes())
        .expect("failed to write rustflags probe output");
}
