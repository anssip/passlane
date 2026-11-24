//! `uniffi-bindgen` as a workspace bin. Since UniFFI ~0.30 the published
//! crate ships no binaries and `cargo install uniffi-bindgen` fails, so
//! the CLI lives here and runs as
//! `cargo run -p uniffi-bindgen -- generate --library … --language swift`
//! (see crates/passlane-ffi/generate-bindings.sh and passlane#44).
fn main() {
    uniffi::uniffi_bindgen_main();
}
