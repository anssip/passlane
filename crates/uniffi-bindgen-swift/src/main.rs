//! The Swift-specific `uniffi-bindgen` frontend as a workspace bin: the
//! `--xcframework`/`--modulemap` output the plain CLI cannot generate,
//! which the passlane-ios XCFramework pipeline builds on (passlane#45).
//! Kept next to `uniffi-bindgen` so the repo carries the whole toolchain
//! the iOS side documents, on one UniFFI version line.
fn main() {
    uniffi::uniffi_bindgen_swift();
}
