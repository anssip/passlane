#!/bin/sh
# Generate the foreign-language bindings for passlane-ffi (passlane#44).
#
# Usage: generate-bindings.sh [language] [out-dir] [target-triple]
#   language       uniffi language id (default: swift)
#   out-dir        where the bindings land (default: crates/passlane-ffi/bindings,
#                  gitignored — the bindings are generated, not committed)
#   target-triple  cargo triple to build the library for (default: host)
#
# The bindgen CLI is a workspace bin (uniffi-bindgen is not
# cargo-installable since UniFFI ~0.30), and runs in --library mode: it
# reads the component metadata straight out of the compiled cdylib, so the
# bindings cannot drift from the scaffolding. For the Swift
# modulemap/XCFramework output that passlane#45 packs into the iOS app,
# run `cargo run -p uniffi-bindgen-swift -- …` instead.
set -eu

language="${1:-swift}"
out_dir="${2:-crates/passlane-ffi/bindings}"
target_triple="${3:-}"

cd "$(dirname "$0")/../.."

if [ -n "$target_triple" ]; then
    cargo build -p passlane-ffi --release --target "$target_triple"
    lib="target/$target_triple/release/libpasslane_ffi.a"
else
    cargo build -p passlane-ffi --release
    lib="target/release/libpasslane_ffi.$([ "$(uname)" = Darwin ] && echo dylib || echo so)"
fi

# The out-dir is created, never cleaned: bindgen overwrites its own
# files, and deleting what else is in a caller-supplied directory is not
# this script's business.
mkdir -p "$out_dir"
cargo run -p uniffi-bindgen -- generate --library "$lib" --language "$language" --out-dir "$out_dir"
echo "Bindings written to $out_dir/"
