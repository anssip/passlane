#!/bin/sh
# Build PasslaneCore.xcframework — the artifact the iOS app links
# (passlane#45).
#
# Usage: make ios-framework          (from the repo root)
#        sh crates/passlane-ffi/build-ios.sh
#
# Output, in target/ios/ (gitignored build output):
#   PasslaneCore.xcframework/   the linked artifact: a static-lib slice for
#                               every target below, each carrying the C FFI
#                               header and module.modulemap in its Headers/
#                               directory — Xcode discovers the Clang module
#                               through the linked framework, so the consumer
#                               needs no extra module wiring
#   PasslaneCore.swift          the UniFFI-generated Swift module — the
#                               consumer compiles it into the app target
#
# Consumer wiring is those two items and nothing else; see
# docs/features/ios-framework.md for the full story.
#
# Prerequisites:
#   - Xcode (xcodebuild)
#   - rustup targets: rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   - nothing to cargo-install: the bindgen CLI is a workspace bin
#     (uniffi-bindgen is not cargo-installable since UniFFI ~0.30) and cargo
#     run resolves it on the same UniFFI version line as the scaffolding
#
# The platform slices are the two the v1 app needs: device and Apple
# Silicon simulator. Future slices (the v1.1 Mac helper's
# arm64-apple-darwin, Catalyst, watchOS) are one entry in TARGETS away,
# plus a lipo step should a fat slice ever be needed.
set -eu

MODULE_NAME=PasslaneCore
# The Clang module name the generated Swift imports: crate name + FFI,
# derived by uniffi-bindgen-swift. Not chosen, just matched.
FFI_MODULE_NAME=passlane_ffiFFI
# The output location is a consumer contract (docs/features/ios-framework.md
# references target/ios/ from the app repo), so it stays fixed. The build
# INPUTS below follow cargo wherever it actually writes: CARGO_TARGET_DIR or
# build.target-dir in .cargo/config.toml — the repo .gitignores a local
# config.toml, so asking cargo is the only reliable answer.
OUT_DIR=target/ios
TARGETS="aarch64-apple-ios aarch64-apple-ios-sim"

cd "$(dirname "$0")/../.."

if ! command -v xcodebuild >/dev/null 2>&1; then
    echo "error: xcodebuild not found — install Xcode and run:" >&2
    echo "       sudo xcode-select -s /Applications/Xcode.app" >&2
    exit 1
fi

# Where cargo writes build output for this workspace (absolute, or relative
# to the workspace root). Fallback covers cargo metadata failing for any
# reason: the default is the plain target/ next to the workspace manifest.
target_dir=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
[ -n "$target_dir" ] || target_dir=target

# 1. Host build: the Swift bindgen reads the component metadata straight
#    out of the compiled cdylib (--library mode), so the bindings cannot
#    drift from the scaffolding.
cargo build --release --locked -p passlane-ffi
host_lib=$target_dir/release/libpasslane_ffi.dylib

# 2. The binding artifacts, generated into a staging dir and placed where
#    the consumer expects them. rm only touches this pipeline's own output.
rm -rf "$OUT_DIR"
stage=$OUT_DIR/stage
headers=$OUT_DIR/headers
mkdir -p "$stage" "$headers"

# Swift sources. --module-name is a modulemap concern only; the Swift file
# and its import line are namespace-derived, so it is not passed here.
cargo run -q --locked -p uniffi-bindgen-swift -- "$host_lib" "$stage" --swift-sources
mv "$stage/passlane_ffi.swift" "$OUT_DIR/$MODULE_NAME.swift"

# The C header, and the modulemap declaring it as the Clang module the
# Swift file imports (`#if canImport(passlane_ffiFFI)` takes its
# separate-module branch because of it). Both land in the headers dir that
# step 4 packs into every framework slice. The modulemap must be called
# module.modulemap: that is the only name clang's implicit module lookup
# discovers on an include path.
cargo run -q --locked -p uniffi-bindgen-swift -- "$host_lib" "$stage" --headers
cp "$stage/$FFI_MODULE_NAME.h" "$headers/"
cargo run -q --locked -p uniffi-bindgen-swift -- "$host_lib" "$stage" \
    --modulemap \
    --module-name "$FFI_MODULE_NAME" \
    --modulemap-filename "$FFI_MODULE_NAME.modulemap"
mv "$stage/$FFI_MODULE_NAME.modulemap" "$headers/module.modulemap"

# 3. The static libs, one release build per slice.
for t in $TARGETS; do
    cargo build --release --locked -p passlane-ffi --no-default-features --target "$t"
done

# 4. Assemble the xcframework: one -library per slice, all carrying the
#    same headers dir. xcodebuild picks the slice matching the consumer's
#    build destination at link time.
# Word splitting of $framework_args is the point (POSIX sh has no arrays).
framework_args=""
for t in $TARGETS; do
    framework_args="$framework_args -library $target_dir/$t/release/libpasslane_ffi.a -headers $headers"
done
xcodebuild -create-xcframework $framework_args \
    -output "$OUT_DIR/$MODULE_NAME.xcframework" >/dev/null

rm -rf "$stage" "$headers"

# Smoke-check the product rather than trust the quiet exit: the framework
# manifest, the Swift module, and the Clang module packed into every slice.
test -f "$OUT_DIR/$MODULE_NAME.xcframework/Info.plist"
test -f "$OUT_DIR/$MODULE_NAME.swift"
find "$OUT_DIR/$MODULE_NAME.xcframework" -name module.modulemap | grep -q .

echo "$MODULE_NAME.xcframework and $MODULE_NAME.swift are in $OUT_DIR/:"
find "$OUT_DIR/$MODULE_NAME.xcframework" -name '*.a' -exec lipo -info {} \; | sed 's/^/  /'
echo "Consumer wiring (docs/features/ios-framework.md): link the xcframework and"
echo "compile $MODULE_NAME.swift into the app target — nothing else."
