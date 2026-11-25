# The iOS XCFramework (`make ios-framework`)

One command turns `passlane-ffi` into what the iOS app links: a
`PasslaneCore.xcframework` with the Rust core compiled for device and
Apple Silicon simulator, plus the UniFFI-generated `PasslaneCore.swift`
(passlane#45, [passlane-ios PLAN §2/§3]). The app repo pins a passlane
revision and consumes exactly those two items — no Rust toolchain
knowledge ever enters an Xcode project.

```
$ make ios-framework
PasslaneCore.xcframework and PasslaneCore.swift are in target/ios/:
  Non-fat file: target/ios/PasslaneCore.xcframework/ios-arm64-simulator/libpasslane_ffi.a is architecture: arm64
  Non-fat file: target/ios/PasslaneCore.xcframework/ios-arm64/libpasslane_ffi.a is architecture: arm64
Consumer wiring (docs/features/ios-framework.md): link the xcframework and
compile PasslaneCore.swift into the app target — nothing else.
```

## What the artifact is

The pipeline (`crates/passlane-ffi/build-ios.sh`) does four things:

1. Builds the host cdylib and runs the workspace `uniffi-bindgen-swift`
   bin against it (`--library` mode: the bindings are read out of the
   compiled library, so they cannot drift from the scaffolding).
2. Generates the Swift sources and the C FFI header.
3. Builds `libpasslane_ffi.a` for every target in the script's `TARGETS`
   list — today `aarch64-apple-ios` (device) and `aarch64-apple-ios-sim`
   (Apple Silicon simulator).
4. Packs the libs into one xcframework with `xcodebuild
   -create-xcframework`, each slice carrying `Headers/` with the C header
   and `module.modulemap`.

Output in `target/ios/` (gitignored):

| File | What it is |
|---|---|
| `PasslaneCore.xcframework/` | The linked artifact; per slice: `libpasslane_ffi.a` + `Headers/{module.modulemap, passlane_ffiFFI.h}` |
| `PasslaneCore.swift` | The generated Swift module, compiled into the consuming app target |

## Consumer wiring

Two items, nothing else:

1. **Link `PasslaneCore.xcframework`** in the app target (Link Binary
   With Libraries; static, so nothing is embedded or signed). Xcode picks
   the slice matching the build destination automatically.
2. **Compile `PasslaneCore.swift`** into the same target.

That is all — in particular, no `SWIFT_INCLUDE_PATHS`, no bridging
header. The generated Swift starts with
`#if canImport(passlane_ffiFFI)`; the Clang module that satisfies it is
`module.modulemap` packed in the framework's `Headers/`, which Xcode
discovers through the linked framework. (The module is named
`passlane_ffiFFI` — crate name + FFI, derived by the generator, not
chosen. `PasslaneCore` is only the framework and Swift module name.)

### Getting the artifact

Today (the app repo tracks it as ios#2 wiring): check passlane out as a
git submodule at a pinned revision and run `make ios-framework` from the
app repo's bootstrap; the Xcode project references
`../passlane/target/ios/` with the two items above. That guarantees the
app runs the Rust code of exactly the pinned revision.

Later: CI's `ios-framework` job already uploads `target/ios/` as an
artifact of every master push. When the app track wants it, cut a GitHub
Release with that zip and point an SPM `binaryTarget` at the release URL
— the artifact's layout is chosen so that step is mechanical.

## Prerequisites and reproducibility

- Xcode (for `xcodebuild`) — `sudo xcode-select -s /Applications/Xcode.app`
- rustup targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`
- Nothing to `cargo install`: `uniffi-bindgen` has shipped no binaries
  since UniFFI ~0.30, so the CLI is a workspace bin
  (`crates/uniffi-bindgen-swift`), resolved by `cargo run` on the same
  UniFFI version line as the `passlane-ffi` scaffolding — the generated
  bindings and the Rust side cannot mismatch.

Every cargo invocation in the script passes `--locked`, so the build
resolves exactly the checked-in dependency set. That pins the crate
versions — not the binaries: CI's `stable` toolchain and `macos-latest`
runner image float, so the same revision can produce different bytes
across a toolchain or SDK update.

The output location is fixed at `target/ios/` (the consumer contract);
the build inputs follow `CARGO_TARGET_DIR` / `.cargo/config.toml`
wherever cargo actually writes them — the script asks cargo for its
target directory rather than assuming `target/`.

## How it is verified

- CI (`ios-framework` job) runs the script from a clean checkout on every
  PR and push, asserts the framework structure, and uploads the artifact.
- The acceptance test for the pipeline: a blank xcodegen SwiftUI app in a
  scratch directory that links the framework and compiles
  `PasslaneCore.swift` (nothing else), built for the iPhone simulator and
  for generic iOS device with code signing disabled — both slices link —
  and a test case that opens a scratch vault through the real FFI
  (`PasslaneVault.open` → `search` → `secret`) on the simulator.

## Future slices

New platforms are one entry in the script's `TARGETS` (plus a `lipo`
step if a fat slice is ever wanted): `arm64-apple-darwin` for the v1.1
Mac helper (Bluetooth LE transport), Catalyst, watchOS — the order the
[passlane-ios PLAN] phases need them.
