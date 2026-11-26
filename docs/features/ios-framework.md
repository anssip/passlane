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

## The approval surface (passlane#82)

The same two artifacts carry the approval-protocol types the phone-key
service (passlane-ios#2) drives. The FFI stays thin — every function
maps types and bytes onto `passlane-approval`, where the protocol logic
lives — and stateless where possible: the app persists its identity
secret bytes and its peer pins in its own Keychain, and drives replay
protection over a file in its app-group container; nothing on the Rust
side reads or writes a directory the CLI owns. Records and enums map to
Swift *value* types holding only values (strings, integers, `Data`), so
no `Sendable` escapes; secrets cross as `Data` parameters (scrubbed by
the callee) or as zeroizing `SecretBytes` objects, never as record
fields. Envelopes cross as the unpadded base64url string that is the
wire form in links and QR codes.

What the app drives:

- **Pairing** — `approvalOpenPairingRequest` (the QR's secret and the
  request envelope in, the CLI's pin out), the two confirmation-code
  functions for the human checks, `approvalSealPairingResponse` back.
  The CLI-role halves (`approvalSealPairingRequest`,
  `approvalOpenPairingResponse`) are exposed for symmetry and the
  round-trip tests.
- **Approving** — `approvalOpenRequest` verifies a request envelope
  (pin check, freshness, signature, replay) and returns an
  `OpenedApprovalRequest` whose `view()` feeds the approval screen
  (vault, operation, requester, scope, expiry) and whose `challenge()`
  fetches the request's challenge when the decision needs to answer it;
  Face ID gates the next step; `approvalAnswerChallenge` turns the held
  phone-key secret plus the challenge into the 20-byte answer;
  `approvalSealDecision` signs and seals the decision (echoing the
  request id) as the blob the CLI redeems.
- **Enrollment (the sheet scan-back check)** —
  `approvalGeneratePhoneKeySecret` for the key the recovery sheet
  carries, plus the `approvalEnrollmentChallenge` /
  `approvalEnrollmentConfirmationCode` /
  `approvalVerifyWebauthnAssertion` trio of the Phase 0 ceremony.
- **Pins and routing** — `ApprovalPeerPin` (public material, the pin's
  exact persisted form), `approvalNewPin`, `approvalPinEncKid`,
  `approvalKid`.

The identity is `ApprovalIdentity` — software keys in v1, restored per
run from the Keychain bytes its secret accessors hand out. A
Secure-Enclave identity (non-extractable, biometry-gated) would need a
signing callback in a later revision; this surface deliberately has no
callbacks, Swift calls Rust only.

### The agent-answer path (recorded decision)

The HMAC-SHA1 answer the session agent redeems — HMAC over the vault
challenge with the phone-held secret — is **not** covered by the vault
surface: `ChallengeFactor` + `PasslaneVault.open` *verify* a secret by
opening a vault **file**, and the phone-key service has no vault file at
hand — the challenge arrives inside the request envelope. So the
computation joined the protocol crate
(`passlane_approval::message::answer_challenge`, the same construction
keepass-ng's `LocalChallenge` and CryptoKit implement) and crosses the
FFI byte-oriented as `approvalAnswerChallenge(secret, challenge)`:
secret and challenge in as `Data`, the 20-byte answer out as a
zeroizing `SecretBytes`.

### Replay protection (recorded decision)

The app drives the nonce check against its app-group container by
passing `ApprovalNonceStore.load(path)` a file path in it, reusing the
protocol crate's `FileNonceStore` rather than a byte-snapshot API: the
file-backed store already gives what a snapshot would make the app
reimplement in Swift — atomic write-then-rename persistence, owner-only
permissions, and an exclusive advisory lock that serializes the app and
its extensions on one view of the nonces. The open functions record a
verified envelope's nonce and persist it before returning (a crash
cannot reopen a replay window), so the object is meant to be held only
while processing one envelope — the lock lives for the object's
lifetime.

### The submodule pin

The app repo consumes this surface by moving its passlane git-submodule
pin to the revision this merges into (see *Getting the artifact*): the
submodule build produces the same two items, now with the approval
types in `PasslaneCore.swift`. Swift-side consumption is ios#2's
verification; until that pin moves, the Rust-side tests
(`crates/passlane-ffi/tests/approval_smoke.rs`) exercise exactly the
FFI-visible functions — each round-trip plays the phone through this
crate's exported surface and the CLI through `passlane-approval`
directly, proving the app opens and answers what the CLI seals.

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
target directory rather than assuming `target/`. An ambient
`build.target` (a `.cargo/config.toml` up the tree — a consumer repo
could carry one for its other Rust work) is likewise overridden: every
cargo invocation in the script pins `--target` explicitly, the host
build and the bindgen runs to the host triple. And if anyone points
cargo's target directory inside `target/ios/` — which this pipeline
clears on every run — the script refuses rather than eat the cache.

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
