# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Passlane is a password manager and authenticator CLI written in Rust that uses Keepass as the storage backend. It supports storing credentials, payment cards, secure notes, and TOTP (Time-based One-Time Passwords). The application supports KDB, KDBX3, and KDBX4 file formats and can optionally use key files for additional security.

## Related Repositories and Roadmap

The iOS app and the phone-as-key / approval-protocol work are planned in the [passlane-ios repo](https://github.com/anssip/passlane-ios) — see its [PLAN.md](https://github.com/anssip/passlane-ios/blob/main/PLAN.md) (the roadmap of record for Phase 0, the v1 wedge, and later phases). Implementation is tracked in this repo's issues #42–54: the cargo workspace split (`passlane-core`, `passlane-ffi`), the keepass-ng challenge-response feature split and `ChallengeResponseKey::External` variant (both released upstream in keepass-ng 0.12, via ssrlive/keepass-ng#2 and #3), virtual and phone-held hardware keys, the approval protocol crate, link transport, and the session agent. Upcoming structural changes (crate layout, feature gates) follow that plan — read it before large refactors.

## Development Commands

### Building
```bash
cargo build --release
```

### Running
```bash
cargo run
```

### Testing
```bash
cargo test
```

### Running with specific features
```bash
# Run with logging enabled
RUST_LOG=debug cargo run
```

### Single test execution
```bash
cargo test <test_name>
```

### Mobile (no-USB) build check
`passlane-core` without its `usb` feature is what the iOS app consumes: libusb does not exist there, so virtual challenge-response keys are in and the USB backend is out. Check that configuration with (needs Xcode; install the targets once with `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`):
```bash
cargo build -p passlane-core --no-default-features --target aarch64-apple-ios
cargo build -p passlane-core --no-default-features --target aarch64-apple-ios-sim
cargo test -p passlane-core --no-default-features
```
CI runs all three; code in `passlane-core` that needs a YubiKey must sit behind `#[cfg(feature = "usb")]`, imports included.

### iOS framework build (passlane-ffi)
The artifact the iOS app links — `PasslaneCore.xcframework` + the generated `PasslaneCore.swift` — is one command (CI's `ios-framework` job runs it on every push and uploads the artifact):
```bash
make ios-framework
```
Consumer wiring and prerequisites: `docs/features/ios-framework.md`.

## Development Workflow

- All new features from GitHub issues are implemented on a new branch and merged via a pull request on GitHub — never committed directly to master.
- CoPilot reviews every PR. Use the `copilot-review-loop` skill to drive the review loop and address all review comments until the PR is approved.
- Verification must include exercising the CLI itself with all affected options and commands — building and running the real flows, not just `cargo test` — in addition to unit tests.
- Unit tests are added for every new feature as part of the change, not as a follow-up.

## Architecture

### Core Design Pattern: Action-Based Architecture

The codebase uses an action-based pattern where all user commands are implemented as actions that implement either:
- `Action` trait: Simple actions that don't require vault access (e.g., init, lock, unlock, generate password)
- `UnlockingAction` trait: Actions that require unlocking a vault (e.g., show, add, delete, edit, import, export)

### Workspace Layout

The repo is a cargo workspace: the root package is the `passlane` CLI, and `crates/*` holds shared library crates (`passlane-core`, `passlane-approval`, `passlane-agent`, and `passlane-ffi` — the UniFFI surface the iOS app consumes, issue #44; `crates/uniffi-bindgen*` are the workspace-bin bindgen CLIs it generates bindings with). `passlane-core` carries the platform-independent logic (KeePass vault, password generator, pure hardware-key config) so the CLI and the iOS app share a single kdbx implementation; its `usb` cargo feature (off by default, enabled by the CLI) gates real YubiKey support, keeping libusb out of mobile builds.

```
crates/passlane-core/    # Platform-independent core (lib crate), consumed by the CLI
├── src/vault/           # Vault abstraction layer
│   ├── vault_trait.rs   # Traits: Vault, PasswordVault, PaymentVault, NoteVault, TotpVault
│   ├── keepass_vault.rs # Keepass implementation (only implementation currently)
│   └── entities.rs      # Data models: Credential, PaymentCard, Note, Totp, Error
├── src/generator.rs     # Password generation/validation
├── src/challenge.rs     # ChallengeFactor: virtual keys (everywhere) and YubiKey (usb feature)
└── src/hwkey.rs         # HwKeyConfig parsing, user-facing device-error messages

src/                     # The passlane CLI package
├── main.rs              # CLI definition using clap, command routing to actions
├── actions/             # All user commands implemented as actions
│   ├── mod.rs          # Action traits and common utilities
│   ├── add.rs          # Add credentials, payment cards, notes, or TOTP
│   ├── delete.rs       # Delete entries
│   ├── edit.rs         # Edit existing entries
│   ├── export.rs       # Export to CSV
│   ├── generate.rs     # Generate passwords
│   ├── import.rs       # Import from CSV
│   ├── init.rs         # First-time setup (creates the first vault)
│   ├── lock.rs         # Lock vaults (remove from keychain)
│   ├── show.rs         # Display entries
│   ├── unlock.rs       # Unlock vaults (store in keychain)
│   └── vault.rs        # Manage vaults: list/add/use/remove/rename/info
├── vault_registry.rs    # Named-vault registry (vaults.json), active vault, current-vault global, migration
├── store.rs            # File I/O: CSV operations, low-level config-dir helpers
├── keychain.rs         # OS keychain integration for master password storage
├── hwkey.rs            # Interactive hardware-key flows: enrollment prompts, recovery, backup reminder
├── phone_key/          # Phone-held key (issue #53): KDF-seed reader, link transport,
│   │                   #   enrollment; answers arrive as keepass-ng External challenges
│   ├── kdf_seed.rs     #   Read a vault's challenge from the cleartext kdbx outer header
│   ├── transport.rs    #   The link transport: QR/link out, pasted or agent-held answer in
│   └── enroll.rs       #   The enrollment sequence (sheet scan-back gates the re-key)
└── ui/                 # User interface components
    ├── input.rs        # Interactive prompts and input handling
    └── output.rs       # Formatted output and table rendering
```

### Multiple Vaults

Passlane manages any number of **named vaults**; each is one kdbx file plus optional keyfile and hardware-key factors, and any vault can hold all entry types (credentials, payment cards, notes, TOTP). Vault configurations live in `~/.passlane/vaults.json`; the vault used by default is the **active vault**, recorded in `~/.passlane/.active_vault`. Every command accepts a global `--vault <NAME>` flag (or `PASSLANE_VAULT` env var) to target another vault; `main.rs` resolves the target before dispatch and stores it in the process-global current vault (`vault_registry::current()`), which `unlock()` and friends read. `unlock -o`/`passwd -o` are legacy aliases for `--vault totp` (the migrated TOTP vault). On first run after upgrading, the pre-multi-vault dot-file config is migrated automatically (main vault → `default`, TOTP vault → `totp`).

### Challenge-Response Factors

A vault's composite key can include a challenge-response factor (HMAC-SHA1 over the vault's challenge), represented by `passlane_core::challenge::ChallengeFactor`:

- `Virtual { secret_hex }` — the 20-byte HMAC-SHA1 secret as 40 hex characters, answered locally with no device and no touch. It is both the **virtual key** that is the mobile path and the **recovery secret** of a lost hardware key (`hwkey remove --secret`): the same key material. Build it with `ChallengeFactor::from_secret_hex`, which validates the secret.
- `Yubikey { slot, serial }` — a connected key's HMAC-SHA1 slot; it exists only with the `usb` cargo feature and every open and save waits for a touch. Build it with `ChallengeFactor::yubikey`, which checks that the key is connected.

Both map onto keepass-ng's `ChallengeResponseKey` and protect one vault format, so a vault enrolled with a virtual key opens with a `LocalChallenge` and vice versa. A **new** virtual key is always a 20-byte key in hex: `from_secret_hex` validates it, and so do `new_with_challenge_factor` and `update_challenge_factor` — keepass-ng alone would accept any hex string, an empty one included. Opening is never stricter than the file format: a vault that another tool protected with a secret of another length still opens and re-saves, and `from_existing_secret_hex` builds the factor for it (`hwkey remove --secret` tries it with a note when the secret is not 40 characters). `KeepassVault::open_with_challenge_factor`, `new_with_challenge_factor` and `update_challenge_factor` take the factor (and re-challenge it on every save); `open`, `new` and `update_challenge_response` still accept keepass-ng's own key type. Only a YubiKey gets the "Touch your hardware key" notice. The vault registry (`vaults.json`) records physical keys only (`hwkey: {slot, serial}`) and never a secret.

Never match keepass-ng's `ChallengeResponseKey` in `passlane-core` without a wildcard fallback arm: its YubiKey variant exists whenever *any* crate in the build enables keepass-ng's USB feature, which need not be core's `usb`, so an exhaustive match with a cfg-gated arm does not compile in that combination (see `ChallengeFactor::try_from`; CI builds it).

### Configuration Files

Passlane stores configuration in `~/.passlane/`:
- `vaults.json`: The vault registry — `[{name, path, keyfile?, hwkey?}]` per vault
- `.active_vault`: Name of the vault commands use by default
- `.completion_cache.<name>`: Per-vault shell-completion caches (entry titles/usernames)

### Vault Trait System

The vault abstraction uses composition of traits:
- `PasswordVault`: Credential CRUD operations
- `PaymentVault`: Payment card CRUD operations
- `NoteVault`: Secure note CRUD operations
- `TotpVault`: TOTP entry CRUD operations
- `Vault`: Combines all four traits

This design allows for potential alternative storage backends beyond Keepass, though currently only `KeepassVault` is implemented.

### Action Execution Flow

1. `main.rs` parses CLI arguments using clap, migrates legacy config if needed, and resolves the target vault (`--vault`/env/active) into the current-vault global
2. Subcommand is matched to an Action implementation
3. Actions are categorized as `RoutedAction::Action` or `RoutedAction::UnlockingAction`
4. `UnlockingAction` types automatically unlock the current vault before execution
5. Vault unlocking walks one chain for every command (`actions/mod.rs`, sources injected for the tests): a live session-agent session first — the only source guaranteed prompt-free — then the OS keychain, then the password prompt, taking the first that opens the vault. Without a terminal on stdin nothing may block: no hardware-key touch, no unbounded keychain wait, no password prompt; an agent named by `PASSLANE_AGENT_SOCK` that cannot be used is an error, never a silent fallback (see `docs/features/session-agent.md`)
6. Actions use the `MatchHandlerTemplate` pattern to handle single vs. multiple search results uniformly

### ItemType Pattern

Commands that work with different entry types (credentials, payments, notes, TOTP) use the `ItemType` enum to determine which vault trait methods to call. This is determined from command-line flags (`-p` for payments, `-n` for notes, `-o` for OTP); the entries live in whatever vault the command targets.

### Master Password Storage

The `keychain` module uses the OS keychain (Keychain on macOS, Credential Manager on Windows, Secret Service on Linux) to securely store master passwords — one entry per vault (`passlane_master_pwd` service, vault name as the account). Users can "unlock" vaults to store passwords, enabling seamless access, or "lock" them to remove the stored passwords and require manual entry; several vaults can be unlocked at once (`lock` targets one vault, `lock --all` locks everything).

## Key Dependencies

- `keepass-ng`: Keepass file format support with save_kdbx4 and totp features
- `clap`: CLI argument parsing
- `keyring`: Cross-platform keychain access
- `clipboard`: Clipboard integration for copying passwords
- `comfy-table`: Table rendering for list views
- `inquire`: Interactive prompts
- `csv`: CSV import/export
- `serde`: Serialization for data models
- `uuid`: Entry identification

## Development Notes

- The CLI starts the interactive REPL when run without arguments
- All entry types (credentials, payments, notes, TOTP) use UUIDs for identification
- Search functionality uses regex patterns
- Clipboard integration automatically copies passwords/OTPs when displaying single results
- The TOTP implementation continuously refreshes and copies codes to clipboard
- CSV import expects columns: username, password, title (older exports with a `service` column are accepted; `url`, `tags`, `expires`, `expiry_time` and `custom_attributes` columns are optional)
- Keepass compatibility is maintained through the `keepass-ng` crate
