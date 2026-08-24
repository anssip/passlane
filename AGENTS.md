# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Passlane is a password manager and authenticator CLI written in Rust that uses Keepass as the storage backend. It supports storing credentials, payment cards, secure notes, and TOTP (Time-based One-Time Passwords). The application supports KDB, KDBX3, and KDBX4 file formats and can optionally use key files for additional security.

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

## Architecture

### Core Design Pattern: Action-Based Architecture

The codebase uses an action-based pattern where all user commands are implemented as actions that implement either:
- `Action` trait: Simple actions that don't require vault access (e.g., init, lock, unlock, generate password)
- `UnlockingAction` trait: Actions that require unlocking a vault (e.g., show, add, delete, edit, import, export)

### Module Structure

```
src/
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
├── vault/               # Vault abstraction layer
│   ├── vault_trait.rs  # Traits: Vault, PasswordVault, PaymentVault, NoteVault, TotpVault
│   ├── keepass_vault.rs # Keepass implementation (only implementation currently)
│   └── entities.rs     # Data models: Credential, PaymentCard, Note, Totp, Error
├── vault_registry.rs    # Named-vault registry (vaults.json), active vault, current-vault global, migration
├── store.rs            # File I/O: CSV operations, low-level config-dir helpers
├── keychain.rs         # OS keychain integration for master password storage
├── crypto.rs           # Cryptographic utilities
└── ui/                 # User interface components
    ├── input.rs        # Interactive prompts and input handling
    └── output.rs       # Formatted output and table rendering
```

### Multiple Vaults

Passlane manages any number of **named vaults**; each is one kdbx file plus optional keyfile and hardware-key factors, and any vault can hold all entry types (credentials, payment cards, notes, TOTP). Vault configurations live in `~/.passlane/vaults.json`; the vault used by default is the **active vault**, recorded in `~/.passlane/.active_vault`. Every command accepts a global `--vault <NAME>` flag (or `PASSLANE_VAULT` env var) to target another vault; `main.rs` resolves the target before dispatch and stores it in the process-global current vault (`vault_registry::current()`), which `unlock()` and friends read. `unlock -o`/`passwd -o` are legacy aliases for `--vault totp` (the migrated TOTP vault). On first run after upgrading, the pre-multi-vault dot-file config is migrated automatically (main vault → `default`, TOTP vault → `totp`).

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
5. Vault unlocking checks OS keychain first, prompts for password if not found
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

- The CLI defaults to generating a password when run without arguments
- All entry types (credentials, payments, notes, TOTP) use UUIDs for identification
- Search functionality uses regex patterns
- Clipboard integration automatically copies passwords/OTPs when displaying single results
- The TOTP implementation continuously refreshes and copies codes to clipboard
- CSV import expects columns: username, password, title (older exports with a `service` column are accepted; `url`, `tags`, `expires`, `expiry_time` and `custom_attributes` columns are optional)
- Keepass compatibility is maintained through the `keepass-ng` crate
