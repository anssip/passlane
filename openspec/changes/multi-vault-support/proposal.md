## Why

Passlane supports exactly one password vault plus one TOTP vault, identified implicitly by fixed config files (`~/.passlane/.vault_path`, `~/.passlane/.totp_vault_path`). Users with separate password stores — personal, work, family — must either merge them into one file or juggle multiple installations by hand. Managing several named vaults from a single installation, with an "active vault" default and a per-command override, removes that pain.

## What Changes

- **Unified vault model.** A vault is a named kdbx file with optional keyfile and optional hardware-key (YubiKey challenge-response) factors. Any vault can hold credentials, payment cards, secure notes **and** TOTP entries; the special "TOTP vault" role is gone. The `-o/--otp` flag on item commands means "operate on the TOTP entries of the target vault".
- **Vault registry.** Vault configurations live in `~/.passlane/vaults.json` (`{name, path, keyfile, hwkey}` per vault). The active vault is recorded in `~/.passlane/.active_vault`. The old dot-files (`.vault_path`, `.totp_vault_path`, `.keyfile_path`, `.totp_keyfile_path`, `.hwkey`) are migrated automatically on first run: the old main vault becomes `default`, the old TOTP vault becomes `totp`, and the old keychain entries are re-keyed per vault (best-effort).
- **Vault selection.** Every command accepts a global `--vault <NAME>` flag (also `PASSLANE_VAULT` env var). Precedence: flag → env → active vault → the only registered vault. `unlock -o` / `passwd -o` remain as aliases for `--vault totp`.
- **New `passlane vault` subcommand group**: `list` (state table), `add [NAME]` (create or register an existing kdbx, with keyfile/hwkey/password prompts), `use <NAME>` (alias `switch`), `remove <NAME>` (deregisters, never deletes files), `rename <OLD> <NEW>`, `info [NAME]`.
- **Per-vault unlock state.** One keychain entry per vault (`passlane_master_pwd` service, vault name as account). `lock` locks the target vault; `lock --all` locks every vault. Several vaults can be unlocked simultaneously.
- **Per-vault completion caches** (`~/.passlane/.completion_cache.<name>`); generated shell completion scripts resolve the active vault's cache at completion time.
- **REPL**: `vault` / `vault list` and `vault use <name>` commands; switching also switches the current session; `status` lists all vaults with active marker and lock state; first-run detection uses the registry.
- `hwkey add/remove/status` and `passwd` operate on the target vault; hardware-key enrollment is stored in the registry entry instead of `~/.passlane/.hwkey`.

## Capabilities

### New Capabilities
- `vault-registry`: Storing named vault configurations (`vaults.json`), the active-vault pointer, name validation, and the automatic migration from the pre-multi-vault dot-file configuration.
- `vault-management`: The `passlane vault` subcommand group (list/add/use/remove/rename/info) and the global `--vault` flag / `PASSLANE_VAULT` override.

### Modified Capabilities
- `password-prompting`: Master passwords are stored per vault (keychain account = vault name); unlock prompts name the vault; `unlock -o` is an alias for `--vault totp`.
- `repl-session`: `vault`/`vault list`/`vault use <name>` commands; `unlock otp` prints a hint pointing at `vault use totp`; `status` lists all vaults.

## Impact

- **Code**: New `src/vault_registry.rs` and `src/actions/vault.rs`; `init` reduced to first-vault setup shared with `vault add`; removal of the `unlock_totp_vault`/`is_totp_vault` special-casing across actions; keychain/store/hwkey/completion-cache refactors; `main.rs` startup gains migration + target-vault resolution before dispatch.
- **Dependencies**: clap gains the `env` feature (for `PASSLANE_VAULT`). No new crates.
- **APIs**: New `--vault` global flag and `vault` subcommand group; `lock` gains `--all`; `unlock`/`passwd` keep `-o` as a deprecated alias. Existing commands otherwise unchanged for single-vault users.
- **Migration**: Automatic, idempotent, runs before any command; legacy dot-files are removed only after the registry is written; kdbx files are never touched. Downgrading after migration is not supported (old versions cannot read `vaults.json`).
