## 1. Vault registry

- [x] 1.1 New `src/vault_registry.rs`: `VaultConfig { name, path, keyfile, hwkey }`, versioned serde registry file `~/.passlane/vaults.json` (0600, atomic write), name validation `[A-Za-z0-9_-]{1,64}`, uniqueness
- [x] 1.2 Active-vault pointer `~/.passlane/.active_vault` with get/set; `set_active` validates the name exists
- [x] 1.3 `resolve`: explicit name → active vault → single registered vault; helpful errors listing configured names
- [x] 1.4 Process-global current vault (`set_current`/`current`/`init_current`), set in `main()` before dispatch
- [x] 1.5 Migration from legacy dot-files: `default` ← `.vault_path`/`.keyfile_path`/`.hwkey`, `totp` ← `.totp_vault_path`/`.totp_keyfile_path`; registry written before legacy files are deleted
- [x] 1.6 Unit tests: round-trip, name validation, resolve precedence, active-pointer maintenance on remove/rename, migration variants (full, totp-only, fresh, existing registry, defaults)

## 2. Keychain and store

- [x] 2.1 `keychain.rs`: per-vault entries (`passlane_master_pwd` service, vault name as account); drop the TOTP service
- [x] 2.2 `migrate_legacy_password(from_service, to_vault)`: copy + delete of legacy entries, best-effort
- [x] 2.3 `store.rs`: remove single-vault accessors and `.hwkey` file helpers; keep `dir_path` (pub(crate)), `create_private_file`, CSV helpers
- [x] 2.4 `hwkey.rs`: serde on `HwKeyConfig`; `configured_challenge_response_key(&HwKeyConfig)`; keep `parse` for migration

## 3. Unified unlock path

- [x] 3.1 `actions/mod.rs`: delete `unlock_totp_vault`; `get_vault_properties` reads the current vault's path/keyfile/hwkey; password prompt labeled with the vault name
- [x] 3.2 Remove `UnlockingAction::is_totp_vault` and all overrides; `execute` always opens the resolved vault
- [x] 3.3 `add.rs`: drop `is_totp`/vault branching; ItemType::Totp uses TotpVault methods on the opened vault
- [x] 3.4 Remove `is_totp` fields from show/list/edit/delete actions and their constructors/tests

## 4. Vault-aware commands

- [x] 4.1 `unlock`: unlocks target vault, stores password under its account, refreshes its cache
- [x] 4.2 `lock`: locks target vault only; new `--all` flag iterates the registry
- [x] 4.3 `passwd`: target vault's path/keyfile/hwkey; per-vault keychain update
- [x] 4.4 `hwkey add/remove/status`: operate on the target vault; enrollment stored in the registry entry; rollback/restore orderings preserved

## 5. CLI wiring

- [x] 5.1 Global `--vault <NAME>` arg (clap `env` feature, `$PASSLANE_VAULT`), propagated to all subcommands
- [x] 5.2 `vault` subcommand group: list/add/use (alias switch)/remove/rename/info
- [x] 5.3 `main()` startup: parse → migrate → resolve+set current (explicit-name failures abort) → completion-cache refresh → dispatch
- [x] 5.4 Legacy aliases: `unlock -o` / `passwd -o` map to `--vault totp` when no explicit vault is given

## 6. Vault management flows

- [x] 6.1 `setup_vault` shared by `init` and `vault add`: name validation, new/existing choice, default path `~/.passlane/<name>.kdbx`, keyfile, password prompts, existing-vault open-verification, optional hwkey enrollment with registry-rollback
- [x] 6.2 `init`: no-op message when vaults exist; otherwise first-vault setup
- [x] 6.3 `vault remove`: confirmation, keychain + cache cleanup, active-pointer handover; never deletes vault files
- [x] 6.4 `vault rename`: preconditions validated up front (check_rename); registry renamed before the keychain entry move, so a keychain failure degrades to a one-time re-prompt instead of orphaning the stored password; active pointer follows

## 7. Completion cache & REPL

- [x] 7.1 Per-vault cache file `.completion_cache.<name>`; update/ensure/read/clear derive from the current vault; `clear_cache_for(name)` for lock/remove
- [x] 7.2 `completions` action: cache generation from the current vault; generated scripts resolve the active vault's cache at completion time (bash/zsh/fish expressions with `default` fallback)
- [x] 7.3 REPL: `vault`/`vault list` and `vault use <name>` (switches the session's current vault); `unlock otp` prints a hint; `status` lists vaults with active marker + lock state; first-run detection via the registry; help text updated

## 8. Docs

- [x] 8.1 README: multi-vault section, updated unlock/lock/passwd/authenticator/completions/syncing sections, help output
- [x] 8.2 AGENTS.md: architecture (vault registry, unified vaults), config files section
- [x] 8.3 TODO.md: tick the multi-vault item

## 9. Verification

- [x] 9.1 `cargo test` green (183+ tests incl. new registry/migration/REPL-parse tests)
- [x] 9.2 Manual smoke test with isolated `$HOME`: legacy-config migration, `vault list/use/info/rename`, `--vault` flag + `PASSLANE_VAULT`, unknown-vault error, `lock`/`lock --all`, `gen`, full unlock of a fixture vault (credentials + one-shot TOTP code) through the registry
