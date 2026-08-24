## Context

Pre-multi-vault, two hardcoded vault roles run through four seams:

1. `store.rs` dot-file accessors (`get_vault_path`, `get_totp_vault_path`, `get_keyfile_path`, `get_totp_keyfile_path`) — parameterless globals read at unlock time.
2. `keychain.rs` — two fixed entries (`passlane_master_pwd` / `passlane_totp_master_pwd`, account `passlane`).
3. `actions/mod.rs` — `unlock()` vs `unlock_totp_vault()`, selected per action via `UnlockingAction::is_totp_vault()`.
4. Per-vault-agnostic extras: single `.hwkey` config file, single `.completion_cache`, and the `store::has_vault_path()` first-run check used by the REPL.

Entry typing inside a kdbx is per-entry (`keepass_vault.rs` detects TOTP entries by shape via `node_has_totp`, payments by custom fields), so the storage layer already supports mixed-content vaults — only the action layer's "which file to open" logic was split.

## Goals / Non-Goals

**Goals**
- Named vaults with independent location, master password, keyfile and hardware-key enrollment.
- One active vault used by default; `--vault`/`PASSLANE_VAULT` overrides per command.
- Automatic, lossless migration of existing installations; kdbx files are never touched.
- Per-vault unlock state: several vaults can be unlocked at once; `lock` targets one vault, `--all` covers everything.
- Minimal churn in the action layer: keep the parameterless-global style by making the *current vault* a process-wide resolved value.

**Non-Goals**
- Merging or moving vault data between vaults.
- Dynamic shell completion of vault names after `--vault` (the registry is read at completion time only for the completion cache path; name completion can be added later).
- Changing the kdbx entry formats.

## Decisions

### One vault kind, no TOTP special case
Each registered vault is `{name, path, keyfile?, hwkey?}`. TOTP entries live wherever the user puts them; `-o` selects the TOTP entries of the target vault. This deletes `unlock_totp_vault`, `is_totp_vault`, the `ask_*_totp_*` prompt family and the TOTP keychain service instead of generalizing them.

### Registry file + separate active pointer
`~/.passlane/vaults.json` (serde, versioned, written 0600 atomically via temp-file + rename) holds the list; `~/.passlane/.active_vault` holds one name. A separate pointer keeps switching an atomic single-line write and matches the existing dot-file idiom; it also lets generated shell scripts resolve the active vault's completion cache without parsing JSON (`cat .active_vault`).

Vault names are validated to `[A-Za-z0-9_-]{1,64}` and must be unique — they become keychain account names and cache filename suffixes.

### Resolution: explicit → active → single
`resolve(explicit)`: an explicit name (from `--vault`/`PASSLANE_VAULT`, or the legacy `unlock -o`/`passwd -o` alias mapping to `totp`) must exist or the command aborts with an error listing the configured names. Without one, the active vault wins; a stale pointer warns and is ignored; exactly one registered vault is used implicitly; otherwise the command errors telling the user to pick.

The resolved vault is stored in a process-global (`RwLock<Option<VaultConfig>>`) set once in `main()` before dispatch (and re-set by the REPL on `vault use`). This preserves the existing parameterless lookups (`store::get_vault_path()` call sites became `vault_registry::current()`) without threading a parameter through every action and both dispatch paths (clap + REPL struct literals).

### Keychain: one account per vault
`Entry::new("passlane_master_pwd", <vault-name>)`. Migration copies the two legacy entries to `default`/`totp` and deletes the originals, best-effort: a locked machine simply re-prompts once at the next unlock. `rename` moves the entry before renaming in the registry; `remove` deletes it (a stored password for an unregistered vault would linger forever).

### Migration ordering
Triggered when `vaults.json` is absent and any legacy dot-file exists, before any command runs (including `vault list`). Order: build registry → write `vaults.json` + `.active_vault` → re-key keychain (best-effort) → delete legacy dot-files (only after the successful write; a failed delete is inert and merely warns). The hardware-key config parses into the `default` vault's registry entry. Fresh installs (no dot-files) skip migration and land in the existing first-run flow.

### Hardware key per vault
`HwKeyConfig { slot, serial }` becomes a serde field of the registry entry; `.hwkey` parsing survives only for migration. `hwkey add/remove/status` read the target vault from the current-vault global. The enroll/rollback ordering from the pre-existing design is kept: the vault is re-saved with the factor *before* the enrollment is persisted, and `hwkey remove` clears the registry entry *before* stripping the factor from the vault, restoring it if the vault update fails.

### lock/unlock semantics
`unlock` opens the target vault and stores its password under its own keychain account. `lock` removes exactly the target vault's entry (plus its completion cache); `--all` iterates the registry. Vault lock state = presence of the keychain entry, surfaced by `vault list` and REPL `status`.

### Completion cache per vault
`~/.passlane/.completion_cache.<name>`, written 0600 as before. All cache entry points derive the name from the current-vault global; `lock` clears the target's file. Generated completion scripts embed a shell expression that resolves the active vault at completion time (`$(cat ~/.passlane/.active_vault)` with a `default` fallback) instead of a baked-in path.

### `vault add` and `init` share one flow
`setup_vault(name)` (in `actions/vault.rs`) drives both: name prompt/validation → new vs existing → location (default `~/.passlane/<name>.kdbx`) → keyfile → password (new: double entry; existing: single entry + open-verify) → optional hwkey enrollment for new vaults → registry write (with hwkey rollback if it fails) → optional make-active → optional keychain store. `init` is that flow with an empty registry; otherwise it reports the configured vaults.

An existing vault that needs a hardware key is registered by password-verify first and enrolled afterwards via `hwkey add` — verification cannot include an unknown factor.

## Risks / Trade-offs

- **Process-global current vault** hides the data flow slightly; accepted because the codebase already used parameterless globals for the same purpose, and both dispatch surfaces (clap, REPL) needed the value without signature churn. `current()` returns a helpful error when unset rather than panicking.
- **Migration is one-way**: older passlane versions cannot read `vaults.json`. The migration prints a notice naming the registry file.
- **Best-effort keychain migration** can leave the old entry behind if the keychain is unavailable; that is the pre-migration status quo and no weaker.
- `--vault` with an unknown name aborts even for vault-independent commands (`gen`); predictable and cheap to avoid.
