## Why

The `ask_password` function uses `inquire::Password::new()` which enables confirmation (double-prompt) by default. This means every password entry prompts the user twice. When unlocking a vault, users must type their master password twice unnecessarily. When initializing a new master password via `ask_new_master_password()`, which already manually prompts twice and compares, the underlying `ask_password` adds its own confirmation — resulting in 4 total password prompts instead of 2.

## What Changes

- The general `ask_password` function in `src/ui/input.rs` will use `.without_confirmation()` on the `inquire::Password` prompt, making it a single-prompt function suitable for entering existing passwords.
- `ask_new_master_password` already implements its own confirmation logic (two calls to `ask_password` with comparison), so it will continue to work correctly — now prompting exactly twice as intended.
- `ask_master_password` (used when unlocking vaults) will now prompt exactly once.
- `ask_totp_master_password` (calls `ask_password` internally) will also prompt exactly once.
- No changes to `ask_new_password` in credential editing, which creates its own `Password::new()` prompt directly and retains built-in confirmation — appropriate for setting new credential passwords.

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- `src/ui/input.rs`: `ask_password` function modified to add `.without_confirmation()`
- All vault unlock flows (main vault + TOTP vault) will prompt once instead of twice
- Init flow (`ask_new_master_password`) will prompt twice instead of four times
- Credential password entry via `ask_new_password` is unaffected (uses its own `Password::new()`)
