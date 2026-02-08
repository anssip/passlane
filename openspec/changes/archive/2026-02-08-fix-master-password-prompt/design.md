## Context

The `inquire` crate (v0.7.5) `Password::new()` enables confirmation by default — users type a password, then are asked to retype it for confirmation. This is the right default for *creating* passwords, but wrong for *entering* existing ones (unlocking vaults).

Currently `ask_password()` in `src/ui/input.rs` is the shared low-level function used by both unlock flows and password-creation flows. It does not call `.without_confirmation()`, so every call prompts twice.

There is also a separate `ask_new_password()` function (used when editing credentials) that creates its own `Password::new()` prompt directly — it is not affected by changes to `ask_password()`.

## Goals / Non-Goals

**Goals:**
- Unlocking a vault (main or TOTP) prompts for the master password exactly once
- Creating a new master password (init flow) prompts exactly twice (enter + confirm)
- No regression in credential password editing flow

**Non-Goals:**
- Changing the confirmation behavior of `ask_new_password()` (credential editing)
- Adding password strength validation
- Changing any vault unlocking logic beyond the prompt count

## Decisions

**Add `.without_confirmation()` to `ask_password()`**

`ask_password()` is the base function. Making it single-prompt is correct because:
- Callers that need confirmation already implement it themselves (e.g., `ask_new_master_password` prompts twice and compares)
- All unlock paths (`ask_master_password`, `ask_totp_master_password`) need single-prompt behavior
- The `ask_password` in `add.rs` (entering a password to save) also benefits — no reason to confirm a password you're importing/storing

Alternative considered: creating a separate `ask_password_no_confirm()` function. Rejected because there's no caller that needs the current double-prompt behavior from `ask_password` itself — every confirmation case is already handled at a higher level.

## Testing

The interactive prompt functions (`ask_master_password`, `ask_new_master_password`) cannot be unit-tested directly since `inquire::Password` requires a terminal. To make the confirmation logic testable, refactor by extracting the password-reading dependency:

**Approach: inject a password provider function**

Introduce internal helper functions that accept a closure `Fn(&str) -> String` as the password reader, instead of calling `ask_password` directly:

- `ask_master_password_with<F>(question: Option<&str>, reader: F) -> String` — calls `reader` once and returns the result.
- `ask_new_master_password_with<F>(reader: F) -> String` — calls `reader` twice, compares, retries on mismatch.

The public functions (`ask_master_password`, `ask_new_master_password`) delegate to these helpers with `ask_password` as the reader.

**Tests:**

1. **`test_ask_master_password_prompts_once`** — provide a mock reader that counts invocations. Assert it is called exactly once.
2. **`test_ask_new_master_password_prompts_twice_on_match`** — provide a mock reader returning the same password each time. Assert it is called exactly twice and returns the password.
3. **`test_ask_new_master_password_retries_on_mismatch`** — provide a mock reader returning different passwords on the first pair and matching passwords on the second pair. Assert it is called four times total (2 failed + 2 succeeded) and returns the matching password.

## Risks / Trade-offs

**[Minimal risk]** The change is a single method call addition (`.without_confirmation()`) on one function. All existing confirmation logic in `ask_new_master_password()` is preserved since it handles its own two-prompt-and-compare flow independently. The testable helper functions are internal and don't change the public API.
