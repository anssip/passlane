## Context

Currently, `copy_to_clipboard` in `src/actions/mod.rs` is a fire-and-forget helper that sets the system clipboard via the `clipboard` crate. It is called from:

- `ShowCredentialsTemplate` (`show.rs`) — single-match and multi-match credential display
- `GeneratePasswordAction` (`generate.rs`) — after generating a random password

In both cases the process exits shortly after the copy, leaving the password in the clipboard indefinitely.

## Goals / Non-Goals

**Goals:**
- Clear the clipboard 10 seconds after a password is copied by `show` (credentials) or `generate`.
- Only clear if the clipboard still contains the value Passlane placed there (avoid destroying unrelated content the user copied in the meantime).
- Provide visible feedback that the clipboard will be auto-cleared.
- Provide a `--out` flag on `show` and `generate` that skips the clipboard entirely and prints the password to STDOUT only, enabling scripting and piping use cases.

**Non-Goals:**
- Making the timeout configurable (hardcode 10 seconds for now; can be added later).
- Applying the timeout to payment card numbers, TOTP codes, or the `add` command.
- Applying the timeout to clipboard copies in the REPL (`src/repl/mod.rs`) — can be a follow-up.

## Decisions

### 1. New `copy_to_clipboard_timed` function

Introduce a new function alongside the existing `copy_to_clipboard`:

```rust
pub fn copy_to_clipboard_timed(value: &str, timeout_secs: u64) -> JoinHandle<()>
```

It copies the value to the clipboard, stores a clone of the value, and spawns a background thread that:
1. Sleeps for `timeout_secs` seconds.
2. Reads the current clipboard content.
3. If it still matches the original value, sets the clipboard to an empty string.

Returns the `JoinHandle` so the caller can join it before the process exits.

**Why a new function instead of modifying the existing one?** The existing `copy_to_clipboard` is also used by payment cards, TOTP, notes, and the `add` command — all of which should keep the current fire-and-forget behaviour. A separate function avoids touching unrelated code paths.

### 2. Blocking at the call site

Both `show` (credential path) and `generate` are short-lived — the process exits almost immediately after the copy. A detached thread would be killed on process exit.

The call sites will join the returned `JoinHandle` before returning their result, which blocks the process for the remaining timeout duration. During this wait the user sees a message like:

```
Password copied to clipboard! Clipboard will be cleared in 10 seconds.
```

This is the standard pattern used by other CLI password managers (e.g., `pass`).

**Alternative considered — detached child process:** Spawning an external process (`sleep 10 && clear-clipboard`) would let the CLI exit immediately but introduces platform-specific complexity and makes the "smart clear" check (clipboard still matches?) much harder. Rejected for complexity.

### 3. Smart clear via content comparison

Before clearing, the thread reads the clipboard and compares it to the original copied value. If they differ, the user has copied something else and the clipboard is left untouched. This avoids a frustrating experience where a user's subsequent copy is unexpectedly wiped.

The `clipboard` crate's `get_contents()` method is used for the comparison.

### 4. `--out` flag to skip clipboard

A new `--out` boolean flag is added to the `show` and `generate` subcommands in `main.rs`. When set:

- The password is printed to STDOUT (it already is for `generate`; for `show` credentials it is displayed in a table).
- `copy_to_clipboard` / `copy_to_clipboard_timed` are **not called** at all.
- No timeout, no blocking, no clipboard interaction — the process exits immediately.
- The "Password copied to clipboard" message is replaced with just the password value on STDOUT (clean output for piping).

This flag is threaded through as a field on `ShowAction` and `GeneratePasswordAction`, and checked before the clipboard call.

**Why `--out` instead of `--no-clipboard`?** Shorter, script-friendly, and conveys the intent (output to STDOUT) rather than describing what is skipped.

## Risks / Trade-offs

- **[Process blocks for up to 10 seconds]** → Acceptable trade-off for security. Users expect this from password manager CLIs. Ctrl+C is always available to exit early (the clipboard will not be cleared in that case, but that's the user's explicit choice).
- **[Clipboard read may fail]** → If `get_contents()` errors (e.g., clipboard unavailable), skip the clear silently. Don't crash on cleanup.
- **[Thread panic safety]** → The spawned thread should not panic. Wrap clipboard operations in the thread with error handling.
- **[`--out` prints password in cleartext to STDOUT]** → This is the explicit intent for scripting. Users opt in with the flag. No additional warning needed.
