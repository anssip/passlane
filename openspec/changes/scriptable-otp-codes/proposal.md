## Why

The `json-output-and-list-command` change made credentials, payment cards, and notes scriptable: `list --json` prints to stdout with no clipboard interaction and no prompts. TOTP has a gap, though. There is **no non-interactive way to obtain a generated TOTP code**:

- `show -o` generates the live code, but only inside an interactive watch loop — it copies the code to the clipboard, prints a countdown, and blocks until the user presses `q`. It never exits on its own.
- `list -o` is non-interactive but outputs the stored TOTP *secret and config* (`secret`, `algorithm`, `period`, `digits`), not a current code. A script would have to re-implement TOTP generation from the secret.

So a script that just needs the current 6-digit code must drive the interactive `show -o`: read its stdout until the `Code NNNNNN` line appears, then kill the process before it blocks on the countdown. This is exactly what the Flowzymes monthly automation has to do today to log into Braintree (it streams `show braintree -o -v --plain` and terminates it). That is brittle — it depends on output wording, output buffering, and process signals.

This change adds a first-class, one-shot way to print the current TOTP code to stdout and exit, in both plain text and JSON, with no clipboard and no interactive prompt — closing the gap so the scripting story is consistent across all entry types.

## What Changes

- Add a `--code` flag to the existing scripting-oriented `list` command. With `-o`, `list -o --code [REGEXP]` outputs the **currently valid generated code** for each matching TOTP authorizer instead of the stored secret/config. Honors `--json`.
- Add a `--once` flag to `show -o`. `show -o --once <REGEXP>` prints the current code for the single matching authorizer to stdout and exits `0` immediately — no clipboard, no countdown, no keypress wait. On multiple matches it errors (non-zero) rather than prompting; on no match it errors (non-zero).
- Define a JSON envelope for generated codes: `type: "totp_codes"`, with `count` and an `entries` array of `{ label, issuer, code, valid_for_seconds }`. The stored `secret` is **never** included in code output.
- Neither new path copies to the clipboard or displays interactive prompts (consistent with the `list` contract).
- The existing interactive `show -o` watch loop and the existing `list -o` secret listing are unchanged and remain the defaults.

## Capabilities

### New Capabilities

- `scriptable-otp-codes`: Non-interactive retrieval of generated TOTP codes — the `--code` output mode on `list`, the `--once` one-shot mode on `show`, their plain-text and JSON formats, clipboard/prompt suppression, and exit-code behavior.

### Modified Capabilities

- `list-command`: The `list` subcommand gains a `--code` flag that, combined with `-o`, switches TOTP output from stored secrets to generated codes.

## Impact

- **Code — `src/actions/list.rs`**: `ListAction` gains a `code: bool` field; `list_totp` branches on it to call `Totp::get_code()` per match and emit codes (plain + JSON via a new `totp_codes` output shape) instead of secrets.
- **Code — `src/actions/show.rs`**: `ShowAction` gains a `once: bool` field; `ShowTotpTemplate` short-circuits to a one-shot print-and-exit path (no clipboard, no listener/countdown threads) when set, with non-zero exit on zero or multiple matches.
- **Code — `src/main.rs`**: add `--code` to the `list` subcommand and `--once` to the `show` subcommand; both are `ArgAction::SetTrue`.
- **Code — serialization**: a small serializable struct for the `totp_codes` envelope (reusing the existing `ListOutput`-style `{ type, count, entries }` pattern). The TOTP `secret` field is excluded from this output.
- **APIs**: new flags `list --code` and `show --once`. No breaking changes; existing behavior is the default.
- **Security**: generated codes are short-lived and already exposed via the interactive `show`; the stored secret is never printed by either new path.
- **Downstream**: the Flowzymes `fetch_braintree_csv.py` OTP helper can drop its stream-and-terminate logic in favor of `passlane show braintree -o --once` (or `list -o --code --json`).
