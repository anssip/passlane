## Context

Passlane has two relevant command surfaces for TOTP:

- `show -o` (`src/actions/show.rs`, `ShowTotpTemplate::show_code`) — interactive. Spawns a keyboard-listener thread and a countdown thread, copies each generated code to the clipboard, and loops calling `Totp::get_code()` until the user presses `q` (or Ctrl-D). It never terminates non-interactively.
- `list -o` (`src/actions/list.rs`, `list_totp`) — non-interactive, scripting-oriented. Outputs the stored TOTP entries (label, issuer, **secret**, algorithm, period, digits) as plain text or, with `--json`, as a `{ type: "totp", count, entries }` envelope. It does not generate codes.

`Totp::get_code()` already returns `TotpCode { value: String, valid_for_seconds: u64 }` (`src/vault/entities.rs`), so generating a current code is a single call — the missing piece is purely a non-interactive *output path* for it.

## Goals / Non-Goals

**Goals**
- Provide a one-shot, non-interactive way to print the current generated TOTP code to stdout and exit.
- Offer both a bulk/JSON-friendly form (`list -o --code`) and a single-entry convenience form (`show -o --once`).
- Keep the contract identical to `list`: no clipboard, no prompts, immediate stdout, useful exit codes.

**Non-Goals**
- Changing the default behavior of interactive `show -o` (the watch loop stays).
- Changing the default behavior of `list -o` (secret listing stays; codes are opt-in via `--code`).
- Auto-detecting TTY vs pipe to switch modes implicitly. Explicit flags are clearer and avoid surprising behavior changes; TTY auto-detection is noted as a possible future follow-up.

## Decisions

### Two access paths, one core
Both new paths are thin wrappers over `Totp::get_code()`. They differ only in ergonomics:

- `list -o --code [REGEXP]` — fits the existing "list = scripting" capability, supports `--json`, and naturally handles multiple matches (emits a code per authorizer). This is the **recommended scripting interface**.
- `show -o --once <REGEXP>` — matches the mental model of users who reach for `show` to get "the" code, and directly removes the need to kill the interactive process. It is single-valued: exactly one match required.

Shipping both keeps the change small (they share `get_code()`) while covering both habits. If scope must shrink, `list -o --code` alone satisfies the core need; `show --once` is the secondary convenience.

### JSON shape
Reuse the established envelope `{ "type": <string>, "count": <n>, "entries": [...] }`. For codes, `type` is `"totp_codes"` and each entry is `{ "label", "issuer", "code", "valid_for_seconds" }`. This is deliberately distinct from the existing `"totp"` type (which carries the secret) so consumers can tell secret-listing from code-generation, and so the secret is structurally absent from code output.

### Ambiguity and errors
- `list -o --code` follows existing `list` semantics: zero matches → empty result (`count: 0` / "Found 0 …"), multiple matches → a code line per match. Non-interactive, never prompts.
- `show -o --once` is single-valued by contract: zero matches → error to stderr, non-zero exit; more than one match → error to stderr naming the matched labels, non-zero exit (it does **not** fall back to the interactive index prompt). This makes it safe to use unattended in scripts.

### Clipboard
Neither path touches the clipboard. The interactive `show -o` still copies (governed by the existing `clipboard-timeout` capability); these scripting paths are explicitly clipboard-free, matching `list`.

## Risks / Trade-offs

- **Two ways to do one thing.** Mitigated by clear documentation: `list -o --code` for scripting/JSON/bulk, `show -o --once` for a quick single code. Both call the same generator.
- **Code value lifetime.** A printed code is valid only for `valid_for_seconds`; including that field lets callers decide whether to use or re-fetch. Documented in `--help` and the README.
- **Exit-code contract** must be reliable for scripts. Covered explicitly by spec scenarios.

## Migration

No migration. Purely additive flags. The Flowzymes Braintree login helper can switch from streaming-and-killing `show -o` to `show braintree -o --once` (or `list -o --code --json`) once released, but that is downstream and out of scope for this change.
