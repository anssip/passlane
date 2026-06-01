## 1. CLI flags

- [ ] 1.1 Add `--code` flag (`ArgAction::SetTrue`) to the `list` subcommand in `src/main.rs`, with help text noting it applies to `-o`
- [ ] 1.2 Add `--once` flag (`ArgAction::SetTrue`) to the `show` subcommand in `src/main.rs`, with help text noting it prints a single code and exits

## 2. List `--code` (generated codes)

- [ ] 2.1 Add a `code: bool` field to `ListAction` and populate it from the `code` arg in `ListAction::new`
- [ ] 2.2 In `list_totp`, branch on `self.code`: when set, call `Totp::get_code()` for each matching authorizer instead of reading the secret
- [ ] 2.3 Add a serializable code-entry struct `{ label, issuer, code, valid_for_seconds }` and a `totp_codes` envelope `{ type, count, entries }` (mirror the existing `ListOutput` pattern; ensure `secret` is not serialized)
- [ ] 2.4 Implement plain-text code output (label + current code per match)
- [ ] 2.5 Implement JSON code output via the `totp_codes` envelope when `--json` is set
- [ ] 2.6 Ensure `--code` is a no-op for non-OTP entry types

## 3. Show `--once` (one-shot code)

- [ ] 3.1 Add an `once: bool` field to `ShowAction` and populate it from the `once` arg in `ShowAction::new`
- [ ] 3.2 In the TOTP branch of `ShowAction::run_with_vault`, when `once` is set, bypass `ShowTotpTemplate`'s interactive loop
- [ ] 3.3 One-shot path: resolve matches; exactly one → print `get_code().value` to stdout, return success; zero matches → error to stderr, non-zero exit; multiple matches → error to stderr listing labels, non-zero exit (no interactive prompt)
- [ ] 3.4 Confirm one-shot path does not spawn the keyboard-listener or countdown threads and does not copy to the clipboard

## 4. Tests

- [ ] 4.1 Unit/integration test: `list -o --code` prints codes, not secrets
- [ ] 4.2 Test: `list -o --code --json` produces `type: "totp_codes"` with `label`, `issuer`, `code`, `valid_for_seconds` and no `secret`
- [ ] 4.3 Test: `show -o --once <unique>` prints one code and exits 0 without blocking
- [ ] 4.4 Test: `show -o --once` exits non-zero on zero matches and on multiple matches
- [ ] 4.5 Test: default `show -o` and `list -o` behavior is unchanged

## 5. Docs

- [ ] 5.1 Update `README.md` with `list -o --code [--json]` and `show -o --once` usage and a scripting example
- [ ] 5.2 Note the short-lived nature of generated codes (`valid_for_seconds`) in the relevant `--help` text
