## 1. Core clipboard timeout function

- [x] 1.1 Add `copy_to_clipboard_timed(value: &str, timeout_secs: u64) -> JoinHandle<()>` in `src/actions/mod.rs` that copies to clipboard, spawns a background thread sleeping for `timeout_secs`, then clears clipboard only if content still matches the original value. Wrap clipboard operations in the thread with error handling (no panics).

## 2. Integrate timeout into show command

- [x] 2.1 Add `stdout_only: bool` field to `ShowAction` in `src/actions/show.rs`, parsed from the `--out` CLI flag.
- [x] 2.2 Thread `stdout_only` into `ShowCredentialsTemplate` (add it as a field).
- [x] 2.3 Update `ShowCredentialsTemplate::handle_one_match`: if `stdout_only`, print password to STDOUT and return without clipboard copy; otherwise call `copy_to_clipboard_timed`, join the handle, and return the updated message ("Password copied to clipboard! Clipboard will be cleared in 10 seconds.").
- [x] 2.4 Update `ShowCredentialsTemplate::handle_many_matches`: same logic — if `stdout_only`, print selected password to STDOUT; otherwise use `copy_to_clipboard_timed` with join and updated message.

## 3. Integrate timeout into generate command

- [x] 3.1 Add `stdout_only: bool` field to `GeneratePasswordAction` in `src/actions/generate.rs`.
- [x] 3.2 Update `GeneratePasswordAction::run`: if `stdout_only`, print password to STDOUT and return without clipboard copy; otherwise call `copy_to_clipboard_timed`, join the handle, and return the updated message.

## 4. CLI flag definitions

- [x] 4.1 Add `--out` flag to the `show` subcommand in `src/main.rs` with help text "Print password to stdout instead of copying to clipboard."
- [x] 4.2 Add `--out` flag to the `gen` subcommand in `src/main.rs` with the same help text.
- [x] 4.3 Update `GeneratePasswordAction` construction in `main.rs` to pass the `--out` flag value (change from unit struct to `GeneratePasswordAction::new(sub_matches)`).

## 5. Testing

- [x] 5.1 Verify `cargo build --release` compiles without errors.
- [x] 5.2 Verify `cargo test` passes.
- [x] 5.3 Manual test: run `passlane show <service>` — confirm password is copied, message shows timeout notice, and clipboard is cleared after 10 seconds.
- [x] 5.4 Manual test: run `passlane gen` — confirm password is printed, clipboard is set, and cleared after 10 seconds.
- [x] 5.5 Manual test: run `passlane show <service> --out` — confirm password is printed to STDOUT, no clipboard copy, process exits immediately.
- [x] 5.6 Manual test: run `passlane gen --out` — confirm password is printed to STDOUT, no clipboard copy, process exits immediately.
