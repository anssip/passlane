## 1. Fix password prompt confirmation

- [x] 1.1 Add `.without_confirmation()` to the `Password::new()` call in `ask_password()` in `src/ui/input.rs`

## 2. Refactor for testability

- [x] 2.1 Create `ask_master_password_with<F: Fn(&str) -> String>(question: Option<&str>, reader: F) -> String` helper that calls `reader` once and returns the result
- [x] 2.2 Create `ask_new_master_password_with<F: FnMut(&str) -> String>(reader: F) -> String` helper that calls `reader` twice, compares, and retries on mismatch
- [x] 2.3 Refactor `ask_master_password` to delegate to `ask_master_password_with` with `ask_password` as the reader
- [x] 2.4 Refactor `ask_new_master_password` to delegate to `ask_new_master_password_with` with `ask_password` as the reader

## 3. Tests

- [x] 3.1 Add `test_ask_master_password_prompts_once` — mock reader counts invocations, assert called exactly once
- [x] 3.2 Add `test_ask_new_master_password_prompts_twice_on_match` — mock reader returns same password, assert called twice, returns password
- [x] 3.3 Add `test_ask_new_master_password_retries_on_mismatch` — mock reader returns mismatched pair then matching pair, assert called four times, returns matching password

## 4. Verify

- [x] 4.1 Run `cargo test` and confirm all tests pass
- [x] 4.2 Run `cargo build --release` and confirm no warnings or errors
