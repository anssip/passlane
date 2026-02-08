## 1. CLI entry point changes

- [x] 1.1 Add `gen` subcommand to the clap `Command` definition in `main.rs` that generates a password and copies to clipboard
- [x] 1.2 Add `repl` subcommand to the clap `Command` definition in `main.rs`
- [x] 1.3 Change the default no-args behavior in `main.rs` from `GeneratePasswordAction` to launching the REPL
- [x] 1.4 Wire up `gen` subcommand to dispatch to `GeneratePasswordAction`
- [x] 1.5 Wire up `repl` subcommand and no-args case to call `repl::start_repl()`

## 2. REPL module scaffold

- [x] 2.1 Create `src/repl/mod.rs` with `pub fn start_repl()` that contains the main loop skeleton (welcome banner, rustyline editor setup, readline loop, quit/exit/Ctrl-D handling)
- [x] 2.2 Create `src/repl/commands.rs` with `ReplCommand` enum and `parse_input(line: &str)` function that splits on whitespace, resolves command name (case-insensitive), item type aliases, and remaining argument
- [x] 2.3 Create `src/repl/help.rs` with `print_help(command: Option<&str>)` that prints general help (all commands summary) or command-specific help
- [x] 2.4 Create `src/repl/completer.rs` with a rustyline `Helper` struct implementing `Completer`, `Hinter`, `Highlighter`, and `Validator` — completing command names on first token and type names on second token
- [x] 2.5 Add `mod repl;` to `main.rs`

## 3. Command parsing and type resolution

- [x] 3.1 Implement item type alias resolution: `creds`/`cred`/`credentials` → Credential, `cards`/`card`/`payments` → Payment, `notes`/`note` → Note, `otp`/`totp` → Totp
- [x] 3.2 Implement the parsing logic that distinguishes type tokens from argument tokens — if the second token is not a known type alias, treat it as a search argument and default to Credential type
- [x] 3.3 Handle unknown commands by printing an error message suggesting `help`
- [x] 3.4 Handle empty input (just return to prompt without action)

## 4. Command dispatch

- [x] 4.1 Implement `show` dispatch: construct `ShowAction` with parsed `item_type`, `grep` (default `.*` for credentials when no pattern given), and `verbose: false`, then call `execute()`
- [x] 4.2 Implement `add` dispatch: construct `AddAction` with parsed `item_type`, `generate: false`, `clipboard: false`, then call `run()`
- [x] 4.3 Implement `edit` dispatch: construct `EditAction` with parsed `item_type` and `grep`, then call `execute()`. Print error if credential type and no regex provided
- [x] 4.4 Implement `delete` dispatch: construct `DeleteAction` with parsed `item_type` and `grep`, then call `execute()`. Print error if credential type and no regex provided
- [x] 4.5 Implement `gen` dispatch: construct `GeneratePasswordAction` and call `run()`
- [x] 4.6 Implement `import` dispatch: construct `ImportCsvAction` with the file path argument, print error if no path provided
- [x] 4.7 Implement `export` dispatch: construct `ExportAction` with parsed `item_type` and file path argument, print error if no path provided
- [x] 4.8 Implement `lock` dispatch: construct `LockAction` and call `run()`
- [x] 4.9 Implement `unlock` dispatch: construct `UnlockAction` with `totp` flag set based on whether `otp` was the argument, then call `run()`
- [x] 4.10 Implement `help` dispatch: call `help::print_help()` with optional command name argument
- [x] 4.11 Implement `status` dispatch: check `keychain::get_master_password()` and `keychain::get_totp_master_password()` for availability, print vault paths from `store::get_vault_path()` and `store::get_totp_vault_path()`

## 5. Action struct accessibility

- [x] 5.1 Ensure all action struct fields used by the REPL are `pub` — review `ShowAction`, `AddAction`, `EditAction`, `DeleteAction`, `ImportCsvAction`, `ExportAction`, `UnlockAction` and add `pub` to any private fields that need direct construction
- [x] 5.2 Ensure `ImportCsvAction` and `ExportAction` can be constructed without `ArgMatches` — add direct-field constructors or make fields pub if they currently require `ArgMatches`

## 6. First-run and welcome

- [x] 6.1 In `start_repl()`, check `store::has_vault_path()` before entering the loop — if false, print welcome message and run `InitAction.run()`
- [x] 6.2 Print the welcome banner (app name, hint for `help` and `quit`) when vault is already configured

## 7. Rustyline integration

- [x] 7.1 Configure rustyline `Editor` with Emacs edit mode and the custom `Helper` from `completer.rs`
- [x] 7.2 Load history from `~/.passlane/.repl_history` on startup (ignore error if file doesn't exist)
- [x] 7.3 Save history to `~/.passlane/.repl_history` on quit/exit/EOF

## 8. Error handling

- [x] 8.1 Wrap all command dispatch calls in the REPL loop with error handling that prints the error to stderr and continues to the next prompt
- [x] 8.2 Handle Ctrl-C (rustyline `Interrupted`) by returning to the prompt without exiting

## 9. Help text

- [x] 9.1 Write general help text listing all commands with brief one-line descriptions
- [x] 9.2 Write detailed help text for each command: `show`, `add`, `edit`, `delete`, `gen`, `import`, `export`, `lock`, `unlock`, `status`

## 10. Testing

- [x] 10.1 Add unit tests for `parse_input()` covering: command+type+argument, command+type, command only, case insensitivity, unknown command, empty input, type alias resolution, ambiguous type-vs-argument cases
- [x] 10.2 Add unit tests for the completer: verify command completion on first token, type completion on second token, no completion on third token
- [x] 10.3 Verify the full build compiles with `cargo build`
- [x] 10.4 Verify existing tests still pass with `cargo test`
