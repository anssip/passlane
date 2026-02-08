## 1. Dependencies and Project Setup

- [x] 1.1 Add `clap_complete` crate to `Cargo.toml` dependencies

## 2. Completion Cache Module

- [x] 2.1 Create `src/completion_cache.rs` module with cache file path constant (`~/.passlane/.completion_cache`)
- [x] 2.2 Implement `update_cache(vault: &Box<dyn Vault>)` — reads all credentials from vault, extracts deduplicated service names and usernames, writes one per line to cache file
- [x] 2.3 Implement `clear_cache()` — deletes the cache file, no error if missing
- [x] 2.4 Implement `read_cache() -> Vec<String>` — reads cache file lines, returns empty vec if file missing
- [x] 2.5 Implement `refresh_if_stale()` — checks cache file age, if >7 days old and master password is in keychain, opens vault and calls `update_cache`
- [x] 2.6 Register the module in `main.rs` (`mod completion_cache;`)

## 3. Completions CLI Subcommand

- [x] 3.1 Add `completions` subcommand to `cli()` in `main.rs` with optional `<SHELL>` positional argument (bash, zsh, fish)
- [x] 3.2 Create `src/actions/completions.rs` with `CompletionsAction` struct implementing `Action` trait
- [x] 3.3 Implement shell resolution: use explicit argument if provided, otherwise `Shell::from_env()`, error with supported shell list if neither works
- [x] 3.4 Implement `run()`: call `clap_complete::generate()` with the resolved shell and the `Command` from `cli()`, writing to stdout
- [x] 3.5 Register module in `src/actions/mod.rs` (`pub mod completions;`)
- [x] 3.6 Wire up the `completions` subcommand match arm in `main.rs` to `CompletionsAction`

## 4. Dynamic Completions in Generated Scripts

- [x] 4.1 Extend the generated bash completion script with a custom completer function that reads `~/.passlane/.completion_cache` for argument positions of `show`, `edit`, `delete` subcommands
- [x] 4.2 Extend the generated zsh completion script with a custom completer function that reads the cache file for `show`, `edit`, `delete` argument positions
- [x] 4.3 Extend the generated fish completion script with a custom completer function that reads the cache file for `show`, `edit`, `delete` argument positions
- [x] 4.4 Ensure dynamic completions gracefully fall back to no suggestions when cache file is missing

## 5. Cache Lifecycle Integration

- [x] 5.1 Update `UnlockAction` to call `update_cache()` after successful main vault unlock
- [x] 5.2 Update `LockAction` to call `clear_cache()` when locking
- [x] 5.3 Update `AddAction` to call `update_cache()` after successful add (for credential entries)
- [x] 5.4 Update `EditAction` to call `update_cache()` after successful edit
- [x] 5.5 Update `DeleteAction` to call `update_cache()` after successful delete
- [x] 5.6 Update `ImportCsvAction` to call `update_cache()` after successful import
- [x] 5.7 Add `refresh_if_stale()` call at CLI startup in `main.rs` (before dispatching any command)

## 6. REPL Completions Command

- [x] 6.1 Add `Completions` variant to `ReplCommand` enum in `src/repl/commands.rs`
- [x] 6.2 Add `"completions"` to `parse_input()` matching and to `COMMAND_NAMES` for tab completion
- [x] 6.3 Implement `Completions` dispatch in `src/repl/mod.rs` — print installation instructions with examples for bash, zsh, and fish
- [x] 6.4 Add `completions` entry to `src/repl/help.rs` — brief description in general help, detailed help for `help completions`

## 7. REPL Dynamic Entry Name Completion

- [x] 7.1 Add shared entry name list (`Arc<Mutex<Vec<String>>>`) to REPL state, populated on REPL start after vault unlock
- [x] 7.2 Update `ReplHelper` completer to accept and use the shared entry name list
- [x] 7.3 Implement 3rd-token completion: for `show`, `edit`, `delete` commands, suggest matching entry names from the shared list
- [x] 7.4 Implement 2nd-token completion for entry names: when 1st token is `show`/`edit`/`delete` and 2nd token doesn't match a type name, suggest entry names alongside type names
- [x] 7.5 Refresh the shared entry name list after vault-modifying REPL commands (`add`, `edit`, `delete`, `import`)

## 8. Testing

- [x] 8.1 Add unit tests for `completion_cache` module: `update_cache`, `clear_cache`, `read_cache`, `refresh_if_stale`
- [x] 8.2 Add unit tests for `CompletionsAction`: explicit shell, auto-detect, unsupported shell error
- [x] 8.3 Add unit tests for REPL command parsing of `completions` command
- [x] 8.4 Add unit tests for REPL completer entry name suggestions (3rd token, 2nd token fallback, non-search commands excluded)
- [x] 8.5 Verify generated completion scripts contain dynamic completer functions (bash, zsh, fish)
