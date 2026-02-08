## Context

Passlane is a CLI password manager built with clap (builder API) for argument parsing. It has two interaction modes: a traditional CLI with subcommands (`passlane show`, `passlane add`, etc.) and an interactive REPL with its own command parser and rustyline-based tab completion.

Currently, users must remember subcommands and flags or rely on `--help`. The REPL already has tab completion for its own commands via rustyline, but the CLI mode has no shell-level completion support.

The `clap_complete` crate is the official companion to clap for generating shell completion scripts and works directly with clap's builder API `Command` — no migration to derive macros is needed.

## Goals / Non-Goals

**Goals:**
- Provide a `completions` subcommand that generates shell completion scripts for bash, zsh, and fish
- Auto-detect the user's shell when no shell argument is provided
- Make completions easy to install with a single eval or redirect command
- Add a `completions` REPL command that prints installation instructions
- Cover all existing CLI subcommands and their flags in the generated completions
- Provide dynamic completions for vault entry names (service names, usernames) via a lightweight cache file
- Extend REPL tab completion to suggest entry names from in-memory vault data

**Non-Goals:**
- PowerShell or elvish support — can be added later since `clap_complete` supports them, but we'll start with the three most common Unix shells
- Changing the existing clap builder API to derive macros
- Caching passwords or sensitive data in the completion cache — only service names and usernames

## Decisions

### 1. Use `clap_complete` for script generation

**Decision:** Use the `clap_complete` crate with `generate()` to produce completion scripts from the existing `Command` definition.

**Rationale:** `clap_complete` is the official clap companion, maintained by the same team. It takes a `&mut Command` and writes the completion script to any `impl Write`. Since passlane already uses clap's builder API, no migration is needed — `clap_complete::generate()` accepts builder-style `Command` directly.

**Alternatives considered:**
- Hand-written completion scripts: Fragile, must be updated manually whenever commands change.
- `clap` derive macros: Would require rewriting `main.rs` CLI definition. Unnecessary since `clap_complete` works with the builder API.

### 2. Auto-detect shell via `Shell::from_env()`

**Decision:** When the user runs `passlane completions` without specifying a shell, use `clap_complete::Shell::from_env()` which reads the `$SHELL` environment variable. If detection fails and no shell is given, print an error listing supported shells.

**Rationale:** Reduces friction — most users just want completions for their current shell. `Shell::from_env()` is built into `clap_complete` so there's no custom detection logic needed.

**Alternatives considered:**
- Always require explicit shell argument: Adds friction for the common case.
- Parent process inspection: More accurate (detects current shell vs. login shell) but platform-specific and complex. `$SHELL` is good enough for the overwhelmingly common case where login shell = current shell.

### 3. Implement as a simple `Action` (no vault access)

**Decision:** The `completions` command will implement the `Action` trait, not `UnlockingAction`. It needs no vault access — just the clap `Command` definition.

**Rationale:** Generating completions is a pure CLI concern. It should work even before any vault is initialized.

**Implementation:** Create `src/actions/completions.rs` with a `CompletionsAction` struct that holds the shell choice (explicit or auto-detected) and the `Command` definition. The `run()` method calls `clap_complete::generate()` writing to stdout.

### 4. Extract `cli()` function for reuse

**Decision:** The `cli()` function in `main.rs` already returns a `Command` and is a standalone function. `CompletionsAction` will accept a `clap::Command` parameter so it can call `generate()` on it. The `completions` subcommand itself will be added to the `Command` returned by `cli()`.

**Rationale:** The completion generator needs the full `Command` tree to enumerate all subcommands and flags. Passing it in avoids circular dependencies.

### 5. Completion cache file for dynamic CLI completions

**Decision:** Maintain a lightweight cache file at `~/.passlane/.completion_cache` containing service names and usernames. The cache is a simple newline-delimited text file. CLI shell completion scripts read from this file to provide dynamic entry name suggestions.

**Cache lifecycle:**
- **Created/updated** when: `unlock` succeeds, or any vault-modifying action completes (`add`, `edit`, `delete`, `import`)
- **Auto-refreshed** when: the cache file exists but is older than 7 days and the vault is unlocked (password in keychain). Any CLI command that runs through the normal action flow checks the cache age on startup. If stale, it silently refreshes in the background before proceeding. This handles the case where a user unlocks once and doesn't lock for weeks — the cache stays fresh without manual intervention.
- **Deleted** when: `lock` is run
- **Not present** when: vault has never been unlocked, or has been locked

**Cache format:** One entry per line, plain text. Service names and usernames, deduplicated. No passwords or sensitive data.

**Rationale:** Each shell Tab press spawns a new process. Opening the vault (with argon2 key derivation) on every Tab press would add ~100-500ms latency, which is unacceptable. A cache file can be read in sub-millisecond time. The cache only contains identifiers (service names, usernames) — no secrets — so the security risk is minimal and comparable to shell history.

**Alternatives considered:**
- Opening the vault on every Tab press: Too slow due to argon2.
- In-memory daemon/socket: Over-engineered for this use case.
- No dynamic completions: Functional but misses a significant UX opportunity.

**Implementation:** Create a `completion_cache` module in `src/` with functions: `update_cache(vault)` (reads all entries, writes cache), `clear_cache()` (deletes the file), `read_cache() -> Vec<String>` (reads entries for completion), `refresh_if_stale()` (checks file age, refreshes if >7 days old and vault is unlocked via keychain). The generated shell scripts will include a custom completer function that reads from this file for argument positions.

### 6. REPL dynamic completions from in-memory vault data

**Decision:** Extend the rustyline completer to suggest service names and usernames on the 3rd token position for commands that accept entry name arguments (`show`, `edit`, `delete`). The completer reads from in-memory vault data.

**Rationale:** The REPL already has the vault open in memory. Adding entry name completion on the 3rd token is a natural extension of the existing completer (which already handles command names on 1st token and item types on 2nd token). No cache file needed — just query the live vault.

**Implementation:** The `ReplHelper` completer will need access to a shared list of entry names. On REPL start (after vault unlock) and after any modifying command, refresh the entry name list. Use `Arc<Mutex<Vec<String>>>` or similar to share between the completer and the command dispatcher.

### 7. REPL `completions` command prints instructions only

**Decision:** The REPL `completions` command will print shell-specific installation instructions (how to run `passlane completions` from outside the REPL and where to put the output). It will NOT generate the scripts itself.

**Rationale:** Shell completions must be loaded by the shell, not by passlane's REPL. The REPL can only helpfully tell the user what to run. The REPL already has its own rustyline-based tab completion for REPL commands.

### 8. Save to file and print rc instruction

**Decision:** The `completions` subcommand saves the completion script to `~/.passlane/completions.<shell>` (e.g., `completions.zsh`) and prints the `source` command that the user should add to their shell rc file.

**Rationale:** This is simpler than stdout piping — users run `passlane completions` once, copy the printed line to their rc file, done. The file lives alongside other passlane config in `~/.passlane/`, keeping things tidy. Re-running the command regenerates the file (e.g., after a passlane update adds new subcommands).

**Alternatives considered:**
- Output to stdout (pipe/eval): More composable but requires users to understand shell redirection. The file-based approach is friendlier for the common case.

## Risks / Trade-offs

- **`$SHELL` vs. actual shell**: `Shell::from_env()` reads the login shell, which might differ from the running shell. Users in this situation can use the explicit argument. This is a known limitation shared by most CLI tools. → Mitigation: Document the explicit override clearly in help text and REPL instructions.
- **Completion freshness**: If passlane is updated with new subcommands, users need to regenerate completions. → Mitigation: This is standard for all CLI tools. Mention it in the REPL instructions.
- **clap_complete dependency**: Adds a new crate dependency. → Mitigation: It's lightweight, officially maintained by the clap team, and commonly used.
- **Cache staleness**: The completion cache could become stale if the vault is modified by another tool (e.g., directly editing the .kdbx file with KeePass), or if the user stays unlocked for a long time without modifying entries via passlane. → Mitigation: The cache is refreshed on every `unlock` and vault-modifying action. Additionally, the cache auto-refreshes when older than 7 days (if the vault is unlocked via keychain). Users can also re-run `unlock` to force a manual refresh.
- **Cache file contains entry names on disk**: Service names and usernames are written to `~/.passlane/.completion_cache` in plaintext. → Mitigation: This is non-secret metadata comparable to what ends up in shell history. The file is deleted on `lock`. The cache contains no passwords, TOTP secrets, or payment card numbers.
- **REPL completer shared state**: The rustyline completer needs access to vault entry names, which introduces shared mutable state between the completer and command dispatcher. → Mitigation: Use `Arc<Mutex<Vec<String>>>` for thread-safe sharing. The entry list is small and updates are infrequent.
