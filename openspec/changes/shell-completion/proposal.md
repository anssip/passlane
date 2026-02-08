## Why

Passlane has a rich CLI with many subcommands and flags, but users must memorize them or check `--help` each time. Shell completion scripts let the shell auto-complete commands, flags, and subcommands on Tab press, which is standard practice for modern CLI tools. Clap already supports generating these scripts, so the implementation cost is low for a big usability win. Both the CLI mode (subcommands) and the REPL mode (built-in tab completion via rustyline) should be covered.

## What Changes

- Add a new `completions` subcommand to the CLI that outputs shell completion scripts for bash, zsh, and fish to stdout.
- The shell argument is optional — when omitted, auto-detect the user's shell via `clap_complete::aot::Shell::from_env()` (reads `$SHELL`). When provided explicitly (e.g., `passlane completions bash`), use the specified shell. If auto-detection fails and no shell is specified, print a helpful error listing the supported shells (bash, zsh, fish).
- The command saves the completion script to `~/.passlane/completions.<shell>` and prints the `source` command to add to the user's shell rc file. Re-running regenerates the file.
- The CLI completion scripts cover all subcommands (`show`, `add`, `edit`, `delete`, `gen`, `list`, `export`, `csv`, `lock`, `unlock`, `repl`, `completions`) and their respective flags.
- **Dynamic completions via cache**: When the vault is unlocked, a lightweight completion cache file (`~/.passlane/.completion_cache`) is written containing service names and usernames. CLI shell completions read from this cache to provide dynamic entry name completions for commands like `show`, `edit`, and `delete`. The cache is created/updated on `unlock` and any vault-modifying action (`add`, `edit`, `delete`, `import`), and deleted on `lock`. When the cache file doesn't exist (vault locked), completions fall back to static subcommand/flag completion only.
- **REPL dynamic completions**: The REPL's rustyline completer is extended to complete service names and usernames on the 3rd token, using the already in-memory vault data.
- Add a `completions` command to the REPL that outputs usage instructions for generating and installing shell completion scripts.

## Capabilities

### New Capabilities
- `shell-completion`: Generating and outputting shell completion scripts for bash, zsh, and fish via a CLI subcommand, with dynamic entry name completions via a cache file, and providing completion installation instructions from the REPL.
- `completion-cache`: Managing a lightweight cache file of service names and usernames that enables fast dynamic shell completions without opening the vault on each Tab press.

### Modified Capabilities
- `repl-session`: Add the `completions` command to the REPL command set and extend the rustyline tab completer to suggest service names/usernames on the 3rd token from in-memory vault data.

## Impact

- **Code**: New `completions` action in `src/actions/`, new subcommand in `src/main.rs`, new REPL command handler in `src/repl/`, new completion cache module, modifications to `unlock`/`lock`/`add`/`edit`/`delete`/`import` actions to update the cache.
- **Dependencies**: Add `clap_complete` crate (the official clap companion for shell completion generation). The CLI definition in `main.rs` may need to switch from the builder API to derive macros, or the builder-based `Command` can be passed directly to `clap_complete::generate()`.
- **APIs**: New `passlane completions <shell>` subcommand. No breaking changes to existing commands.
- **Systems**: New cache file at `~/.passlane/.completion_cache`. Contains only service names and usernames (no passwords). Created on unlock, deleted on lock.
