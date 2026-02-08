## Why

Passlane currently requires users to invoke separate CLI commands for every operation, which means remembering subcommand syntax and flags. This makes interactive workflows (browsing entries, copying a password, then editing a note) cumbersome. A REPL (Read-Eval-Print Loop) mode gives users a persistent, interactive session where commands are short and discoverable, and new users can explore functionality without reading `--help` pages. Vault access works the same as in CLI mode — if the vault is unlocked (master password stored in the OS keychain), commands work seamlessly; if locked, the user is prompted for the master password as usual.

## What Changes

- **New `repl` subcommand**: Launches an interactive shell session. Becomes the default when `passlane` is run with no arguments (replacing the current "generate a password" default).
- **Standard vault access**: Vault unlocking works identically to CLI mode — if the vault has been unlocked (master password stored in the OS keychain via `unlock`), commands access it seamlessly. If locked, the user is prompted for the master password. The `unlock` and `lock` commands are available within the REPL to manage keychain storage.
- **Short interactive commands**: All existing functionality is exposed as short REPL commands (`show`, `add`, `edit`, `delete`, `otp`, `gen`, `export`, `import`, `lock`, `unlock`, `help`, `quit`). Item type is selected via subcommand rather than flags (e.g., `show cards` instead of `show -p`).
- **Tab completion and history**: Leverages the existing `rustyline` dependency for command/argument completion, persistent history across sessions (`~/.passlane/.repl_history`), and line-editing.
- **Rich table output**: Uses existing `comfy-table` rendering for all list/show output within the REPL.
- **Welcome banner and guided start**: On first launch (no vault exists), the REPL runs the init flow automatically. On subsequent launches, it shows a welcome banner with a quick-reference command list.
- **`help` command**: Inline help for every command, with a top-level overview and per-command detail (`help show`, `help add`, etc.).
- **Session status line**: Shows vault status and entry counts on startup and via a `status` command.
- **BREAKING**: Running `passlane` with no arguments currently generates a random password. This will change to launching the REPL. Password generation moves to `passlane gen` (also available as `gen` inside the REPL). Users who rely on `passlane` (no args) in scripts for password generation will need to use `passlane gen` instead.

## Capabilities

### New Capabilities
- `repl-session`: The interactive REPL loop — command parsing, dispatch, session lifecycle (startup, vault unlock, prompt loop, quit), persistent history, tab completion, and welcome/help output.

### Modified Capabilities
_(No existing spec-level requirements change. The REPL reuses existing vault traits and action logic; it adds a new entry point, not new vault behavior.)_

## Impact

- **`src/main.rs`**: Default (no-args) behavior changes from `GeneratePasswordAction` to launching the REPL. New `repl` subcommand added to clap definition.
- **New module `src/repl/`**: Contains REPL loop, command parser, completer, session state, and help text.
- **Existing actions**: No changes to action logic itself — the REPL dispatches to the same `Action`/`UnlockingAction` implementations. Vault unlocking follows the same keychain-based flow as CLI mode.
- **Dependencies**: No new crates — `rustyline` (already v14.0.0) and `comfy-table` (already v7.0.1) cover all needs.
- **Scripting compatibility**: Users piping `passlane` output in scripts must switch from bare `passlane` to `passlane gen` for password generation. All other subcommands remain unchanged.
