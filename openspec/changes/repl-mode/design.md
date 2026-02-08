## Context

Passlane is a CLI password manager that dispatches commands via clap subcommands to `Action` and `UnlockingAction` implementations. Each `UnlockingAction` opens the vault (checking the OS keychain for a stored master password, prompting if not found), performs its operation, and exits. The app already depends on `rustyline` (v14, used for multiline input in `ui/input.rs`) and `comfy-table` (v7, used for all table rendering in `ui/output.rs`).

The REPL adds a new entry point that loops over user input, parsing short commands and dispatching to the same action implementations. Vault access works identically to CLI mode — each command that needs the vault goes through the existing `unlock()`/`unlock_totp_vault()` flow.

## Goals / Non-Goals

**Goals:**
- Provide an interactive session where users can issue multiple commands without restarting the process
- Make all existing functionality accessible via short, memorable commands with natural syntax (e.g., `show cards` instead of `passlane show -p`)
- Offer tab completion for commands and subcommands, and persistent command history
- Guide new users: auto-run `init` if no vault exists, show a welcome banner with command reference
- Reuse existing action logic — the REPL is a new front-end, not a rewrite of business logic

**Non-Goals:**
- Caching or holding the vault open in memory across commands (vault access stays keychain-based, same as CLI)
- A TUI with panels, scrolling, or cursor-based navigation — this is a line-oriented REPL
- Replacing the CLI interface — all existing `passlane <subcommand>` invocations continue to work unchanged
- Custom keybindings beyond what rustyline provides out of the box

## Decisions

### 1. REPL as a new module `src/repl/`, not an action

The REPL is a session loop, not a single-shot action. It doesn't fit the `Action` or `UnlockingAction` trait (which return a result and exit). Instead, it lives in a new `src/repl/` module with its own entry point called from `main.rs`.

**Structure:**
```
src/repl/
├── mod.rs          # Public entry: start_repl()
├── commands.rs     # Command enum, parsing, dispatch
├── completer.rs    # Rustyline Completer + Hinter + Helper
└── help.rs         # Help text for all commands
```

**Alternative considered:** Implementing the REPL as an `Action`. Rejected because actions are designed to run once and return — the REPL needs to loop indefinitely and manage its own prompt.

### 2. Command parsing: simple split, not clap

REPL commands are parsed by splitting input on whitespace and matching the first token. This keeps commands feeling lightweight and interactive, without clap's error formatting (which is designed for CLI `--help` output, not interactive sessions).

**Command grammar:**
```
<command> [<type>] [<argument>]

Commands:
  show [creds|cards|notes|otp] [REGEXP]   Show entries (creds is default)
  add [cred|card|note|otp]                Add an entry (cred is default)
  edit [cred|card|note|otp] [REGEXP]      Edit an entry
  delete [cred|card|note|otp] [REGEXP]    Delete an entry
  gen                                      Generate a password
  import <file>                            Import credentials from CSV
  export [creds|cards|notes|otp] <file>   Export to CSV
  unlock [otp]                             Store master password in keychain
  lock                                     Remove master passwords from keychain
  status                                   Show vault status
  help [command]                           Show help
  quit / exit                              Exit the REPL
```

Type aliases: `creds`/`cred`/`credentials` → Credential, `cards`/`card`/`payments` → Payment, `notes`/`note` → Note, `otp`/`totp` → Totp.

When the type is omitted, commands default to credentials (matching CLI behavior). `show` with no arguments lists all credentials (equivalent to `show creds .*`).

**Alternative considered:** Reusing clap for REPL command parsing. Rejected because clap's `process::exit` on parse errors would kill the REPL session, and the `--flag` style feels wrong in an interactive context.

### 3. Dispatch to existing actions by constructing them directly

The REPL constructs `Action`/`UnlockingAction` structs directly with the parsed parameters, rather than going through clap's `ArgMatches`. Most action structs already have simple fields (`grep`, `item_type`, `verbose`, etc.) that can be set directly.

For example, to handle `show cards`:
```rust
let action = ShowAction {
    grep: None,
    verbose: false,
    item_type: ItemType::Payment,
    is_totp: false,
};
action.execute()?;
```

This requires making action struct fields `pub` where they aren't already (most already are). No changes to action logic itself.

**Alternative considered:** Building synthetic `ArgMatches` and passing them to `Action::new()`. Rejected as fragile and unnecessarily complex — constructing the struct directly is cleaner.

### 4. Rustyline setup: custom Helper with command completion

The REPL uses a custom rustyline `Helper` that implements `Completer`, `Hinter`, `Highlighter`, and `Validator`. The completer provides:

- **First token**: completes command names (`show`, `add`, `edit`, `delete`, `gen`, `import`, `export`, `unlock`, `lock`, `status`, `help`, `quit`, `exit`)
- **Second token**: completes type names when applicable (`creds`, `cards`, `notes`, `otp`)

No completion for regex arguments or file paths (too complex for limited benefit).

History is stored at `~/.passlane/.repl_history` and loaded/saved automatically by rustyline.

### 5. Welcome banner and first-run detection

On REPL startup:
1. Check if a vault is configured (`store::has_vault_path()`)
2. If not → print welcome message and run `InitAction` automatically
3. If yes → print a short banner with version and quick-reference command list

The banner is compact — just enough to orient the user:
```
🔐 Passlane — interactive mode
Type 'help' for commands, 'quit' to exit.
```

### 6. Error handling: print and continue

In CLI mode, errors cause a non-zero exit. In the REPL, errors are printed to stderr and the prompt returns. The REPL never exits on an action error — only `quit`/`exit`/Ctrl-D terminate the session.

### 7. The `status` command

A REPL-only command that shows:
- Whether the main vault is accessible (tries `keychain::get_master_password()` to check)
- Whether the TOTP vault is accessible
- Vault file paths

This is lightweight — it checks keychain availability, not vault contents (which would require unlocking).

### 8. Default no-args behavior change

`main.rs` changes so that running `passlane` with no arguments launches the REPL instead of generating a password. Password generation is available as `passlane gen` (new clap subcommand) and `gen` inside the REPL.

The `gen` subcommand is added to the clap CLI definition so it works both inside and outside the REPL.

## Risks / Trade-offs

- **[Breaking change: no-args behavior]** → Users who run bare `passlane` in scripts expecting a generated password will break. Mitigation: document in changelog, the new command is just `passlane gen`.
- **[Rustyline conflict with inquire]** → Some actions use `inquire` for interactive prompts (Select, Confirm, Password). Rustyline and inquire both manipulate the terminal. In practice this works because rustyline yields control during action execution (it's not reading while inquire is). No conflict expected, but if issues arise, the REPL could temporarily drop the rustyline editor during action execution.
- **[Vault re-open per command]** → Each command that touches the vault opens and parses the KDBX file. For large vaults this adds latency. This matches CLI behavior and is acceptable for now. A future optimization could cache the vault in the REPL session, but that's a non-goal for this change.
- **[TOTP continuous display]** → The `show otp` flow spawns threads for continuous code refresh with keyboard input monitoring. This works in the REPL because rustyline isn't active during action execution. The TOTP action's blocking loop runs until the user presses 'q', then control returns to the REPL prompt.
