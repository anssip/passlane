## ADDED Requirements

### Requirement: Completions CLI subcommand exists
The system SHALL provide a `completions` subcommand that generates shell completion scripts and writes them to stdout.

#### Scenario: Subcommand is available
- **WHEN** the user runs `passlane completions --help`
- **THEN** the system displays help text describing the completions subcommand, including supported shells (bash, zsh, fish)

### Requirement: Generate completion script for an explicit shell
The `completions` subcommand SHALL accept an optional positional argument specifying the target shell. Supported values SHALL be `bash`, `zsh`, and `fish` (case-insensitive).

#### Scenario: Generate bash completions
- **WHEN** the user runs `passlane completions bash`
- **THEN** the system writes a valid bash completion script to stdout

#### Scenario: Generate zsh completions
- **WHEN** the user runs `passlane completions zsh`
- **THEN** the system writes a valid zsh completion script to stdout

#### Scenario: Generate fish completions
- **WHEN** the user runs `passlane completions fish`
- **THEN** the system writes a valid fish completion script to stdout

#### Scenario: Unsupported shell name
- **WHEN** the user runs `passlane completions powershell`
- **THEN** the system prints an error listing the supported shells (bash, zsh, fish) and exits with a non-zero status code

### Requirement: Auto-detect shell when no argument is provided
When the `completions` subcommand is run without a shell argument, the system SHALL auto-detect the user's shell using the `$SHELL` environment variable (via `clap_complete::Shell::from_env()`).

#### Scenario: Auto-detect bash
- **WHEN** the user runs `passlane completions` and `$SHELL` is `/bin/bash`
- **THEN** the system writes a bash completion script to stdout

#### Scenario: Auto-detect zsh
- **WHEN** the user runs `passlane completions` and `$SHELL` is `/bin/zsh`
- **THEN** the system writes a zsh completion script to stdout

#### Scenario: Auto-detect fish
- **WHEN** the user runs `passlane completions` and `$SHELL` is `/usr/bin/fish`
- **THEN** the system writes a fish completion script to stdout

#### Scenario: Auto-detection fails
- **WHEN** the user runs `passlane completions` and `$SHELL` is unset or contains an unrecognized shell
- **THEN** the system prints an error message explaining that the shell could not be detected, lists the supported shells (bash, zsh, fish), and exits with a non-zero status code

### Requirement: Completion script covers all CLI subcommands and flags
The generated completion script SHALL include completions for all passlane CLI subcommands (`init`, `add`, `edit`, `show`, `list`, `delete`, `csv`, `export`, `gen`, `lock`, `unlock`, `repl`, `completions`) and their respective flags and arguments.

#### Scenario: Completing subcommand names
- **WHEN** the user types `passlane ` and triggers shell completion
- **THEN** the shell suggests all available subcommands

#### Scenario: Completing flags for a subcommand
- **WHEN** the user types `passlane show -` and triggers shell completion
- **THEN** the shell suggests flags for the `show` subcommand (e.g., `-p`, `-n`, `-o`, `-v`, `-c`, `--out`)

### Requirement: Save to file and print rc instruction
The `completions` subcommand SHALL save the completion script to `~/.passlane/completions.<shell>` (e.g., `completions.bash`, `completions.zsh`, `completions.fish`) and print a message showing the file path and the `source` command to add to the user's shell rc file.

#### Scenario: Save and instruct for zsh
- **WHEN** the user runs `passlane completions zsh`
- **THEN** the system saves the script to `~/.passlane/completions.zsh` and prints instructions to add `source "~/.passlane/completions.zsh"` to `~/.zshrc`

#### Scenario: Save and instruct for bash
- **WHEN** the user runs `passlane completions bash`
- **THEN** the system saves the script to `~/.passlane/completions.bash` and prints instructions to add `source "~/.passlane/completions.bash"` to `~/.bashrc`

#### Scenario: Regenerate overwrites existing file
- **WHEN** the user runs `passlane completions` and a completions file already exists
- **THEN** the system overwrites the existing file with the newly generated script

### Requirement: Dynamic completions from cache
The generated completion scripts SHALL include a custom completer function that reads entry names from `~/.passlane/.completion_cache` to provide dynamic completions for argument positions of commands that accept entry name patterns (`show`, `edit`, `delete`).

#### Scenario: Dynamic completion when vault is unlocked
- **WHEN** the vault has been unlocked (cache file exists), the user types `passlane show gi` and triggers shell completion
- **THEN** the shell suggests matching entries from the cache (e.g., "github")

#### Scenario: Dynamic completion when vault is locked
- **WHEN** the vault is locked (cache file does not exist), the user types `passlane show gi` and triggers shell completion
- **THEN** the shell provides no entry name suggestions (falls back to default file completion or no suggestions)

#### Scenario: Dynamic completion for edit command
- **WHEN** the cache file exists and the user types `passlane edit goo` and triggers shell completion
- **THEN** the shell suggests matching entries from the cache (e.g., "google")

#### Scenario: Dynamic completion for delete command
- **WHEN** the cache file exists and the user types `passlane delete git` and triggers shell completion
- **THEN** the shell suggests matching entries from the cache (e.g., "github", "gitlab")

### Requirement: No vault access required
The `completions` subcommand SHALL NOT require vault access or a master password. It SHALL work even before any vault is initialized.

#### Scenario: Run before init
- **WHEN** the user runs `passlane completions bash` before running `passlane init`
- **THEN** the system generates the completion script successfully without prompting for a password
