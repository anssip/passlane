## ADDED Requirements

### Requirement: Completions REPL command
The REPL SHALL support a `completions` command that prints instructions for generating and installing shell completion scripts for the CLI mode.

#### Scenario: Run completions in REPL
- **WHEN** the user enters `completions` at the REPL prompt
- **THEN** the system prints instructions explaining how to generate and install shell completions using the `passlane completions` CLI subcommand, with examples for bash, zsh, and fish

#### Scenario: Tab-complete the completions command
- **WHEN** the user types `comp` and presses Tab at the REPL prompt
- **THEN** the input is completed to `completions`

### Requirement: Help includes completions command
The REPL `help` command SHALL include the `completions` command in its output.

#### Scenario: General help lists completions
- **WHEN** the user enters `help` at the REPL prompt
- **THEN** the output includes `completions` with a brief description

#### Scenario: Help for completions command
- **WHEN** the user enters `help completions` at the REPL prompt
- **THEN** the system displays detailed help for the `completions` command

### Requirement: REPL dynamic entry name completion
The REPL's rustyline tab completer SHALL suggest service names and usernames on the 3rd token position for commands that accept entry name arguments (`show`, `edit`, `delete`). The suggestions SHALL come from the in-memory vault data.

#### Scenario: Complete service name on 3rd token
- **WHEN** the user types `show creds gi` and presses Tab at the REPL prompt
- **THEN** the input is completed to `show creds github` (if "github" is a known service name)

#### Scenario: Complete service name when type is omitted
- **WHEN** the user types `show gi` and presses Tab at the REPL prompt
- **THEN** the input is completed to `show github` (if "github" is a known service name, treated as 2nd token default-credential argument)

#### Scenario: Multiple matching entries
- **WHEN** the user types `show creds g` and presses Tab and both "github" and "google" exist
- **THEN** the system shows both options for the user to choose from

#### Scenario: Entry names refreshed after modification
- **WHEN** the user adds a new credential for "gitlab" and then types `show git` and presses Tab
- **THEN** "gitlab" appears as a completion candidate alongside "github"

#### Scenario: No entry name completion for non-search commands
- **WHEN** the user types `add cred gi` and presses Tab
- **THEN** no entry name suggestions are shown (add does not search existing entries)
