## ADDED Requirements

### Requirement: REPL entry point
The system SHALL provide a `repl` subcommand that launches an interactive session. Running `passlane` with no arguments SHALL launch the REPL. Running `passlane repl` SHALL also launch the REPL.

#### Scenario: Launch REPL with no arguments
- **WHEN** the user runs `passlane` with no arguments
- **THEN** the system launches the interactive REPL session

#### Scenario: Launch REPL explicitly
- **WHEN** the user runs `passlane repl`
- **THEN** the system launches the interactive REPL session

### Requirement: Password generation subcommand
The system SHALL provide a `gen` subcommand that generates a random password and copies it to the clipboard, preserving the functionality previously available by running `passlane` with no arguments.

#### Scenario: Generate password via CLI
- **WHEN** the user runs `passlane gen`
- **THEN** the system generates a random password, copies it to the clipboard, and prints it to stdout

### Requirement: First-run guided setup
When the REPL starts and no vault is configured, the system SHALL automatically run the init flow to guide the user through first-time setup.

#### Scenario: No vault configured
- **WHEN** the REPL starts and no vault path is configured
- **THEN** the system prints a welcome message and runs the `init` flow automatically

#### Scenario: Vault already configured
- **WHEN** the REPL starts and a vault path is already configured
- **THEN** the system prints the welcome banner and shows the REPL prompt without running init

### Requirement: Welcome banner
When the REPL starts with a configured vault, the system SHALL display a compact welcome banner that includes a hint about the `help` and `quit` commands.

#### Scenario: Banner on startup
- **WHEN** the REPL starts with a configured vault
- **THEN** the system displays a banner line and a hint to type `help` for commands

### Requirement: REPL prompt loop
The system SHALL display a prompt, read user input, execute the corresponding command, display the result, and return to the prompt. This loop SHALL continue until the user types `quit`, `exit`, or sends EOF (Ctrl-D).

#### Scenario: Execute a command and return to prompt
- **WHEN** the user enters a valid command at the REPL prompt
- **THEN** the system executes the command, displays the result, and shows the prompt again

#### Scenario: Quit the REPL
- **WHEN** the user types `quit` or `exit`
- **THEN** the REPL session ends and the process exits

#### Scenario: EOF terminates the REPL
- **WHEN** the user sends EOF (Ctrl-D) at the prompt
- **THEN** the REPL session ends and the process exits

#### Scenario: Empty input
- **WHEN** the user presses Enter without typing anything
- **THEN** the system shows the prompt again without executing anything

### Requirement: Command parsing
The system SHALL parse REPL input by splitting on whitespace. The first token is the command, the optional second token is the item type, and remaining tokens are arguments. Commands SHALL be case-insensitive.

#### Scenario: Command with type and argument
- **WHEN** the user enters `show creds github`
- **THEN** the system parses command=`show`, type=`Credential`, argument=`github`

#### Scenario: Command with type only
- **WHEN** the user enters `add card`
- **THEN** the system parses command=`add`, type=`Payment`, argument=none

#### Scenario: Command only
- **WHEN** the user enters `gen`
- **THEN** the system parses command=`gen`, type=none, argument=none

#### Scenario: Case insensitivity
- **WHEN** the user enters `SHOW Cards`
- **THEN** the system parses it the same as `show cards`

#### Scenario: Unknown command
- **WHEN** the user enters an unrecognized command
- **THEN** the system prints an error message suggesting `help` and returns to the prompt

### Requirement: Item type aliases
The system SHALL accept multiple aliases for each item type. `creds`, `cred`, and `credentials` SHALL map to Credential. `cards`, `card`, and `payments` SHALL map to Payment. `notes` and `note` SHALL map to Note. `otp` and `totp` SHALL map to Totp.

#### Scenario: Type alias resolution
- **WHEN** the user enters `show payments`
- **THEN** the system treats the type as Payment, equivalent to `show cards`

#### Scenario: Default type
- **WHEN** the user enters a command that accepts a type but no type is provided (e.g., `show github`)
- **THEN** the system defaults to Credential type and treats the token as the search argument

### Requirement: Show command
The `show` command SHALL display entries from the vault. It SHALL accept an optional type (`creds`, `cards`, `notes`, `otp`) and an optional regex pattern. When no type is given, it defaults to credentials. When no pattern is given for credentials, it SHALL show all credentials.

#### Scenario: Show all credentials
- **WHEN** the user enters `show`
- **THEN** the system displays all credentials in a table

#### Scenario: Show credentials matching pattern
- **WHEN** the user enters `show github`
- **THEN** the system displays credentials whose service matches `github`

#### Scenario: Show payment cards
- **WHEN** the user enters `show cards`
- **THEN** the system displays all payment cards

#### Scenario: Show notes
- **WHEN** the user enters `show notes`
- **THEN** the system displays all secure notes

#### Scenario: Show OTP entries
- **WHEN** the user enters `show otp`
- **THEN** the system displays all TOTP entries

#### Scenario: Show OTP entries matching pattern
- **WHEN** the user enters `show otp github`
- **THEN** the system displays TOTP entries matching `github`

### Requirement: Add command
The `add` command SHALL add a new entry to the vault. It SHALL accept an optional type (`cred`, `card`, `note`, `otp`), defaulting to credential. The system SHALL prompt the user interactively for the entry details using the existing input prompts.

#### Scenario: Add credential
- **WHEN** the user enters `add`
- **THEN** the system prompts for credential details and saves the new credential

#### Scenario: Add payment card
- **WHEN** the user enters `add card`
- **THEN** the system prompts for payment card details and saves the new card

#### Scenario: Add note
- **WHEN** the user enters `add note`
- **THEN** the system prompts for note details and saves the new note

#### Scenario: Add OTP
- **WHEN** the user enters `add otp`
- **THEN** the system prompts for TOTP details and saves the new entry

### Requirement: Edit command
The `edit` command SHALL edit an existing entry. It SHALL accept a type and an optional regex pattern. For credentials, a regex pattern is required. The system SHALL use the existing edit prompts.

#### Scenario: Edit credential
- **WHEN** the user enters `edit github`
- **THEN** the system searches for credentials matching `github` and enters the edit flow

#### Scenario: Edit payment card
- **WHEN** the user enters `edit card`
- **THEN** the system lists payment cards and enters the edit flow

#### Scenario: Edit note
- **WHEN** the user enters `edit note`
- **THEN** the system lists notes and enters the edit flow

#### Scenario: Edit OTP
- **WHEN** the user enters `edit otp`
- **THEN** the system lists TOTP entries and enters the edit flow

### Requirement: Delete command
The `delete` command SHALL delete an existing entry. It SHALL accept a type and an optional regex pattern. For credentials, a regex pattern is required. The system SHALL use the existing delete flow with confirmation.

#### Scenario: Delete credential
- **WHEN** the user enters `delete github`
- **THEN** the system searches for credentials matching `github` and enters the delete flow

#### Scenario: Delete payment card
- **WHEN** the user enters `delete card`
- **THEN** the system lists payment cards and enters the delete flow

### Requirement: Gen command
The `gen` command SHALL generate a random password, copy it to the clipboard, and print it. This is available both as a REPL command and as the `passlane gen` CLI subcommand.

#### Scenario: Generate password in REPL
- **WHEN** the user enters `gen` at the REPL prompt
- **THEN** the system generates a password, copies it to the clipboard, and prints it

### Requirement: Import command
The `import` command SHALL import credentials from a CSV file. It SHALL require a file path argument.

#### Scenario: Import from CSV
- **WHEN** the user enters `import /path/to/file.csv`
- **THEN** the system imports credentials from the specified CSV file

#### Scenario: Import without file path
- **WHEN** the user enters `import` without a file path
- **THEN** the system prints an error message indicating a file path is required

### Requirement: Export command
The `export` command SHALL export vault entries to a CSV file. It SHALL accept an optional type and require a file path.

#### Scenario: Export credentials
- **WHEN** the user enters `export credentials.csv`
- **THEN** the system exports all credentials to the specified file

#### Scenario: Export payment cards
- **WHEN** the user enters `export cards cards.csv`
- **THEN** the system exports payment cards to the specified file

### Requirement: Lock command
The `lock` command SHALL remove stored master passwords from the OS keychain for both vaults.

#### Scenario: Lock vaults
- **WHEN** the user enters `lock`
- **THEN** the system removes stored master passwords from the keychain and confirms

### Requirement: Unlock command
The `unlock` command SHALL store the master password in the OS keychain. It SHALL accept an optional `otp` argument to unlock the TOTP vault specifically.

#### Scenario: Unlock main vault
- **WHEN** the user enters `unlock`
- **THEN** the system prompts for the master password (if needed), verifies it by opening the vault, and stores it in the keychain

#### Scenario: Unlock TOTP vault
- **WHEN** the user enters `unlock otp`
- **THEN** the system prompts for the TOTP vault master password (if needed), verifies it, and stores it in the keychain

### Requirement: Status command
The `status` command SHALL display vault accessibility information: whether the main vault and TOTP vault have master passwords stored in the keychain, and the configured vault file paths.

#### Scenario: Show status
- **WHEN** the user enters `status`
- **THEN** the system displays whether each vault is unlocked (password in keychain) or locked, and the vault file paths

### Requirement: Help command
The `help` command SHALL display command reference information. Without arguments, it SHALL show a summary of all commands. With a command name argument, it SHALL show detailed help for that command.

#### Scenario: General help
- **WHEN** the user enters `help`
- **THEN** the system displays a list of all available commands with brief descriptions

#### Scenario: Command-specific help
- **WHEN** the user enters `help show`
- **THEN** the system displays detailed usage for the `show` command including types and arguments

#### Scenario: Help for unknown command
- **WHEN** the user enters `help foo`
- **THEN** the system prints an error indicating the command is not recognized

### Requirement: Tab completion
The REPL SHALL provide tab completion for command names on the first token and item type names on the second token using rustyline's completion support.

#### Scenario: Complete command name
- **WHEN** the user types `sh` and presses Tab
- **THEN** the input is completed to `show`

#### Scenario: Complete item type
- **WHEN** the user types `show ca` and presses Tab
- **THEN** the input is completed to `show cards`

#### Scenario: No completion available
- **WHEN** the user types `show cards gith` and presses Tab
- **THEN** nothing is completed (no completion for regex arguments)

### Requirement: Persistent command history
The REPL SHALL persist command history to `~/.passlane/.repl_history` and load it on startup. History SHALL be available via up/down arrow keys.

#### Scenario: History persists across sessions
- **WHEN** the user runs commands in a REPL session, quits, and starts a new REPL session
- **THEN** the previous session's commands are available via up-arrow

#### Scenario: History file created automatically
- **WHEN** the REPL starts and no history file exists
- **THEN** the system creates the history file on first save without error

### Requirement: Error handling in REPL
Action errors in the REPL SHALL be printed to stderr and the prompt SHALL return. The REPL SHALL NOT exit on action errors.

#### Scenario: Vault error
- **WHEN** a command fails (e.g., wrong master password, vault file not found)
- **THEN** the error message is printed and the REPL prompt returns

#### Scenario: Interrupted action
- **WHEN** the user presses Ctrl-C during an action prompt
- **THEN** the action is cancelled and the REPL prompt returns
