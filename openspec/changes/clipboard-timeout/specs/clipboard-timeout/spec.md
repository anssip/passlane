## ADDED Requirements

### Requirement: Clipboard auto-clear after password copy
When a credential password is copied to the clipboard by the `show` command or a generated password is copied by the `generate` command, the system SHALL clear the clipboard after 10 seconds.

The system SHALL only clear the clipboard if its current content still matches the value that was copied. If the user has copied different content in the meantime, the clipboard SHALL be left untouched.

#### Scenario: Clipboard cleared after show command copies password
- **WHEN** a user runs `show` and a single credential is found, causing the password to be copied to the clipboard
- **THEN** the system copies the password to the clipboard, displays "Password copied to clipboard! Clipboard will be cleared in 10 seconds.", waits 10 seconds, and clears the clipboard

#### Scenario: Clipboard cleared after show command with row selection
- **WHEN** a user runs `show`, multiple credentials are found, and the user selects a row number to copy
- **THEN** the system copies the selected password to the clipboard, displays "Password copied to clipboard! Clipboard will be cleared in 10 seconds.", waits 10 seconds, and clears the clipboard

#### Scenario: Clipboard cleared after generate command
- **WHEN** a user runs `generate`
- **THEN** the system generates a password, copies it to the clipboard, displays the password with a message that the clipboard will be cleared in 10 seconds, waits 10 seconds, and clears the clipboard

#### Scenario: Clipboard not cleared when content has changed
- **WHEN** a password is copied to the clipboard by `show` or `generate`, and the user copies different content to the clipboard before the 10-second timeout expires
- **THEN** the system SHALL NOT clear the clipboard

### Requirement: Stdout-only output with --out flag
The `show` and `generate` commands SHALL accept an `--out` flag. When `--out` is provided, the password SHALL be printed to STDOUT only. The system SHALL NOT copy the password to the clipboard and SHALL NOT apply any clipboard timeout.

#### Scenario: Show command with --out flag
- **WHEN** a user runs `show <REGEXP> --out` and a single credential is found
- **THEN** the system prints the password to STDOUT without copying to the clipboard and exits immediately

#### Scenario: Show command with --out flag and multiple matches
- **WHEN** a user runs `show <REGEXP> --out` and multiple credentials are found
- **THEN** the system displays the credentials table and prompts for row selection, then prints the selected password to STDOUT without copying to the clipboard and exits immediately

#### Scenario: Generate command with --out flag
- **WHEN** a user runs `generate --out`
- **THEN** the system generates a password, prints it to STDOUT without copying to the clipboard, and exits immediately

#### Scenario: Default behaviour without --out flag
- **WHEN** a user runs `show` or `generate` without the `--out` flag
- **THEN** the system copies the password to the clipboard with the 10-second auto-clear timeout (default behaviour)
