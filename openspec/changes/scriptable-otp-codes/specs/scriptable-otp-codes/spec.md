## ADDED Requirements

### Requirement: Generated TOTP code output in the list command

When the `--code` flag is provided together with `-o` (OTP), the `list` command SHALL output the currently valid generated code for each matching TOTP authorizer instead of the stored secret and configuration. The command SHALL generate codes via the vault's TOTP code generation (equivalent to `Totp::get_code()`) and SHALL NOT include the stored secret in `--code` output.

The command SHALL remain non-interactive and SHALL NOT copy any value to the clipboard, consistent with the `list` command contract.

#### Scenario: List generates codes in plain text
- **WHEN** the user runs `passlane list -o --code` and the TOTP vault contains authorizers
- **THEN** for each matching authorizer the output SHALL include its label and its current generated code
- **AND** the output SHALL NOT include the stored secret

#### Scenario: List generates codes filtered by regex
- **WHEN** the user runs `passlane list -o --code braintree` and an authorizer labelled `braintree:api@iki.fi` exists
- **THEN** the output SHALL include the current generated code for that authorizer only

#### Scenario: List code output does not touch the clipboard
- **WHEN** the user runs `passlane list -o --code`
- **THEN** the system SHALL NOT copy any code to the clipboard and SHALL NOT display an interactive prompt

#### Scenario: `--code` without `-o` has no effect on other entry types
- **WHEN** the user runs `passlane list --code` (credentials) or with `-p`/`-n`
- **THEN** the `--code` flag SHALL be ignored and output SHALL be unchanged for those entry types

### Requirement: JSON output format for generated codes

When `--code` and `--json` are provided together with `-o`, the system SHALL output a JSON object with the envelope `{ "type": "totp_codes", "count": <n>, "entries": [...] }`. The `count` field SHALL equal the length of `entries`. Each entry SHALL contain the fields `label`, `issuer`, `code`, and `valid_for_seconds`. The stored `secret` SHALL NOT appear in this output. The output SHALL be pretty-printed JSON written to stdout.

#### Scenario: JSON output for generated codes
- **WHEN** the user runs `passlane list -o --code --json` and the TOTP vault contains a matching authorizer
- **THEN** the output SHALL be valid JSON with `"type": "totp_codes"` and each entry SHALL contain `label`, `issuer`, `code`, and `valid_for_seconds`
- **AND** no entry SHALL contain a `secret` field

#### Scenario: JSON code envelope count matches entries
- **WHEN** two authorizers match the filter
- **THEN** the JSON output SHALL have `"count": 2` and an `entries` array of length 2

### Requirement: One-shot code retrieval in the show command

The `show` command SHALL accept a `--once` flag. When `show -o --once <REGEXP>` is run and exactly one TOTP authorizer matches, the system SHALL print that authorizer's current generated code to stdout and exit immediately with status `0`. In this mode the system SHALL NOT copy the code to the clipboard, SHALL NOT print a countdown, and SHALL NOT wait for keyboard input.

#### Scenario: One-shot prints a single code and exits
- **WHEN** the user runs `passlane show -o --once braintree` and exactly one authorizer matches `braintree`
- **THEN** the system SHALL print the current generated code to stdout
- **AND** the process SHALL exit with status `0` without waiting for a keypress
- **AND** the system SHALL NOT copy the code to the clipboard

#### Scenario: One-shot with no match errors
- **WHEN** the user runs `passlane show -o --once nope` and no authorizer matches
- **THEN** the system SHALL write an error message to stderr and exit with a non-zero status

#### Scenario: One-shot with multiple matches errors instead of prompting
- **WHEN** the user runs `passlane show -o --once git` and more than one authorizer matches
- **THEN** the system SHALL write an error to stderr identifying the matched authorizer labels and exit with a non-zero status
- **AND** the system SHALL NOT display the interactive row-selection prompt

### Requirement: Interactive behavior is preserved by default

In the absence of the new flags, the existing behavior SHALL be unchanged: `show -o` SHALL run the interactive watch loop (clipboard copy, countdown, exit on `q`), and `list -o` SHALL output stored TOTP entries including the secret.

#### Scenario: Default show is still interactive
- **WHEN** the user runs `passlane show -o braintree` without `--once`
- **THEN** the system SHALL behave as before, copying the code to the clipboard and displaying the interactive countdown

#### Scenario: Default list still outputs secrets
- **WHEN** the user runs `passlane list -o` without `--code`
- **THEN** the system SHALL output the stored TOTP entries (including the secret), as before
