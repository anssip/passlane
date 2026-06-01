## MODIFIED Requirements

### Requirement: List command exists as a CLI subcommand

The system SHALL provide a `list` subcommand that outputs vault entries to stdout for scripting and automation. The command SHALL accept the following flags:

- `--json` — output as JSON instead of plain text
- `-p, --payments` — list payment cards
- `-n, --notes` — list secure notes
- `-o, --otp` — list TOTP entries
- `-c, --credentials` — list credentials (default when no type flag is provided)
- `-v, --verbose` — show full details in plain text output
- `--code` — when combined with `-o`, output the currently generated TOTP code for each matching authorizer instead of the stored secret (see the `scriptable-otp-codes` capability)

The command SHALL accept an optional positional `<REGEXP>` argument to filter entries by regex pattern.

#### Scenario: List command appears in CLI help

- **WHEN** the user runs `passlane --help`
- **THEN** the output SHALL include the `list` subcommand with a description indicating it is for scripting and automation

#### Scenario: Default entry type is credentials

- **WHEN** the user runs `passlane list` without any type flag
- **THEN** the system SHALL list credentials

#### Scenario: Type flags select entry type

- **WHEN** the user runs `passlane list -p`
- **THEN** the system SHALL list payment cards
- **WHEN** the user runs `passlane list -n`
- **THEN** the system SHALL list secure notes
- **WHEN** the user runs `passlane list -o`
- **THEN** the system SHALL list TOTP entries

#### Scenario: Code flag switches OTP output to generated codes

- **WHEN** the user runs `passlane list -o --code`
- **THEN** the system SHALL output generated TOTP codes rather than stored secrets, as defined by the `scriptable-otp-codes` capability
