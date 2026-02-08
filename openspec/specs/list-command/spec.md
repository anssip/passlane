### Requirement: List command exists as a CLI subcommand

The system SHALL provide a `list` subcommand that outputs vault entries to stdout for scripting and automation. The command SHALL accept the following flags:

- `--json` — output as JSON instead of plain text
- `-p, --payments` — list payment cards
- `-n, --notes` — list secure notes
- `-o, --otp` — list TOTP entries
- `-c, --credentials` — list credentials (default when no type flag is provided)
- `-v, --verbose` — show full details in plain text output

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

### Requirement: List command requires vault unlock

The system SHALL unlock the appropriate vault before listing entries. For TOTP entries (`-o`), the TOTP vault SHALL be unlocked. For all other entry types, the main vault SHALL be unlocked. The unlock flow SHALL follow the same pattern as the `show` command (check OS keychain first, prompt for master password if not stored).

#### Scenario: Vault is unlocked via keychain

- **WHEN** the user runs `passlane list` and the master password is stored in the OS keychain
- **THEN** the system SHALL unlock the vault without prompting for the password

#### Scenario: Vault unlock prompts for password

- **WHEN** the user runs `passlane list` and no master password is stored in the OS keychain
- **THEN** the system SHALL prompt the user for the master password

#### Scenario: TOTP vault is used for OTP entries

- **WHEN** the user runs `passlane list -o`
- **THEN** the system SHALL unlock the TOTP vault (not the main vault)

### Requirement: List command does not interact with clipboard or prompt

The `list` command SHALL NOT copy any values to the clipboard. The `list` command SHALL NOT display interactive prompts for selecting entries. All matching entries SHALL be printed to stdout immediately.

#### Scenario: No clipboard interaction

- **WHEN** the user runs `passlane list` and one credential matches
- **THEN** the system SHALL print the credential to stdout and SHALL NOT copy the password to the clipboard

#### Scenario: No interactive selection prompt

- **WHEN** the user runs `passlane list` and multiple credentials match
- **THEN** the system SHALL print all matching credentials to stdout without prompting the user to select one

### Requirement: Regex filtering for credentials

When a `<REGEXP>` positional argument is provided, the system SHALL filter credentials by matching the regex against service names. When no `<REGEXP>` is provided, the system SHALL list all credentials.

#### Scenario: Filter credentials by regex

- **WHEN** the user runs `passlane list google`
- **THEN** the system SHALL output only credentials whose service name matches the regex `google`

#### Scenario: List all credentials without filter

- **WHEN** the user runs `passlane list` without a `<REGEXP>` argument
- **THEN** the system SHALL output all credentials in the vault

#### Scenario: Regex filtering for TOTP entries

- **WHEN** the user runs `passlane list -o github`
- **THEN** the system SHALL output only TOTP entries matching the regex `github`

#### Scenario: No regex filtering for payments and notes

- **WHEN** the user runs `passlane list -p` or `passlane list -n`
- **THEN** the system SHALL output all entries of that type (regex argument is accepted but not applied to payments/notes since the vault trait does not support filtering for these types)

### Requirement: JSON output format

When the `--json` flag is provided, the system SHALL output entries as a JSON object with the following envelope structure:

```json
{
  "type": "<entry_type>",
  "count": <number>,
  "entries": [...]
}
```

The `type` field SHALL be one of: `"credentials"`, `"payment_cards"`, `"notes"`, `"totp"`. The `count` field SHALL equal the length of the `entries` array. The output SHALL be pretty-printed JSON written to stdout.

#### Scenario: JSON output for credentials

- **WHEN** the user runs `passlane list --json` and the vault contains credentials
- **THEN** the output SHALL be valid JSON with `"type": "credentials"` and each entry SHALL contain the fields: `uuid`, `service`, `username`, `password`, `note`, `last_modified`
- **THEN** the `note` field SHALL be `null` for credentials without a note and a string value for credentials with a note

#### Scenario: JSON output for payment cards

- **WHEN** the user runs `passlane list -p --json` and the vault contains payment cards
- **THEN** the output SHALL be valid JSON with `"type": "payment_cards"` and each entry SHALL contain the fields: `id`, `name`, `name_on_card`, `number`, `cvv`, `expiry` (with `month` and `year`), `color`, `billing_address`, `last_modified`

#### Scenario: JSON output for notes

- **WHEN** the user runs `passlane list -n --json` and the vault contains notes
- **THEN** the output SHALL be valid JSON with `"type": "notes"` and each entry SHALL contain the fields: `id`, `title`, `content`, `last_modified`

#### Scenario: JSON output for TOTP entries

- **WHEN** the user runs `passlane list -o --json` and the TOTP vault contains entries
- **THEN** the output SHALL be valid JSON with `"type": "totp"` and each entry SHALL contain the fields: `id`, `label`, `issuer`, `secret`, `algorithm`, `period`, `digits`, `last_modified`
- **THEN** the output SHALL NOT contain a `current_code` field

#### Scenario: JSON output with combined flags

- **WHEN** the user runs `passlane list google --json`
- **THEN** the output SHALL be valid JSON containing only credentials matching `google`

### Requirement: Plain text output format

When the `--json` flag is NOT provided, the system SHALL output entries in a human-readable plain text format. The output SHALL begin with a summary line `Found N <type>:` (or `Found 0 <type>.` for empty results).

#### Scenario: Plain text credentials without verbose

- **WHEN** the user runs `passlane list` without `--json` or `-v` and the vault contains credentials
- **THEN** each credential SHALL be printed as a multi-line table row with `Service` and `Username/email` columns
- **THEN** the Service cell SHALL contain the service name on the first line, and the note (prefixed with 📝, if present) followed by the modified date on the second line

#### Scenario: Plain text credentials with verbose

- **WHEN** the user runs `passlane list -v` without `--json` and the vault contains credentials
- **THEN** each credential SHALL be printed as a multi-line table row with `Service`, `Username/email`, and `Password` columns
- **THEN** the Service cell SHALL contain the service name on the first line, and the note (prefixed with 📝, if present) followed by the modified date on the second line

#### Scenario: Plain text payment cards without verbose

- **WHEN** the user runs `passlane list -p` without `--json` or `-v` and the vault contains payment cards
- **THEN** each payment card SHALL be printed with `Name:`, `Last 4:`, `Color:`, `Expiry:`, and `Last Modified:` fields
- **THEN** the `Last 4:` field SHALL display the last 4 digits of the card number in masked format `•••• XXXX`
- **THEN** if the card number contains fewer than 4 characters, the `Last 4:` field SHALL display `•••• ` followed by the full number

#### Scenario: Plain text payment cards with verbose

- **WHEN** the user runs `passlane list -p -v` without `--json` and the vault contains payment cards
- **THEN** each payment card SHALL be printed with all card fields including `Name:`, `Name on Card:`, `Number:`, `CVV:`, `Expiry:`, and optionally `Color:` and `Billing Address:`

#### Scenario: Plain text notes

- **WHEN** the user runs `passlane list -n` without `--json`
- **THEN** each note SHALL be printed with `Title:` and `Content:` fields

#### Scenario: Plain text TOTP entries

- **WHEN** the user runs `passlane list -o` without `--json`
- **THEN** each TOTP entry SHALL be printed with `Label:`, `Issuer:`, and `Secret:` fields

### Requirement: Empty results handling

When no entries match, the system SHALL output a valid result with zero entries. The command SHALL exit with code 0.

#### Scenario: Empty JSON output

- **WHEN** the user runs `passlane list google --json` and no credentials match
- **THEN** the output SHALL be `{ "type": "credentials", "count": 0, "entries": [] }` and the exit code SHALL be 0

#### Scenario: Empty plain text output

- **WHEN** the user runs `passlane list google` and no credentials match
- **THEN** the output SHALL print `Found 0 credentials.` and the exit code SHALL be 0

### Requirement: Error handling

When vault unlock fails or an invalid regex is provided, the system SHALL print an error message to stderr and exit with code 1. No JSON or plain text entry output SHALL be written to stdout on error.

#### Scenario: Invalid master password

- **WHEN** the user runs `passlane list` and provides an incorrect master password
- **THEN** the system SHALL print an error to stderr and exit with code 1

#### Scenario: Invalid regex pattern

- **WHEN** the user runs `passlane list "[invalid"` with a malformed regex
- **THEN** the system SHALL print an error to stderr and exit with code 1

### Requirement: Entity serialization support

All vault entity types (`Credential`, `PaymentCard`, `Note`, `Totp`, `Address`, `Expiry`) SHALL be serializable to JSON via serde. The `Credential` type SHALL serialize its `uuid` field (not skip it). The `Credential` type SHALL serialize its `note` field (as `null` when absent or as a string when present). Field names in JSON output SHALL use snake_case.

#### Scenario: Credential UUID is included in JSON

- **WHEN** a credential is serialized to JSON
- **THEN** the output SHALL contain a `uuid` field with the credential's UUID value

#### Scenario: Credential note is included in JSON

- **WHEN** a credential with note "work account" is serialized to JSON
- **THEN** the output SHALL contain `"note": "work account"`

#### Scenario: Credential without note is serialized to JSON

- **WHEN** a credential without a note is serialized to JSON
- **THEN** the output SHALL contain `"note": null`

#### Scenario: All entity types are serializable

- **WHEN** any vault entity type is serialized via `serde_json::to_string_pretty`
- **THEN** the serialization SHALL succeed without error and produce valid JSON
