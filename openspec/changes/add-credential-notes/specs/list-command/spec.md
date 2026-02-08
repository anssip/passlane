## MODIFIED Requirements

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
