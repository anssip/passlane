## MODIFIED Requirements

### Requirement: Plain text output format

When the `--json` flag is NOT provided, the system SHALL output entries in a human-readable plain text format. The output SHALL begin with a summary line `Found N <type>:` (or `Found 0 <type>.` for empty results).

#### Scenario: Plain text credentials without verbose

- **WHEN** the user runs `passlane list` without `--json` or `-v` and the vault contains credentials
- **THEN** each credential SHALL be printed with `Service:` and `Username:` fields, and the password SHALL NOT be shown

#### Scenario: Plain text credentials with verbose

- **WHEN** the user runs `passlane list -v` without `--json` and the vault contains credentials
- **THEN** each credential SHALL be printed with `Service:`, `Username:`, `Password:`, and `Last Modified:` fields

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
