### Requirement: Credential entity has an optional note field

The `Credential` entity SHALL have an optional `note` field of type `Option<String>`. When no note is provided, the field SHALL default to `None`. The field SHALL be serializable and deserializable via serde. Deserialization of data missing the note field (e.g., existing CSV files) SHALL succeed with the note defaulting to `None`.

#### Scenario: Credential created without a note

- **WHEN** a credential is created without specifying a note
- **THEN** the credential's note field SHALL be `None`

#### Scenario: Credential created with a note

- **WHEN** a credential is created with the note "work account"
- **THEN** the credential's note field SHALL be `Some("work account")`

#### Scenario: Credential deserialized from CSV without note column

- **WHEN** a CSV file with columns `username`, `password`, `service` (no `note` column) is imported
- **THEN** each credential SHALL be created with note defaulting to `None`

#### Scenario: Credential serialized to JSON includes note field

- **WHEN** a credential with note "admin access" is serialized to JSON
- **THEN** the JSON output SHALL contain `"note": "admin access"`

#### Scenario: Credential without note serialized to JSON

- **WHEN** a credential without a note is serialized to JSON
- **THEN** the JSON output SHALL contain `"note": null`

### Requirement: Credential note is stored in KeePass entry notes field

The system SHALL store the credential's note in the KeePass entry's native notes field using `set_notes`. The system SHALL read the credential's note from the KeePass entry's notes field using `get_notes`. When the KeePass entry has no notes value or an empty notes value, the credential's note SHALL be `None`.

#### Scenario: Saving a credential with a note to KeePass

- **WHEN** a credential with note "shared team login" is saved to the vault
- **THEN** the KeePass entry's notes field SHALL contain "shared team login"

#### Scenario: Saving a credential without a note to KeePass

- **WHEN** a credential with no note is saved to the vault
- **THEN** the KeePass entry's notes field SHALL NOT be set (or SHALL be empty)

#### Scenario: Loading a credential with a note from KeePass

- **WHEN** a KeePass entry in the "Passwords" group has notes field "work account"
- **THEN** the loaded credential's note SHALL be `Some("work account")`

#### Scenario: Loading a credential without notes from KeePass

- **WHEN** a KeePass entry in the "Passwords" group has no notes field
- **THEN** the loaded credential's note SHALL be `None`

#### Scenario: Updating a credential preserves or changes the note

- **WHEN** a credential's note is changed from "old note" to "new note" and saved
- **THEN** the KeePass entry's notes field SHALL contain "new note"

### Requirement: Adding a credential prompts for an optional note

When adding a credential, the system SHALL prompt the user for an optional note after the username prompt. The note prompt SHALL accept an empty value (pressing Enter) to skip. When the user provides a note, it SHALL be stored with the credential. When the user skips the note, the credential's note SHALL be `None`.

#### Scenario: User provides a note when adding a credential

- **WHEN** the user adds a credential and enters "work account" at the note prompt
- **THEN** the saved credential SHALL have note `Some("work account")`

#### Scenario: User skips the note when adding a credential

- **WHEN** the user adds a credential and presses Enter at the note prompt without typing anything
- **THEN** the saved credential SHALL have note `None`

### Requirement: Editing a credential allows modifying the note

When editing a credential, the system SHALL prompt for the note with the existing note value as the default. The user SHALL be able to change, clear, or keep the existing note.

#### Scenario: User edits the note to a new value

- **WHEN** the user edits a credential that has note "old note" and types "new note" at the note prompt
- **THEN** the updated credential SHALL have note `Some("new note")`

#### Scenario: User keeps the existing note

- **WHEN** the user edits a credential that has note "work account" and presses Enter at the note prompt
- **THEN** the updated credential SHALL retain note `Some("work account")`

#### Scenario: User clears the note

- **WHEN** the user edits a credential that has note "old note" and clears the note field
- **THEN** the updated credential SHALL have note `None`

### Requirement: Credentials table displays note and modified date on a second line

In the credentials table (used by `show` and `list` commands), each credential row SHALL use multi-line cell content. The first line SHALL show the index, service, and username. The second line in the Service column SHALL show the note (if present) prefixed with 📝, followed by the modified date. When the credential has no note, the second line SHALL show only the modified date.

#### Scenario: Table row for credential with a note

- **WHEN** a credential with service "google.com", username "user@gmail.com", note "work account", and modified date "15.01.2024 14:30" is displayed in the table
- **THEN** the Service cell SHALL contain two lines: "google.com" on the first line and "📝 work account  Modified: 15.01.2024 14:30" on the second line

#### Scenario: Table row for credential without a note

- **WHEN** a credential with service "github.com", username "devuser", no note, and modified date "20.02.2024 10:00" is displayed in the table
- **THEN** the Service cell SHALL contain two lines: "github.com" on the first line and "Modified: 20.02.2024 10:00" on the second line

#### Scenario: Verbose table includes password and still shows note on second line

- **WHEN** a credential with a note is displayed in the table with verbose mode enabled
- **THEN** the table SHALL include the Password column AND the second line in the Service cell SHALL still show the note and modified date

### Requirement: Single credential detail view shows note

When a single credential is displayed in detail (e.g., `show` command matching exactly one result), the note SHALL be shown if present. The note SHALL NOT be shown if it is `None`.

#### Scenario: Detail view with note

- **WHEN** a single credential with note "admin access" is displayed
- **THEN** the output SHALL include the note value "admin access"

#### Scenario: Detail view without note

- **WHEN** a single credential with no note is displayed
- **THEN** the output SHALL NOT display a note field or note line

### Requirement: CSV export includes note field

When credentials are exported to CSV, the output SHALL include a `note` column. Credentials without a note SHALL have an empty value in the note column.

#### Scenario: Export credential with note to CSV

- **WHEN** a credential with note "work account" is exported to CSV
- **THEN** the CSV row SHALL include "work account" in the note column

#### Scenario: Export credential without note to CSV

- **WHEN** a credential with no note is exported to CSV
- **THEN** the CSV row SHALL have an empty value in the note column

### Requirement: CSV import handles note field

When credentials are imported from CSV, the system SHALL read the `note` column if present. If the CSV file does not have a `note` column, import SHALL succeed with all notes defaulting to `None`.

#### Scenario: Import CSV with note column

- **WHEN** a CSV file with columns `username`, `password`, `service`, `note` is imported and a row has note "shared login"
- **THEN** the imported credential SHALL have note `Some("shared login")`

#### Scenario: Import CSV without note column

- **WHEN** a CSV file with columns `username`, `password`, `service` (no `note` column) is imported
- **THEN** all imported credentials SHALL have note `None`
