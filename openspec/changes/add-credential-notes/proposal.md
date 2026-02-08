## Why

When users have multiple accounts on the same service (e.g., personal and work Gmail accounts, or multiple AWS accounts), the only distinguishing fields are username and service URL. A free-form note field on credentials would let users annotate entries with context like "work account", "shared team login", or "admin access", making it easier to identify and manage multiple accounts on the same service.

## What Changes

- Add an optional `note` field to the `Credential` entity
- Store and retrieve the note using the KeePass entry's notes field (which is currently unused for credentials)
- Prompt for an optional note when adding or editing credentials
- Display the note in credential output (tables, detail views, JSON)
- Include the note field in CSV import/export

## Capabilities

### New Capabilities

- `credential-notes`: Adding, storing, displaying, and editing notes on credential entries

### Modified Capabilities

- `list-command`: JSON and plain text output for credentials must include the new note field

## Impact

- **Entities**: `Credential` struct gains an optional `note: Option<String>` field
- **Vault layer**: `KeepassVault` credential read/write must handle the KeePass entry notes field; `create_password_entry`, `update_credential`, `get_node_values`/`node_to_credential` all need updates
- **UI input**: `ask_credentials` and `ask_modified_credential` must prompt for an optional note
- **UI output**: `show_credentials_table` must display the note (in verbose mode); JSON serialization must include it
- **CSV**: Import/export must handle an additional `note` column; backward compatibility with existing CSV files (missing note column) should be maintained
- **Serde**: `Credential` deserialization must handle missing `note` field gracefully (default to `None`)
