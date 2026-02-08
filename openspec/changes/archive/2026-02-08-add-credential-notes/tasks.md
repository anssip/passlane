## 1. Credential Entity

- [x] 1.1 Add `note: Option<String>` field to `Credential` struct in `src/vault/entities.rs` with `#[serde(default)]` attribute
- [x] 1.2 Update `Credential::new()` to accept an `Option<&str>` note parameter
- [x] 1.3 Add `pub fn note(&self) -> Option<&str>` accessor method to `Credential`
- [x] 1.4 Add unit tests: credential created with note, credential created without note, JSON serialization includes note field, JSON serialization with `None` note produces `null`

## 2. KeePass Vault Storage

- [x] 2.1 Update `get_node_values` in `src/vault/keepass_vault.rs` to read the KeePass entry notes field via `get_notes()` and return it as an `Option<String>` (treat empty/missing as `None`)
- [x] 2.2 Update `node_to_credential` to pass the notes value to `Credential::new()`
- [x] 2.3 Update `create_password_entry` to call `entry.set_notes()` when the credential has a note
- [x] 2.4 Update `update_credential` to call `entry.set_notes()` with the credential's note (set to `None`/empty when note is absent)

## 3. UI Input

- [x] 3.1 Update `ask_credentials` in `src/ui/input.rs` to prompt for an optional note after the username prompt, passing the result to `Credential::new()`
- [x] 3.2 Update `ask_modified_credential` to prompt for note with the existing note as default, allowing the user to change, keep, or clear it

## 4. UI Output — Table Display

- [x] 4.1 Update `show_credentials_table` in `src/ui/output.rs` to use multi-line cells: first line shows service name, second line shows note (📝 prefix, if present) and modified date — remove the separate `Modified` column
- [x] 4.2 In verbose mode, keep the Password column but still use multi-line Service cell for note + modified date
- [x] 4.3 Update single-credential detail view (in `show` action) to display the note if present, omit if `None`

## 5. CSV Import/Export

- [x] 5.1 Verify that `write_credentials_to_csv` in `src/store.rs` serializes the note field (serde `Serialize` on `Credential` should handle this automatically)
- [x] 5.2 Verify that `read_from_csv` handles CSV files without a note column gracefully (serde `#[serde(default)]` on the note field)
- [x] 5.3 Add test: export credential with note to CSV produces note column; import CSV without note column defaults to `None`

## 6. Update All Credential::new() Call Sites

- [x] 6.1 Update all existing `Credential::new()` calls across the codebase to pass the new note parameter (use `None` where no note context exists)

## 7. Build and Test

- [x] 7.1 Run `cargo build --release` and fix any compilation errors
- [x] 7.2 Run `cargo test` and verify all existing and new tests pass
