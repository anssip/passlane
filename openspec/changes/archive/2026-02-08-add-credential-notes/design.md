## Context

The `Credential` entity currently has four fields: `uuid`, `password`, `service`, `username`, and `last_modified`. KeePass entries have a built-in notes field (`get_notes`/`set_notes`) that is already used by payment cards (for structured data) and by secure notes (for content), but is **unused for credential entries**. Credentials are stored in the "Passwords" KeePass group, separate from "Payments" and "Notes" groups, so there is no field collision.

CSV import/export uses serde deserialization directly on `Credential`, so any schema change must be backward compatible with existing CSV files that lack a note column.

## Goals / Non-Goals

**Goals:**
- Add an optional free-form note to credentials for annotating entries
- Store the note in the KeePass entry's native notes field (no custom fields needed)
- Display the note in verbose/detail views and JSON output
- Maintain backward compatibility with existing vaults (entries without notes) and CSV files

**Non-Goals:**
- Structured/typed notes or metadata (tags, categories) — this is a free-form text field only
- Full-text search across notes — search remains service-name based
- Note field for payment cards or TOTP entries (they already use the notes field differently)
- Rich text or markdown rendering of notes

## Decisions

### 1. Use `Option<String>` for the note field

**Decision**: The note field is `Option<String>`, defaulting to `None`.

**Rationale**: Notes are optional — most credentials won't have one. Using `Option` avoids storing empty strings in KeePass and makes backward compatibility natural. Serde's `#[serde(default)]` handles missing fields during CSV import.

**Alternative considered**: Required `String` defaulting to `""` — rejected because it would write empty notes to every KeePass entry and make intent less clear.

### 2. Store in KeePass entry's native notes field

**Decision**: Use `entry.get_notes()` / `entry.set_notes()` to read/write the credential note, storing the value as plain text.

**Rationale**: The KeePass notes field is the natural place for this data. It's already available on every entry and is displayed by other KeePass clients (KeePassXC, etc.), providing interoperability. Credential entries currently don't use this field at all.

**Alternative considered**: KeePass custom string fields — rejected because the native notes field is simpler and more portable across KeePass clients.

### 3. Note is prompted but optional during add/edit

**Decision**: When adding or editing a credential, prompt for a note with an empty default. Pressing Enter skips it. During edit, the existing note is shown as the default value.

**Rationale**: Keeps the workflow fast for users who don't need notes while making the feature discoverable. Consistent with how optional fields work elsewhere (e.g., payment card color).

### 4. Display note and modified date on a 2nd line in table view

**Decision**: In the credentials table, each credential occupies a multi-line row. The first line shows the index, service, and username. The second line shows the note (if present) and the modified date, rendered in the Service column using `\n` within the cell content. In JSON output, the note field is always present (as `null` or a string). In single-credential detail view (`show` command with one match), the note is always shown if present.

comfy-table (the table rendering library used by Passlane) natively supports multi-line cells — embedding `\n` in a `Cell::new()` value renders the content across multiple lines within the same logical row, with proper border alignment. No additional columns are needed.

**Layout (non-verbose):**
```
+---+-------------------------------------+-------------------+
| # | Service                             | Username/email    |
+=============================================================+
| 0 | google.com                          | user@gmail.com    |
|   | 📝 work account  Modified: 15.01.24 |                   |
|---+-------------------------------------+-------------------|
| 1 | github.com                          | devuser           |
|   | Modified: 20.02.24                  |                   |
+---+-------------------------------------+-------------------+
```

When verbose mode is active, the password column is added (as before) and the second line still shows the note and modified date.

**Rationale**: Showing the note in the default (non-verbose) view makes it immediately useful for distinguishing multiple accounts on the same service — which is the primary use case. Moving the modified date to the second line keeps the table compact (fewer columns) while showing more information. The multi-line approach avoids adding a wide "Note" column that would stretch the table horizontally.

### 5. CSV backward compatibility via serde default

**Decision**: Use `#[serde(default)]` on the note field so CSV files without a note column deserialize successfully with `None`. Export always includes the note column.

**Rationale**: Users may have existing CSV exports or third-party CSV files. Failing to import them would be a breaking change. Serde's default handling makes this seamless.

## Risks / Trade-offs

- **[Interop with KeePass clients]** → Other KeePass clients will show the note in their notes field. This is actually a benefit — notes are portable. However, if a user edits the notes field in KeePassXC, that text will appear as the credential's note in Passlane. This is acceptable and expected behavior.

- **[Payment card notes field conflict]** → Payment cards store structured data (name on card, number, CVV, etc.) in the KeePass notes field using a line-based format. Since credentials and payment cards live in separate KeePass groups ("Passwords" vs "Payments"), there is no conflict. No risk here.

- **[CSV column ordering]** → Adding a new column to CSV export changes the schema. Existing CSV import workflows that rely on column position rather than headers could break. Mitigation: serde CSV uses headers, so header-based parsing is unaffected. Column-position-based external tools may need updating — this is documented as a known change.
