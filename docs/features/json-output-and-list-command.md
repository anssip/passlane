# JSON Output and List Command

**Status:** Planned
**Priority:** High
**Related Issue:** N/A
**Author:** Anssi
**Date:** 2025-11-16

## Overview

This document outlines the design for adding JSON output support and a new `list` command to Passlane. This feature enables automation, scripting, and integration with other tools while maintaining the current interactive user experience.

## Motivation

Currently, Passlane is optimized for interactive terminal use. The `show` command:
- Copies passwords to clipboard without displaying them
- Provides interactive prompts for multiple matches
- Formats output in human-readable tables

While excellent for manual use, this makes automation difficult. Users want to:
- Integrate with security analysis tools
- Automate password rotation
- Generate reports and statistics
- Export to other password managers
- Build custom workflows

See the scripting examples in `TODO.md` for detailed use cases.

## Goals

1. **Add machine-readable output** without breaking existing UX
2. **Enable scripting and automation** workflows
3. **Maintain security** - don't accidentally expose passwords in logs
4. **Keep existing commands unchanged** - backward compatibility
5. **Follow existing patterns** - use same flags (`-p`, `-n`, `-o`) as other commands

## Non-Goals

- Replacing the interactive `show` command
- Creating a full REST API
- Adding remote access capabilities

## Design

### New Command: `list`

Add a new `list` command for machine-readable output that complements the interactive `show` command.

#### Command Syntax

```bash
# List all credentials
passlane list

# List credentials matching search term (regex)
passlane list <regexp>

# List payment cards
passlane list -p [regexp]

# List secure notes
passlane list -n [regexp]

# List TOTP entries
passlane list -o [regexp]

# Output as JSON
passlane list --json
passlane list google --json
passlane list -p --json
```

#### Flags

- `-p, --payments` - List payment cards
- `-n, --notes` - List secure notes
- `-o, --otp` - List TOTP entries
- `-c, --credentials` - List credentials (default, can be explicit)
- `--json` - Output as JSON instead of plain text
- `-v, --verbose` - Show full details in plain text (not just metadata)

### Behavior Differences: `show` vs `list`

| Feature | `show` (Interactive) | `list` (Machine-readable) |
|---------|---------------------|---------------------------|
| **Output format** | Human-readable tables | Plain text or JSON |
| **Clipboard** | Copies password/OTP | No clipboard interaction |
| **Multiple matches** | Interactive prompt to select | Prints all matches |
| **Password display** | Hidden (clipboard only) | Shown in output (careful!) |
| **Use case** | Manual terminal use | Scripting, automation |
| **Prompts** | Yes (selection, confirmation) | No prompts |
| **Exit behavior** | Waits for user input | Immediate exit |

### JSON Output Schema

#### Credentials

```json
{
  "type": "credentials",
  "count": 2,
  "entries": [
    {
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "service": "google.com",
      "username": "user@example.com",
      "password": "secretpassword123",
      "last_modified": "2024-11-15T10:30:00Z"
    },
    {
      "uuid": "660e8400-e29b-41d4-a716-446655440001",
      "service": "github.com",
      "username": "user@example.com",
      "password": "anotherpassword456",
      "last_modified": "2024-10-20T14:22:00Z"
    }
  ]
}
```

#### Payment Cards

```json
{
  "type": "payment_cards",
  "count": 1,
  "entries": [
    {
      "uuid": "770e8400-e29b-41d4-a716-446655440002",
      "name": "Visa Gold",
      "name_on_card": "John Doe",
      "number": "4532123456789012",
      "cvv": "123",
      "expiry": {
        "month": 6,
        "year": 2025
      },
      "color": "Gold",
      "billing_address": {
        "street": "123 Main St",
        "city": "Springfield",
        "state": "IL",
        "zip": "62701",
        "country": "US"
      },
      "last_modified": "2024-09-10T08:15:00Z"
    }
  ]
}
```

#### Secure Notes

```json
{
  "type": "notes",
  "count": 1,
  "entries": [
    {
      "uuid": "880e8400-e29b-41d4-a716-446655440003",
      "title": "WiFi Passwords",
      "text": "Home: password123\nOffice: password456",
      "last_modified": "2024-11-01T16:45:00Z"
    }
  ]
}
```

#### TOTP Entries

```json
{
  "type": "totp",
  "count": 1,
  "entries": [
    {
      "uuid": "990e8400-e29b-41d4-a716-446655440004",
      "issuer": "GitHub",
      "account": "user@example.com",
      "secret": "JBSWY3DPEHPK3PXP",
      "current_code": "123456",
      "valid_for_seconds": 23,
      "last_modified": "2024-08-15T12:00:00Z"
    }
  ]
}
```

### Plain Text Output (without `--json`)

When `--json` is not specified, output should be similar to current `show` output but print all matches without interaction:

```
Found 2 credentials:

Service: google.com
Username: user@example.com
Password: secretpassword123
Modified: 15.11.2024 10:30

Service: github.com
Username: user@example.com
Password: anotherpassword456
Modified: 20.10.2024 14:22
```

**Security Note:** Plain text output shows passwords. Users should be cautious when redirecting to files or using in scripts that log output.

## Implementation Approach

### 1. Add Serde Serialization to Entities

Update entities in `src/vault/entities.rs`:

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct Credential {
    #[serde(rename = "uuid")]
    uuid: Uuid,
    password: String,
    service: String,
    username: String,
    last_modified: DateTime<Utc>,
}

// Similar updates for PaymentCard, Note, Totp
```

### 2. Create ListAction

New file: `src/actions/list.rs`

```rust
pub struct ListAction {
    item_type: ItemType,
    search_pattern: Option<String>,
    json_output: bool,
}

impl UnlockingAction for ListAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        match self.item_type {
            ItemType::Credential => self.list_credentials(vault),
            ItemType::Payment => self.list_payments(vault),
            ItemType::Note => self.list_notes(vault),
            ItemType::Totp => self.list_totp(vault),
        }
    }
}
```

### 3. Add JSON Output Helpers

Create `src/json_output.rs`:

```rust
pub struct JsonOutput<T> {
    pub type_name: &'static str,
    pub count: usize,
    pub entries: Vec<T>,
}

pub fn serialize_to_json<T: Serialize>(output: JsonOutput<T>) -> Result<String, Error> {
    serde_json::to_string_pretty(&output)
        .map_err(|e| Error::new(&format!("JSON serialization error: {}", e)))
}
```

### 4. Update CLI Definition in main.rs

```rust
.subcommand(
    Command::new("list")
        .about("Lists entries from the vault (for scripting/automation)")
        .arg(arg!(
            --json "Output as JSON"
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -p --payments "List payment cards."
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -n --notes "List secure notes."
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -o --otp "List TOTP entries."
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -c --credentials "List credentials (default)."
        ).action(ArgAction::SetTrue))
        .arg(arg!(
            -v --verbose "Show full details in plain text output."
        ).action(ArgAction::SetTrue))
        .arg(arg!(<REGEXP> "Regular expression to filter entries.").required(false))
)
```

### 5. Update Cargo.toml

Ensure `serde` feature is enabled for all entity types. Current dependencies already include `serde` with derive feature, so minimal changes needed.

## Example Usage

### Password Strength Analysis

```bash
# Check all passwords for strength
passlane list --json | jq -r '.entries[].password' | while read pwd; do
  echo "Password: $pwd"
  echo "$pwd" | password-strength-checker
done
```

### Find Duplicate Passwords

```bash
# Find services using the same password
passlane list --json | jq -r '
  .entries | group_by(.password) |
  map(select(length > 1) | {
    password: .[0].password,
    services: [.[].service]
  })
'
```

### Export to 1Password Format

```bash
passlane list --json | jq '
  .entries[] | {
    title: .service,
    username: .username,
    password: .password,
    category: "login"
  }
' > 1password_import.json
```

### Generate Statistics

```bash
# Count passwords by age
passlane list --json | jq -r '
  .entries[] |
  "\(.service),\(.last_modified)"
' | while IFS=, read service date; do
  age_days=$(( ($(date +%s) - $(date -d "$date" +%s)) / 86400 ))
  echo "$service: $age_days days old"
done | sort -t: -k2 -n
```

### Automated Testing

```bash
# Extract credentials for automated testing
SERVICE="https://github.com"
CREDS=$(passlane list "$SERVICE" --json)
USERNAME=$(echo "$CREDS" | jq -r '.entries[0].username')
PASSWORD=$(echo "$CREDS" | jq -r '.entries[0].password')

# Use in test automation
curl -u "$USERNAME:$PASSWORD" https://api.github.com/user
```

## Security Considerations

### 1. Accidental Exposure

**Risk:** JSON output includes passwords in plain text, which could be logged or exposed.

**Mitigations:**
- Clear documentation warning about sensitive data
- Consider adding `--include-passwords` flag (default: exclude)
- README examples show safe piping practices
- Shell history warnings in documentation

### 2. Command-line Arguments

**Risk:** Search patterns in command history might reveal service names.

**Mitigation:**
- This is existing behavior with `show` command
- Document secure practices (history cleanup, HISTCONTROL)

### 3. Clipboard vs stdout

**Current `show`:** Safe - copies to clipboard without displaying
**New `list`:** Displays to stdout - intentional for piping

**Documentation:** Clearly explain the security trade-off and when to use each command.

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_json_serialization_credentials() {
        // Test JSON output matches schema
    }

    #[test]
    fn test_list_with_search_pattern() {
        // Test regex filtering
    }

    #[test]
    fn test_plain_text_output() {
        // Test non-JSON output format
    }
}
```

### Integration Tests

```bash
# Test JSON output is valid
passlane list --json | jq . > /dev/null || echo "Invalid JSON"

# Test search filtering
COUNT=$(passlane list google --json | jq '.count')
[ "$COUNT" -gt 0 ] || echo "No matches found"

# Test payment cards
passlane list -p --json | jq '.type' | grep -q "payment_cards"
```

### Manual Testing Checklist

- [ ] `passlane list` shows all credentials
- [ ] `passlane list google` filters correctly
- [ ] `passlane list -p` shows payment cards
- [ ] `passlane list -n` shows notes
- [ ] `passlane list -o` shows TOTP entries
- [ ] `--json` produces valid JSON
- [ ] JSON schema matches specification
- [ ] Plain text output is readable
- [ ] No clipboard interaction occurs
- [ ] No interactive prompts appear
- [ ] Works with empty vault
- [ ] Works with single entry
- [ ] Works with multiple matches

## Documentation Updates

### README.md

Add new section under "Usage":

```markdown
### Scripting and Automation

The `list` command provides machine-readable output for scripting:

\`\`\`bash
# List all credentials as JSON
passlane list --json

# Find specific credentials
passlane list google --json

# List payment cards
passlane list -p --json
\`\`\`

**Security Warning:** Unlike `show`, the `list` command outputs passwords to stdout.
Be careful when redirecting output to files or using in scripts that log commands.
```

### Man Page / Help Text

Update command descriptions to clarify the difference between `show` and `list`.

## Future Enhancements

### Phase 2 (Not in initial implementation)

- [ ] Add `--exclude-passwords` flag for safer default
- [ ] Add `--format` option (json, csv, yaml)
- [ ] Add filtering options (`--older-than`, `--weaker-than`)
- [ ] Add `passlane list --all` to list all entry types at once
- [ ] Consider adding streaming JSON output for large vaults

## Questions and Open Issues

1. **Should we add rate limiting?** If users pipe all passwords to external API (like pwned passwords), should we throttle?
2. **Password masking option?** Should we support `*****` masking in plain text output?
3. **TOTP current code?** TOTP codes change every 30s - should JSON include current code or just the secret?
   - **Decision:** Include both for flexibility

## Alternatives Considered

### Alternative 1: Only add `--json` flag to existing `show`

**Pros:** Simpler, fewer commands
**Cons:** Mixing interactive and non-interactive modes in one command creates confusion

### Alternative 2: Separate tool/binary for JSON output

**Pros:** Clean separation
**Cons:** Maintenance burden, duplicated vault logic

### Alternative 3: Create a daemon/server mode

**Pros:** More powerful
**Cons:** Over-engineered for the use case, security concerns

**Selected Approach:** New `list` command provides best balance of simplicity and clarity.

## Timeline

**Estimated Effort:** 2-3 days

- Day 1: Implement basic `list` command with plain text output
- Day 2: Add JSON serialization and `--json` flag
- Day 3: Testing, documentation, examples

## References

- [TODO.md Scripting Examples](../../TODO.md)
- [keepass-ng crate documentation](https://docs.rs/keepass-ng/)
- [Serde JSON documentation](https://docs.rs/serde_json/)
