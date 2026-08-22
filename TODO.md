# TODO

## Roadmap

### High Priority / Next Up

#### Core Features
- [x] **JSON Output for Scripting** ⭐ - Add `--json` flag to show, export, and new list command for automation
- [x] Add note field to credentials (useful when you have several accounts on the same service)
- [ ] **Configurable Password Generation** - Support options like `--length`, `--no-special`, `--passphrase`
- [ ] Fuzzy Search - Support fuzzy matching instead of just regex (e.g., `passlane show goog` finds "google.com")
- [ ] Password Strength Analysis - Built-in password strength checker and audit command

#### Security Enhancements
- [ ] Password Audit Command - Identify weak, reused, or old passwords
- [ ] Check against pwned passwords API integration
- [ ] **Password History/Versioning** - Track password changes over time (keepass-ng 0.11: `Entry::get_history()` / `update_history()` are now written and read back on save)
- [x] **Clipboard Timeout** - Auto-clear clipboard after X seconds
- [ ] **Auto-lock on Timeout** - Remove from keychain after period of inactivity
- [ ] Master password strength enforcement on init

#### UX Improvements
- [x] Show first 4 digits of payment card numbers in list
- [x] **Interactive mode / REPL** (`passlane shell`)
- [ ] **Shell Completion** - Generate completion scripts for bash/zsh/fish
- [ ] **Duplicate Detection** - Warn when adding similar credentials
- [ ] Better table formatting with color coding for password age/strength (`passlane shell`)

#### Advanced Features
- [ ] **Tags/Categories** - Tag credentials and filter by tags (keepass-ng 0.11: `Entry::get_tags()` / `get_tags_mut()`, tags are now persisted on save)
- [ ] **Favorites/Pinning** - Quick access to frequently used credentials
- [ ] **Multi-Vault Support** - Manage multiple vaults (personal, work, family)
- [ ] **Custom Fields** - Support arbitrary fields (API keys, security questions, etc.) (keepass-ng 0.11: `Entry::set_additional_attribute()` / `get()`, read + write)
- [ ] **Attachment Support** - Store files in vault (keepass-ng 0.11: `Entry::attachments` is first-class and written to the inner-header binary pool on save)

### Unlocked by the keepass-ng 0.11 upgrade

The dependency upgrade to keepass-ng 0.11 (from 0.9) exposed these new capabilities. Each would need its feature flag enabled in `Cargo.toml` where noted.

| Capability | keepass-ng 0.11 API | Passlane opportunity |
|---|---|---|
| Database merge (`merge` feature) | `Database::merge(&mut self, &other) -> MergeLog` — matches entries/groups by UUID, last-writer-wins via modification times, handles deletions, custom icons, and entry history | **Vault Sync/Merge** — `passlane sync` to merge a synced/remote copy of the vault with local changes; natural fit for vaults kept in Dropbox/iCloud/Syncthing folders |
| Attachments, read + write | `Entry::attachments: HashMap<String, Attachment>`; binaries written to the inner-header pool on save | Attachment Support (see Advanced Features) |
| Custom string fields, read + write | `Entry::get(key)`, `Entry::set_additional_attribute(key, value)` | Custom Fields (see Advanced Features). Chosen direction: also migrate payment cards from "Key: value" lines in the notes field to proper protected custom fields, with transparent read-migration for existing vaults |
| Recycle bin / trash | `Database::create_recycle_bin()`, `node_is_in_recycle_bin()`, `recycle_bin_enabled()`; `merge` honors deletions | Trash/restore workflow — today passlane disables the recycle bin and deletes are permanent |
| Entry history round-trip | `Entry::get_history()`, `update_history()`, `purge_history()`; history is merged by `Database::merge` | Password History/Versioning (see Security Enhancements) |
| YubiKey challenge-response (`challenge_response` feature) | `DatabaseKey::with_challenge_response_key(ChallengeResponseKey)` with `LocalChallenge(secret)` / `YubikeyChallenge(slot)` variants | ✅ Done — `passlane hwkey add/remove/status` plus an optional step in `passlane init`; enrollment config in `~/.passlane/.hwkey` |
| JSON serialization (`serialization` feature) | `Database` implements `Serialize` | JSON export / backup tooling beyond the entry-level `--json` output |
| KDBX 4.1 + diagnostics | `Database::get_version()` reads the version without decrypting; `DatabaseVersion::KDB4(minor)`; QualityCheck | `passlane info` vault diagnostics; upgrade-on-save for legacy KDBX3 vaults (only KDBX 4.x can be saved today) |
| Icons | `Icon`/`IconId`/`CustomIcon`, `Database::purge_unused_custom_icons()` | Low priority for a CLI; useful if `list` output ever gets icons or exports target GUI clients |

### Future Enhancements

#### Import/Export
- [ ] Direct import from Chrome/Firefox password exports
- [ ] Import from Bitwarden export
- [ ] Import from KeePassXC
- [ ] **QR Code Export for TOTP** - Generate QR codes to transfer to mobile apps

#### Management Features
- [ ] **Vault Backup Management** - `backup create`, `backup list`, `backup restore`
- [ ] **Vault Statistics Dashboard** - `passlane stats` showing password health metrics
- [ ] **Template System** - Pre-defined templates for common services (AWS, GitHub, etc.)
- [ ] **Alias Support** - Create shortcuts for frequently accessed entries
- [ ] **Batch Operations** - Delete/export multiple entries by tag or pattern

#### Additional Entry Types
- [ ] **SSH Key Management** - Store and manage SSH keys
- [ ] SSH Agent integration for automation

#### Nice to Have
- [ ] Update notifications (opt-in check for new versions)
- [ ] Make it possible to sign up to a mailing list to be notified of updates
- [ ] Improve readme
- [ ] Try icloud db storage
- [ ] Add an option to pass master password from the command line
- [ ] remove anyhow?

### Completed
- [x] Make sure first usage asks for configuration values to be stored in the config file
- [x] Show service field with only 30 first characters
- [x] Sanitize all input to be stored (to remove all characters not allowed in Keepass XML)
- [x] Show dates for each entry
- [x] Editing of entries
- [x] add TOTP support
- [x] first time vault creation
- [x] invalid password error message
- [x] OTP support

### Scription examples

With JSON output, following could be done.

NOT: make sure you have unlocked the vault before running these commands. Alternatively, you can use the `---master-pwd` flag to provide the password.

1. Integrate with other security tools:

```bash
# Get password and pipe it to a security analysis tool
passlane show alma --json | jq -r '.credentials[0].password' | password-strength-checker

# Bulk check all passwords
passlane list --json | jq -r '.credentials[].password' | password-strength-checker --bulk
```

2. Automated password rotation:

```bash
# Script to rotate passwords for all services
passlane list --json | jq -r '.credentials[] | .service + " " + .username' | while read service username; do
    new_password=$(generate-strong-password)
    update-service-password "$service" "$username" "$new_password"
    passlane update "$service" --username "$username" --password "$new_password"
done
```

3. Export to other password managers:

```bash
# Convert to 1Password format
passlane list --json | jq '
    .credentials[] | {
        title: .service,
        username: .username,
        password: .password,
        type: "login"
    }
' > 1password_import.json
```

4. Create custom reports:

```bash
# Find services using the same password
passlane list --json | jq -r '
    .credentials | group_by(.password) |
    map(select(length > 1) | map(.service)) |
    .[] | @csv
' | column -t -s, -n
```

5. Automate login processes:

```bash
# Use with Selenium for automated testing
SERVICE="https://example.com"
CREDS=$(passlane show "$SERVICE" --json)
USERNAME=$(echo "$CREDS" | jq -r '.credentials[0].username')
PASSWORD=$(echo "$CREDS" | jq -r '.credentials[0].password')

python <<EOF
from selenium import webdriver
driver = webdriver.Chrome()
driver.get("$SERVICE")
driver.find_element_by_id("username").send_keys("$USERNAME")
driver.find_element_by_id("password").send_keys("$PASSWORD")
driver.find_element_by_id("login").click()
EOF
```

6. Sync with cloud services:

```bash
# Sync passwords to a secure cloud storage
passlane list --json | jq -c '.credentials[]' | while read -r cred; do
    service=$(echo "$cred" | jq -r '.service')
    echo "$cred" | aws s3 cp - "s3://secure-bucket/passwords/$service.json"
done
```

7. Generate simple statistics:

```bash
# Count passwords by length
passlane list --json | jq -r '
    .credentials | map(.password | length) |
    group_by(.) | map({length: .[0], count: length}) |
    sort_by(.length)[] | [.length, .count] | @tsv
' | column -t
```

8. Create a simple API:

```bash
# Run a simple API server
passlane list --json > /tmp/passwords.json
python -m http.server 8000 &
curl http://localhost:8000/passwords.json | jq '.credentials[] | select(.service == "example.com")'
```
