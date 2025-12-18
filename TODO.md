# TODO

## Roadmap

### High Priority / Next Up

#### Core Features
- [ ] **JSON Output for Scripting** ⭐ - Add `--json` flag to show, export, and new list command for automation
- [ ] Add note field to credentials (useful when you have several accounts on the same service)
- [ ] **Configurable Password Generation** - Support options like `--length`, `--no-special`, `--passphrase`
- [ ] **Fuzzy Search** - Support fuzzy matching instead of just regex (e.g., `passlane show goog` finds "google.com")
- [ ] **Password Strength Analysis** - Built-in password strength checker and audit command

#### Security Enhancements
- [ ] **Password Audit Command** - Identify weak, reused, or old passwords
- [ ] Check against pwned passwords API integration
- [ ] **Password History/Versioning** - Track password changes over time
- [ ] **Clipboard Timeout** - Auto-clear clipboard after X seconds
- [ ] **Auto-lock on Timeout** - Remove from keychain after period of inactivity
- [ ] Master password strength enforcement on init

#### UX Improvements
- [ ] Show first 4 digits of payment card numbers in list
- [ ] **Shell Completion** - Generate completion scripts for bash/zsh/fish
- [ ] **Duplicate Detection** - Warn when adding similar credentials
- [ ] Better table formatting with color coding for password age/strength
- [ ] Interactive mode / REPL (`passlane shell`)

#### Advanced Features
- [ ] **Tags/Categories** - Tag credentials and filter by tags
- [ ] **Favorites/Pinning** - Quick access to frequently used credentials
- [ ] **Multi-Vault Support** - Manage multiple vaults (personal, work, family)
- [ ] **Custom Fields** - Support arbitrary fields (API keys, security questions, etc.)
- [ ] **Attachment Support** - Store files in vault (Keepass supports this)

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
