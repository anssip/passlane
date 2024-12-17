# TODO

## Roadmap

### Next

- [ ] Make it possible to sign up to a mailing list to be notified of updates
- [ ] Add note field to credentials (userful when you have several accounts on the same service)
- [x] Make sure first usage asks for configuration values to be stored in the config file
- [x] Show service field with only 30 first characters
- [x] Sanitize all input to be stored (to remove all characters not allowed in Keepass XML)
- [x] Show dates for each entry
- [x] Editing of entries
- [ ] Add an option to pass master password from the command line
- [ ] Option to output JSON, for scripting
- [ ] remove anyhow?
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
