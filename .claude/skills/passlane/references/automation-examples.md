# passlane automation examples

Ready-to-adapt patterns for using passlane in automations. All examples assume the vault is
unlocked (`passlane unlock`, plus `passlane unlock -o` for TOTP). Replace placeholder service names
and selectors with the real ones.

## 1. API login: basic auth + TOTP header

Fetch a credential and a fresh 2FA code, then call an API. Anchored regexes keep each lookup
unambiguous.

```bash
#!/usr/bin/env bash
set -euo pipefail

CREDS=$(passlane list '^github\.com$' --json)
USER=$(echo "$CREDS" | jq -r '.entries[0].username')
PASS=$(echo "$CREDS" | jq -r '.entries[0].password')

# Fetch the TOTP code just before the request. Exits non-zero if 0 or >1 authorizers match.
OTP=$(passlane show -o --once '^GitHub$')

curl -fsSL -u "$USER:$PASS" -H "X-GitHub-OTP: $OTP" https://api.github.com/user
```

Notes:
- `set -euo pipefail` makes the script abort if any `passlane` call fails (e.g. locked vault → exit
  1), instead of sending empty credentials.
- Capture secrets into variables; never inline them onto a command line that hits shell history.

## 2. Single-secret extraction with `show --out`

When you only need one password/token, `show --out` is the most direct. Example: load an API token
(stored as a credential) into the environment of a single subprocess, without exporting it globally.

```bash
TOKEN=$(passlane show '^api\.stripe\.com$' --out)
STRIPE_API_KEY="$TOKEN" ./deploy.sh
```

Or pipe it straight into the consumer so it never lands in a variable at all:

```bash
passlane show '^vault\.internal$' --out | some-tool --password-stdin
```

## 3. Browser login (compose with the `playwright-cli` skill)

This is a reference pattern, not a literal script — form selectors are site-specific. The agent
should drive the browser via the `playwright-cli` skill and use passlane only to source the secrets:

1. Read the credential:
   ```bash
   CREDS=$(passlane list '^example\.com$' --json)
   USER=$(echo "$CREDS" | jq -r '.entries[0].username')
   PASS=$(echo "$CREDS" | jq -r '.entries[0].password')
   ```
2. Navigate to the login page; fill the username field with `$USER` and the password field with
   `$PASS`; submit.
3. When the site prompts for a 2FA code, fetch it **at that moment** and fill it in:
   ```bash
   passlane show -o --once '^Example$'
   ```
   If the attempt fails (code expired between fetch and submit), re-fetch and retry — codes rotate
   every ~30 seconds.

Keep the secrets in the automation layer; do not print them into the page log or the transcript.

## 4. Read-only credential audit

`list --json` + `jq` enables safe, local analysis. Find credentials with short passwords:

```bash
passlane list --json \
  | jq -r '.entries[] | select(.password | length < 12) | .service'
```

Find reused passwords across services (groups of size > 1):

```bash
passlane list --json | jq -r '
  [.entries[] | {service, password}]
  | group_by(.password)
  | map(select(length > 1) | map(.service))
'
```

This reads cleartext passwords into the pipeline — run it locally and do not redirect the output to
a file or log.

## Robustness checklist

- **Exit code 1 means something actionable:** a locked vault, no match, or an ambiguous match for
  `--once`/`--out`. Check `$?` (or use `set -e`) and react — don't proceed on empty output.
- **Anchor regexes** (`'^github\.com$'`, `'^GitHub$'`) so single-secret commands resolve to exactly
  one entry. `show -o --once` and `show --out` error on multiple matches.
- **Re-fetch TOTP codes per attempt.** They expire within seconds; never cache or reuse a code.
- **If the vault is locked,** the right fix is for the user to run `passlane unlock` (and
  `passlane unlock -o`). The agent cannot supply the master password non-interactively.
