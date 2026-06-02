---
name: passlane
description: Use passlane (a Keepass-backed password manager + authenticator CLI) to retrieve credentials, payment cards, secure notes, and generate TOTP codes for automation — e.g. programmatically logging into websites and APIs. Use when the user wants to script a login, fetch a password or 2FA code from their vault, audit stored credentials, or build automations that authenticate using passlane.
allowed-tools: Bash(passlane:*)
---

# passlane

`passlane` is a command-line password manager and authenticator that stores data in the Keepass
encrypted format. It holds **credentials** (service/username/password), **payment cards**,
**secure notes**, and **TOTP authenticators** (time-based 2FA codes). It exposes scripting-friendly
output (`--json`, `--out`, `--once`, `--code`) so agents can read secrets and feed them into
automations without touching the clipboard or any interactive UI.

There are **two separate vaults**, each with its own master password:
- the **main vault** — credentials, payment cards, secure notes
- the **TOTP vault** — authenticator secrets (addressed with the `-o` flag on most commands)

## Prerequisite: the vault must be unlocked

Non-interactive use requires the master password to be stored in the OS keychain. The **user** runs
these one-time, interactive setup commands themselves:

```bash
passlane unlock      # store the main vault master password in the OS keychain
passlane unlock -o   # store the TOTP vault master password in the OS keychain
passlane lock        # remove stored master passwords (re-locks)
```

There is **no environment variable or stdin** to supply the master password. If the vault is locked,
passlane will **block on an interactive prompt** — which hangs unattended automation. So:

> If a `passlane` command blocks or fails because the vault is locked, **stop and ask the user to
> run `passlane unlock` (and `passlane unlock -o` for 2FA codes)**. Do not try to supply the
> master password yourself.

## Reading secrets (the core of automation)

Two commands are built for scripts and print to **stdout**:

### `passlane list [REGEXP] [--json] [-v]`
Machine-readable listing. Default lists **credentials**; add a type flag to list something else:
`-p` payment cards, `-n` notes, `-o` TOTP entries. An optional `REGEXP` filters by service/issuer.

- `passlane list --json` — JSON envelope (best for parsing with `jq`).
- `passlane list github --json` — only entries matching `github`.
- `passlane list -v` — plain text **including passwords**.

> WARNING: `list --json` and `list -v` print **passwords in cleartext** to stdout. Default plain
> `list` (no `-v`) shows service/username/note only — no password.

### `passlane show <REGEXP> --out`
Print a **single** matched password to stdout — no clipboard, no countdown, exits immediately. Use
this when you need exactly one secret.

```bash
passlane show '^github\.com$' --out
```

**Rule of thumb:** use `list --json | jq` for structured extraction or multiple fields; use
`show --out` for one password.

## JSON output reference

Every `--json` response is an envelope:

```json
{ "type": "credentials", "count": 2, "entries": [ ... ] }
```

Entry fields by `type`:

| `type`          | entry fields |
| --------------- | ------------ |
| `credentials`   | `uuid`, `service`, `username`, `password`, `note` (optional), `last_modified` |
| `payment_cards` | `id`, `name`, `name_on_card`, `number`, `cvv`, `expiry` (`{month, year}`), `color?`, `billing_address?`, `last_modified` |
| `notes`         | `id`, `title`, `content`, `last_modified` |
| `totp`          | `id`, `label`, `issuer`, `secret`, `algorithm`, `period`, `digits`, `last_modified` |
| `totp_codes`    | `label`, `issuer`, `code`, `valid_for_seconds` — **never includes the stored secret** |

## TOTP / 2FA codes

Most logins need a fresh time-based code. Two ways to get one:

### `passlane show -o --once <REGEXP>` — recommended for a single code
Prints the one matching current code to stdout and exits.

```bash
passlane show -o --once github   # -> 447091
```

- **Zero matches** → exit code `1`, stderr: `No matching OTP authorizer found.`
- **Multiple matches** → exit code `1`, stderr: `Multiple OTP authorizers match: <labels>. Refine the search pattern to match exactly one.`

Because ambiguity is an error, **anchor your pattern** (e.g. `'^GitHub$'`) so it matches exactly one
authorizer.

### `passlane list -o --code [REGEXP] [--json]` — multiple codes / expiry window
Outputs the current code for every matching authorizer. With `--json`, each entry includes
`valid_for_seconds` so you know how long the code stays valid.

```bash
passlane list -o --code --json
```

> TOTP codes are valid only for a few seconds. **Fetch them just before use and never cache them.**
> Re-fetch on each retry.

## Other commands

| Command | Notes |
| ------- | ----- |
| `passlane gen [--out]` | Generate a random password. `--out` prints to stdout (otherwise copies to clipboard). |
| `passlane add [-p\|-n\|-o] [-g] [-l]` | Add a credential/card/note/TOTP. **Interactive** (prompts). |
| `passlane edit <REGEXP> [-p\|-n\|-o]` | Edit an entry. **Interactive.** |
| `passlane delete <REGEXP> [-c\|-p\|-n\|-o]` | Delete entries. **Interactive.** |
| `passlane csv <FILE>` | Import credentials from a CSV file. |
| `passlane export [-p\|-n\|-o] <FILE>` | Export the vault to CSV. |
| `passlane passwd [-o]` | Change a vault's master password. **Interactive.** |
| `passlane completions [SHELL]` | Generate shell completions (bash/zsh/fish). |
| `passlane init` | First-time setup. **Interactive.** |
| `passlane repl` | Interactive REPL (also launched by running `passlane` with no args). |

`add`, `edit`, `delete`, `passwd`, `init`, and `repl` are prompt-driven and **not suited to
unattended automation** — only the reading commands above are.

## Safety rules

- **Never** echo retrieved passwords or TOTP codes into chat, logs, or files you commit.
- Pipe secrets directly into the consuming command, or capture into a shell variable with
  `VAR=$(passlane ...)` — avoid inlining a secret into a command line where it lands in shell
  history or process listings.
- Fetch TOTP codes **just-in-time**, immediately before the request that uses them.
- Match patterns precisely (anchored regex) so `show -o --once` and `show --out` resolve to exactly
  one entry.
- Treat exit code `1` as actionable: a **locked vault**, **no match**, or **ambiguous match**. Check
  it and react rather than proceeding with empty output.

## Worked examples

For ready-to-adapt scripts — API login with basic auth + TOTP, single-secret extraction, browser
login combined with the `playwright-cli` skill, and a read-only credential audit — read
[references/automation-examples.md](references/automation-examples.md) when you are actually
building an automation.
