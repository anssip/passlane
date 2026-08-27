# Passlane

![passlane-logo-small](https://github.com/anssip/passlane/assets/271711/6041f6fb-816f-43e9-b54c-325180addef1)

A password manager and authenticator CLI using Keepass as the storage backend. In addition to passwords, it supports
**authenticator functionality** with Timed One Time Passwords (TOTP), secure saving and managing of
**payment cards** and **secure notes**.

Passlane uses the Keepass encrypted file format for storing the data.

Passlane is written in Rust.

## Latest release

### [v4.0.0](https://github.com/anssip/passlane/releases/tag/v4.0.0)

- Add multi-vault support: manage any number of named vaults (`vault add`, `vault list`, `vault use`, `vault remove`, `vault rename`, `vault info`), switch with the global `--vault <NAME>` flag or `PASSLANE_VAULT` env var, and track the active vault. All entry types (credentials, payment cards, notes, TOTP) can now live in any vault. The pre-multi-vault config is migrated automatically on first run (main vault → `default`, TOTP vault → `totp`); `unlock -o`/`passwd -o` remain as legacy aliases for `--vault totp`
- Add hardware key (YubiKey) challenge-response as an additional unlock factor for the main vault
- Align the stored entry format with the KeePass entry model: credentials and payment cards are stored in custom fields instead of notes, improving compatibility with other KeePass clients
- Upgrade keepass-ng from 0.9 to 0.11. Existing vaults are upgraded in memory from KDBX 4.0 to KDBX 4.1 on open, so the first save after upgrading works (keepass-ng 0.11 only writes KDBX 4.1; the format is a superset of 4.0 that all current KeePass clients read). Verified round-trip with KeePassXC, including TOTP entries
- Fix: payment cards saved without a billing address no longer fail to load ("InvalidFormat" panic); card fields in the notes are now matched by name instead of line position, so notes reordered in another KeePass client still load, and an unparseable expiry skips the entry instead of panicking

See the [full changelog](CHANGELOG.md) for earlier releases.

## Features

- Keepass storage format which allows you to use the vault with other Keepass compatible applications
  - Supports KDB, KDBX3 and KDBX4 file formats
  - The keepass storage file can be optionally secured using a [key file](https://keepassxc.org/docs/) to provide additional protection
  - Optional hardware key (e.g. a YubiKey) challenge-response factor for unlocking the vault
- Generate and save passwords
- Full KeePass entry format for credentials: title, URL, note, tags, expiry date and custom attributes (custom fields) — all fields are visible in other KeePass compatible applications
- Add optional notes to credentials (useful when you have several accounts on the same service)
- Save and view payment card information
- Save and view secure notes
- Authenticator functionality with TOTP
- Import passwords from CSV files
- Export vault contents to CSV files
- Clipboard auto-clear: passwords are automatically cleared from the clipboard after 20 seconds
- `--out` flag for scripting: output passwords to stdout instead of the clipboard
- Shell tab completion for bash, zsh, and fish with dynamic title/username suggestions
- REPL mode (interactive mode)

## Table of contents

- [Interactive Mode (REPL)](#interactive-mode-repl)
- [Installation](#installation)
- [Usage](#usage)
  - [Locking and unlocking the vault](#locking-and-unlocking-the-vault)
  - [Hardware key (YubiKey) unlock](#hardware-key-yubikey-unlock)
  - [Generating and saving passwords](#generating-and-saving-passwords)
  - [Using saved credentials](#using-saved-credentials)
  - [Payment cards](#payment-cards)
  - [Secure notes](#secure-notes)
  - [Authenticator functionality](#authenticator-functionality)
  - [Migrating from 1Password, LastPass, Dashlane etc.](#migrating-from-1password-lastpass-dashlane-etc)
  - [Import from CSV](#import-from-csv)
  - [Export to CSV](#export-to-csv)
  - [Scripting and Automation](#scripting-and-automation)
    - [AI Agent Skill](#ai-agent-skill)
  - [Shell Completion](#shell-completion)
- [Syncing data to your devices](#syncing-data-to-your-devices)
- [Security](#security)
- [Other Keepass compatible applications](#other-keepass-compatible-applications)

## Interactive Mode (REPL)

The easiest way to get started with Passlane is to simply run it:

```bash
passlane
```

This launches an interactive session where you can use all of Passlane's features with short, easy-to-remember commands. If this is your first time, Passlane will walk you through creating a vault automatically.

```
🔐 Passlane — interactive mode
Type 'help' for commands, 'quit' to exit.

passlane> show user@
Found 3 credentials:
+---+------------------+---------------------+
|   | Title            | Username/email      |
+===+==================+=====================+
| 0 | github.com       | user@example.com    |
| 1 | google.com       | user@gmail.com      |
| 2 | aws.amazon.com   | user@company.com   |
+---+------------------+---------------------+
> To show one of these credentials, please enter a row number from the table above: 0
Unlocking vault...
+----------------+----------------------+
| Title          | github.com           |
|----------------+----------------------|
| URL            | https://github.com   |
|----------------+----------------------|
| Username       | user@example.com     |
|----------------+----------------------|
| Tags           | work                 |
|----------------+----------------------|
| Expires        | -                    |
|----------------+----------------------|
| Last modified  | 23.08.2026 09:34     |
+----------------+----------------------+
Password copied to clipboard!

passlane> add card
Enter card name: ...

passlane> gen
kX9#mP2$vL5@nQ8w
Password copied to clipboard.

passlane> quit
```

### Available REPL commands

| Command                   | Description                             |
| ------------------------- | --------------------------------------- |
| `show [type] [pattern]`   | Show entries (default: all credentials) |
| `add [type]`              | Add a new entry (default: credential)   |
| `edit [type] [pattern]`   | Edit an existing entry                  |
| `delete [type] [pattern]` | Delete an entry                         |
| `gen`                     | Generate a random password              |
| `import <file>`           | Import credentials from a CSV file      |
| `export [type] <file>`    | Export entries to a CSV file            |
| `unlock [otp]`            | Store master password in keychain       |
| `lock`                    | Remove master passwords from keychain   |
| `status`                  | Show vault status                       |
| `completions`             | Show how to install shell completions   |
| `help [command]`          | Show help for a command                 |
| `quit` / `exit`           | Exit the session                        |

**Types:** `creds` (default), `cards`, `notes`, `otp` — with aliases like `cred`, `card`, `note`, `totp`, `payments`, `credentials`.

The REPL supports **tab completion** for commands and types, and **command history** (up/down arrows) that persists across sessions.

> **Note:** All REPL functionality is available as CLI subcommands (`passlane show`, `passlane add`, etc.). For example, to generate a password from the command line without entering the REPL, use `passlane gen`.

## Installation

1. Download the [latest release](https://github.com/anssip/passlane/releases)
2. Unpack the archive
3. Place the unarchived binary `passlane` to your $PATH

### To compile from sources

1. Install rust development environment: [rustup](https://rustup.rs)
2. On Linux, install the USB development packages needed by the hardware key support: `libusb-1.0-0-dev` and `libudev-dev` on Debian/Ubuntu, or `libusb-devel` and `systemd-devel` on Fedora. macOS and Windows need no extra prerequisites.
3. Clone this repo
4. Run build: `cargo build --release`
5. Add the built `passlane` binary to your `$PATH`

### Nix

Run with nix - following launches the interactive REPL:

```bash
nix run github:anssip/passlane
```

To generate a password directly:

```bash
nix run github:anssip/passlane -- gen
```

See below for more information on how to use the CLI.

## Usage

### First time setup

Run the init command to create a new vault file, or to link passlane to an existing Keepass compatible vault file. The command will interactively ask you for the required information.

```bash
passlane init
```

You place the vault file to the cloud allowing access from all your devices. [See below for more info](#syncing-data-to-your-devices).

### Keypass key file

In addition to the master password, you can use a key file to provide additional protection for the vault file. At this
time, Passlane cannot be used to create a key file, but you can create one with KeepassXC or other Keepass compatible
app. Once you have the file, configure the location of this file in the `.keyfile_path` file in the `~/.passlane/` directory.

### Hardware key (YubiKey) unlock

You can require a hardware security key (such as a YubiKey) as an additional unlock factor for the main vault, using the
same HMAC-SHA1 challenge-response mechanism as KeepassXC. The vault is then encrypted with the master password (and key
file, if configured) plus the hardware key: something you know + something you have.

Note that this is *not* the same as passkeys (FIDO2/WebAuthn): it uses the key's HMAC-SHA1 challenge-response slots. A
YubiKey supports both, independently — enrolling a slot does not interfere with passkey use on the same device.

Prerequisite: program one of the key's challenge-response slots and save the printed secret. It is the only way to
recover the vault if the key is lost:

```bash
ykman otp chalresp --generate 2
```

Enroll the key (or answer yes to the hardware key question during `passlane init` when creating a new vault):

```bash
passlane hwkey add
```

After enrolling, the hardware key must be connected whenever the vault is opened or saved:

- Read commands (`show`, `list`, `export`) need one touch, when opening the vault.
- Commands that modify the vault (`add`, `edit`, `delete`, `csv`, `passwd`) touch the key twice: once to open the vault, and once to authorize saving.

`passlane unlock` still caches the master password in the keychain — the hardware key does not replace the password, it
adds a factor on top of it.

Check the enrollment status and connected keys:

```bash
passlane hwkey status
```

Remove the hardware key from the vault (requires one last touch):

```bash
passlane hwkey remove
```

If the key is lost, recover using the backed-up slot secret printed by ykman:

```bash
passlane hwkey remove --secret
```

The vault remains usable in other Keepass compatible applications: register the same challenge-response slot in e.g.
KeepassXC's database security settings. On Linux, USB access to the key requires libusb to be installed.

### Locking and unlocking the vault

Use the unlock command to store the active vault's master password in your computer's keychain. This way you don't have to enter the
master password every time you access your passwords and other vault contents. On Macs you can then use biometric authentication
to gain access to the keychain and further to the vault without typing any passwords.

```bash
passlane unlock
```

You can later remove the master password from the keychain with the lock command. It locks the vault given
with `--vault`, or the active vault; `passlane lock --all` locks every configured vault.

```bash
passlane lock
```

To get help on the available commands:

#### Changing the master password

Rotate the master password of the vault with the `passwd` command. You'll be prompted for the current master password (always — the keychain-stored value is not used here), and then twice for the new one. The vault file is re-encrypted in place with a key derived from the new password. If the current master password was stored in the system keychain, the entry is updated automatically so that subsequent unlocks keep working seamlessly.

```bash
passlane passwd
```

To change the master password of another vault, target it with `--vault`:

```bash
passlane passwd --vault work
```

### Multiple vaults

Passlane can manage any number of named vaults — for example personal, work and family. Each vault is a
separate Keepass file with its own location, master password, optional keyfile and optional hardware-key
(YubiKey) protection. Any vault can hold credentials, payment cards, secure notes **and** one time
passwords.

Vaults are registered in `~/.passlane/vaults.json`; one vault is marked as the **active vault** and is
used by all commands by default.

```bash
# List vaults (the * marks the active one) and their lock state
passlane vault list

# Create a new vault, or register an existing Keepass file, interactively
passlane vault add work

# Switch the active vault
passlane vault use work

# Show details of one vault
passlane vault info work

# Rename or deregister (the vault file is never deleted)
passlane vault rename work company
passlane vault remove work
```

Every command accepts the global `--vault <name>` flag (or the `PASSLANE_VAULT` environment variable)
to operate on another vault without switching:

```bash
passlane --vault work show google
PASSLANE_VAULT=work passlane list --json
```

Each vault is unlocked and locked separately, so your personal vault can stay unlocked while the work
vault stays locked (`passlane unlock --vault work`, `passlane lock --vault work`).

```bash
➜ passlane -h

A password manager using Keepass as the storage backend.

Usage: passlane [OPTIONS] [COMMAND]

Commands:
  init       Initialize passlane. Walks you through the configuration process.
  vault      Manage vaults: list them, add one, switch the active vault, remove or rename.
  add        Adds an item to the vault. Without arguments adds a new credential, use -p to add a payment card and -n to add a secure note.
  edit       Edit an entry.
  csv        Imports credentials from a CSV file.
  delete     Deletes one or more entries.
  show       Shows one or more entries.
  list       Lists entries from the vault for scripting and automation. WARNING: outputs passwords to stdout.
  lock       Lock a vault by removing its stored master password. Use --all to lock every vault.
  unlock     Unlock a vault: open it and store the master password in the keychain.
  passwd     Change the master password of the vault.
  hwkey      Manage the hardware key (e.g. a YubiKey) that protects a vault with challenge-response.
  export     Exports the vault contents to a CSV file.
  gen        Generate a random password and copy it to the clipboard.
  repl       Launch the interactive REPL session.
  completions  Generate shell completions and save to ~/.passlane/. Shows the line to add to your shell rc file.
  help       Print this message or the help of the given subcommand(s)

Options:
      --vault <NAME>  Name of the vault to use for this command. Defaults to $PASSLANE_VAULT, then the active vault (see 'passlane vault use'). [env: PASSLANE_VAULT=]
  -h, --help          Print help
```

### Generating and saving passwords

To generate a new password without saving it. The generated password value is copied to the clipboard and **automatically cleared after 20 seconds**. If you press Ctrl+C during the wait, the clipboard is cleared immediately before exiting.

```bash
passlane gen
```

To generate a password and print it to stdout without copying to the clipboard (useful for scripting):

```bash
passlane gen --out
```

To save new credentials by copying the password from clipboard:

```bash
passlane add --clipboard
```

To generate a new password and save credentials with one command:

```bash
passlane add -g
```

When adding credentials, you will be prompted for a title, an optional URL, the username and an optional note. The note is useful for annotating entries, e.g., "work account" or "admin access".

Credentials also support **advanced fields** — tags, an expiry date and custom attributes (KeePass custom fields). They are never prompted by default; answer yes to the "Configure advanced fields?" question when adding or editing a credential to set them:

- **Tags** — free-form labels, separated by semicolons; entries can be searched by tag with `show`/`list`
- **Expiry date** — marks the credential as expiring on a given date (`YYYY-MM-DD`)
- **Custom attributes** — extra name/value fields stored on the entry, e.g., a recovery code or a customer number; they are also visible in other KeePass compatible applications

When editing, skipping the advanced prompt keeps any existing tags, expiry date and custom attributes unchanged.

### Using saved credentials

You can search and show saved credentials with regular expressions

```bash
passlane show <regexp>
```

Run `passlane show foobar.com` → shows the full details of the matching credential (title, URL, username, note, tags, expiry date and custom attributes) and copies its password to the clipboard. The clipboard is **automatically cleared after 20 seconds**. If you press Ctrl+C during the wait, the clipboard is cleared immediately before exiting.

To print the password to stdout instead of copying to the clipboard (useful for scripting):

```bash
passlane show <regexp> --out
```

If the search finds more than one matches:

```bash
➜  bin passlane show google
Unlocking vault...
Found 5 credentials:
+---+------------------------------------------+--------------------------------+
|   | Title                                    | Username/email                 |
+===+==========================================+================================+
| 0 | google.com                               | anssi@emmy.fi                  |
|   | 📝 personal         Modified: 23.10.2024 |                                |
|---+------------------------------------------+--------------------------------|
| 1 | accounts.google.com                      | anssi@amm.co.jp                |
|   | 🔗 https://accounts.google.com           |                                |
|   | 🏷 work          Modified: 23.04.2024    |                                |
|---+------------------------------------------+--------------------------------|
| 2 | google.com                               | anssi.piirainen@flowplayer.com |
|   | 📝 work account  Modified: 23.04.2024    |                                |
|---+------------------------------------------+--------------------------------|
| 3 | google.com                               | anssip                         |
|   | Modified: 23.04.2024 14:15               |                                |
|---+------------------------------------------+--------------------------------|
| 4 | google.com                               | anssi@carbon.video             |
|   | 📝 Carbon Video  Modified: 23.04.2024    |                                |
+---+------------------------------------------+--------------------------------+
? To show one of these credentials, please enter a row number from the table above
[Press q to exit without showing the credential]
```

Each credential row shows the title and username on the first line, and optional details — URL (🔗), tags (🏷), note (📝) and the last modified date — on the following lines. Notes are useful for distinguishing between multiple accounts on the same service.

Selecting a row shows the full entry details, including tags, expiry date and custom attributes, and copies the password to the clipboard. Add `-v` to also display the password in the detail view.

### Payment cards

To list all your saved payment cards.

```bash
➜  bin passlane show -p
Unlocking vault...
Found 3 payment cards:
+---+-------------------------+------------+-------+--------+------------------+
|   | Name                    | Last 4     | Color | Expiry | Modified         |
+==============================================================================+
| 0 | OP Corporate Gold (NPD) | •••• 4821  | Gold  | 1/2029 | 23.10.2024 13:15 |
|---+-------------------------+------------+-------+--------+------------------|
| 1 | Binance                 | •••• 7703  | black | 4/2010 | 23.10.2024 13:15 |
|---+-------------------------+------------+-------+--------+------------------|
| 2 | Visa Gold (personal)    | •••• 9156  | Gold  | 6/2025 | 23.10.2024 13:15 |
+---+-------------------------+------------+-------+--------+------------------+
? To see card details, enter a row number from the table above
[Press q to exit without showing]
```

To save a payment card:

```bash
passlane add -p
```

You can delete a note with the delete command and the -n option.

### Secure notes

You can also save and manage **secure notes** in Passlane. The contents of notes, the title and the note text itself, are all fully encrypted and only visible to you.

You can store multiline notes in the vault. To add a secure note:

```
passlane add -n
```

To delete secure notes:

```
passlane delete -n
```

To show secure notes:

```
passlane show -n
```

### Authenticator functionality

One time passwords (OTPs) are entries in a vault, just like credentials, cards and notes — any vault
can hold them. Fresh installs get a single vault; if you want the two-factor-authentication benefit of
keeping the OTP seeds in a different file (and behind a different password) than your passwords,
create a second vault for them:

```bash
passlane vault add totp
```

That vault gets its own master password, which you can store in your computer's keychain to avoid
typing it every time:

```bash
passlane unlock --vault totp
```

To add a new one time password authentication entry to the current vault:

```bash
passlane add -o
```

Use -o to show the one time passwords. Following lists all OTP entries in the active vault:

```bash
passlane show -o
```

To look up by name of the issuer, use the following command:

```bash
passlane show -o heroku
```

the output will be:

```bash
Unlocking vault...
Found 1 matching OTP authorizers:

Code 447091 (also copied to clipboard). Press q to exit.
Next code in 23 seconds
.......................
.......................
Code 942344 (also copied to clipboard). Press q to exit.
Next code in 30 seconds
..............................
...
```

Upgrading from an older Passlane that had a separate TOTP vault file? The first run of the new version
migrates it automatically: the old TOTP vault becomes a regular vault named `totp`, and the old
password vault becomes the vault named `default`. `passlane unlock -o` keeps working as an alias for
`passlane --vault totp unlock`.

#### Getting a single code for scripts

The interactive `show -o` above never exits on its own. For scripting, use `show -o --once <regexp>` to print the current code for the single matching authorizer to stdout and exit immediately — no clipboard, no countdown, no keypress:

```bash
passlane show -o --once braintree
# 447091
```

It exits non-zero if no authorizer matches, or if more than one matches (it lists the matched labels instead of prompting). Codes are short-lived, so fetch them right before use.

To get codes for one or more authorizers non-interactively, use `list -o --code` (see [Scripting and Automation](#scripting-and-automation) below).

### Import from CSV

You can import credentials from a CSV file. With this approach, you can easily migrate from less elegant and often expensive commercial services.

First, make sure that the CSV file has a header line (1st line) with the following column titles:

- username
- password
- title (or `service` / `url` — older Passlane exports and [Firefox exports](https://support.mozilla.org/en-US/kb/export-login-data-firefox) work out of the box)
- url (optional)
- note (optional)
- tags (optional, separated by semicolons)
- expires (optional, `true`/`false`) and expiry_time (optional, RFC 3339 timestamp, e.g. `2027-01-31T00:00:00Z`)
- custom_attributes (optional, `key=value` pairs separated by semicolons)

The `title` field is the name of the service. The `service` and `url` columns are accepted as aliases for it, so no preparation is needed for older Passlane exports or Firefox-exported CSVs — in Firefox exports the URL doubles as the title. All other columns are optional — if omitted, credentials will be imported without them.

To export the credentials to a CSV file and import the file into Passlane:

```bash
passlane csv <path_to_csv_file>
```

Here are links to instructions for doing the CSV export:

- [Firefox](https://support.mozilla.org/en-US/kb/export-login-data-firefox)
- [LastPass](https://support.lastpass.com/help/how-do-i-nbsp-export-stored-data-from-lastpass-using-a-generic-csv-file)
- [1Password](https://support.1password.com/export/)
- [Dashlane](https://support.dashlane.com/hc/en-us/articles/202625092-Export-your-passwords-from-Dashlane)

### Export to CSV

You can export all your vault contents to CSV files. The exported files can be imported to other password managers or to a spreadsheet program.

To export credentials to a file called creds.csv

```bash
passlane export creds.csv
```

The credentials CSV includes all entry fields: title, url, username, note, tags, expiry and custom_attributes — using the same column format that [import accepts](#import-from-csv).

To export payment cards to a file called cards.csv.

```bash
passlane export -p cards.csv
```

To export secure notes to a file called notes.csv

```bash
passlane export -n notes.csv
```

### Scripting and Automation

The `list` command provides machine-readable output for scripting and automation. Unlike `show`, it prints all matches to stdout without clipboard interaction or interactive prompts.

For quick single-password lookups in scripts, you can also use `show --out` or `gen --out` to print a password to stdout without clipboard interaction:

```bash
# Get a single password to stdout
passlane show github --out

# Generate a password to stdout
passlane gen --out
```

> **⚠️ Security Warning:** The `list` command and `--out` flag output passwords and secrets to stdout. Be careful when redirecting output to files or using in scripts that log output.

```bash
# List all credentials
passlane list

# List credentials matching a regex
passlane list google

# List all credentials as JSON
passlane list --json

# List specific entry types
passlane list -p              # payment cards
passlane list -n              # secure notes
passlane list -o              # TOTP entries (stored secrets/config)
passlane list -p --json       # payment cards as JSON

# Generate the currently valid TOTP codes (not the stored secrets)
passlane list -o --code              # plain text: label + current code
passlane list -o --code braintree    # only authorizers matching the regex
passlane list -o --code --json       # JSON envelope: type "totp_codes"

# Verbose plain text (includes passwords)
passlane list -v
```

`list -o --code` outputs the *generated* code for each matching authorizer instead of the stored secret. The JSON form uses the envelope `{ "type": "totp_codes", "count": <n>, "entries": [{ "label", "issuer", "code", "valid_for_seconds" }] }`. The stored secret is never included in code output, and codes are valid only for `valid_for_seconds`, so fetch them right before use.

#### Scripting Examples

Find duplicate passwords using `jq`:

```bash
passlane list --json | jq -r '
  .entries | group_by(.password) |
  map(select(length > 1) | {
    password: .[0].password,
    titles: [.[].title]
  })
'
```

Extract credentials for a specific service:

```bash
CREDS=$(passlane list github --json)
USERNAME=$(echo "$CREDS" | jq -r '.entries[0].username')
PASSWORD=$(echo "$CREDS" | jq -r '.entries[0].password')
NOTE=$(echo "$CREDS" | jq -r '.entries[0].note // empty')
```

Export to another format:

```bash
passlane list --json | jq '.entries[] | {title, username, password}' > export.json
```

Fetch a TOTP code to log in non-interactively:

```bash
# Single authorizer: print just the code and exit
CODE=$(passlane show -o --once braintree)

# Or pick a code out of the JSON envelope
CODE=$(passlane list -o --code braintree --json | jq -r '.entries[0].code')
```

#### AI Agent Skill

Passlane ships with a **Claude Agent Skill** that teaches an AI agent how to drive these scripting
features — fetching credentials, generating TOTP codes, and wiring them into website/API login
automations. The skill lives in [`.claude/skills/passlane/`](.claude/skills/passlane/) (also
reachable via the top-level `skills/` symlink).

Install it into your own agent by copying the folder into your skills directory:

```bash
# User-level (available to all your projects)
cp -r /path/to/passlane/.claude/skills/passlane ~/.claude/skills/

# Or project-level
cp -r /path/to/passlane/.claude/skills/passlane <your-project>/.claude/skills/
```

The agent can only read your vault non-interactively while it is unlocked — run `passlane unlock`
first (and `passlane unlock --vault totp` if your OTP entries live in a separate vault), since there
is no way to supply the master password unattended.

### Shell Completion

Passlane supports tab completion for bash, zsh, and fish. In addition to completing subcommands and flags, it provides **dynamic completions** that suggest entry titles and usernames from your vault.

#### Enabling shell completion

Run the `completions` command to generate and install the completion script for your shell:

```bash
# Auto-detect your shell
passlane completions

# Or specify the shell explicitly
passlane completions zsh
passlane completions bash
passlane completions fish
```

This saves the completion script to `~/.passlane/completions.<shell>` and prints the `source` command to add to your shell rc file. For example, for zsh:

```
Completions saved to /Users/you/.passlane/completions.zsh

Add this line to ~/.zshrc:

  source "/Users/you/.passlane/completions.zsh"

Then restart your shell or run the command above.
```

Add the printed `source` line to your rc file (`~/.zshrc`, `~/.bashrc`, or `~/.config/fish/config.fish`), then restart your shell.

> **Tip:** After upgrading Passlane, re-run `passlane completions` to regenerate the script with any new commands.

#### Dynamic completions

When your vault is unlocked, Passlane maintains a lightweight completion cache per vault at `~/.passlane/.completion_cache.<name>` containing entry titles and usernames (no passwords or secrets). This enables dynamic tab completions for `show`, `edit`, `delete`, and `list` commands; the completions follow the active vault.

The cache is automatically:

- **Created** when you run `passlane unlock` or any command that opens the vault
- **Updated** when you add, edit, delete, or import entries
- **Refreshed** when older than 7 days (if the vault is unlocked via keychain)
- **Deleted** when you run `passlane lock`

#### Examples

Complete subcommands:

```bash
$ passlane sh<TAB>
show
```

Complete flags:

```bash
$ passlane show -<TAB>
-p  -n  -o  -v  -c  --out
```

Complete entry titles and usernames from your vault:

```bash
$ passlane show gi<TAB>
github.com:alice@example.com    gitlab.com:bob@company.com

$ passlane show goo<TAB>
google.com:user@gmail.com    google.com:user@work.com

$ passlane edit git<TAB>
github.com:alice@example.com    gitlab.com:bob@company.com

$ passlane delete drop<TAB>
dropbox.com:user@example.com
```

When the vault is locked (cache file doesn't exist), completions fall back to subcommands and flags only — no entry titles are suggested.

## Syncing data to your devices

You can place vault files in a cloud storage service like Dropbox, Google Drive, or iCloud Drive.
This way you can access your passwords from all your devices.
By default, Passlane creates new vaults in the `~/.passlane/` directory; when adding a vault you can
point it at any location (e.g. a folder inside Dropbox). Existing vault files are registered the same
way with `passlane vault add` — or, since vaults are plain Keepass databases, moved and re-registered
at any time.

## Security

In July 2026 the full codebase went through a security audit, performed with Claude Fable 5,
covering cryptography, secret handling, vault file I/O, file permissions, logging, and
dependencies. The audit found 9 issues —
3 high, 3 medium, and 3 low severity — plus a handful of informational hardening recommendations.
All of them have been fixed.

The full report is available in [docs/security-audit-2026-07-19.md](docs/security-audit-2026-07-19.md).

## Other Keepass compatible applications

There are several other Keepass compatible applications that you can use to access the vault file:

- [KeepassXC](https://keepassxc.org/) is a desktop application for Windows, macOS, and Linux
- [KeepassXC-Browser](https://github.com/keepassxreboot/keepassxc-browser)
- [KeePassium](https://keepassium.com/) is a mobile application for iOS
- ... and many others
