# Passlane

![passlane-logo-small](https://github.com/anssip/passlane/assets/271711/6041f6fb-816f-43e9-b54c-325180addef1)

A password manager and authenticator CLI using Keepass as the storage backend. In addition to passwords, it supports
**authenticator functionality** with Timed One Time Passwords (TOTP), secure saving and managing of
**payment cards** and **secure notes**.

Passlane uses the Keepass encrypted file format for storing the data.

Passlane is written in Rust.

## Features

- Keepass storage format which allows you to use the vault with other Keepass compatible applications
  - Supports KDB, KDBX3 and KDBX4 file formats
  - The keepass storage file can be optionally secured using a [key file](https://keepassxc.org/docs/) to provide additional protection
- Generate and save passwords
- Add optional notes to credentials (useful when you have several accounts on the same service)
- Save and view payment card information
- Save and view secure notes
- Authenticator functionality with TOTP
- Import passwords from CSV files
- Export vault contents to CSV files

## Table of contents

- [Interactive Mode (REPL)](#interactive-mode-repl)
- [Installation](#installation)
- [Usage](#usage)
  - [Locking and unlocking the vault](#locking-and-unlocking-the-vault)
  - [Generating and saving passwords](#generating-and-saving-passwords)
  - [Using saved credentials](#using-saved-credentials)
  - [Payment cards](#payment-cards)
  - [Secure notes](#secure-notes)
  - [Authenticator functionality](#authenticator-functionality)
  - [Migrating from 1Password, LastPass, Dashlane etc.](#migrating-from-1password-lastpass-dashlane-etc)
  - [Import from CSV](#import-from-csv)
  - [Export to CSV](#export-to-csv)
  - [Scripting and Automation](#scripting-and-automation)
- [Syncing data to your devices](#syncing-data-to-your-devices)
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

passlane> show
Found 3 credentials:
+---+------------------+---------------------+
|   | Service          | Username/email      |
+===+==================+=====================+
| 0 | github.com       | user@example.com    |
| 1 | google.com       | user@gmail.com      |
| 2 | aws.amazon.com   | admin@company.com   |
+---+------------------+---------------------+

passlane> show github
Password copied to clipboard!

passlane> add card
Enter card name: ...

passlane> gen
kX9#mP2$vL5@nQ8w
Password copied to clipboard.

passlane> quit
```

### Available REPL commands

| Command | Description |
|---------|-------------|
| `show [type] [pattern]` | Show entries (default: all credentials) |
| `add [type]` | Add a new entry (default: credential) |
| `edit [type] [pattern]` | Edit an existing entry |
| `delete [type] [pattern]` | Delete an entry |
| `gen` | Generate a random password |
| `import <file>` | Import credentials from a CSV file |
| `export [type] <file>` | Export entries to a CSV file |
| `unlock [otp]` | Store master password in keychain |
| `lock` | Remove master passwords from keychain |
| `status` | Show vault status |
| `help [command]` | Show help for a command |
| `quit` / `exit` | Exit the session |

**Types:** `creds` (default), `cards`, `notes`, `otp` — with aliases like `cred`, `card`, `note`, `totp`, `payments`, `credentials`.

The REPL supports **tab completion** for commands and types, and **command history** (up/down arrows) that persists across sessions.

> **Note:** All existing CLI subcommands (`passlane show`, `passlane add`, etc.) continue to work as before. To generate a password from the command line without entering the REPL, use `passlane gen`.

## Installation

1. Download the [latest release](https://github.com/anssip/passlane/releases)
2. Unpack the archive
3. Place the unarchived binary `passlane` to your $PATH

### To compile from sources

1. Install rust development environment: [rustup](https://rustup.rs)
2. Clone this repo
3. Run build: `cargo build --release`
4. Add the built `passlane` binary to your `$PATH`

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

### Locking and unlocking the vault

Use the unlock command to store the master password in your computer's keychain. This way you don't have to enter the
master password every time you access your passwords and other vault contents. On Macs you can then use biometric authentication
to gain access to the keychain and further to the vault without typing any passwords.

```bash
passlane unlock
```

You can later remove the master password from the keychain with the lock command.

The one time passwords (OTPs) are stored in a separate vault file. You can unlock it with the same command
accompanied with the -o option.

```bash
passlane unlock -o
```

To lock the vaults use the lock command. This locks both the password vault and the OTP vault:

```bash
passlane lock
```

To get help on the available commands:

```bash
➜ passlane -h

A password manager using Keepass as the storage backend.

Usage: passlane [COMMAND]

Commands:
  init    Initialize passlane. Walks you through the configuration process.
  add     Adds an item to the vault. Without arguments adds a new credential, use -p to add a payment card and -n to add a secure note.
  edit    Edit an entry.
  csv     Imports credentials from a CSV file.
  delete  Deletes one or more entries.
  show    Shows one or more entries.
  list    Lists entries from the vault for scripting and automation. WARNING: outputs passwords to stdout.
  lock    Lock the vaults to prevent all access
  unlock  Opens the vaults and grants access to the entries
  export  Exports the vault contents to a CSV file.
  gen     Generate a random password and copy it to the clipboard.
  repl    Launch the interactive REPL session.
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### Generating and saving passwords

To generate a new password without saving it. The generated password value is also copied to the clipboard.

```bash
passlane gen
```

To save new credentials by copying the password from clipboard:

```bash
passlane add --clipboard
```

To generate a new password and save credentials with one command:

```bash
passlane add -g
```

When adding credentials, you will be prompted for an optional note. This is useful for annotating entries, e.g., "work account" or "admin access".

### Using saved credentials

You can search and show saved credentials with regular expressions

```bash
passlane show <regexp>
```

Run `passlane show foobard.com` --> shows foobar.com's password and also copies the value to the clipboard.

If the search finds more than one matches:

```bash
➜  bin passlane show google
Unlocking vault...
Found 5 credentials:
+---+------------------------------------------+--------------------------------+
|   | Service                                  | Username/email                 |
+===+==========================================+================================+
| 0 | google.com                               | anssi@emmy.fi                  |
|   | 📝 personal         Modified: 23.10.2024 |                                |
|---+------------------------------------------+--------------------------------|
| 1 | https://accounts.google.com/si           | anssi@amm.co.jp                |
|   | Modified: 23.04.2024 14:15               |                                |
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
? To copy one of these passwords to clipboard, please enter a row number from the table above  
[Press q to exit without copying the password]
```

Each credential row shows the service and username on the first line, and an optional note (prefixed with 📝) along with the last modified date on the second line. Notes are useful for distinguishing between multiple accounts on the same service.

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

By default, Passlane stores the Timed One Time Passwords in a file named `totp.json` in the `~/.passlane/` directory.
You can change the location by storing the file path in a text file called `.totp_vault_path` in the `~/.passlane/` directory.
**We recommend that you store the file in a separate location that is different from the main vault file.** This way
you gain the benefit of two-factor authentication. You don't want to store these eggs in the same basket.

Here is an example where teh totp vault file is stored in Dropbox:

```bash
~/.passlane > cat .totp_vault_path
/Users/anssi/Dropbox/stuff/totp.kdbx
```

The TOTP vault has a separate master password that you need to enter when you access the one time passwords.
You can also store the master password in your computer's keychain to avoid typing it every time. Use
the unlock command with the `-o` option for this purpose.

```bash
passlane unlock -o
```

To add a new one time password authentication entry:

```bash
passlane add -o
```

Use -o to show the one time passwords. Following lists all OTP entries in the vault:

```bash
passlane show -o
```

To look up by name of the issuer, use the following command:

```bash
passlane show -o heroku
```

the output will be:

```bash
Unlocking TOTP vault...
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

### Import from CSV

You can import credentials from a CSV file. With this approach, you can easily migrate from less elegant and often expensive commercial services.

First, make sure that the CSV file has a header line (1st line) with the following column titles:

- username
- password
- service
- note (optional)

The `service` field is the URL or name of the service. The `note` column is optional — if omitted, credentials will be imported without notes. When importing from Dashlane, the only necessary preparation is to rename `url` to `service`.

To export the credentials to a CSV file and import the file into Passlane:

```bash
passlane csv <path_to_csv_file>
```

Here are links to instructions for doing the CSV export:

- [LastPass](https://support.lastpass.com/help/how-do-i-nbsp-export-stored-data-from-lastpass-using-a-generic-csv-file)
- [1Password](https://support.1password.com/export/)
- [Dashlane](https://support.dashlane.com/hc/en-us/articles/202625092-Export-your-passwords-from-Dashlane)

### Export to CSV

You can export all your vault contents to CSV files. The exported files can be imported to other password managers or to a spreadsheet program.

To export credentials to a file called creds.csv

```bash
passlane export creds.csv
```

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

> **⚠️ Security Warning:** The `list` command outputs passwords and secrets to stdout. Be careful when redirecting output to files or using in scripts that log output.

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
passlane list -o              # TOTP entries
passlane list -p --json       # payment cards as JSON

# Verbose plain text (includes passwords)
passlane list -v
```

#### Scripting Examples

Find duplicate passwords using `jq`:

```bash
passlane list --json | jq -r '
  .entries | group_by(.password) |
  map(select(length > 1) | {
    password: .[0].password,
    services: [.[].service]
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
passlane list --json | jq '.entries[] | {title: .service, username, password}' > export.json
```

## Syncing data to your devices

You can place the vault file to a cloud storage service like Dropbox, Google Drive, or iCloud Drive.
This way you can access your passwords from all your devices.
By default, Passlane assumes that the file is located at `~/.passlane/store.kdbx`.
You can change the location by storing the file path in a text file called `.vault_path` at the `~/.passlane/` directory.

For example, this shows how John has stored the path `/Users/john/Dropbox/Stuff/store.kdbx` to the `.vault_path` file:

```bash
➜  ~ cat ~/.passlane/.vault_path
/Users/john/Dropbox/Stuff/store.kdbx
```

## Other Keepass compatible applications

There are several other Keepass compatible applications that you can use to access the vault file:

- [KeepassXC](https://keepassxc.org/) is a desktop application for Windows, macOS, and Linux
- [KeepassXC-Browser](https://github.com/keepassxreboot/keepassxc-browser)
- [KeePassium](https://keepassium.com/) is a mobile application for iOS
- ... and many others
