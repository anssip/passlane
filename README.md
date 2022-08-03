# Passlane

A lightning-fast password manager for the command line

![Screenshot](https://i.imgur.com/jCVJiLT.png)

## Features

- Generate passwords
- Place the generated password into the clipboard
- Save previously generated password from the clipboard
- Sync the generated password to OS specific keychains, including Mac's iCloud Keychain
- Import passwords from CSV files

### Online Vault

You can use Passlane in two different modes:

1. As a standalone CLI tool that stores the credentials on your local disk.
2. Use the Passlane Vault to store the, and have them safely available to all your devices and computers.

The Online Vault is secured by Auth0 and OAuth 2.0. All passwords are stored encrypted and the _master password_ is not stored on our servers. The master password is only used locally to descrypt the password values and never sent to our API servers.

The Online Vault will soon support team management features which makes it possible to safely share credentials with team members.

If you want to take advantage of the Passlane Vault, [head over to passlanevault.com and sign up](https://passlanevault.com).

## Installation

1. Download the [latest release](https://github.com/anssip/passlane/releases)
2. Unpack the archive
3. Place the unarchived binary `passlane` to your $PATH
4. Enjoy!

## Usage

```bash
$  passlane -h
passlane
A password manager and a CLI client for the online Passlane Vault

USAGE:
    passlane [SUBCOMMAND]

OPTIONS:
    -h, --help    Print help information

SUBCOMMANDS:
    add              Adds a new credential to the vault.
    csv              Imports credentials from a CSV file.
    delete           Deletes one or more credentials by searching with the specified regular
                     expression.
    help             Print this message or the help of the given subcommand(s)
    keychain-push    Pushes all credentials to the OS specific keychain.
    login            Login to passlanevault.com
    password         Change the master password.
    push             Pushes all local credentials to the online vault.
    show             Shows one or more credentials by searching with the specified regular
                     expression.
```

### Generate a new password

- Sign up for a new service in the web browser
- Run `passlane` --> gnerates and saves a new password to the clipboard
- Use the generated password from the clipboard
- After successful signup: Open terminal and run `passlane -s` to save the password

### Using saved credentials

Later on, when logging in to foobar.com:

- Run `passlane show foobard.com` --> copies foobar.com's password to clipboard.
- Use the password from clipboard to login

If the search finds more than one matches:

```bash
$ passlane show google.com
Please enter master password: *********
Found 9 matches:
+---+--------------------------------+------------------------------------+
|   | Service                        | Username/email                     |
+=========================================================================+
| 0 | https://accounts.google.com    | jack@megacorp.com                  |
|---+--------------------------------+------------------------------------|
| 1 | https://accounts.google.com    | jack1p@gmail.com                   |
|---+--------------------------------+------------------------------------|
| 2 | https://accounts.google.com    | jck@hey.com                        |
|---+--------------------------------+------------------------------------|
| 3 | https://accounts.google.com    | jackrussel@gmail.com               |
|---+--------------------------------+------------------------------------|
To copy one of these passwords to clipboard, please enter a row number from
the table above, or press q to exit: 3
Password from index 3 copied to clipboard!
```

_or alternatively_

- Let MacOS propose the saved password. It knows it because Passlane also syncs to the keychain.

### Syncing with the system Keychain

Passlane uses the [keyring crate](https://crates.io/crates/keyring) to sync credentials to the operating system's keychain. Syncing should work on Linux, iOS, macOS, and Windows.

Use option `add` command together with option `-k` to save the last generated password to the Passlane storage file _and_ to the keychain:

```
passlane add -k
```

To sync all Passlane stored options to the keychain use the `keychain-push` command:

```
passlane keychain-push
```

### Migrating from 1Password, LastPass, Dashlane etc.

You can import credentials from a CSV file. With this approach, you can easily migrate from less elegant and often expensive commercial services.

First, make sure that the CSV file has a header line (1st line) with the following column titles:

- username
- password
- service

The `service` field is the URL or name of the service. When importing from Dashlane, the only necessary preparation is to rename `url` to `service`.

To export the credentials to a CSV file and import the file into Passlane:

```bash
passlane csv <path_to_csv_file>
```

Here are links to instructions for doing the CSV export:

- [LastPass](https://support.lastpass.com/help/how-do-i-nbsp-export-stored-data-from-lastpass-using-a-generic-csv-file)
- [1Password](https://support.1password.com/export/)
- [Dashlane](https://support.dashlane.com/hc/en-us/articles/202625092-Export-your-passwords-from-Dashlane)

## Roadmap

### 1.0

- [x] access_token expiration handling: add created Instant to AccessTokens
- [x] --save option to save online
- [x] --csv to push to online vault, if user has a vault
- [x] switch to use commands instead of options in the command line
- [x] delete to delete from the online vault

### 2.0 (upcoming)

- [] multiple vaults support
- [] web UI for the online service

### previous versions

- [x] delete passwords
- [x] show grep results in a table, copy password to clipboard by row index

- [x] if "Failed: Unable to retrieve value from clipboard" --> prompt for the password to be saved
- [x] [read password without showing input](https://stackoverflow.com/questions/28924134/how-can-i-get-password-input-without-showing-user-input)
- [x] import from CSV
- [x] separate CLI option to sync to keychain
- [x] possibility to show passwords when multiple search matches
