# Passlane

A lightning-fast password manager for the command line. The data is saved in an online vault at [passlanevault.com](https://passlanevault.com). There is also a web interface that you can use to access your credentials on any device.

![Screenshot](https://i.imgur.com/TMB8DbS.png)

## Features

- Generate and save passwords
- Full management features
- Online storage
- Sync the generated password to OS specific keychains, including Mac's iCloud Keychain
- Import passwords from CSV files

### Online Vault

You can use Passlane in two different modes:

1. As a standalone CLI tool that stores the credentials on your local disk.
2. Use the **Passlane Vault** as storage, and have the credentials safely available in all your devices and computers.

The Passlane Vault is secured by Auth0 and OAuth 2.0. All passwords are stored encrypted and the _master password_ is not stored on our servers. The master password is only used locally to decrypt the password values and never sent to our servers.

If you want to take advantage of the Passlane Vault, head over to [passlanevault.com](https://passlanevault.com) and sign up for a **free account**. Once you have the account, run

```bash
passlane login
```

to connect the CLI with the vault.

## Installation

1. Download the [latest release](https://github.com/anssip/passlane/releases)
2. Unpack the archive
3. Place the unarchived binary `passlane` to your $PATH
4. Enjoy!
5. Optionally sign up in passlanevault.com to enable online storage and have the credentials data available to all your devices.

### To compile from sources

1. Install rust development environment: [rustup](https://rustup.rs)
2. Clone this repo
3. Build `cargo build --release`
4. Add the built `passlane` binary to your `$PATH`

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
    migrate          Migrate from legacy local credential store to passlane version 1.0 format
    login            Login to passlanevault.com
    password         Change the master password.
    push             Pushes all local credentials to the online vault.
    show             Shows one or more credentials by searching with the specified regular
                     expression.
```

### Generating and saving passwords

To generate a new password without saving it. The generated password value is also copied to the clipboard.

```
passlane
```

To save a password from clipboard:

```
passlane add -c
```

To generate a new password and save it with one command:

```
passlane add -g
```

### Using saved credentials

You can search and show saved passwords with regular expressions

```
passlane show <regexp>
```

Run `passlane show foobard.com` --> shows foobar.com's password and alco copies the value to the clipboard.

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

- Let MacOS propose the saved password. It knows it because Passlane can also sync to the keychain. See below for mor info.

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

### 1.1

- [ ] Master password update for the online vault

### 2.0

- [ ] multiple vaults support
- [ ] web UI for the online service
