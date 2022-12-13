# Passlane

A lightning-fast password manager for the command line and for the Web. The data is saved in an online vault at [passlanevault.com](https://passlanevault.com). There is also a web interface that you can use to access your credentials on any device.

![Screenshot](https://i.imgur.com/TMB8DbS.webp)

## Web interface

![Web UI](https://i.imgur.com/Gr6Ae7F_d.webp?maxwidth=300&fidelity=grand)

## Features

- CLI and Web user interfaces (see below)
- Generate and save passwords
- Full management features
- Online storage with access from any device
- Import passwords from CSV files

## Installation

1. Download the [latest release](https://github.com/anssip/passlane/releases)
2. Unpack the archive
3. Place the unarchived binary `passlane` to your $PATH

### To compile from sources

1. Install rust development environment: [rustup](https://rustup.rs)
2. Clone this repo
3. Build `cargo build --release`
4. Add the built `passlane` binary to your `$PATH`

### Create an account

The Passlane Vault is secured by Auth0 and OAuth 2.0. All passwords are stored encrypted.

> Passlane stores the encryption key on your device. It never sends it out to the passlane vault servers or anywhere else. Only you, the end user, can access the encrypted data in the vault. You are the only person who has access to the encryption key.

Head over to [passlanevault.com](https://passlanevault.com) and sign up for a **free account**. Once you have the account, run

```bash
passlane login
```

to connect the CLI with the vault. The connection will stay active after that. Use the `lock` and `unlock` commands to open and close access to the vault contents after you have logged in.

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
    add         Adds a new credential to the vault.
    csv         Imports credentials from a CSV file.
    delete      Deletes one or more credentials by searching with the specified regular
                    expression.
    help        Print this message or the help of the given subcommand(s)
    lock        Lock the vaults to prevent access to clear-text passwords
    login       Login to passlanevault.com
    password    Change the master password.
    show        Shows one or more credentials by searching with the specified regular
                    expression.
    unlock      Opens the vaults and grants access to clear-text passwords
```

### Locking and unlocking

Before accessing your passwords you should unlock:

```
passlane unlock
```

This will ask for your master password which is then used to generate an encryption key. The encryption key is used for encrypting and storing password entries, and for retrieveing and decrypting these entries.

At the end of the session, lock the vaults and nobody can access the data.

```
passlane lock
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

### 2.0

Encryption keys

### Next

- [ ] Update Web UI. Check [this component](https://github.com/tbleckert/react-select-search).
- [ ] Encrypt evertyhing in the entries?

### 3.0

- [ ] Export of vault contents
- [ ] push to vault from keychain
- [ ] multiple vaults support
- [ ] new vault items: payment cards, notes
