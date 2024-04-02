# Passlane

Passlane is a password manager for the command line and for the Web. There is also a web interface at [passlanevault.com](https://passlanevault.com) that you can use to access your credentials on any device.

Passlane also supports secure saving and managing of **payment cards** and **secure notes**.

Passlane CLI is written in Rust.

![Screenshot](https://i.imgur.com/TMB8DbS.webp)

## Features

- You control the encryption keys: Your keys, your data.
- CLI and Web user interfaces (see below)
- Generate and save passwords
- Save and view payment card information
- Save and view secure notes
- Full management features
- Online storage with access from any device
- Import passwords from CSV files
- Export vault contents to CSV files

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

Run with nix  - following creates a new password:

```bash
nix run github:anssip/passlane
```

See below for more information on how to use the CLI.

### Create an account

The Passlane Vault is secured by Auth0 and OAuth 2.0. All passwords are stored encrypted.

> Passlane stores the encryption key on your device. It never sends it out to the passlane vault servers or anywhere else. Only you, the end user, can access the encrypted data in the vault. You are the only person who has access to the encryption key.

Head over to [passlanevault.com](https://passlanevault.com) and sign up for a **free account**. Once you have the account, run

```bash
passlane login
```

after logging in, unlock the vault. The first time you run this, it will ask you to pick up a master password. 
The master password is used to generate an encryption key that is used to encrypt and decrypt the vault contents.

```bash
passlane unlock
```


to connect the CLI with the vault. The connection will stay active after that. Use the `lock` and `unlock` commands to open and close access to the vault contents after you have logged in.

## Usage

```bash
$  passlane -h
A password manager and a CLI client for the online Passlane Vault

Usage: passlane [COMMAND]

Commands:
  login     Login to the online vault.
  password  Change the master password.
  add       Adds an item to the vault. Without arguments adds a new credential, use -p to add a payment card.
  csv       Imports credentials from a CSV file.
  delete    Deletes one or more entries.
  show      Shows one or more entries.
  lock      Lock the vaults to prevent all access
  unlock    Opens the vaults and grants access to the entries
  export    Exports the vault contents to a CSV file.
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### Locking and unlocking

Before accessing your passwords you should unlock:

```bash
passlane unlock
```

This will ask for your master password which is then used to generate an encryption key. The encryption key is used for encrypting and storing password entries, and for retrieveing and decrypting these entries.

At the end of the session, lock the vaults and nobody can access the data.

```bash
passlane lock
```

### Generating and saving passwords

To generate a new password without saving it. The generated password value is also copied to the clipboard.

```bash
passlane
```

To save new credentials by copying the password from clipboard:

```bash
passlane add -c --clipboard
```

To generate a new password and save credentials with one command:

```bash
passlane add -c -g
```

### Using saved credentials

You can search and show saved credentials with regular expressions

```bash
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

### Payment cards

To list all your saved payment cards.

```bash
passlane show -p

Found 1 payment cards:
+---+---------------+-------+--------+--------+
|   | Name          | Color | Last 4 | Expiry |
+=============================================+
| 0 | Personal Visa | White | 1234   | 9/25   |
+---+---------------+-------+--------+--------+
Do you want to see the card details? (y/n) y
```

To save a payment card:

```bash
passlane add -p
```

You can delete a note with the delete command and the -n option.


### Secure notes

You can also save and manage **secure notes** in Passlane. The contents of notes, the title and the note text itself, are all fully encrypted and only visible to you.

To add a secure note:

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
