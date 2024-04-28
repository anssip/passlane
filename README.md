# Passlane

A password manager CLI using Keepass as the storage backend. In addition to passwords, It supports secure saving and managing of 
**payment cards** and **secure notes**. Passlane uses the Keepass encrypted file format for storing the data.

Passlane CLI is written in Rust.

![Screenshot](https://i.imgur.com/TMB8DbS.webp)

## Features

- Keepass storage format which allows you to use the vault with other Keepass compatible applications
  - Supports KDB, KDBX3 and KDBX4 file formats
  - The keepass storage file can be optionally secured using a [key file](https://keepassxc.org/docs/) to provide additional protection
- Generate and save passwords
- Save and view payment card information
- Save and view secure notes
- Import passwords from CSV files
- Export vault contents to CSV files

## Table of contents

- [Installation](#installation)
- [Usage](#usage)
  - [Locking and unlocking the vault](#locking-and-unlocking-the-vault)
  - [Generating and saving passwords](#generating-and-saving-passwords)
  - [Using saved credentials](#using-saved-credentials)
  - [Payment cards](#payment-cards)
  - [Secure notes](#secure-notes)
  - [Migrating from 1Password, LastPass, Dashlane etc.](#migrating-from-1password-lastpass-dashlane-etc)
  - [Export to CSV](#export-to-csv)
- [Syncing data to your devices](#syncing-data-to-your-devices)
- [Other Keepass compatible applications](#other-keepass-compatible-applications)

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

## Usage

### Locking and unlocking the vault

Use the unlock command to store the master password in your computer's keychain. This way you don't have to enter the
master password every time you access your passwords and other vault contents. On Macs you can then use biometric authentication
to gain access to the keychain and further to the vault without typing any passwords.

```bash
passlane unlock
```

You can later remove the master password from the keychain with the lock command.

```bash
passlane lock
```

To get help on the available commands:

```bash
$  passlane -h
A password manager for the command line

Usage: passlane [COMMAND]

Commands:
  add     Adds an item to the vault. Without arguments adds a new credential, use -p to add a payment card.
  csv     Imports credentials from a CSV file.
  delete  Deletes one or more entries.
  show    Shows one or more entries.
  lock    Lock the vaults to prevent all access
  unlock  Opens the vaults and grants access to the entries
  export  Exports the vault contents to a CSV file.
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
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

Run `passlane show foobard.com` --> shows foobar.com's password and also copies the value to the clipboard.

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

## Syncing data to your devices

You can place the vault file to a cloud storage service like Dropbox, Google Drive, or iCloud Drive. 
This way you can access your passwords from all your devices.
By default, Passlane assumes that the file is located at `~/.passlane/store.kdbx`. 
You can change the location by storing the file path in a text file called `.vault_path` at the `~/.passlane/` directory.

For example, this shows how John has stored the path `/Users/john/Dropbox/Stuff/store.kdbx` to the `.vault_path` file:

```bash
➜  ~ cat ~/.passlane/.vault_path                                                                                      ~
/Users/john/Dropbox/Stuff/store.kdbx%   
```

## Other Keepass compatible applications

There are several other Keepass compatible applications that you can use to access the vault file:

- [KeepassXC](https://keepassxc.org/) is a desktop application for Windows, macOS, and Linux
- [KeepassXC-Browser](https://github.com/keepassxreboot/keepassxc-browser)
- [KeePassium](https://keepassium.com/) is a mobile application for iOS
- ... and many others

