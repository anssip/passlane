# Passlane

A lightning-fast password generator for the command line

## Features

- Generate passwords
- Works seamlessly with Mac's spotlight search when generating passwords
- Places the generated password into the clipboard
- Save previously generated password from the clipboard
- Syncs the generated password to Mac's keychain

## Usage

### Generate a new password

- Sign up for a new service in the web browser
- Hit `CMD` + `space` and run `passlane` --> saves the password to the clipboard
- Use the generated password from the clipboard
- After successful signup: Open terminal and run `passlane -s` to save the password

### Using saved credentials

Later on, when logging in to foobar.com:

- Hit `CMD` + `space` and run `passlane -g foobard.com` --> copies foobar.com's password to clipboard
- Use th password from clipboard to login

_or alternatively_

- Let MacOS propose the saved password. It knows it because Passlane also syncs to the keychain.

### Syncing with the system Keychain

Passlane uses the [keyring crate](https://crates.io/crates/keyring) to sync credentials to the operating system's keychain. Syncing should work on Linux, iOS, macOS, and Windows.

Use option `-s` together with `-k` to save the last generated password to the Passlane storage file _and_ to the keychain:

```
passlane -s -k
```

To sync all Passlane stored options to the keychain use the `-k` option alone:

```
passlane -s -k
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
passlane --csv <path_to_csv_file>
```

Here are links to instructions for doing the CSV export:

- [LastPass](https://support.lastpass.com/help/how-do-i-nbsp-export-stored-data-from-lastpass-using-a-generic-csv-file)
- [1Password](https://support.1password.com/export/)
- [Dashlane](https://support.dashlane.com/hc/en-us/articles/202625092-Export-your-passwords-from-Dashlane)

## TODO

- [] delete passwords (should also remove from keychain)
- [x] import from CSV
- [s] separate CLI option to sync to keychain
- [] online sync?
