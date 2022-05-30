# Passlane

A lightning-fast password generator for the command line

## Features

- Generate passwords
- Works seamlessly with Mac's spotlight search when generating passwords
- Places the generated password into the clipboard
- Save previously generated password from clipboard
- Syncs the generated password to Mac's keychain

## Usage

### Generate new password

- Sign up to a new service in the web browser
- Hit `CMD` + `space` and run `passlane` --> saves the password to the clipboard
- Use the generated password from clipboard
- Afte successful signup: Open terminal and run `passlane -s` to save the password

### Using saved credentials

Later on when logging in to foobar.com:

- Hit `CMD` + `space` and run `passlane -g foobard.com` --> copies foobar.com's password to clipboard
- Use th password from clipboard to login

_or alternatively_

- Let MacOS propose the saved password. It knows it because passlane also saves to the keychain.

### Migrating from 1Password, LastPass, Dashlane etc.

You can import credentials from a CSV file. With this approach, you can easily migrate from less elegant and oftentimes expensive commercial services.

First, make sure that the CSV file has a header line (1st line) with following column titles:

- username
- password
- service

The `service` field is the URL or name of the service. When importing from Dashlane, the only necessary preparation is to rename `url` to `service`.

To export the credentials to a CSV file and import the file into passlane:

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
- [] separate CLI option to sync to Keychain
- [] online sync?
