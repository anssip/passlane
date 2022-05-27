# genpass

A lightning-fast password generator and manager written in Rust

## Features

- Generate passwords
- Works seamlessly with Mac's spotlight search when generating passwords
- Places the generated password into the clipboard
- Save previously generated password from clipboard
- Syncs the generated password to Mac's keychain

## Typical flow:

- Sign up to a new service in the web browser
- Hit `CMD` + `space` and run `genpass` --> saves the password to the clipboard
- Use the generated password from clipboard
- Afte successful signup: Open terminal and run `genpass -s` to save the password

Later on when logging in to foobar.com:

- Hit `CMD` + `space` and run `genpass -g foobard.com` --> copies foobar.com's password to clipboard
- Use th password from clipboard to login

_or alternatively_

- Let MacOS propose the saved password. It knows it because genpass also saves to the keychain.

## TODO

- delete passwords (should also remove from keychain)
- import from CSV
- online sync?
