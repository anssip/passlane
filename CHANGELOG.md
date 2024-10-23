# Changelog

## [2.5.0]

- Added the init command to easily start using this tool
- Made the UI prompts more user friendly and look better

## [2.4.3]

- Added the edit command to edit entries in the vault
- Fixed a panic that occurred when generating passwords with running passlane without any options

## [2.4.2]

- Fix to validate all input from the command line to be stored (to remove all characters not allowed in Keepass XML)
- Show last modified date for each entry in the results tables
- Fix to store OTPs as protected values in the Keepass file

## [2.4.1]

(skipped)

## [2.4.0]

- Added support for TOTP (Time-based One-Time Password) codes
- Refactor the code base significantly

## [2.3.2]

- Switch to keepass-ng dependency

## [2.3.1]

- Fix to show a proper error message when entering incorrect master password
- Fix to initial creation of the Keepass file

## [2.3.0]

- Switch to Keepass storage format
- Remove online vault

## [2.2.2]

- Fix login

## [2.2.1]

- Fix to allow multiline notes
- Export of vault contents (credentials, secure notes, payment cards)

## [2.2.0]

- Added secure notes

## [2.1.1]

- Fixed to allow null values in the user account first name and last name. [#4](https://github.com/anssip/passlane/issues/4)

## [2.1.0]

- Added possibility to manage payment cards.

## [2.0.0]

- Introduced encryption keys.
- Added the possibility to keep the vault open (with `passlane unlock`) so that the master password is not prompted with every password query.
- Encryption keys are kept on client device, only the end user can decrypt and access sensitive password info.

## [1.0.1]

- Add ability to update the master password in the online vault. Changing the master password updates every credential with newly encrypted passwords.

## [1.0.0]

- Online vault at https://passlanevault.com
- Switch to use commands instead of options in the command line
- Generate & save at the same time using `passlane add -g`
- Delete should not ask master password
- `migrate` command to migrate from old format without iv

## [0.1.4]

- New feature: Show results in table when querying for passwords using `--gerp`
- New feature: Add possibility to delete passwords using `--delete`
- Fixed: "Failed: Unable to retrieve value from clipboard" --> prompt for the password to be saved

## [0.1.3]

- Add ability to save passwords entered by the user - not just saving of the previously genereted one from clipboard.
- Added `--verbose` option to show passwords when grepping with the `--g` option.
- Passwords prompt input no longer shows the entered passwords.

# [0.1.0]

- Initial release
