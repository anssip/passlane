# Changelog

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
