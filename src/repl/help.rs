pub fn print_help(command: Option<&str>) {
    match command {
        None => print_general_help(),
        Some(cmd) => print_command_help(cmd),
    }
}

fn print_general_help() {
    println!(
        r#"
Available commands:

  show [type] [pattern]   Show entries (default: all credentials)
  add [type]              Add a new entry (default: credential)
  edit [type] [pattern]   Edit an existing entry
  delete [type] [pattern] Delete an entry
  gen                     Generate a random password
  import <file>           Import credentials from a CSV file
  export [type] <file>    Export entries to a CSV file
  unlock [otp]            Store master password in keychain
  lock                    Remove master passwords from keychain
  status                  Show vault status
  completions             Show how to install shell completions
  help [command]          Show help (or help for a specific command)
  quit / exit             Exit the REPL

Types: creds, cards, notes, otp
  Aliases: cred/credentials, card/payments, note, totp

Type 'help <command>' for detailed usage."#
    );
}

fn print_command_help(cmd: &str) {
    match cmd {
        "show" => println!(
            r#"
show [type] [pattern] — Show entries from the vault

  show                Show all credentials
  show <pattern>      Show credentials matching the regex pattern
  show cards          Show all payment cards
  show notes          Show all secure notes
  show otp            Show all TOTP entries
  show otp <pattern>  Show TOTP entries matching the pattern

When a single credential is found, its password is copied to clipboard."#
        ),
        "add" => println!(
            r#"
add [type] — Add a new entry to the vault

  add          Add a new credential (prompts for details)
  add card     Add a new payment card
  add note     Add a new secure note
  add otp      Add a new TOTP entry"#
        ),
        "edit" => println!(
            r#"
edit [type] [pattern] — Edit an existing entry

  edit <pattern>      Edit credentials matching the regex pattern
  edit card           Edit a payment card
  edit note           Edit a secure note
  edit otp            Edit a TOTP entry"#
        ),
        "delete" => println!(
            r#"
delete [type] [pattern] — Delete an entry

  delete <pattern>    Delete credentials matching the regex pattern
  delete card         Delete a payment card
  delete note         Delete a secure note
  delete otp          Delete a TOTP entry"#
        ),
        "gen" => println!(
            r#"
gen — Generate a random password

  Generates a secure random password, prints it, and copies it to clipboard."#
        ),
        "import" => println!(
            r#"
import <file> — Import credentials from a CSV file

  import /path/to/file.csv

  The CSV file should have columns: username, password, service"#
        ),
        "export" => println!(
            r#"
export [type] <file> — Export entries to a CSV file

  export output.csv             Export all credentials
  export cards cards.csv        Export payment cards
  export notes notes.csv        Export secure notes"#
        ),
        "lock" => println!(
            r#"
lock — Lock the vaults

  Removes stored master passwords from the OS keychain for both the main
  vault and the TOTP vault."#
        ),
        "unlock" => println!(
            r#"
unlock [otp] — Unlock a vault

  unlock       Unlock the main vault (store password in keychain)
  unlock otp   Unlock the TOTP vault"#
        ),
        "status" => println!(
            r#"
status — Show vault status

  Displays whether each vault is unlocked (password stored in keychain)
  or locked, and shows the configured vault file paths."#
        ),
        "completions" => println!(
            r#"
completions — Show shell completion installation instructions

  Displays how to set up tab-completion for bash, zsh, and fish.
  Run 'passlane completions' from your terminal (not the REPL) to
  generate the script and get the line to add to your shell rc file.

  The REPL already has built-in tab completion for commands and types."#
        ),
        _ => {
            eprintln!("Unknown command: '{}'. Type 'help' for available commands.", cmd);
        }
    }
}
