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
  unlock                  Store the active vault's master password in keychain
  lock                    Remove the active vault's master password from keychain
  vault [list]            List configured vaults
  vault use <name>        Switch the active vault
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

  The CSV file should have columns: username, password, title
  (older exports with a 'service' column are also accepted)"#
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
lock — Lock the active vault

  Removes the active vault's stored master password from the OS keychain.
  Use 'passlane lock --all' from the terminal to lock every vault."#
        ),
        "unlock" => println!(
            r#"
unlock — Unlock the active vault

  Opens the active vault and stores its master password in the keychain.
  Switch vaults first with 'vault use <name>'."#
        ),
        "vault" => println!(
            r#"
vault — Work with multiple vaults

  vault / vault list   List configured vaults and their state
  vault use <name>     Make a vault the active one (also switch this session)

  Add, remove or rename vaults from the terminal with 'passlane vault add',
  'passlane vault remove' and 'passlane vault rename'."#
        ),
        "status" => println!(
            r#"
status — Show vault status

  Lists all configured vaults, marks the active one with *, and shows
  whether each is unlocked (password stored in keychain) or locked."#
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
