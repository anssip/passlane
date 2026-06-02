extern crate clipboard;
extern crate magic_crypt;

mod actions;
mod completion_cache;
mod crypto;
mod keychain;
mod repl;
mod store;
mod ui;
mod vault;

use crate::actions::add::AddAction;
use crate::actions::change_password::ChangePasswordAction;
use crate::actions::completions::CompletionsAction;
use crate::actions::delete::DeleteAction;
use crate::actions::edit::EditAction;
use crate::actions::export::ExportAction;
use crate::actions::generate::GeneratePasswordAction;
use crate::actions::help::PrintHelpAction;
use crate::actions::import::ImportCsvAction;
use crate::actions::list::ListAction;
use crate::actions::lock::LockAction;
use crate::actions::show::ShowAction;
use crate::actions::unlock::UnlockAction;
use actions::*;
use clap::{arg, ArgAction, Command};
use init::InitAction;
use std::env;

pub fn cli() -> Command {
    Command::new("passlane")
        .about("A password manager using Keepass as the storage backend.")
        .subcommand_required(false)
        .arg_required_else_help(false)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("init")
                .about("Initialize passlane. Walks you through the configuration process.")
        )
        .subcommand(
            Command::new("add")
                .about("Adds an item to the vault. Without arguments adds a new credential, use -p to add a payment card and -n to add a secure note.")
                .arg(arg!(
                    -p --payments "Add a payment card."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -n --notes "Add a secure note."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -o --otp "Add a One Time Password authorizer."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -g --generate "Generate the password to be saved."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -l --clipboard "Get the password to save from the clipboard."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("edit")
                .about("Edit an entry.")
                .arg(arg!(-c --credentials "Edit credentials.").action(ArgAction::SetTrue).requires("search"))
                .arg(arg!(-p --payments "Edit payment cards.").action(ArgAction::SetTrue))
                .arg(arg!(-n --notes "Edit secure notes.").action(ArgAction::SetTrue))
                .arg(arg!(-o --otp "Edit One Time Password authorizer.").action(ArgAction::SetTrue))
                .arg(arg!(<REGEXP> "The regular expression used to search services whose credentials to edit.").group("search").required(false))
                .arg_required_else_help(true)
        )
        .subcommand(
            Command::new("csv")
                .about("Imports credentials from a CSV file.")
                .arg(arg!(<FILE_PATH> "The the CSV file to import."))
        )
        .subcommand(
            Command::new("delete")
                .about("Deletes one or more entries.")
                .arg(arg!(
                    -c --credentials "Delete credentials."
                ).action(ArgAction::SetTrue).requires("search"))
                .arg(arg!(
                    -p --payments "Delete payment cards."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -n --notes "Delete secure notes."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -o --otp "Delete One Time Password authorizer."
                ).action(ArgAction::SetTrue))
                .arg(arg!(<REGEXP> "The regular expression used to search services whose credentials to delete.").group("search").required(false))
                .arg_required_else_help(true)
        )
        .subcommand(
            Command::new("show")
                .about("Shows one or more entries.")
                .arg(arg!(
                    -v --verbose "Verbosely display matches table in clear text."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -p --payments "Shows payment cards."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -o --otp "Shows one time passwords (OTPs)"
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -n --notes "Shows secure notes."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -c --credentials "Shows credentials by searching with the specified regular expression."
                ).action(ArgAction::SetTrue).requires("search"))
                .arg(arg!(
                    --out "Print password to stdout instead of copying to clipboard."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    --plain "Render tables without borders for narrower output."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    --once "With -o, print the single matching OTP code to stdout and exit (no clipboard, no countdown). Errors if zero or multiple authorizers match. The code is valid only briefly."
                ).action(ArgAction::SetTrue))
                .arg(arg!(<REGEXP> "Regular expression used to search services to show.").group("search").required(false))
                .arg_required_else_help(true)
        )
        .subcommand(
            Command::new("list")
                .about("Lists entries from the vault for scripting and automation. WARNING: outputs passwords to stdout.")
                .arg(arg!(
                    --json "Output as JSON"
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -v --verbose "Show full details in plain text output."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -p --payments "List payment cards."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -n --notes "List secure notes."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -o --otp "List TOTP entries."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -c --credentials "List credentials (default)."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    --code "With -o, output the currently generated TOTP code for each match instead of the stored secret. Codes are valid only briefly (see valid_for_seconds)."
                ).action(ArgAction::SetTrue))
                .arg(arg!(<REGEXP> "Regular expression to filter entries.").required(false))
        )
        .subcommand(
            Command::new("lock")
                .about("Lock the vaults to prevent all access")
        )
        .subcommand(
            Command::new("unlock")
                .about("Opens the vaults and grants access to the entries")
                .arg(arg!(
                    -o --otp "Opens the one time passwords vault"
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("passwd")
                .about("Change the master password of the vault.")
                .arg(arg!(
                    -o --otp "Change the master password of the one time passwords vault."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("export")
                .about("Exports the vault contents to a CSV file.")
                .arg(arg!(
                    -p --payments "Exporet payment cards."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -n --notes "Export secure notes."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -o --otp "Shows one time passwords (OTPs)"
                ).action(ArgAction::SetTrue))
                .arg(arg!(<file_path> "The the CSV file to export to."))
        )
        .subcommand(
            Command::new("gen")
                .about("Generate a random password and copy it to the clipboard.")
                .arg(arg!(
                    --out "Print password to stdout instead of copying to clipboard."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("repl")
                .about("Launch the interactive REPL session.")
        )
        .subcommand(
            Command::new("completions")
                .about("Generate shell completions and save to ~/.passlane/. Shows the line to add to your shell rc file.")
                .arg(arg!([SHELL] "Target shell (bash, zsh, fish). Auto-detected from $SHELL if omitted."))
        )

}

fn main() {
    env_logger::init();
    completion_cache::refresh_if_stale();
    let matches = cli().get_matches();

    enum VaultAction {
        Action(Box<dyn Action>),
        UnlockingAction(Box<dyn UnlockingAction>),
    }

    let action = match matches.subcommand() {
        Some(("init", _)) => VaultAction::Action(Box::new(InitAction {})),
        Some(("add", sub_matches)) => VaultAction::Action(Box::new(AddAction::new(sub_matches))),
        Some(("show", sub_matches)) => {
            VaultAction::UnlockingAction(Box::new(ShowAction::new(sub_matches)))
        }
        Some(("list", sub_matches)) => {
            VaultAction::UnlockingAction(Box::new(ListAction::new(sub_matches)))
        }
        Some(("delete", sub_matches)) => {
            VaultAction::UnlockingAction(Box::new(DeleteAction::new(sub_matches)))
        }
        Some(("csv", sub_matches)) => {
            VaultAction::UnlockingAction(Box::new(ImportCsvAction::new(sub_matches)))
        }
        Some(("lock", _)) => VaultAction::Action(Box::new(LockAction {})),
        Some(("unlock", sub_matches)) => {
            VaultAction::Action(Box::new(UnlockAction::new(sub_matches)))
        }
        Some(("passwd", sub_matches)) => {
            VaultAction::Action(Box::new(ChangePasswordAction::new(sub_matches)))
        }
        Some(("export", sub_matches)) => {
            VaultAction::UnlockingAction(Box::new(ExportAction::new(sub_matches)))
        }
        Some(("edit", sub_matches)) => {
            VaultAction::UnlockingAction(Box::new(EditAction::new(sub_matches)))
        }
        Some(("gen", sub_matches)) => {
            VaultAction::Action(Box::new(GeneratePasswordAction::new(sub_matches)))
        }
        Some(("completions", sub_matches)) => {
            let shell = sub_matches.get_one::<String>("SHELL").cloned();
            VaultAction::Action(Box::new(CompletionsAction::new(shell, cli())))
        }
        Some(("repl", _)) => {
            repl::start_repl();
            return;
        }
        _ => {
            if env::args().len() == 1 {
                repl::start_repl();
                return;
            } else {
                VaultAction::Action(Box::new(PrintHelpAction::new(cli())))
            }
        }
    };
    match action {
        VaultAction::Action(action) => {
            action
                .run()
                .map(|msg| println!("{}", msg))
                .unwrap_or_else(|e| {
                    eprintln!("{}", e);
                    std::process::exit(1);
                });
        }
        VaultAction::UnlockingAction(action) => {
            action
                .execute()
                .map(|msg| println!("{}", msg.unwrap_or("".to_string())))
                .unwrap_or_else(|e| {
                    eprintln!("{}", e);
                    std::process::exit(1);
                });
        }
    }
}
